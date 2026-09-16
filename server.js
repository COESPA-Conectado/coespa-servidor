// ============================================================================
// COESPA Conectado — servidor (sinalização WebSocket + cadastro/login)
// ----------------------------------------------------------------------------
// Este arquivo tem duas partes:
//   1) A parte de WebSocket (salas, GPS, vídeo, controle de prova) — é a
//      mesma lógica que você já tinha, só com uma checagem nova no "join".
//   2) A parte NOVA: três rotas HTTP para cadastro e login, que conversam
//      com o banco de dados no Supabase.
// ============================================================================

const WebSocket = require("ws");
const http = require("http");
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ----------------------------------------------------------------------------
// Configuração — estes valores NUNCA ficam escritos no código. Eles vêm de
// "variáveis de ambiente" que você vai cadastrar no painel do Render
// (aba "Environment"). Isso evita que a senha do banco ou a chave secreta
// apareçam no GitHub ou em qualquer lugar público.
// ----------------------------------------------------------------------------
const DATABASE_URL = process.env.DATABASE_URL;   // string de conexão do Supabase
const JWT_SECRET = process.env.JWT_SECRET;       // uma frase secreta, só sua, para "assinar" os tokens
const SETUP_KEY = process.env.SETUP_KEY;         // senha extra, só para criar o PRIMEIRO usuário SEF

if (!DATABASE_URL || !JWT_SECRET || !SETUP_KEY) {
  console.warn(
    "AVISO: faltam variáveis de ambiente (DATABASE_URL, JWT_SECRET ou SETUP_KEY). " +
    "Configure-as no painel do Render em Environment antes de usar o cadastro/login."
  );
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // o Supabase exige conexão criptografada
});

// ----------------------------------------------------------------------------
// Servidor HTTP (Express) — recebe as chamadas de cadastro/login do site
// ----------------------------------------------------------------------------
const app = express();
app.use(express.json());

// Permite que o site (hospedado em outro domínio, na Hostinger) chame estas
// rotas. Sem isso, o navegador bloqueia a chamada por segurança (CORS).
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-setup-key");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.get("/", (req, res) => {
  res.send("COESPA Conectado — servidor no ar.");
});

// Confere se quem está chamando a rota enviou um token válido de SEF/Central.
// Isso é o que garante que só a SEF cadastra gente nova.
function requireCentral(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Não autenticado." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "central") {
      return res.status(403).json({ error: "Só a SEF pode fazer isso." });
    }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Sessão inválida ou expirada. Faça login novamente." });
  }
}

// --- LOGIN --------------------------------------------------------------
// O navegador manda usuário e senha; o servidor confere no banco e, se
// bater, devolve um "token" (um crachá temporário) que o navegador guarda
// e usa depois para provar quem é, sem precisar mandar a senha de novo.
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Informe usuário e senha." });
  }
  try {
    const { rows } = await pool.query("select * from users where username=$1", [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Usuário ou senha inválidos." });

    const senhaCorreta = await bcrypt.compare(password, user.password_hash);
    if (!senhaCorreta) return res.status(401).json({ error: "Usuário ou senha inválidos." });

    const token = jwt.sign(
      { sub: user.id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: "18h" }
    );
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// --- CADASTRO (só a SEF pode chamar) ------------------------------------
app.post("/api/register", requireCentral, async (req, res) => {
  const { username, password, name, role } = req.body || {};
  if (!username || !password || !name || !role) {
    return res.status(400).json({ error: "Preencha todos os campos." });
  }
  if (!["athlete", "central"].includes(role)) {
    return res.status(400).json({ error: "Papel inválido." });
  }
  if (String(password).length < 4) {
    return res.status(400).json({ error: "A senha precisa ter pelo menos 4 caracteres." });
  }
  try {
    const existe = await pool.query("select id from users where username=$1", [username]);
    if (existe.rows.length) {
      return res.status(409).json({ error: "Esse nome de usuário já existe." });
    }
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "insert into users(name, role, username, password_hash) values ($1,$2,$3,$4) returning id, name, role, username, created_at",
      [name, role, username, hash]
    );
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    console.error("Erro no cadastro:", err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// --- LISTAR USUÁRIOS (só a SEF vê) --------------------------------------
// Serve para a tela da SEF mostrar, em qualquer aparelho, todos os atletas
// já cadastrados — resolvendo o problema de sincronização entre dispositivos.
app.get("/api/users", requireCentral, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "select id, name, role, username, created_at from users order by created_at desc"
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("Erro ao listar usuários:", err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// --- CRIAÇÃO DO PRIMEIRO USUÁRIO (uso único) ----------------------------
// Como só a SEF pode cadastrar gente, e no início não existe NENHUMA SEF
// cadastrada, esta rota especial cria a primeira conta. Ela só funciona:
//   a) se a tabela de usuários estiver vazia, e
//   b) se quem chamar souber a "SETUP_KEY" (uma senha extra que só você,
//      o desenvolvedor, vai saber — ela fica só no Render, não no site).
// Depois que existir 1 usuário, esta rota se desativa sozinha.
app.post("/api/setup-first-admin", async (req, res) => {
  try {
    const chave = req.headers["x-setup-key"];
    if (!chave || chave !== SETUP_KEY) {
      return res.status(403).json({ error: "Chave de configuração inválida." });
    }
    const { rows: contagem } = await pool.query("select count(*)::int as total from users");
    if (contagem[0].total > 0) {
      return res.status(403).json({ error: "Já existe usuário cadastrado. Use o login normal." });
    }
    const { username, password, name } = req.body || {};
    if (!username || !password || !name) {
      return res.status(400).json({ error: "Preencha todos os campos." });
    }
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "insert into users(name, role, username, password_hash) values ($1,'central',$2,$3) returning id, name, role, username",
      [name, username, hash]
    );
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    console.error("Erro ao criar primeiro usuário:", err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// ----------------------------------------------------------------------------
// Servidor WebSocket (sinalização) — mesma lógica de antes, com UMA mudança:
// no "join", se o papel for "central" ou "athlete", agora é obrigatório
// enviar um token válido (recebido no /api/login). Isso fecha a brecha de
// alguém simplesmente "se declarar" SEF sem ter feito login de verdade.
// ----------------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const rooms = new Map();
const getRoom = (id) => {
  if (!rooms.has(id)) rooms.set(id, new Map());
  return rooms.get(id);
};

wss.on("connection", (ws) => {
  ws.id = Math.random().toString(36).slice(2);
  ws.roomId = null;
  ws.meta = {};
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.type === "list-competitions") {
      const list = [...rooms.entries()]
        .map(([pin, room]) => ({
          pin,
          name: room.compName || "",
          athletes: [...room.values()].filter((c) => c.meta.role === "athlete").length,
          raceStarted: !!room.raceStarted,
        }))
        .filter((r) => r.athletes > 0 || r.raceStarted);
      ws.send(JSON.stringify({ type: "competitions-list", competitions: list }));
      return;
    }

    if (m.type === "join") {
      let role = m.role, name = m.name, uid = m.uid;

      // NOVO: exige token válido para quem afirma ser SEF ou atleta.
      if (role === "central" || role === "athlete") {
        try {
          const payload = jwt.verify(m.token || "", JWT_SECRET);
          if (payload.role !== role) {
            ws.send(JSON.stringify({ type: "join-error", message: "Sessão não corresponde ao papel escolhido." }));
            return;
          }
          role = payload.role;
          name = payload.name;
          uid = payload.username;
        } catch {
          ws.send(JSON.stringify({ type: "join-error", message: "Sessão inválida ou expirada. Faça login novamente." }));
          return;
        }
      }

      ws.roomId = m.room || "COESPA-DEMO";
      ws.meta = { role, name, uid };
      const room = getRoom(ws.roomId);
      if (role === "central" && m.compName) room.compName = m.compName;
      room.set(ws.id, ws);

      const peers = [...room.entries()]
        .filter(([id]) => id !== ws.id)
        .map(([id, c]) => ({ id, role: c.meta.role, name: c.meta.name, uid: c.meta.uid }));
      ws.send(JSON.stringify({ type: "joined", peers, raceStarted: !!room.raceStarted }));

      for (const [id, c] of room) {
        if (id !== ws.id && c.readyState === 1) {
          c.send(JSON.stringify({ type: "peer-joined", peer: { id: ws.id, role: ws.meta.role, name: ws.meta.name, uid: ws.meta.uid } }));
        }
      }
      return;
    }

    if (!ws.roomId) return;
    const room = getRoom(ws.roomId);

    if (["race-start", "race-stop", "race-reset"].includes(m.type)) {
      if (ws.meta.role !== "central") return;
      if (m.type === "race-start") room.raceStarted = true;
      if (m.type === "race-stop") room.raceStarted = false;
      for (const [, c] of room) if (c !== ws && c.readyState === 1) c.send(JSON.stringify(m));
      return;
    }

    if (m.to !== undefined) {
      const t = room.get(m.to);
      if (t && t.readyState === 1) {
        m.from = ws.id;
        t.send(JSON.stringify(m));
      }
      return;
    }

    for (const [id, c] of room) {
      if (id !== ws.id && c.readyState === 1) c.send(JSON.stringify(m));
    }
  });

  ws.on("close", () => {
    if (!ws.roomId) return;
    const room = getRoom(ws.roomId);
    room.delete(ws.id);
    if (!room.size) rooms.delete(ws.roomId);
    for (const [, c] of room) if (c.readyState === 1) c.send(JSON.stringify({ type: "peer-left", id: ws.id }));
  });

  ws.on("error", () => {});
});

// A cada 30s, fecha conexões que pararam de responder (celular sem sinal,
// aba fechada sem avisar, etc.) para não acumular "fantasmas" em memória.
setInterval(() => {
  wss.clients.forEach((c) => {
    if (c.isAlive === false) return c.terminate();
    c.isAlive = false;
    if (c.readyState === 1) c.ping();
  });
}, 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Servidor COESPA na porta " + PORT));
