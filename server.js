// Servidor de sinalização + login + persistência do COESPA Conectado.
// Esta versão NÃO serve o HTML — o frontend fica hospedado à parte (ex.: Hostinger),
// porque hospedagens compartilhadas comuns não rodam Node.js / WebSocket.
// Publique este arquivo em um serviço que rode Node.js continuamente (ex.: Render).
// A URL gerada (ex.: https://coespa-servidor.onrender.com) alimenta DUAS constantes
// no index.html: SIGNALING_URL (trocando "https://" por "wss://") e API_URL
// (a mesma URL, com "https://" mesmo — é usada para login/cadastro via fetch).
//
// ===== Variáveis de ambiente necessárias (configurar no painel do Render) =====
//   SUPABASE_URL              -> Project URL (Settings → API, no painel do Supabase)
//   SUPABASE_SERVICE_ROLE_KEY -> service_role key (Settings → API) — NUNCA no front-end
//   SEF_USERNAME, SEF_PASSWORD-> login "de fábrica" da SEF/Central (funciona mesmo
//                                sem nenhuma linha no banco — resolve o problema de
//                                "quem cadastra o primeiro usuário?")
//   JWT_SECRET                -> qualquer texto longo e aleatório, mantido em segredo
//   CORS_ORIGIN (opcional)    -> domínio da Hostinger (ex.: https://seusite.com);
//                                sem isso, aceita qualquer origem ("*")
//
// ===== Tabelas do Supabase (rodar uma vez no SQL Editor do projeto) =====
//   create table app_users (
//     id bigint generated always as identity primary key,
//     username text unique not null,
//     password_hash text not null,
//     name text not null,
//     role text not null check (role in ('athlete','central')),
//     squad text,                 -- [ADICIONADO] esquadrão do atleta (Amarelo/Azul/Verde/Branco/Prata)
//     million text,                -- [ADICIONADO] milhão, numeração única do aluno (ex.: "26/1137")
//     created_at timestamptz default now()
//   );
//   -- Se a tabela já existe, rode em vez disso:
//   --   alter table app_users add column if not exists squad text;
//   --   alter table app_users add column if not exists million text;
//   create table competitions (
//     pin text primary key,
//     name text,
//     created_at timestamptz default now(),
//     race_started boolean default false,
//     course jsonb default '[]'::jsonb,
//     map_url text,
//     map_corners jsonb,
//     map_opacity double precision
//   );
//   create table gps_log (
//     id bigint generated always as identity primary key,
//     pin text,
//     athlete_uid text,
//     athlete_name text,
//     lat double precision, lon double precision, alt double precision,
//     accuracy double precision, dist double precision, elev double precision,
//     recorded_at timestamptz default now()
//   );
//
// Teste local: defina as variáveis de ambiente (ex.: num arquivo .env carregado
// manualmente) e rode: npm install && npm start

const http = require("http");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const WebSocket = require("ws");

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "troque-este-segredo-antes-de-publicar";
const SEF_USERNAME = (process.env.SEF_USERNAME || "sef").toLowerCase();
const SEF_PASSWORD = process.env.SEF_PASSWORD || "1234";

const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
  : null;
if (!supabase) console.warn("[aviso] SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY não configurados — login de atletas e persistência ficam indisponíveis (a SEF ainda consegue entrar com SEF_USERNAME/SEF_PASSWORD).");

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json({ limit: "8mb" })); // o mapa da prova vai embutido como imagem (base64), por isso o limite maior

// ===== Autenticação HTTP (login/cadastro) =====
function signToken(user) { return jwt.sign({ role: user.role, username: user.username }, JWT_SECRET, { expiresIn: "12h" }); }
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sem token de acesso." });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Sessão inválida ou expirada. Faça login novamente." }); }
}
function requireCentral(req, res, next) {
  if (req.user?.role !== "central") return res.status(403).json({ error: "Só a SEF / Central pode fazer isso." });
  next();
}

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Preencha usuário e senha." });
  const u = String(username).trim().toLowerCase();

  // Login "de fábrica" da SEF — sempre funciona, mesmo com o banco vazio ou fora do ar.
  if (u === SEF_USERNAME && password === SEF_PASSWORD) {
    const user = { role: "central", username: u, name: "SEF / CENTRAL" };
    return res.json({ token: signToken(user), user });
  }

  if (!supabase) return res.status(503).json({ error: "Banco de dados não configurado no servidor." });
  try {
    const { data, error } = await supabase.from("app_users").select("*").eq("username", u).maybeSingle();
    if (error) throw error;
    if (!data || !(await bcrypt.compare(password, data.password_hash))) {
      return res.status(401).json({ error: "Usuário ou senha incorretos." });
    }
    const user = { role: data.role, username: data.username, name: data.name };
    res.json({ token: signToken(user), user });
  } catch (e) {
    console.error("Erro no login:", e.message);
    res.status(500).json({ error: "Erro ao consultar o banco de dados." });
  }
});

app.post("/api/register", requireAuth, requireCentral, async (req, res) => {
  const { username, password, name, role, squad, million } = req.body || {};
  if (!username || !password || !name || password.length < 4 || !["athlete", "central"].includes(role)) {
    return res.status(400).json({ error: "Preencha nome, usuário, um perfil válido e uma senha com pelo menos 4 caracteres." });
  }
  // [ADICIONADO] esquadrão e milhão só se aplicam a atletas; valida o formato do milhão (AA/NNNN)
  // quando ele vier preenchido, mas não impede o cadastro de contas antigas que ainda não o enviem.
  const SQUADS = ["Amarelo", "Azul", "Verde", "Branco", "Prata"];
  if (role === "athlete" && squad && !SQUADS.includes(squad)) {
    return res.status(400).json({ error: "Esquadrão inválido." });
  }
  if (role === "athlete" && million && !/^\d{2}\/\d{1,6}$/.test(String(million).trim())) {
    return res.status(400).json({ error: "Milhão em formato inválido. Use AA/NNNN, ex.: 26/1137." });
  }
  if (!supabase) return res.status(503).json({ error: "Banco de dados não configurado no servidor." });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from("app_users").insert({
      username: String(username).trim().toLowerCase(), password_hash: hash, name: String(name).trim(), role,
      squad: role === "athlete" && squad ? squad : null,
      million: role === "athlete" && million ? String(million).trim() : null,
    });
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Esse usuário já existe." });
      throw error;
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("Erro ao cadastrar usuário:", e.message);
    res.status(500).json({ error: "Erro ao cadastrar." });
  }
});

app.get("/api/users", requireAuth, requireCentral, async (req, res) => {
  if (!supabase) return res.json({ users: [] });
  try {
    const { data, error } = await supabase.from("app_users").select("username,name,role,squad,million").order("name"); // [ADICIONADO] squad,million
    if (error) throw error;
    res.json({ users: data || [] });
  } catch (e) {
    res.status(500).json({ error: "Erro ao consultar o banco de dados." });
  }
});

// Resposta simples em / , só para health check do serviço de hospedagem.
app.get("/", (req, res) => {
  res.type("text/plain").send("COESPA Conectado — servidor de sinalização no ar.");
});

// ===== Persistência (Supabase) — funções auxiliares, nunca travam a sinalização =====
async function loadCompetition(pin) {
  if (!supabase) return null;
  try {
    const { data } = await supabase.from("competitions").select("*").eq("pin", pin).maybeSingle();
    return data || null;
  } catch { return null; }
}
async function upsertCompetition(pin, patch) {
  if (!supabase) return;
  try { await supabase.from("competitions").upsert({ pin, ...patch }); }
  catch (e) { console.error("Erro ao salvar competição:", e.message); }
}
function logGps(pin, msg) {
  if (!supabase) return;
  supabase.from("gps_log").insert({
    pin, athlete_uid: msg.uid, athlete_name: msg.name,
    lat: msg.lat, lon: msg.lon, alt: msg.alt, accuracy: msg.accuracy, dist: msg.dist, elev: msg.elev,
  }).then(({ error }) => { if (error) console.error("Erro ao gravar GPS:", error.message); });
}

// ===== Servidor HTTP + WebSocket (sinalização) =====
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

let nextId = 1;
const rooms = new Map(); // room -> Map(id -> {id, ws, role, name, uid})
const raceState = new Map(); // room -> boolean (prova iniciada?)
const competitionNames = new Map(); // room -> nome da competição (informado pela Central)
const courseState = new Map(); // room -> array de pontos do percurso (largada/controles/chegada)
const mapImageState = new Map(); // room -> {url, corners, opacity} do mapa georreferenciado, ou null

function peersOf(room) {
  if (!rooms.has(room)) rooms.set(room, new Map());
  return rooms.get(room);
}

function broadcastToRoom(room, msg, excludeId) {
  const peers = peersOf(room);
  peers.forEach(p => {
    if (p.id !== excludeId && p.ws.readyState === WebSocket.OPEN) {
      p.ws.send(JSON.stringify(msg));
    }
  });
}

wss.on("connection", (ws) => {
  ws.id = nextId++;
  ws.room = null;
  ws.role = null;

  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === "join") {
      // Espectador não tem login — para atleta/SEF, o token do /api/login precisa ser válido.
      if (msg.role !== "spectator") {
        try { jwt.verify(msg.token || "", JWT_SECRET); }
        catch {
          ws.send(JSON.stringify({ type: "join-error", message: "Sessão inválida. Faça login novamente." }));
          return;
        }
      }

      ws.room = msg.room || "COESPA-DEMO";
      ws.role = msg.role;
      ws.name = msg.name;
      ws.uid = msg.uid;
      if (ws.role === "central" && msg.compName) competitionNames.set(ws.room, msg.compName);

      // Se a sala não está em memória (primeira pessoa a entrar, ou o servidor
      // reiniciou), tenta recuperar percurso/mapa/estado da prova salvos no Supabase.
      if (!rooms.has(ws.room)) {
        const saved = await loadCompetition(ws.room);
        if (saved) {
          if (saved.race_started) raceState.set(ws.room, true);
          if (saved.name) competitionNames.set(ws.room, saved.name);
          if (Array.isArray(saved.course) && saved.course.length) courseState.set(ws.room, saved.course);
          if (saved.map_url && saved.map_corners) {
            mapImageState.set(ws.room, { url: saved.map_url, corners: saved.map_corners, opacity: saved.map_opacity });
          }
        }
      }
      const peers = peersOf(ws.room);

      const list = [...peers.values()].map(p => ({ id: p.id, role: p.role, name: p.name }));
      ws.send(JSON.stringify({
        type: "joined",
        peers: list,
        raceStarted: !!raceState.get(ws.room),
        course: courseState.get(ws.room) || [],
        mapImage: mapImageState.get(ws.room) || null,
      }));

      peers.forEach(p => p.ws.readyState === WebSocket.OPEN &&
        p.ws.send(JSON.stringify({ type: "peer-joined", peer: { id: ws.id, role: ws.role, name: ws.name } })));

      peers.set(ws.id, { id: ws.id, ws, role: ws.role, name: ws.name });

      if (ws.role === "central") upsertCompetition(ws.room, { name: competitionNames.get(ws.room) || null });
      return;
    }

    if (["offer", "answer", "ice", "renegotiate"].includes(msg.type)) {
      const peers = peersOf(ws.room);
      const target = peers.get(msg.to);
      if (target && target.ws.readyState === WebSocket.OPEN) {
        target.ws.send(JSON.stringify({ ...msg, from: ws.id }));
      }
      return;
    }

    if (msg.type === "gps") {
      broadcastToRoom(ws.room, { ...msg, from: ws.id }, ws.id);
      logGps(ws.room, msg); // grava o histórico para replay/resultados futuros (não bloqueia o repasse)
      return;
    }
    if (msg.type === "cam-status") {
      broadcastToRoom(ws.room, { ...msg, from: ws.id }, ws.id);
      return;
    }

    if (msg.type === "course-sync") {
      if (ws.role !== "central") return;
      courseState.set(ws.room, Array.isArray(msg.points) ? msg.points : []);
      broadcastToRoom(ws.room, { type: "course-sync", points: courseState.get(ws.room) }, ws.id);
      upsertCompetition(ws.room, { course: courseState.get(ws.room) });
      return;
    }

    if (msg.type === "map-image") {
      if (ws.role !== "central") return;
      if (msg.remove) {
        mapImageState.delete(ws.room);
        broadcastToRoom(ws.room, { type: "map-image", remove: true }, ws.id);
        upsertCompetition(ws.room, { map_url: null, map_corners: null, map_opacity: null });
      } else if (msg.url && msg.corners) {
        mapImageState.set(ws.room, { url: msg.url, corners: msg.corners, opacity: msg.opacity });
        broadcastToRoom(ws.room, { type: "map-image", url: msg.url, corners: msg.corners, opacity: msg.opacity }, ws.id);
        upsertCompetition(ws.room, { map_url: msg.url, map_corners: msg.corners, map_opacity: msg.opacity ?? null });
      }
      return;
    }

    if (msg.type === "list-competitions") {
      const list = [...rooms.entries()]
        .filter(([, peers]) => [...peers.values()].some(p => p.role === "central"))
        .map(([room, peers]) => ({
          pin: room,
          name: competitionNames.get(room) || "",
          athletes: [...peers.values()].filter(p => p.role === "athlete").length,
          raceStarted: !!raceState.get(room),
        }));
      ws.send(JSON.stringify({ type: "competitions-list", competitions: list }));
      return;
    }

    if (msg.type === "race-start" || msg.type === "race-stop" || msg.type === "race-reset") {
      if (msg.type !== "race-reset") raceState.set(ws.room, msg.type === "race-start");
      broadcastToRoom(ws.room, { ...msg, from: ws.id }, ws.id);
      if (msg.type !== "race-reset") upsertCompetition(ws.room, { race_started: msg.type === "race-start" });
      return;
    }
  });

  ws.on("close", () => {
    if (!ws.room) return;
    const peers = peersOf(ws.room);
    peers.delete(ws.id);
    peers.forEach(p => p.ws.readyState === WebSocket.OPEN &&
      p.ws.send(JSON.stringify({ type: "peer-left", id: ws.id })));
    if (peers.size === 0) {
      rooms.delete(ws.room);
      raceState.delete(ws.room);
      competitionNames.delete(ws.room);
      courseState.delete(ws.room);
      mapImageState.delete(ws.room);
      // Note: os dados continuam salvos no Supabase mesmo com a sala vazia —
      // só o cache em memória é limpo, para não crescer sem limite.
    }
  });
});

server.listen(PORT, () => console.log("COESPA Conectado rodando na porta " + PORT));
