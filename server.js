const WebSocket=require("ws");const http=require("http");
const server=http.createServer((req,res)=>{res.writeHead(200,{"Content-Type":"text/plain"});res.end("COESPA - Servidor de sinalizacao rodando")});
const wss=new WebSocket.Server({server});
const rooms=new Map();
const getRoom=id=>{if(!rooms.has(id))rooms.set(id,new Map());return rooms.get(id)};

wss.on("connection",ws=>{
  ws.id=Math.random().toString(36).slice(2);ws.roomId=null;ws.meta={};
  ws.on("message",raw=>{
    let m;try{m=JSON.parse(raw)}catch{return}
    if(m.type==="list-competitions"){
      const list=[...rooms.entries()].map(([pin,room])=>({pin,name:room.compName||"",
        athletes:[...room.values()].filter(c=>c.meta.role==="athlete").length,raceStarted:!!room.raceStarted}))
        .filter(r=>r.athletes>0||r.raceStarted);
      ws.send(JSON.stringify({type:"competitions-list",competitions:list}));return;
    }
    if(m.type==="join"){
      ws.roomId=m.room||"COESPA-DEMO";ws.meta={role:m.role,name:m.name,uid:m.uid};
      const room=getRoom(ws.roomId);
      if(m.role==="central"&&m.compName)room.compName=m.compName;
      room.set(ws.id,ws);
      const peers=[...room.entries()].filter(([id])=>id!==ws.id).map(([id,c])=>({id,role:c.meta.role,name:c.meta.name,uid:c.meta.uid}));
      ws.send(JSON.stringify({type:"joined",peers,raceStarted:!!room.raceStarted}));
      for(const[id,c]of room)if(id!==ws.id&&c.readyState===1)c.send(JSON.stringify({type:"peer-joined",peer:{id:ws.id,role:ws.meta.role,name:ws.meta.name,uid:ws.meta.uid}}));
      return;
    }
    if(!ws.roomId)return;
    const room=getRoom(ws.roomId);
    if(["race-start","race-stop","race-reset"].includes(m.type)){
      if(ws.meta.role!=="central")return;
      if(m.type==="race-start")room.raceStarted=true;
      if(m.type==="race-stop")room.raceStarted=false;
      for(const[,c]of room)if(c!==ws&&c.readyState===1)c.send(JSON.stringify(m));
      return;
    }
    if(m.to!==undefined){const t=room.get(m.to);if(t&&t.readyState===1){m.from=ws.id;t.send(JSON.stringify(m))}return}
    for(const[id,c]of room)if(id!==ws.id&&c.readyState===1)c.send(JSON.stringify(m));
  });
  ws.on("close",()=>{
    if(!ws.roomId)return;
    const room=getRoom(ws.roomId);room.delete(ws.id);
    if(!room.size)rooms.delete(ws.roomId);
    for(const[,c]of room)if(c.readyState===1)c.send(JSON.stringify({type:"peer-left",id:ws.id}));
  });
});
setInterval(()=>wss.clients.forEach(c=>{if(c.readyState===1)c.ping()}),30000);
const PORT=process.env.PORT||3000;
server.listen(PORT,()=>console.log("Servidor COESPA na porta "+PORT));
