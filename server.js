import express from "express";
import http from "http";
import path from "path";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import session from "express-session";
import multer from "multer";
import { Server } from "socket.io";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database(path.join(__dirname, "data", "chat.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL, display_name TEXT NOT NULL, avatar TEXT DEFAULT '',
 bio TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rooms(
 id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL, description TEXT DEFAULT '', private INTEGER DEFAULT 0,
 password TEXT DEFAULT '', owner_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS memberships(
 user_id INTEGER NOT NULL, room_id INTEGER NOT NULL, role TEXT DEFAULT 'member',
 PRIMARY KEY(user_id,room_id)
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
 type TEXT DEFAULT 'text', body TEXT DEFAULT '', file_url TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reads(
 user_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
 PRIMARY KEY(user_id,message_id)
);
`);

app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",maxAge:7*24*60*60*1000}
}));
app.use("/uploads", express.static(path.join(__dirname,"uploads")));
app.use(express.static(path.join(__dirname,"public")));

const storage = multer.diskStorage({
 destination: (_,__,cb)=>cb(null,path.join(__dirname,"uploads")),
 filename: (_,file,cb)=>cb(null,Date.now()+"-"+crypto.randomBytes(6).toString("hex")+path.extname(file.originalname))
});
const upload = multer({storage, limits:{fileSize:100*1024*1024}});

const auth = (req,res,next)=> req.session.userId ? next() : res.status(401).json({error:"يجب تسجيل الدخول"});
const userById = id => db.prepare("SELECT id,username,display_name,avatar,bio,created_at FROM users WHERE id=?").get(id);
const roomByCode = code => db.prepare("SELECT * FROM rooms WHERE code=?").get(code);
const isMember = (uid,rid)=>!!db.prepare("SELECT 1 FROM memberships WHERE user_id=? AND room_id=?").get(uid,rid);

app.post("/api/register", async (req,res)=>{
  const {username,password,displayName,bio=""}=req.body;
  if(!username || !password || !displayName) return res.status(400).json({error:"املأ الحقول المطلوبة"});
  if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:"اليوزر يجب أن يكون 3-24 حرفاً أو رقماً"});
  if(password.length<6) return res.status(400).json({error:"كلمة السر 6 أحرف على الأقل"});
  try{
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare("INSERT INTO users(username,password,display_name,bio) VALUES(?,?,?,?)").run(username,hash,displayName,bio);
    req.session.userId=info.lastInsertRowid;
    res.json({user:userById(req.session.userId)});
  }catch(e){res.status(400).json({error:"اليوزر مستخدم مسبقاً"});}
});
app.post("/api/login", async (req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username||"");
  if(!u || !(await bcrypt.compare(req.body.password||"",u.password))) return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
  req.session.userId=u.id; res.json({user:userById(u.id)});
});
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",auth,(req,res)=>res.json({user:userById(req.session.userId)}));

app.post("/api/profile",auth,upload.single("avatar"),(req,res)=>{
  const {displayName,bio}=req.body;
  const avatar=req.file?"/uploads/"+req.file.filename:undefined;
  if(avatar) db.prepare("UPDATE users SET display_name=?,bio=?,avatar=? WHERE id=?").run(displayName,bio||"",avatar,req.session.userId);
  else db.prepare("UPDATE users SET display_name=?,bio=? WHERE id=?").run(displayName,bio||"",req.session.userId);
  res.json({user:userById(req.session.userId)});
});

function generateCode(){
  let code; do { code=String(Math.floor(1000000+Math.random()*9000000)); } while(roomByCode(code)); return code;
}
app.post("/api/rooms",auth,(req,res)=>{
  const {name,description="",isPrivate=false,password=""}=req.body;
  if(!name?.trim()) return res.status(400).json({error:"اسم الغرفة مطلوب"});
  if(isPrivate && password.length<4) return res.status(400).json({error:"كلمة سر الغرفة 4 أحرف على الأقل"});
  const code=generateCode();
  const info=db.prepare("INSERT INTO rooms(code,name,description,private,password,owner_id) VALUES(?,?,?,?,?,?)")
    .run(code,name.trim(),description, isPrivate?1:0, isPrivate?password:"", req.session.userId);
  db.prepare("INSERT INTO memberships(user_id,room_id,role) VALUES(?,?,?)").run(req.session.userId,info.lastInsertRowid,"owner");
  res.json({room:roomByCode(code)});
});
app.get("/api/rooms",auth,(req,res)=>{
  const rooms=db.prepare(`SELECT r.id,r.code,r.name,r.description,r.private,r.owner_id,
    (SELECT COUNT(*) FROM memberships m WHERE m.room_id=r.id) members
    FROM rooms r JOIN memberships x ON x.room_id=r.id WHERE x.user_id=? ORDER BY r.created_at DESC`).all(req.session.userId);
  res.json({rooms});
});
app.post("/api/rooms/join",auth,(req,res)=>{
  const r=roomByCode(req.body.code?.trim());
  if(!r) return res.status(404).json({error:"الغرفة غير موجودة"});
  if(r.private && r.password!==req.body.password) return res.status(403).json({error:"كلمة سر الغرفة غير صحيحة"});
  db.prepare("INSERT OR IGNORE INTO memberships(user_id,room_id,role) VALUES(?,?,?)").run(req.session.userId,r.id,"member");
  res.json({room:r});
});
app.get("/api/rooms/:code",auth,(req,res)=>{
  const r=roomByCode(req.params.code);
  if(!r || !isMember(req.session.userId,r.id)) return res.status(404).json({error:"الغرفة غير متاحة"});
  const messages=db.prepare(`SELECT m.*,u.username,u.display_name,u.avatar,
    (SELECT COUNT(*) FROM reads z WHERE z.message_id=m.id AND z.user_id!=m.user_id) read_count
    FROM messages m JOIN users u ON u.id=m.user_id WHERE m.room_id=? ORDER BY m.id DESC LIMIT 100`).all(r.id).reverse();
  res.json({room:r,messages});
});
app.post("/api/rooms/:code/messages",auth,(req,res)=>{
  const r=roomByCode(req.params.code); if(!r||!isMember(req.session.userId,r.id)) return res.status(403).json({error:"غير مسموح"});
  const {type="text",body="",fileUrl=""}=req.body;
  const info=db.prepare("INSERT INTO messages(room_id,user_id,type,body,file_url) VALUES(?,?,?,?,?)").run(r.id,req.session.userId,type,body,fileUrl);
  const msg=db.prepare(`SELECT m.*,u.username,u.display_name,u.avatar FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id=?`).get(info.lastInsertRowid);
  io.to("room:"+r.id).emit("message:new",msg);
  res.json({message:msg});
});
app.post("/api/upload",auth,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({error:"لم يتم اختيار ملف"});
  const mime=req.file.mimetype;
  const type=mime.startsWith("image/")?"image":mime.startsWith("video/")?"video":mime.startsWith("audio/")?"audio":"file";
  res.json({url:"/uploads/"+req.file.filename,type,name:req.file.originalname});
});
app.post("/api/rooms/:code/read",auth,(req,res)=>{
  const r=roomByCode(req.params.code); if(!r||!isMember(req.session.userId,r.id)) return res.status(403).end();
  const ids=Array.isArray(req.body.ids)?req.body.ids:[];
  const stmt=db.prepare("INSERT OR IGNORE INTO reads(user_id,message_id) VALUES(?,?)");
  const tx=db.transaction(()=>ids.forEach(id=>stmt.run(req.session.userId,id))); tx();
  io.to("room:"+r.id).emit("messages:read",{userId:req.session.userId,ids});
  res.json({ok:true});
});

io.on("connection",socket=>{
  socket.on("room:join",({code})=>{
    const r=roomByCode(code), uid=socket.request.sessionUserId;
    if(r && uid && isMember(uid,r.id)) socket.join("room:"+r.id);
  });
  socket.on("typing",({code,typing})=>{
    const r=roomByCode(code),uid=socket.request.sessionUserId;
    if(r&&uid&&isMember(uid,r.id)) socket.to("room:"+r.id).emit("typing",{userId:uid,typing});
  });
});
app.use((req,res,next)=>next());
const oldIo=io.engine;
io.use((socket,next)=>{ socket.request.sessionUserId=socket.request.headers["x-user-id"]||null; next(); });

server.listen(process.env.PORT||3000,()=>console.log("Chat app running on http://localhost:"+(process.env.PORT||3000)));
