import express from 'express'
import Database from 'better-sqlite3'
import crypto from 'node:crypto'
const ADMIN=process.env.ADMIN_PASSWORD
if(!ADMIN||ADMIN.length<8){console.error('Set ADMIN_PASSWORD (8+ chars)');process.exit(1)}
const db=new Database(process.env.DB_PATH||'data.db');db.pragma('journal_mode=WAL')
db.exec(`create table if not exists users(id integer primary key,phone text unique,name text,salt text,hash text,balance real default 0,frozen int default 0,last_spin text);
create table if not exists sessions(token text primary key,uid int);
create table if not exists txns(id integer primary key,uid int,utr text unique,amount real,status text default 'Pending',t int);
create table if not exists orders(id integer primary key,uid int,service text,qty int,cost real,link text,pid text,status int default 0,t int)`)
const RATES={Views:[10000,10],Followers:[100,20],Likes:[100,10],Comments:[100,20],Shares:[250,10],Saves:[100,10],Reposts:[200,10],'Story Views':[100,10]}
const ASSETS={1:49,2:79,3:59,4:39}
const SVC=JSON.parse(process.env.SMM_SERVICES||'{}'),API=process.env.SMM_API_URL,KEY=process.env.SMM_API_KEY
const app=express();app.use(express.json({limit:'20kb'}));app.set('trust proxy',1)
const hits=new Map()
const limit=(n)=>(req,res,next)=>{const k=req.ip+req.path,t=Date.now(),a=(hits.get(k)||[]).filter(x=>t-x<60000);a.push(t);hits.set(k,a);a.length>n?res.status(429).json({error:'Too many requests, wait a minute'}):next()}
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString('hex')
const auth=(req,res,next)=>{const r=db.prepare('select u.* from sessions s join users u on u.id=s.uid where s.token=?').get(req.get('x-token')||'');if(!r)return res.status(401).json({error:'Login required'});req.u=r;next()}
const admin=(req,res,next)=>{const a=Buffer.from(req.get('x-admin')||''),b=Buffer.from(ADMIN);a.length===b.length&&crypto.timingSafeEqual(a,b)?next():res.status(403).json({error:'Forbidden'})}
const session=uid=>{const t=crypto.randomBytes(24).toString('hex');db.prepare('insert into sessions values(?,?)').run(t,uid);return t}
const cost=(s,q)=>Math.round(q/RATES[s][0]*RATES[s][1]*100)/100
const provider=async o=>{const r=await fetch(API,{method:'POST',body:new URLSearchParams(o)});return r.json()}

app.post('/api/signup',limit(10),(req,res)=>{const{phone,password,name}=req.body||{}
  if(!/^\d{10}$/.test(phone||'')||(password||'').length<6)return res.status(400).json({error:'10-digit phone and 6+ character password required'})
  if(db.prepare('select 1 from users where phone=?').get(phone))return res.status(400).json({error:'Phone already registered'})
  const salt=crypto.randomBytes(16).toString('hex'),id=db.prepare('insert into users(phone,name,salt,hash) values(?,?,?,?)').run(phone,String(name||'').slice(0,40),salt,hash(password,salt)).lastInsertRowid
  res.json({token:session(id)})})
app.post('/api/login',limit(10),(req,res)=>{const{phone,password}=req.body||{},u=db.prepare('select * from users where phone=?').get(phone||'')
  if(!u||hash(password||'',u.salt)!==u.hash)return res.status(400).json({error:'Wrong phone or password'});res.json({token:session(u.id)})})

app.get('/api/me',auth,async(req,res)=>{
  if(API){const open=db.prepare('select * from orders where uid=? and status<3 and pid is not null order by id desc limit 10').all(req.u.id)
    await Promise.all(open.map(async o=>{try{const j=await provider({key:KEY,action:'status',order:o.pid});const m={Pending:0,Processing:2,'In progress':2,Completed:3,Partial:3,Canceled:3}[j.status]
      if(m!==undefined)db.prepare('update orders set status=? where id=?').run(m,o.id)
      if(j.status==='Canceled'&&!o.refunded){db.prepare('update users set balance=balance+? where id=?').run(o.cost,o.uid)}}catch{}}))}
  const u=db.prepare('select id,phone,name,balance,frozen from users where id=?').get(req.u.id)
  res.json({user:u,balance:u.balance,orders:db.prepare('select id,service,qty,cost,link,status,t from orders where uid=? order by id desc limit 50').all(u.id),txns:db.prepare('select utr,amount as amt,status,t from txns where uid=? order by id desc limit 50').all(u.id)})})

app.post('/api/order',auth,async(req,res)=>{const{service,qty,link}=req.body||{},q=Math.floor(+qty)
  if(!RATES[service]||!(q>0)||q>10000000)return res.status(400).json({error:'Invalid service or quantity'})
  try{if(new URL(link).protocol.slice(0,4)!=='http')throw 0}catch{return res.status(400).json({error:'Invalid link'})}
  const c=cost(service,q);let oid
  const ok=db.transaction(()=>{const u=db.prepare('select balance,frozen from users where id=?').get(req.u.id);if(u.frozen||u.balance<c)return false
    db.prepare('update users set balance=balance-? where id=?').run(c,req.u.id)
    oid=db.prepare('insert into orders(uid,service,qty,cost,link,t) values(?,?,?,?,?,?)').run(req.u.id,service,q,c,link,Date.now()).lastInsertRowid;return true})()
  if(!ok)return res.status(400).json({error:'Low balance or account frozen'})
  if(API&&SVC[service]){try{const j=await provider({key:KEY,action:'add',service:SVC[service],link,quantity:q});if(!j.order)throw new Error(j.error||'rejected')
    db.prepare('update orders set pid=?,status=1 where id=?').run(String(j.order),oid)}
    catch(e){db.prepare('update users set balance=balance+? where id=?').run(c,req.u.id);db.prepare('update orders set status=3 where id=?').run(oid);return res.status(502).json({error:'Provider rejected the order. You were refunded.'})}}
  res.json({id:'BU'+oid,balance:db.prepare('select balance from users where id=?').get(req.u.id).balance})})

app.post('/api/utr',auth,limit(10),(req,res)=>{const{utr,amount}=req.body||{},a=+amount
  if(!/^\d{12}$/.test(utr||'')||!(a>=1&&a<=100000))return res.status(400).json({error:'Invalid UTR or amount',fraud:true})
  try{db.prepare('insert into txns(uid,utr,amount,t) values(?,?,?,?)').run(req.u.id,utr,a,Date.now())}catch{return res.status(400).json({error:'This UTR was already submitted',fraud:true})}
  res.json({ok:true})})

app.post('/api/assets',auth,(req,res)=>{const ids=(req.body?.ids||[]).filter(i=>ASSETS[i]);if(!ids.length)return res.status(400).json({error:'Cart empty'})
  const sub=ids.reduce((s,i)=>s+ASSETS[i],0),total=Math.round(sub*(ids.length>=3?.85:1)*100)/100
  const ok=db.transaction(()=>{const u=db.prepare('select balance,frozen from users where id=?').get(req.u.id);if(u.frozen||u.balance<total)return false
    db.prepare('update users set balance=balance-? where id=?').run(total,req.u.id);return true})()
  if(!ok)return res.status(400).json({error:'Low balance or account frozen'});res.json({token:crypto.randomBytes(5).toString('hex').toUpperCase(),total})})

app.post('/api/spin',auth,(req,res)=>{const d=new Date().toDateString()
  const w=1+crypto.randomInt(3),ok=db.prepare('update users set last_spin=?,balance=balance+? where id=? and (last_spin is null or last_spin!=?)').run(d,w,req.u.id,d).changes
  ok?res.json({win:w}):res.status(400).json({error:'Come back tomorrow for another spin'})})

app.get('/api/admin/pending',admin,(q,res)=>res.json(db.prepare('select t.id,t.utr,t.amount,t.status,u.phone from txns t join users u on u.id=t.uid where t.status=\'Pending\' order by t.id').all()))
app.post('/api/admin/txn',admin,(req,res)=>{const{id,approve}=req.body||{}
  const r=db.transaction(()=>{const t=db.prepare('select * from txns where id=? and status=\'Pending\'').get(id);if(!t)return false
    db.prepare('update txns set status=? where id=?').run(approve?'Approved':'Rejected',id)
    if(approve)db.prepare('update users set balance=balance+? where id=?').run(t.amount,t.uid);return true})()
  res.json({ok:r})})
app.post('/api/admin/user',admin,(req,res)=>{const{phone,add,freeze}=req.body||{}
  if(add)db.prepare('update users set balance=balance+? where phone=?').run(+add,phone)
  if(freeze!==undefined)db.prepare('update users set frozen=? where phone=?').run(freeze?1:0,phone)
  res.json(db.prepare('select phone,balance,frozen from users where phone=?').get(phone)||{error:'No such user'})})

app.use(express.static('public'))
app.listen(process.env.PORT||3000,()=>console.log('Black Universe running'))
