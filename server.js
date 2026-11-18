const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto');
const SECRET=process.env.JWT_SECRET||crypto.randomBytes(32).toString('hex');
if(!process.env.JWT_SECRET)console.warn('JWT_SECRET not set: logins reset on every restart');
const db=new Database(process.env.DB_FILE||path.join(__dirname,'data.db'));
db.exec(`create table if not exists users(id text primary key,name text unique collate nocase,pass text,role text);
create table if not exists datasets(id text primary key,name text,cols text,types text,rows text,owner text);
create table if not exists charts(id text primary key,title text,type text,ds text,x text,y text,agg text,owner text)`);
const app=express();app.use(express.json({limit:'30mb'}));app.use(express.static(path.join(__dirname,'public')));
const uid=()=>crypto.randomBytes(5).toString('hex'),sign=u=>jwt.sign({id:u.id},SECRET,{expiresIn:'7d'}),pub=u=>({id:u.id,name:u.name,role:u.role});
const ROLES=['admin','editor','viewer'],TYPES=['bar','line','pie','doughnut','scatter'],AGGS=['sum','avg','max','count'];
function auth(q,s,n){try{const u=db.prepare('select * from users where id=?').get(jwt.verify((q.headers.authorization||'').slice(7),SECRET).id);if(!u)throw 0;q.user=u;n()}catch(e){s.status(401).json({error:'Unauthorized'})}}
const role=(...r)=>(q,s,n)=>r.includes(q.user.role)?n():s.status(403).json({error:'Forbidden'});
const own=t=>(q,s,n)=>{const r=db.prepare(`select owner from ${t} where id=?`).get(q.params.id);if(!r)return s.status(404).json({error:'Not found'});
 (q.user.role==='admin'||(q.user.role==='editor'&&r.owner===q.user.id))?n():s.status(403).json({error:'Forbidden'})};
const str=(v,n)=>typeof v==='string'&&v.length>0&&v.length<=n;

app.post('/api/register',(q,s)=>{const{name,pass}=q.body||{};
 if(!str(name,40)||name.trim().length<2||!str(pass,200)||pass.length<4)return s.status(400).json({error:'Username and 4+ char password required'});
 if(db.prepare('select 1 from users where name=?').get(name.trim()))return s.status(409).json({error:'Username taken'});
 const first=!db.prepare('select 1 from users').get(),u={id:uid(),name:name.trim(),pass:bcrypt.hashSync(pass,10),role:first?'admin':'editor'};
 db.prepare('insert into users values(@id,@name,@pass,@role)').run(u);s.json({token:sign(u),user:pub(u)})});
app.post('/api/login',(q,s)=>{const u=db.prepare('select * from users where name=?').get(String((q.body||{}).name||'').trim());
 if(!u||!bcrypt.compareSync(String(q.body.pass||''),u.pass))return s.status(401).json({error:'Wrong username or password'});s.json({token:sign(u),user:pub(u)})});

app.get('/api/state',auth,(q,s)=>{const j=JSON.parse;s.json({me:pub(q.user),
 users:q.user.role==='admin'?db.prepare('select id,name,role from users').all():[],
 datasets:db.prepare('select * from datasets').all().map(d=>({...d,cols:j(d.cols),types:j(d.types),rows:j(d.rows)})),
 charts:db.prepare('select * from charts').all()})});

app.post('/api/datasets',auth,role('admin','editor'),(q,s)=>{const d=q.body||{};
 if(!str(d.name,200)||!Array.isArray(d.cols)||!Array.isArray(d.rows)||!d.rows.length||d.rows.length>5000)return s.status(400).json({error:'Invalid dataset (1-5000 rows)'});
 db.prepare('insert into datasets values(?,?,?,?,?,?)').run(uid(),d.name,JSON.stringify(d.cols),JSON.stringify(d.types||{}),JSON.stringify(d.rows),q.user.id);s.json({ok:1})});
app.delete('/api/datasets/:id',auth,own('datasets'),(q,s)=>{db.prepare('delete from charts where ds=?').run(q.params.id);db.prepare('delete from datasets where id=?').run(q.params.id);s.json({ok:1})});

app.post('/api/charts',auth,role('admin','editor'),(q,s)=>{const c=q.body||{};
 if(!str(c.title,200)||!TYPES.includes(c.type)||!AGGS.includes(c.agg)||!str(c.x,200)||!str(c.y,200)||!db.prepare('select 1 from datasets where id=?').get(c.ds))return s.status(400).json({error:'Invalid chart'});
 db.prepare('insert into charts values(?,?,?,?,?,?,?,?)').run(uid(),c.title,c.type,c.ds,c.x,c.y,c.agg,q.user.id);s.json({ok:1})});
app.delete('/api/charts/:id',auth,own('charts'),(q,s)=>{db.prepare('delete from charts where id=?').run(q.params.id);s.json({ok:1})});

app.put('/api/users/:id/role',auth,role('admin'),(q,s)=>{if(q.params.id===q.user.id||!ROLES.includes((q.body||{}).role))return s.status(400).json({error:'Invalid'});
 db.prepare('update users set role=? where id=?').run(q.body.role,q.params.id);s.json({ok:1})});
app.delete('/api/users/:id',auth,role('admin'),(q,s)=>{if(q.params.id===q.user.id)return s.status(400).json({error:'Cannot remove yourself'});
 db.prepare('delete from users where id=?').run(q.params.id);s.json({ok:1})});

app.listen(process.env.PORT||3000,()=>console.log('InsightBoard running on http://localhost:'+(process.env.PORT||3000)));
