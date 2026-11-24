'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000;
const SECRET=process.env.APP_SECRET||(console.warn('WARNING: set APP_SECRET, sessions reset on restart'),crypto.randomBytes(32).toString('hex'));
const db=new DatabaseSync(process.env.DB_FILE||path.join(__dirname,'data.db'));
db.exec('PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;');
db.exec(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
const UP=path.join(__dirname,'uploads');fs.mkdirSync(UP,{recursive:true});
const q=(s,...a)=>db.prepare(s).all(...a), one=(s,...a)=>db.prepare(s).get(...a), run=(s,...a)=>db.prepare(s).run(...a);
let depth=0;const tx=fn=>{const nested=depth>0,sp='sp'+depth;db.exec(nested?'SAVEPOINT '+sp:'BEGIN IMMEDIATE');depth++;try{const r=fn();depth--;db.exec(nested?'RELEASE '+sp:'COMMIT');return r}catch(e){depth--;db.exec(nested?`ROLLBACK TO ${sp};RELEASE ${sp}`:'ROLLBACK');throw e}};
// ---- RBAC seed (rank: guest 0 < user 1 < volunteer 2 < ecostaff 3 < leader 4 < admin 5)
const ROLES=[['user',1,'Пользователь'],['volunteer',2,'Волонтёр'],['ecostaff',3,'Сотрудник экологической группы'],['leader',4,'Руководитель группы'],['admin',5,'Администратор']];
const PERMS={ 'report.create':1,'event.register':1,'wallet.read':1,'offer.redeem':1,'volunteer.apply':1,'report.moderate':3,'redeem.verify':3,'event.manage':4,'news.write':4,'group.manage':4,'catalog.manage':4,'user.manage':5,'audit.read':5 };
tx(()=>{for(const [c,r,t] of ROLES)run('INSERT OR IGNORE INTO roles(code,rank,title) VALUES(?,?,?)',c,r,t);
 for(const [p,minRank] of Object.entries(PERMS)){run('INSERT OR IGNORE INTO permissions(code) VALUES(?)',p);
  for(const r of ROLES)if(r[1]>=minRank)run('INSERT OR IGNORE INTO role_permissions SELECT r.id,p.id FROM roles r,permissions p WHERE r.code=? AND p.code=?',r[0],p)}
 if(!one('SELECT 1 FROM territories'))for(const t of [['Чарвак',41.62,69.95],['Чимган',41.53,70.01],['Бельдерсай',41.52,70.04]])run('INSERT INTO territories(name,lat,lng,description) VALUES(?,?,?,?)',...t,'Координаты приблизительные, администратор может изменить');
 if(process.env.ADMIN_EMAIL&&process.env.ADMIN_PASSWORD&&!one('SELECT 1 FROM users WHERE email=?',process.env.ADMIN_EMAIL))createUser(process.env.ADMIN_EMAIL,process.env.ADMIN_PASSWORD,'Администратор','admin')});
// ---- helpers
function hashPw(p){const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(p,s,64).toString('hex')}
function checkPw(p,h){const [s,k]=h.split(':');return crypto.timingSafeEqual(crypto.scryptSync(p,Buffer.from(s,'hex'),64),Buffer.from(k,'hex'))}
function createUser(email,pw,name,role='user',phone=null,lang='ru'){const r=run('INSERT INTO users(email,pass_hash,role_id) VALUES(?,?,(SELECT id FROM roles WHERE code=?))',email,hashPw(pw),role);
 run('INSERT INTO profiles(user_id,full_name,phone,lang) VALUES(?,?,?,?)',r.lastInsertRowid,name,phone,lang);run('INSERT INTO ecoball_wallets(user_id) VALUES(?)',r.lastInsertRowid);return +r.lastInsertRowid}
const b64=b=>Buffer.from(b).toString('base64url');
const sign=u=>{const p=b64(JSON.stringify({u,e:Date.now()+7*864e5}));return p+'.'+crypto.createHmac('sha256',SECRET).update(p).digest('base64url')};
function auth(req){const m=/^Bearer (.+)$/.exec(req.headers.authorization||'');if(!m)return null;const [p,s]=m[1].split('.');if(!p||!s)return null;
 const ok=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');if(s.length!==ok.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(ok)))return null;
 const d=JSON.parse(Buffer.from(p,'base64url'));if(d.e<Date.now())return null;
 const u=one('SELECT u.id,u.email,u.is_active,r.code role,r.rank,p.full_name,p.lang,p.push_consent FROM users u JOIN roles r ON r.id=u.role_id JOIN profiles p ON p.user_id=u.id WHERE u.id=?',d.u);
 return u&&u.is_active?u:null}
const can=(u,perm)=>!!u&&!!one('SELECT 1 FROM users x JOIN role_permissions rp ON rp.role_id=x.role_id JOIN permissions p ON p.id=rp.permission_id WHERE x.id=? AND p.code=?',u.id,perm);
const audit=(u,a,d,ip)=>run('INSERT INTO audit_logs(user_id,action,detail,ip) VALUES(?,?,?,?)',u?u.id:null,a,d?String(d).slice(0,500):null,ip||null);
class HttpError extends Error{constructor(c,m){super(m);this.code=c}}
const need=(u,perm)=>{if(!u)throw new HttpError(401,'Требуется вход');if(!can(u,perm))throw new HttpError(403,'Недостаточно прав')};
const str=(v,min,max,name)=>{if(typeof v!=='string'||v.trim().length<min||v.length>max)throw new HttpError(400,`Поле «${name}» заполнено неверно`);return v.trim()};
const num=(v,lo,hi,name)=>{v=Number(v);if(!Number.isFinite(v)||v<lo||v>hi)throw new HttpError(400,`Поле «${name}» заполнено неверно`);return v};
const hits=new Map();const limited=(ip,k,max)=>{const key=ip+k,now=Date.now(),a=(hits.get(key)||[]).filter(t=>now-t<6e4);a.push(now);hits.set(key,a);return a.length>max};
// ---- EcoBall: atomic, idempotent
function ecoTx(userId,amount,kind,ref,key){return tx(()=>{if(one('SELECT 1 FROM ecoball_transactions WHERE idempotency_key=?',key))return false;
 run('INSERT INTO ecoball_transactions(user_id,amount,kind,ref,idempotency_key) VALUES(?,?,?,?,?)',userId,amount,kind,ref,key);
 run('UPDATE ecoball_wallets SET balance=balance+? WHERE user_id=?',amount,userId);return true})}
const notify=(uid,text)=>run('INSERT INTO notifications(user_id,text) VALUES(?,?)',uid,text);
const REWARD=+process.env.REPORT_REWARD||10;
// ---- API
const routes=[];const R=(m,p,fn)=>routes.push([m,new RegExp('^'+p.replace(/:\w+/g,'(\\d+)')+'$'),fn]);
R('POST','/api/register',(c)=>{if(limited(c.ip,'auth',10))throw new HttpError(429,'Слишком много попыток');const b=c.body;const email=str(b.email,5,120,'email').toLowerCase();
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))throw new HttpError(400,'Неверный email');const pw=str(b.password,8,100,'пароль');const name=str(b.full_name,2,100,'имя');
 if(!b.accept_terms)throw new HttpError(400,'Необходимо принять соглашение');if(one('SELECT 1 FROM users WHERE email=?',email))throw new HttpError(409,'Email уже зарегистрирован');
 const id=tx(()=>createUser(email,pw,name,'user',b.phone?String(b.phone).slice(0,30):null,['ru','uz','en'].includes(b.lang)?b.lang:'ru'));audit({id},'register',email,c.ip);return {token:sign(id)}});
R('POST','/api/login',(c)=>{if(limited(c.ip,'auth',10))throw new HttpError(429,'Слишком много попыток');const u=one('SELECT id,pass_hash,is_active FROM users WHERE email=?',String(c.body.email||''));
 if(!u||!u.is_active||!checkPw(String(c.body.password||''),u.pass_hash)){audit(null,'login_failed',c.body.email,c.ip);throw new HttpError(401,'Неверный email или пароль')}return {token:sign(u.id)}});
R('POST','/api/reset/request',(c)=>{if(limited(c.ip,'reset',5))throw new HttpError(429,'Слишком много попыток');const u=one('SELECT id FROM users WHERE email=?',String(c.body.email||''));
 if(u){const t=crypto.randomBytes(24).toString('hex');run('UPDATE users SET reset_token_hash=?,reset_expires=? WHERE id=?',crypto.createHash('sha256').update(t).digest('hex'),Date.now()+36e5,u.id);
  // Подключите почтовый сервис (SMTP) в sendMail. Без него ссылка пишется в лог сервера.
  console.log(`[RESET LINK] ${process.env.BASE_URL||''}/#/reset/${t}`)}return {ok:true}});
R('POST','/api/reset/confirm',(c)=>{const h=crypto.createHash('sha256').update(String(c.body.token||'')).digest('hex');const u=one('SELECT id FROM users WHERE reset_token_hash=? AND reset_expires>?',h,Date.now());
 if(!u)throw new HttpError(400,'Ссылка недействительна или устарела');run('UPDATE users SET pass_hash=?,reset_token_hash=NULL,reset_expires=NULL WHERE id=?',hashPw(str(c.body.password,8,100,'пароль')),u.id);audit({id:u.id},'password_reset',null,c.ip);return {ok:true}});
R('GET','/api/me',(c)=>{need(c.user);return {...c.user,perms:q('SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=(SELECT role_id FROM users WHERE id=?)',c.user.id).map(x=>x.code)}});
R('PATCH','/api/me',(c)=>{need(c.user);const b=c.body;if(b.full_name!==undefined)run('UPDATE profiles SET full_name=? WHERE user_id=?',str(b.full_name,2,100,'имя'),c.user.id);
 if(['ru','uz','en'].includes(b.lang))run('UPDATE profiles SET lang=? WHERE user_id=?',b.lang,c.user.id);if(b.push_consent!==undefined)run('UPDATE profiles SET push_consent=? WHERE user_id=?',b.push_consent?1:0,c.user.id);return {ok:true}});
R('GET','/api/territories',()=>q('SELECT * FROM territories ORDER BY name'));
R('GET','/api/reports',(c)=>{const staff=c.user&&can(c.user,'report.moderate');const base='SELECT r.id,r.category,r.title,r.description,r.lat,r.lng,r.status,r.created_at,r.user_id,t.name territory,(SELECT file FROM report_photos WHERE report_id=r.id LIMIT 1) photo FROM environmental_reports r LEFT JOIN territories t ON t.id=r.territory_id';
 if(staff)return q(base+' ORDER BY r.id DESC LIMIT 200');
 return q(base+' WHERE r.status IN(\'in_progress\',\'resolved\') OR r.user_id=? ORDER BY r.id DESC LIMIT 200',c.user?c.user.id:-1).map(r=>({...r,user_id:undefined}))});
R('POST','/api/reports',(c)=>{need(c.user,'report.create');if(limited(c.ip+c.user.id,'rep',10))throw new HttpError(429,'Не более 10 обращений в минуту');const b=c.body;
 const cat=['waste','water','air','fire','tree','other'].includes(b.category)?b.category:(()=>{throw new HttpError(400,'Неверная категория')})();
 const lat=num(b.lat,-90,90,'широта'),lng=num(b.lng,-180,180,'долгота');let file=null;
 if(b.photo){const m=/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(b.photo);if(!m)throw new HttpError(400,'Фото: допустимы JPEG, PNG, WebP');const buf=Buffer.from(m[2],'base64');if(buf.length>3e6)throw new HttpError(400,'Фото больше 3 МБ');
  file=crypto.randomBytes(12).toString('hex')+'.'+(m[1]==='jpeg'?'jpg':m[1]);fs.writeFileSync(path.join(UP,file),buf)}
 const id=tx(()=>{const r=run('INSERT INTO environmental_reports(user_id,territory_id,category,title,description,lat,lng) VALUES(?,?,?,?,?,?,?)',c.user.id,b.territory_id?+b.territory_id:null,cat,str(b.title,3,150,'заголовок'),str(b.description,10,3000,'описание'),lat,lng);
  const id=+r.lastInsertRowid;if(file)run('INSERT INTO report_photos(report_id,file) VALUES(?,?)',id,file);run('INSERT INTO report_status_history(report_id,new_status,changed_by) VALUES(?,?,?)',id,'new',c.user.id);return id});
 audit(c.user,'report.create',id,c.ip);return {id}});
R('PATCH','/api/reports/:id/status',(c,id)=>{need(c.user,'report.moderate');const st=c.body.status;if(!['in_progress','resolved','rejected'].includes(st))throw new HttpError(400,'Неверный статус');
 return tx(()=>{const r=one('SELECT * FROM environmental_reports WHERE id=?',id);if(!r)throw new HttpError(404,'Не найдено');if(r.status===st)return {ok:true,unchanged:true};
  run('UPDATE environmental_reports SET status=? WHERE id=?',st,id);run('INSERT INTO report_status_history(report_id,old_status,new_status,changed_by,note) VALUES(?,?,?,?,?)',id,r.status,st,c.user.id,c.body.note?String(c.body.note).slice(0,500):null);
  notify(r.user_id,`Обращение «${r.title}»: статус изменён на ${st}`);
  if(st==='in_progress')ecoTx(r.user_id,REWARD,'report_accepted','report:'+id,'report-reward:'+id); // повторное принятие не начислит дважды
  audit(c.user,'report.status',`${id}:${st}`,c.ip);return {ok:true}})});
R('GET','/api/events',(c)=>q('SELECT e.*,(SELECT COUNT(*) FROM event_registrations WHERE event_id=e.id) registered,'+(c.user?`EXISTS(SELECT 1 FROM event_registrations WHERE event_id=e.id AND user_id=${+c.user.id})`:'0')+' mine FROM events e ORDER BY starts_at'));
R('POST','/api/events',(c)=>{need(c.user,'event.manage');const b=c.body;const r=run('INSERT INTO events(title,description,territory_id,starts_at,capacity,reward_points,created_by) VALUES(?,?,?,?,?,?,?)',str(b.title,3,150,'название'),String(b.description||'').slice(0,3000),b.territory_id?+b.territory_id:null,str(b.starts_at,8,40,'дата'),num(b.capacity,1,10000,'мест'),num(b.reward_points||0,0,1000,'баллы'),c.user.id);audit(c.user,'event.create',r.lastInsertRowid,c.ip);return {id:+r.lastInsertRowid}});
R('POST','/api/events/:id/register',(c,id)=>{need(c.user,'event.register');return tx(()=>{const e=one('SELECT * FROM events WHERE id=?',id);if(!e)throw new HttpError(404,'Не найдено');if(one('SELECT 1 FROM event_registrations WHERE event_id=? AND user_id=?',id,c.user.id))return {ok:true,already:true};
 if(one('SELECT COUNT(*) n FROM event_registrations WHERE event_id=?',id).n>=e.capacity)throw new HttpError(409,'Мест нет');run('INSERT INTO event_registrations(event_id,user_id) VALUES(?,?)',id,c.user.id);return {ok:true}})});
R('POST','/api/events/:id/award',(c,id)=>{need(c.user,'event.manage');const uid=num(c.body.user_id,1,1e9,'пользователь');const e=one('SELECT * FROM events WHERE id=?',id);
 if(!e||!one('SELECT 1 FROM event_registrations WHERE event_id=? AND user_id=?',id,uid))throw new HttpError(400,'Участник не записан');if(!e.reward_points)throw new HttpError(400,'У мероприятия нет награды');
 const done=ecoTx(uid,e.reward_points,'event_attended','event:'+id,`event-reward:${id}:${uid}`);audit(c.user,'event.award',`${id}:${uid}`,c.ip);return {ok:true,awarded:done}});
R('GET','/api/wallet',(c)=>{need(c.user,'wallet.read');return {balance:one('SELECT balance FROM ecoball_wallets WHERE user_id=?',c.user.id).balance,transactions:q('SELECT amount,kind,ref,created_at FROM ecoball_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100',c.user.id),
 redemptions:q('SELECT r.id,r.status,r.points,o.title,p.name partner,qc.code FROM redemptions r JOIN cashback_offers o ON o.id=r.offer_id JOIN partners p ON p.id=o.partner_id JOIN qr_codes qc ON qc.redemption_id=r.id WHERE r.user_id=? ORDER BY r.id DESC',c.user.id)}});
R('GET','/api/offers',()=>q('SELECT o.id,o.title,o.cost_points,p.name partner,p.address FROM cashback_offers o JOIN partners p ON p.id=o.partner_id WHERE o.is_active=1 AND p.is_active=1'));
R('POST','/api/offers/:id/redeem',(c,id)=>{need(c.user,'offer.redeem');const key=str(c.body.idempotency_key,8,80,'ключ');return tx(()=>{
 const prev=one('SELECT qc.code FROM ecoball_transactions t JOIN redemptions r ON r.id=CAST(t.ref AS INTEGER) JOIN qr_codes qc ON qc.redemption_id=r.id WHERE t.idempotency_key=? AND t.user_id=?',`redeem:${c.user.id}:${key}`,c.user.id);if(prev)return {code:prev.code,repeated:true};
 const o=one('SELECT * FROM cashback_offers WHERE id=? AND is_active=1',id);if(!o)throw new HttpError(404,'Предложение не найдено');
 if(one('SELECT balance FROM ecoball_wallets WHERE user_id=?',c.user.id).balance<o.cost_points)throw new HttpError(402,'Недостаточно EcoBall');
 const r=run('INSERT INTO redemptions(user_id,offer_id,points) VALUES(?,?,?)',c.user.id,o.id,o.cost_points);const code=crypto.randomBytes(9).toString('hex').toUpperCase();run('INSERT INTO qr_codes(code,redemption_id) VALUES(?,?)',code,r.lastInsertRowid);
 ecoTx(c.user.id,-o.cost_points,'redeem',String(r.lastInsertRowid),`redeem:${c.user.id}:${key}`);audit(c.user,'offer.redeem',o.id,c.ip);return {code}})});
R('POST','/api/qr/verify',(c)=>{need(c.user,'redeem.verify');return tx(()=>{const x=one('SELECT qc.id,qc.used_at,qc.redemption_id,o.title FROM qr_codes qc JOIN redemptions r ON r.id=qc.redemption_id JOIN cashback_offers o ON o.id=r.offer_id WHERE qc.code=?',String(c.body.code||'').toUpperCase());
 if(!x)throw new HttpError(404,'Код не найден');if(x.used_at)throw new HttpError(409,'Код уже использован');run("UPDATE qr_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?",x.id);run("UPDATE redemptions SET status='used' WHERE id=?",x.redemption_id);audit(c.user,'qr.verify',x.id,c.ip);return {ok:true,offer:x.title}})});
R('POST','/api/partners',(c)=>{need(c.user,'catalog.manage');const r=run('INSERT INTO partners(name,address) VALUES(?,?)',str(c.body.name,2,120,'название'),String(c.body.address||'').slice(0,200));return {id:+r.lastInsertRowid}});
R('POST','/api/offers',(c)=>{need(c.user,'catalog.manage');const r=run('INSERT INTO cashback_offers(partner_id,title,cost_points) VALUES(?,?,?)',num(c.body.partner_id,1,1e9,'партнёр'),str(c.body.title,3,150,'название'),num(c.body.cost_points,1,1e6,'цена'));return {id:+r.lastInsertRowid}});
R('GET','/api/partners',()=>q('SELECT id,name,address FROM partners WHERE is_active=1'));
R('GET','/api/news',()=>q('SELECT id,title,body,created_at FROM news ORDER BY id DESC LIMIT 50'));
R('POST','/api/news',(c)=>{need(c.user,'news.write');const r=run('INSERT INTO news(title,body,author_id) VALUES(?,?,?)',str(c.body.title,3,150,'заголовок'),str(c.body.body,3,10000,'текст'),c.user.id);audit(c.user,'news.create',r.lastInsertRowid,c.ip);return {id:+r.lastInsertRowid}});
R('POST','/api/volunteer',(c)=>{need(c.user,'volunteer.apply');run('INSERT OR IGNORE INTO volunteers(user_id,about) VALUES(?,?)',c.user.id,String(c.body.about||'').slice(0,1000));return {ok:true}});
R('GET','/api/volunteers',(c)=>{need(c.user,'user.manage');return q('SELECT v.*,p.full_name FROM volunteers v JOIN profiles p ON p.user_id=v.user_id ORDER BY v.created_at DESC')});
R('GET','/api/notifications',(c)=>{need(c.user);return q('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50',c.user.id)});
R('POST','/api/feedback',(c)=>{if(limited(c.ip,'fb',5))throw new HttpError(429,'Слишком много сообщений');run('INSERT INTO feedback(name,email,message) VALUES(?,?,?)',String(c.body.name||'').slice(0,100),String(c.body.email||'').slice(0,120),str(c.body.message,5,3000,'сообщение'));return {ok:true}});
R('GET','/api/search',(c)=>{const s='%'+String(c.url.searchParams.get('q')||'').slice(0,60).replace(/[%_]/g,'')+'%';if(s.length<4)return {news:[],events:[],reports:[]};
 return {news:q('SELECT id,title FROM news WHERE title LIKE ? OR body LIKE ? LIMIT 10',s,s),events:q('SELECT id,title FROM events WHERE title LIKE ? OR description LIKE ? LIMIT 10',s,s),reports:q("SELECT id,title FROM environmental_reports WHERE status IN('in_progress','resolved') AND (title LIKE ? OR description LIKE ?) LIMIT 10",s,s)}});
R('GET','/api/admin/users',(c)=>{need(c.user,'user.manage');return q('SELECT u.id,u.email,u.is_active,r.code role,p.full_name FROM users u JOIN roles r ON r.id=u.role_id JOIN profiles p ON p.user_id=u.id ORDER BY u.id')});
R('PATCH','/api/admin/users/:id',(c,id)=>{need(c.user,'user.manage');const b=c.body;if(id===c.user.id)throw new HttpError(400,'Нельзя менять собственную роль/статус');
 if(b.role){const r=one('SELECT id FROM roles WHERE code=?',b.role);if(!r)throw new HttpError(400,'Неверная роль');run('UPDATE users SET role_id=? WHERE id=?',r.id,id)}
 if(b.is_active!==undefined)run('UPDATE users SET is_active=? WHERE id=?',b.is_active?1:0,id);audit(c.user,'user.update',`${id}:${JSON.stringify(b)}`,c.ip);return {ok:true}});
R('GET','/api/admin/audit',(c)=>{need(c.user,'audit.read');return q('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200')});
R('GET','/api/admin/feedback',(c)=>{need(c.user,'user.manage');return q('SELECT * FROM feedback ORDER BY id DESC LIMIT 200')});
// ---- server
const MIME={'.html':'text/html;charset=utf-8','.js':'text/javascript','.json':'application/json','.css':'text/css','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.txt':'text/plain','.xml':'application/xml'};
const SEC={'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY'};
const send=(res,code,data,h={})=>{const body=typeof data==='string'||Buffer.isBuffer(data)?data:JSON.stringify(data);res.writeHead(code,{...SEC,'Content-Type':'application/json',...h});res.end(body)};
const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://x');const ip=req.socket.remoteAddress;
 if(url.pathname.startsWith('/api/')){let raw='';req.on('data',d=>{raw+=d;if(raw.length>5e6)req.destroy()});req.on('end',()=>{try{
  const hit=routes.find(r=>r[0]===req.method&&r[1].test(url.pathname));if(!hit)return send(res,404,{error:'Не найдено'});
  const body=raw?JSON.parse(raw):{};const m=hit[1].exec(url.pathname);const out=hit[2]({user:auth(req),body,ip,url},...m.slice(1).map(Number));send(res,200,out??{ok:true},{'Cache-Control':'no-store'})}
  catch(e){if(e instanceof HttpError)return send(res,e.code,{error:e.message});if(e instanceof SyntaxError)return send(res,400,{error:'Неверный JSON'});console.error(e);send(res,500,{error:'Внутренняя ошибка'})}});return}
 let f=url.pathname.startsWith('/uploads/')?path.join(UP,path.basename(url.pathname)):path.join(__dirname,'public',decodeURIComponent(url.pathname));
 if(!f.startsWith(__dirname)||(!fs.existsSync(f)||fs.statSync(f).isDirectory()))f=path.join(__dirname,'public','index.html');
 res.writeHead(200,{...SEC,'Content-Type':MIME[path.extname(f)]||'application/octet-stream'});fs.createReadStream(f).pipe(res)});
if(require.main===module)server.listen(PORT,()=>console.log('ECO BOSTONLIQ: http://localhost:'+PORT));
module.exports={server,db};
