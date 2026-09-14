import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PRIVATE_DIR = path.join(ROOT, 'private', 'videos');
fs.mkdirSync(PRIVATE_DIR, { recursive: true });
const prisma = new PrismaClient();
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 400, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(ROOT, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const VIDEO_SECRET = process.env.VIDEO_SECRET || JWT_SECRET;
const OTP_TTL_MIN = Number(process.env.OTP_TTL_MINUTES || 5);
const cookieOpts = req => ({ httpOnly: true, secure: req.secure || req.headers['x-forwarded-proto'] === 'https', sameSite: 'lax', path: '/', maxAge: 8 * 60 * 60 * 1000 });
const sign = u => jwt.sign({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: '8h' });
const auth = role => async (req, res, next) => {
  try {
    const t = req.cookies.jte_token;
    if (!t) return res.status(401).json({ error: 'Unauthorized' });
    const p = jwt.verify(t, JWT_SECRET);
    if (role && p.role !== role) return res.status(403).json({ error: 'Forbidden' });
    req.user = p; next();
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
};
const safe = s => String(s).replace(/[^a-zA-Z0-9._-]/g, '_');
function normalizeMobile(value){
  let s=String(value||'').trim().replace(/[\s\-()]/g,'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d));
  if(s.startsWith('+98')) s='0'+s.slice(3);
  else if(s.startsWith('98')) s='0'+s.slice(2);
  return s;
}
const otpHash = code => crypto.createHash('sha256').update(`${code}:${JWT_SECRET}`).digest('hex');

async function sendOtp(mobile, code) {
  if (process.env.SMS_PROVIDER === 'kavenegar') {
    const apiKey=process.env.KAVENEGAR_API_KEY, template=process.env.KAVENEGAR_TEMPLATE;
    if(!apiKey || !template) throw new Error('سرویس پیامک کاوه‌نگار تنظیم نشده است');
    const url=`https://api.kavenegar.com/v1/${encodeURIComponent(apiKey)}/verify/lookup.json`;
    const body=new URLSearchParams({receptor:mobile,token:code,template});
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
    if(!r.ok) throw new Error('ارسال پیامک ناموفق بود');
    const data=await r.json().catch(()=>null);
    if(data?.return?.status && Number(data.return.status)!==200) throw new Error(data.return.message||'ارسال پیامک ناموفق بود');
    return;
  }
  if (process.env.SMS_PROVIDER === 'twilio') {
    const sid = process.env.TWILIO_ACCOUNT_SID, token = process.env.TWILIO_AUTH_TOKEN, from = process.env.TWILIO_FROM;
    if (!sid || !token || !from) throw new Error('SMS provider is not configured');
    const body = new URLSearchParams({ To: mobile, From: from, Body: `Journey to English: کد ورود شما ${code}` });
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, { method: 'POST', headers: { Authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (!r.ok) throw new Error('SMS send failed');
    return;
  }
  if (process.env.NODE_ENV === 'production') throw new Error('SMS_PROVIDER is not configured');
  console.log(`[DEV OTP] ${mobile}: ${code}`);
}

app.get('/health', (req,res)=>res.json({ status:'ok', service:'journey-to-english' }));
app.get('/api/config', (req,res)=>res.json({ smsOtp: true, devOtp: process.env.NODE_ENV !== 'production' }));

app.post('/api/auth/admin/login', async (req,res)=>{
  const s=z.object({username:z.string().min(1),password:z.string().min(1)}).safeParse(req.body);
  if(!s.success) return res.status(400).json({error:'اطلاعات ورود ناقص است'});
  const u=await prisma.user.findUnique({where:{username:s.data.username}});
  if(!u||u.role!=='ADMIN'||!u.passwordHash||!(await bcrypt.compare(s.data.password,u.passwordHash))) return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است'});
  res.cookie('jte_token',sign(u),cookieOpts(req)).json({ok:true,user:{name:u.name,role:u.role}});
});

app.post('/api/auth/student/request-otp', async (req,res)=>{
  const raw=z.object({mobile:z.string().trim().min(7).max(20)}).safeParse(req.body);
  if(!raw.success) return res.status(400).json({error:'شماره موبایل معتبر نیست'});
  const mobile=normalizeMobile(raw.data.mobile);
  const u=await prisma.user.findUnique({where:{mobile}});
  if(!u||u.role!=='STUDENT') return res.status(404).json({error:'این شماره به عنوان دانش‌آموز ثبت نشده است'});
  const code = String(crypto.randomInt(100000, 1000000));
  await prisma.otpCode.deleteMany({where:{userId:u.id, usedAt:null}});
  await prisma.otpCode.create({data:{userId:u.id,codeHash:otpHash(code),expiresAt:new Date(Date.now()+OTP_TTL_MIN*60*1000)}});
  try { await sendOtp(mobile, code); } catch(e) { await prisma.otpCode.deleteMany({where:{userId:u.id,codeHash:otpHash(code)}}); return res.status(503).json({error:e.message}); }
  res.json({ok:true,expiresInSeconds:OTP_TTL_MIN*60, ...(process.env.NODE_ENV!=='production' ? {devCode:code} : {})});
});
app.post('/api/auth/student/verify-otp', async (req,res)=>{
  const s=z.object({mobile:z.string().trim().min(7).max(20),code:z.string().regex(/^\d{6}$/)}).safeParse(req.body);
  if(!s.success) return res.status(400).json({error:'کد تأیید نامعتبر است'});
  const mobile=normalizeMobile(s.data.mobile);
  const u=await prisma.user.findUnique({where:{mobile}});
  if(!u||u.role!=='STUDENT') return res.status(401).json({error:'دانش‌آموز پیدا نشد'});
  const otp=await prisma.otpCode.findFirst({where:{userId:u.id,usedAt:null,expiresAt:{gt:new Date()}},orderBy:{createdAt:'desc'}});
  if(!otp||otp.attempts>=5||otp.codeHash!==otpHash(s.data.code)) { if(otp) await prisma.otpCode.update({where:{id:otp.id},data:{attempts:{increment:1}}}); return res.status(401).json({error:'کد تأیید نادرست یا منقضی شده است'}); }
  await prisma.otpCode.update({where:{id:otp.id},data:{usedAt:new Date()}});
  res.cookie('jte_token',sign(u),cookieOpts(req)).json({ok:true,user:{name:u.name,role:u.role}});
});
app.post('/api/auth/logout',(req,res)=>res.clearCookie('jte_token',{httpOnly:true,secure:req.secure||req.headers['x-forwarded-proto']==='https',sameSite:'lax',path:'/'}).json({ok:true}));
app.get('/api/me',auth(),async(req,res)=>res.json(await prisma.user.findUnique({where:{id:req.user.sub},select:{id:true,name:true,mobile:true,role:true}})));

app.get('/api/admin/students',auth('ADMIN'),async(req,res)=>res.json(await prisma.user.findMany({where:{role:'STUDENT'},include:{enrollments:{include:{course:true}}},orderBy:{createdAt:'desc'}})));
app.post('/api/admin/students',auth('ADMIN'),async(req,res)=>{const s=z.object({name:z.string().min(2),mobile:z.string().min(7).max(20)}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات دانش‌آموز نامعتبر است'});try{return res.json(await prisma.user.create({data:{name:s.data.name,mobile:normalizeMobile(s.data.mobile),role:'STUDENT'}}))}catch{return res.status(409).json({error:'این شماره موبایل قبلاً ثبت شده است'})}});
app.patch('/api/admin/students/:id',auth('ADMIN'),async(req,res)=>{const s=z.object({name:z.string().min(2),mobile:z.string().min(7).max(20)}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات نامعتبر است'});try{return res.json(await prisma.user.update({where:{id:req.params.id},data:{name:s.data.name,mobile:normalizeMobile(s.data.mobile)}}))}catch{return res.status(409).json({error:'شماره موبایل تکراری است'})}});
app.delete('/api/admin/students/:id',auth('ADMIN'),async(req,res)=>{await prisma.user.delete({where:{id:req.params.id}});res.json({ok:true})});

app.get('/api/admin/courses',auth('ADMIN'),async(req,res)=>res.json(await prisma.course.findMany({include:{lessons:{include:{sections:true},orderBy:{order:'asc'}}},orderBy:{createdAt:'desc'}})));
app.post('/api/admin/courses',auth('ADMIN'),async(req,res)=>{const s=z.object({title:z.string().min(1),description:z.string().optional(),level:z.string().optional()}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات دوره نامعتبر است'});res.json(await prisma.course.create({data:s.data}))});
app.patch('/api/admin/courses/:id',auth('ADMIN'),async(req,res)=>{const s=z.object({title:z.string().min(1),description:z.string().optional(),level:z.string().optional()}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات نامعتبر است'});res.json(await prisma.course.update({where:{id:req.params.id},data:s.data}))});
app.delete('/api/admin/courses/:id',auth('ADMIN'),async(req,res)=>{const c=await prisma.course.findUnique({where:{id:req.params.id},include:{lessons:{include:{sections:true}}}});if(!c)return res.status(404).json({error:'دوره پیدا نشد'});const files=c.lessons.flatMap(l=>l.sections.map(s=>s.videoPath).filter(Boolean));await prisma.course.delete({where:{id:req.params.id}});for(const f of files)fs.rm(path.join(PRIVATE_DIR,f),{force:true},()=>{});res.json({ok:true})});
app.post('/api/admin/courses/:courseId/lessons',auth('ADMIN'),async(req,res)=>{const s=z.object({title:z.string().min(1),order:z.coerce.number().int().optional()}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات درس نامعتبر است'});res.json(await prisma.lesson.create({data:{...s.data,courseId:req.params.courseId}}))});
app.post('/api/admin/lessons/:lessonId/sections',auth('ADMIN'),async(req,res)=>{const s=z.object({title:z.string().min(1),order:z.coerce.number().int().optional()}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات بخش نامعتبر است'});res.json(await prisma.section.create({data:{...s.data,lessonId:req.params.lessonId}}))});
app.delete('/api/admin/sections/:id',auth('ADMIN'),async(req,res)=>{const sec=await prisma.section.delete({where:{id:req.params.id}});if(sec.videoPath)fs.rm(path.join(PRIVATE_DIR,sec.videoPath),{force:true},()=>{});res.json({ok:true})});

const upload=multer({storage:multer.diskStorage({destination:PRIVATE_DIR,filename:(req,file,cb)=>cb(null,`${Date.now()}-${crypto.randomBytes(8).toString('hex')}-${safe(file.originalname)}`)}),limits:{fileSize:1024*1024*1024},fileFilter:(req,file,cb)=>cb(null, file.mimetype.startsWith('video/'))});
app.post('/api/admin/sections/:id/video',auth('ADMIN'),upload.single('video'),async(req,res)=>{if(!req.file)return res.status(400).json({error:'فایل ویدئو انتخاب نشده یا فرمت آن مجاز نیست'});const sec=await prisma.section.findUnique({where:{id:req.params.id}});if(!sec){fs.rm(req.file.path,{force:true},()=>{});return res.status(404).json({error:'بخش پیدا نشد'})}if(sec.videoPath)fs.rm(path.join(PRIVATE_DIR,sec.videoPath),{force:true},()=>{});const updated=await prisma.section.update({where:{id:sec.id},data:{videoPath:req.file.filename}});res.json({ok:true,section:updated})});

app.post('/api/admin/enrollments',auth('ADMIN'),async(req,res)=>{const s=z.object({studentId:z.string(),courseId:z.string(),status:z.enum(['ACTIVE','LOCKED'])}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'اطلاعات دسترسی نامعتبر است'});res.json(await prisma.enrollment.upsert({where:{studentId_courseId:{studentId:s.data.studentId,courseId:s.data.courseId}},update:{status:s.data.status},create:s.data}))});

app.get('/api/student/courses',auth('STUDENT'),async(req,res)=>res.json(await prisma.course.findMany({where:{enrollments:{some:{studentId:req.user.sub,status:'ACTIVE'}}},include:{lessons:{include:{sections:{select:{id:true,title:true,order:true,videoPath:true}}},orderBy:{order:'asc'}}},orderBy:{createdAt:'asc'}})));
app.get('/api/student/locked',auth('STUDENT'),async(req,res)=>res.json(await prisma.enrollment.findMany({where:{studentId:req.user.sub,status:'LOCKED'},include:{course:true}})));

function mimeFor(file){ const ext=path.extname(file).toLowerCase(); return ({'.mp4':'video/mp4','.webm':'video/webm','.ogg':'video/ogg','.mov':'video/quicktime','.m4v':'video/x-m4v'})[ext]||'application/octet-stream'; }
function videoSig(sectionId, exp){ return crypto.createHmac('sha256',VIDEO_SECRET).update(`${sectionId}.${exp}`).digest('hex'); }
app.get('/api/student/sections/:id/video-url',auth('STUDENT'),async(req,res)=>{
  const sec=await prisma.section.findUnique({where:{id:req.params.id},include:{lesson:{include:{course:true}}}});
  if(!sec||!sec.videoPath)return res.status(404).json({error:'ویدئو پیدا نشد'});
  const e=await prisma.enrollment.findUnique({where:{studentId_courseId:{studentId:req.user.sub,courseId:sec.lesson.courseId}}});
  if(!e||e.status!=='ACTIVE')return res.status(403).json({error:'دسترسی به این دوره فعال نیست'});
  const exp=Math.floor(Date.now()/1000)+Number(process.env.VIDEO_URL_TTL_SECONDS||120);
  res.json({url:`/api/video/${sec.id}?exp=${exp}&sig=${videoSig(sec.id,exp)}`,expiresAt:exp});
});
app.get('/api/video/:id',async(req,res)=>{
  try { const exp=Number(req.query.exp), sig=String(req.query.sig||''); if(!exp||exp<Math.floor(Date.now()/1000)||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(videoSig(req.params.id,exp)))) return res.status(401).end(); } catch { return res.status(401).end(); }
  const sec=await prisma.section.findUnique({where:{id:req.params.id}}); if(!sec?.videoPath)return res.status(404).end();
  const file=path.join(PRIVATE_DIR,sec.videoPath); if(!fs.existsSync(file))return res.status(404).end();
  const stat=fs.statSync(file), range=req.headers.range;
  res.setHeader('Content-Type', mimeFor(sec.videoPath)); res.setHeader('Accept-Ranges','bytes'); res.setHeader('Cache-Control','private, no-store');
  if(!range){res.setHeader('Content-Length',stat.size);return fs.createReadStream(file).pipe(res)}
  const [startS,endS]=range.replace(/bytes=/,'').split('-'); const start=Number(startS); const end=endS?Math.min(Number(endS),stat.size-1):stat.size-1; if(start>=stat.size||end<start)return res.status(416).end();
  res.status(206).set({ 'Content-Range':`bytes ${start}-${end}/${stat.size}`, 'Content-Length':end-start+1 }); fs.createReadStream(file,{start,end}).pipe(res);
});

app.get(/.*/,(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Journey to English running on ${port}`));
process.on('SIGTERM',async()=>{await prisma.$disconnect();process.exit(0)});
