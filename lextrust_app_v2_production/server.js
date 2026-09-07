require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const LOCAL_STORAGE = path.join(ROOT, 'storage');
const PROD = process.env.NODE_ENV === 'production';
const STORAGE_DRIVER = String(process.env.STORAGE_DRIVER || (PROD ? 's3' : 'local')).toLowerCase();

if (PROD) {
  const required = ['DATABASE_URL', 'SESSION_SECRET', 'OWNER_USERNAME', 'OWNER_PASSWORD', 'OWNER_CONTACT'];
  const missing = required.filter(k => !process.env[k] || String(process.env[k]).startsWith('CHANGE_THIS'));
  if (missing.length) throw new Error(`Missing required production environment variables: ${missing.join(', ')}`);
  if (STORAGE_DRIVER !== 's3') throw new Error('Production requires STORAGE_DRIVER=s3 so legal evidence is not stored on Render ephemeral disk.');
}

fs.mkdirSync(LOCAL_STORAGE, { recursive: true });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: String(process.env.DATABASE_SSL || '').toLowerCase() === 'true' ? { rejectUnauthorized: false } : false,
  max: 10
});

const s3 = STORAGE_DRIVER === 's3' ? new S3Client({
  region: process.env.S3_REGION || 'auto',
  endpoint: process.env.S3_ENDPOINT || undefined,
  forcePathStyle: String(process.env.S3_FORCE_PATH_STYLE || '').toLowerCase() === 'true',
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY || ''
  }
}) : null;

const PERMISSIONS = ['view_all_cases', 'manage_cases', 'respond_chat', 'assign_cases', 'manage_users', 'view_audit'];
const CASE_STATUSES = ['جديدة', 'قيد المعالجة', 'بانتظار العميل', 'مغلقة'];

function now() { return new Date().toISOString(); }
function safeUsername(v) { return String(v || '').trim().replace(/[^\p{L}\p{N}_.-]/gu, '').slice(0, 40); }
function normalizeContact(v) { return String(v || '').trim().toLowerCase().slice(0, 180); }
function cleanText(v, max = 5000) { return String(v || '').trim().slice(0, max); }
function safeUser(row) {
  if (!row) return null;
  return { id: row.id, username: row.username, contact: row.contact, role: row.role, permissions: row.permissions || [], createdAt: row.created_at || row.createdAt };
}
function auth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'يجب تسجيل الدخول' }); next(); }
function ownerOnly(req, res, next) { if (!req.session.user || req.session.user.role !== 'owner') return res.status(403).json({ error: 'غير مصرح' }); next(); }
function can(user, perm) { return user?.role === 'owner' || (user?.permissions || []).includes(perm); }
function caseNumber(n) { return String(n).padStart(3, '0'); }
function validPermissions(list) { return [...new Set((Array.isArray(list) ? list : []).filter(p => PERMISSIONS.includes(p)))]; }
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim().slice(0, 90); }

async function audit(actorId, action, targetType = null, targetId = null, meta = {}, req = null) {
  await pool.query(
    `INSERT INTO audit_logs(actor_id, action, target_type, target_id, metadata, ip_address, created_at)
     VALUES($1,$2,$3,$4,$5,$6,NOW())`,
    [actorId || null, action, targetType, targetId ? String(targetId) : null, JSON.stringify(meta || {}), req ? clientIp(req) : null]
  );
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      contact VARCHAR(180) NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'client' CHECK (role IN ('owner','employee','client')),
      permissions TEXT[] NOT NULL DEFAULT '{}',
      failed_logins INT NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS permission_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permissions TEXT[] NOT NULL DEFAULT '{}',
      reason TEXT NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      resolved_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS cases (
      id BIGSERIAL PRIMARY KEY,
      case_no BIGSERIAL UNIQUE NOT NULL,
      client_id BIGINT NOT NULL REFERENCES users(id),
      title VARCHAR(220) NOT NULL,
      details TEXT NOT NULL,
      status VARCHAR(40) NOT NULL DEFAULT 'جديدة',
      assigned_to BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS case_notes (
      id BIGSERIAL PRIMARY KEY,
      case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      author_id BIGINT NOT NULL REFERENCES users(id),
      text TEXT NOT NULL,
      internal BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS evidence (
      id BIGSERIAL PRIMARY KEY,
      case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      uploaded_by BIGINT NOT NULL REFERENCES users(id),
      original_name TEXT NOT NULL,
      object_key TEXT NOT NULL,
      mime_type VARCHAR(120) NOT NULL,
      size_bytes BIGINT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      sender_id BIGINT NOT NULL REFERENCES users(id),
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id BIGINT REFERENCES users(id),
      action VARCHAR(100) NOT NULL,
      target_type VARCHAR(60),
      target_id VARCHAR(80),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip_address VARCHAR(90),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_cases_client ON cases(client_id);
    CREATE INDEX IF NOT EXISTS idx_cases_assigned ON cases(assigned_to);
    CREATE INDEX IF NOT EXISTS idx_messages_case ON messages(case_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
  `);

  const ownerUsername = safeUsername(process.env.OWNER_USERNAME || 'owner');
  const ownerPassword = process.env.OWNER_PASSWORD || 'ChangeMe123!';
  const ownerContact = normalizeContact(process.env.OWNER_CONTACT || 'lex.trust.sa@gmail.com');
  const hash = await bcrypt.hash(ownerPassword, 12);
  const existing = await pool.query('SELECT id FROM users WHERE role=$1 LIMIT 1', ['owner']);
  if (!existing.rowCount) {
    await pool.query(`INSERT INTO users(username,password_hash,contact,role,permissions) VALUES($1,$2,$3,'owner',$4)`, [ownerUsername, hash, ownerContact, PERMISSIONS]);
  } else if (process.env.SYNC_OWNER_FROM_ENV === 'true') {
    await pool.query(`UPDATE users SET username=$1,password_hash=$2,contact=$3,permissions=$4,updated_at=NOW() WHERE id=$5`, [ownerUsername, hash, ownerContact, PERMISSIONS, existing.rows[0].id]);
  }
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'development-only-change-this-secret',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: 'lextrust.sid',
  cookie: { httpOnly: true, secure: PROD, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 4 }
}));

app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 25, standardHeaders: true, legacyHeaders: false, message: { error: 'محاولات كثيرة. حاول لاحقًا.' } }));
app.use('/api/register', rateLimit({ windowMs: 60 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false, message: { error: 'تم تجاوز عدد محاولات التسجيل مؤقتًا.' } }));

app.get('/api/csrf', (req, res) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  res.json({ csrf: req.session.csrf });
});
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!req.session.csrf || req.get('x-csrf-token') !== req.session.csrf) return res.status(403).json({ error: 'انتهت جلسة الحماية. حدث الصفحة وحاول مرة أخرى.' });
  next();
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024, files: 1 },
  fileFilter: (_, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    cb(allowed.includes(file.mimetype) ? null : new Error('نوع الملف غير مدعوم. المسموح JPG/PNG/WEBP/PDF'), allowed.includes(file.mimetype));
  }
});

app.get('/health', async (_, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true }); }
  catch { res.status(503).json({ ok: false }); }
});

app.get('/api/config', (_, res) => res.json({
  brand: 'Lex Trust',
  website: process.env.PUBLIC_WEBSITE_URL || 'https://lextrust.sa',
  email: 'lex.trust.sa@gmail.com',
  permissions: PERMISSIONS,
  socials: {
    x: 'https://x.com/Lex_Trust_sa',
    instagram: 'https://www.instagram.com/lex.trust.sa/',
    snapchat: 'https://www.snapchat.com/add/lex.trust'
  }
}));

app.post('/api/register', async (req, res, next) => {
  try {
    const username = safeUsername(req.body.username);
    const password = String(req.body.password || '');
    const contact = normalizeContact(req.body.contact);
    if (username.length < 3 || password.length < 10 || !contact) return res.status(400).json({ error: 'اسم المستخدم 3 أحرف على الأقل، وكلمة المرور 10 أحرف على الأقل، وأدخل رقم الجوال أو البريد.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const q = await pool.query(`INSERT INTO users(username,password_hash,contact,role,permissions) VALUES($1,$2,$3,'client','{}') RETURNING *`, [username, passwordHash, contact]);
    const user = safeUser(q.rows[0]);
    req.session.user = user;
    await audit(user.id, 'user_registered', 'user', user.id, {}, req);
    res.json({ user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل' });
    next(e);
  }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const username = safeUsername(req.body.username);
    const contact = normalizeContact(req.body.contact);
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT * FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1', [username]);
    const u = q.rows[0];
    if (u?.locked_until && new Date(u.locked_until) > new Date()) return res.status(423).json({ error: 'الحساب مقفل مؤقتًا بسبب محاولات دخول فاشلة. حاول بعد عدة دقائق.' });
    const ok = !!u && normalizeContact(u.contact) === contact && await bcrypt.compare(password, u.password_hash);
    if (!ok) {
      if (u) {
        const attempts = Number(u.failed_logins || 0) + 1;
        const lock = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
        await pool.query('UPDATE users SET failed_logins=$1, locked_until=$2, updated_at=NOW() WHERE id=$3', [lock ? 0 : attempts, lock, u.id]);
        await audit(u.id, 'login_failed', 'user', u.id, { locked: !!lock }, req);
      }
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }
    await pool.query('UPDATE users SET failed_logins=0,locked_until=NULL,updated_at=NOW() WHERE id=$1', [u.id]);
    req.session.regenerate(async err => {
      if (err) return next(err);
      req.session.csrf = crypto.randomBytes(32).toString('hex');
      req.session.user = safeUser(u);
      await audit(u.id, 'login_success', 'user', u.id, {}, req);
      res.json({ user: req.session.user, csrf: req.session.csrf });
    });
  } catch (e) { next(e); }
});

app.post('/api/logout', auth, async (req, res) => {
  const uid = req.session.user.id;
  await audit(uid, 'logout', 'user', uid, {}, req);
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));

app.post('/api/permission-requests', auth, async (req, res, next) => {
  try {
    const permissions = validPermissions(req.body.permissions);
    const reason = cleanText(req.body.reason, 1000);
    if (!permissions.length) return res.status(400).json({ error: 'اختر صلاحية واحدة على الأقل' });
    const existing = await pool.query(`SELECT id FROM permission_requests WHERE user_id=$1 AND status='pending' LIMIT 1`, [req.session.user.id]);
    if (existing.rowCount) return res.status(409).json({ error: 'لديك طلب صلاحية قيد المراجعة' });
    const q = await pool.query(`INSERT INTO permission_requests(user_id,permissions,reason) VALUES($1,$2,$3) RETURNING *`, [req.session.user.id, permissions, reason]);
    await audit(req.session.user.id, 'permission_requested', 'permission_request', q.rows[0].id, { permissions }, req);
    res.json({ request: q.rows[0] });
  } catch (e) { next(e); }
});

app.get('/api/owner/permission-requests', ownerOnly, async (_, res, next) => {
  try {
    const q = await pool.query(`SELECT r.*,u.username,u.contact,u.role,u.permissions AS user_permissions,u.created_at AS user_created_at
      FROM permission_requests r JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC`);
    res.json(q.rows.map(r => ({ id:r.id,userId:r.user_id,permissions:r.permissions,reason:r.reason,status:r.status,createdAt:r.created_at,resolvedAt:r.resolved_at,user:{id:r.user_id,username:r.username,contact:r.contact,role:r.role,permissions:r.user_permissions,createdAt:r.user_created_at} })));
  } catch (e) { next(e); }
});

app.post('/api/owner/permission-requests/:id/resolve', ownerOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rq = await client.query('SELECT * FROM permission_requests WHERE id=$1 FOR UPDATE', [req.params.id]);
    if (!rq.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'الطلب غير موجود' }); }
    const r = rq.rows[0];
    if (r.status !== 'pending') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'تمت معالجة هذا الطلب مسبقًا' }); }
    const approved = req.body.status === 'approved';
    const permissions = approved ? validPermissions(req.body.permissions) : [];
    await client.query(`UPDATE permission_requests SET status=$1,resolved_by=$2,resolved_at=NOW() WHERE id=$3`, [approved ? 'approved' : 'rejected', req.session.user.id, r.id]);
    if (approved) await client.query(`UPDATE users SET role='employee',permissions=$1,updated_at=NOW() WHERE id=$2`, [permissions, r.user_id]);
    await client.query('COMMIT');
    await audit(req.session.user.id, approved ? 'permission_approved' : 'permission_rejected', 'user', r.user_id, { permissions }, req);
    res.json({ ok: true });
  } catch (e) { await client.query('ROLLBACK').catch(()=>{}); next(e); }
  finally { client.release(); }
});

app.get('/api/owner/users', ownerOnly, async (_, res, next) => {
  try { const q = await pool.query('SELECT * FROM users ORDER BY created_at DESC'); res.json(q.rows.map(safeUser)); }
  catch (e) { next(e); }
});
app.post('/api/owner/users/:id/permissions', ownerOnly, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const permissions = validPermissions(req.body.permissions);
    const role = req.body.role === 'client' ? 'client' : 'employee';
    const q = await pool.query(`UPDATE users SET role=$1,permissions=$2,updated_at=NOW() WHERE id=$3 AND role<>'owner' RETURNING *`, [role, permissions, id]);
    if (!q.rowCount) return res.status(404).json({ error: 'المستخدم غير موجود أو لا يمكن تعديل المالك' });
    await audit(req.session.user.id, 'user_permissions_changed', 'user', id, { role, permissions }, req);
    res.json({ user: safeUser(q.rows[0]) });
  } catch (e) { next(e); }
});

app.post('/api/cases', auth, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 220), details = cleanText(req.body.details, 10000);
    if (!title || !details) return res.status(400).json({ error: 'أدخل عنوان وتفاصيل القضية' });
    const q = await pool.query(`INSERT INTO cases(client_id,title,details,status) VALUES($1,$2,$3,'جديدة') RETURNING *`, [req.session.user.id, title, details]);
    const c = q.rows[0];
    await audit(req.session.user.id, 'case_created', 'case', c.id, { caseNo: caseNumber(c.case_no) }, req);
    res.json({ case: { id:c.id,number:caseNumber(c.case_no),title:c.title,details:c.details,status:c.status,createdAt:c.created_at } });
  } catch (e) { next(e); }
});

async function visibleCaseRows(user) {
  let where = '', params = [];
  if (user.role === 'owner' || can(user, 'view_all_cases')) {}
  else if (user.role === 'employee') { where = 'WHERE c.assigned_to=$1'; params=[user.id]; }
  else { where = 'WHERE c.client_id=$1'; params=[user.id]; }
  const q = await pool.query(`SELECT c.*,cl.username client_username,cl.contact client_contact,cl.role client_role,cl.permissions client_permissions,cl.created_at client_created_at,
    a.username assignee_username,a.contact assignee_contact,a.role assignee_role,a.permissions assignee_permissions,a.created_at assignee_created_at
    FROM cases c JOIN users cl ON cl.id=c.client_id LEFT JOIN users a ON a.id=c.assigned_to ${where} ORDER BY c.created_at DESC`, params);
  return q.rows;
}

async function decorateCase(row, user) {
  const evid = await pool.query('SELECT id,original_name,note,mime_type,size_bytes,created_at FROM evidence WHERE case_id=$1 ORDER BY created_at DESC', [row.id]);
  let notes = [];
  if (user.role === 'owner' || (user.role === 'employee' && row.assigned_to === user.id)) {
    const nq = await pool.query('SELECT n.id,n.text,n.internal,n.created_at,u.username author FROM case_notes n JOIN users u ON u.id=n.author_id WHERE n.case_id=$1 ORDER BY n.created_at DESC', [row.id]);
    notes = nq.rows.map(n=>({id:n.id,text:n.text,internal:n.internal,createdAt:n.created_at,author:n.author}));
  }
  return {
    id:row.id,number:caseNumber(row.case_no),clientId:row.client_id,title:row.title,details:row.details,status:row.status,assignedTo:row.assigned_to,createdAt:row.created_at,updatedAt:row.updated_at,
    client:{id:row.client_id,username:row.client_username,contact:row.client_contact,role:row.client_role,permissions:row.client_permissions||[],createdAt:row.client_created_at},
    assignee:row.assigned_to?{id:row.assigned_to,username:row.assignee_username,contact:row.assignee_contact,role:row.assignee_role,permissions:row.assignee_permissions||[],createdAt:row.assignee_created_at}:null,
    ownerNotes:notes,
    evidence:evid.rows.map(e=>({id:e.id,name:e.original_name,note:e.note,mimeType:e.mime_type,sizeBytes:Number(e.size_bytes),createdAt:e.created_at,url:`/api/evidence/${e.id}/download`}))
  };
}

app.get('/api/cases', auth, async (req, res, next) => {
  try { const rows = await visibleCaseRows(req.session.user); res.json(await Promise.all(rows.map(r=>decorateCase(r,req.session.user)))); }
  catch (e) { next(e); }
});

async function getAccessibleCase(user, caseId) {
  const q = await pool.query('SELECT * FROM cases WHERE id=$1', [caseId]);
  if (!q.rowCount) return null;
  const c = q.rows[0];
  if (user.role === 'owner' || can(user,'view_all_cases') || c.client_id === user.id || c.assigned_to === user.id) return c;
  return false;
}

app.post('/api/cases/:id/assign', ownerOnly, async (req, res, next) => {
  try {
    const username = safeUsername(req.body.username);
    const uq = await pool.query(`SELECT * FROM users WHERE LOWER(username)=LOWER($1) AND role IN ('employee','owner') LIMIT 1`, [username]);
    if (!uq.rowCount) return res.status(404).json({ error: 'الموظف غير موجود أو ليس لديه صلاحية موظف' });
    const q = await pool.query(`UPDATE cases SET assigned_to=$1,status='قيد المعالجة',updated_at=NOW() WHERE id=$2 RETURNING *`, [uq.rows[0].id, req.params.id]);
    if (!q.rowCount) return res.status(404).json({ error: 'القضية غير موجودة' });
    await audit(req.session.user.id, 'case_assigned', 'case', req.params.id, { assignedTo: uq.rows[0].username }, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/cases/:id/status', auth, async (req, res, next) => {
  try {
    const c = await getAccessibleCase(req.session.user, req.params.id);
    if (!c) return res.status(c === false ? 403 : 404).json({ error: c === false ? 'غير مصرح' : 'القضية غير موجودة' });
    if (!(req.session.user.role === 'owner' || (c.assigned_to === req.session.user.id && can(req.session.user,'manage_cases')))) return res.status(403).json({ error: 'غير مصرح' });
    const status = CASE_STATUSES.includes(req.body.status) ? req.body.status : null;
    if (!status) return res.status(400).json({ error: 'حالة غير صحيحة' });
    await pool.query('UPDATE cases SET status=$1,updated_at=NOW() WHERE id=$2', [status, c.id]);
    await audit(req.session.user.id, 'case_status_changed', 'case', c.id, { status }, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/cases/:id/note', ownerOnly, async (req, res, next) => {
  try {
    const text = cleanText(req.body.text, 5000);
    if (!text) return res.status(400).json({ error: 'اكتب الملاحظة' });
    const cq = await pool.query('SELECT id FROM cases WHERE id=$1', [req.params.id]);
    if (!cq.rowCount) return res.status(404).json({ error: 'القضية غير موجودة' });
    const q = await pool.query(`INSERT INTO case_notes(case_id,author_id,text,internal) VALUES($1,$2,$3,TRUE) RETURNING id`, [req.params.id, req.session.user.id, text]);
    await audit(req.session.user.id, 'case_note_added', 'case', req.params.id, { noteId:q.rows[0].id }, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

async function storeFile(file, caseId) {
  const ext = ({'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp','application/pdf':'.pdf'})[file.mimetype] || '';
  const key = `cases/${caseId}/${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext}`;
  if (STORAGE_DRIVER === 's3') {
    if (!process.env.S3_BUCKET || !process.env.S3_ACCESS_KEY_ID || !process.env.S3_SECRET_ACCESS_KEY) throw new Error('S3/R2 storage is not configured');
    await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key:key, Body:file.buffer, ContentType:file.mimetype, ServerSideEncryption: process.env.S3_SSE || undefined }));
  } else {
    const full = path.join(LOCAL_STORAGE, key);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, file.buffer);
  }
  return key;
}

app.post('/api/cases/:id/evidence', ownerOnly, upload.single('file'), async (req, res, next) => {
  try {
    const cq = await pool.query('SELECT id FROM cases WHERE id=$1', [req.params.id]);
    if (!cq.rowCount) return res.status(404).json({ error: 'القضية غير موجودة' });
    if (!req.file) return res.status(400).json({ error: 'اختر ملفًا' });
    const key = await storeFile(req.file, req.params.id);
    const q = await pool.query(`INSERT INTO evidence(case_id,uploaded_by,original_name,object_key,mime_type,size_bytes,note) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, [req.params.id,req.session.user.id,cleanText(req.file.originalname,240),key,req.file.mimetype,req.file.size,cleanText(req.body.note,1000)]);
    await audit(req.session.user.id, 'evidence_uploaded', 'case', req.params.id, { evidenceId:q.rows[0].id, mime:req.file.mimetype, size:req.file.size }, req);
    res.json({ ok:true });
  } catch (e) { next(e); }
});

app.get('/api/evidence/:id/download', auth, async (req, res, next) => {
  try {
    const q = await pool.query(`SELECT e.*,c.client_id,c.assigned_to FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.id=$1`, [req.params.id]);
    if (!q.rowCount) return res.status(404).json({ error: 'الملف غير موجود' });
    const e = q.rows[0], u = req.session.user;
    if (!(u.role === 'owner' || can(u,'view_all_cases') || e.client_id === u.id || e.assigned_to === u.id)) return res.status(403).json({ error: 'غير مصرح' });
    await audit(u.id, 'evidence_downloaded', 'evidence', e.id, { caseId:e.case_id }, req);
    if (STORAGE_DRIVER === 's3') {
      const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket:process.env.S3_BUCKET, Key:e.object_key, ResponseContentDisposition:`attachment; filename*=UTF-8''${encodeURIComponent(e.original_name)}` }), { expiresIn: 120 });
      return res.redirect(url);
    }
    const full = path.join(LOCAL_STORAGE, e.object_key);
    if (!fs.existsSync(full)) return res.status(404).json({ error: 'الملف غير موجود في التخزين' });
    res.download(full, e.original_name);
  } catch (e) { next(e); }
});

app.get('/api/cases/:id/messages', auth, async (req, res, next) => {
  try {
    const c = await getAccessibleCase(req.session.user, req.params.id);
    if (!c) return res.status(c === false ? 403 : 404).json({ error: c === false ? 'غير مصرح' : 'القضية غير موجودة' });
    const q = await pool.query(`SELECT m.*,u.username,u.contact,u.role,u.permissions,u.created_at user_created_at FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.case_id=$1 ORDER BY m.created_at ASC LIMIT 1000`, [c.id]);
    res.json(q.rows.map(m=>({id:m.id,caseId:m.case_id,senderId:m.sender_id,text:m.text,createdAt:m.created_at,sender:{id:m.sender_id,username:m.username,contact:m.contact,role:m.role,permissions:m.permissions||[],createdAt:m.user_created_at}})));
  } catch (e) { next(e); }
});

app.post('/api/cases/:id/messages', auth, async (req, res, next) => {
  try {
    const c = await getAccessibleCase(req.session.user, req.params.id);
    if (!c) return res.status(c === false ? 403 : 404).json({ error: c === false ? 'غير مصرح' : 'القضية غير موجودة' });
    if (req.session.user.role === 'employee' && !can(req.session.user,'respond_chat')) return res.status(403).json({ error: 'ليس لديك صلاحية الرد على المحادثات' });
    const text = cleanText(req.body.text, 4000);
    if (!text) return res.status(400).json({ error: 'اكتب رسالة' });
    const q = await pool.query(`INSERT INTO messages(case_id,sender_id,text) VALUES($1,$2,$3) RETURNING *`, [c.id, req.session.user.id, text]);
    await audit(req.session.user.id, 'message_sent', 'case', c.id, { messageId:q.rows[0].id }, req);
    res.json({ message:q.rows[0] });
  } catch (e) { next(e); }
});

app.get('/api/owner/audit', ownerOnly, async (req, res, next) => {
  try {
    const q = await pool.query(`SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 250`);
    res.json(q.rows.map(a=>({id:a.id,actorId:a.actor_id,username:a.username,action:a.action,targetType:a.target_type,targetId:a.target_id,metadata:a.metadata,ip:a.ip_address,createdAt:a.created_at})));
  } catch (e) { next(e); }
});

app.use(express.static(PUBLIC_DIR, { maxAge: PROD ? '1h' : 0, etag:true }));
app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'حجم الملف يتجاوز 15MB' });
  res.status(500).json({ error: PROD ? 'حدث خطأ داخلي. تم تسجيله.' : (err.message || 'حدث خطأ') });
});
app.get('*', (_, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

initDb().then(() => app.listen(PORT, () => console.log(`Lex Trust v2 running on http://localhost:${PORT}`))).catch(err => { console.error('Startup failed:', err); process.exit(1); });
