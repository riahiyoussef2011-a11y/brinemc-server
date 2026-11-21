'use strict';
const express = require('express');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const SKIN_DIR = path.join(DATA, 'skins');
const CAPE_DIR = path.join(DATA, 'capes');
const SCH_DIR = path.join(DATA, 'schematics');
[SKIN_DIR, CAPE_DIR, SCH_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

const db = new Database(path.join(DATA, 'brinemc.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS capes(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS schematics(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  filename TEXT NOT NULL,
  thumb_ext TEXT NOT NULL,
  size INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS skins(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created INTEGER NOT NULL
);
`);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use('/api/schematics', express.json({ limit: '17mb' }));
app.use(express.json({ limit: '300kb' }));
app.use(cookieParser());

/* ---- security headers ---- */
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
  if (PROD) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

/* ---- tiny rate limiter (per IP + bucket) ---- */
const hits = new Map();
function limit(bucket, max, windowMs) {
  return (req, res, next) => {
    const k = bucket + ':' + req.ip, now = Date.now();
    const a = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (a.length >= max) return res.status(429).json({ error: 'rate' });
    a.push(now); hits.set(k, a); next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();

/* ---- helpers ---- */
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const NICK_RE = /^[A-Za-z0-9_]{3,16}$/;
const RESERVED = new Set(['admin', 'administrator', 'moderator', 'mod', 'staff', 'support', 'brinemc', 'system', 'root', 'null', 'undefined', 'guest', 'anonymous']);

function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString('hex'); }
function safeEq(a, b) { const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex'); return x.length === y.length && crypto.timingSafeEqual(x, y); }

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const maxAge = 30 * 864e5;
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(token, userId, Date.now() + maxAge);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge, path: '/' });
}
function currentUser(req) {
  const t = req.cookies && req.cookies.sid;
  if (!t || typeof t !== 'string') return null;
  const row = db.prepare('SELECT u.id,u.email,u.nickname,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t);
  if (!row) return null;
  if (row.expires < Date.now()) { db.prepare('DELETE FROM sessions WHERE token=?').run(t); return null; }
  return row;
}
function needUser(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: 'auth' });
  req.user = u; next();
}
/* CSRF: state-changing requests must come from our own origin */
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const o = req.get('origin');
  if (o) { try { if (new URL(o).host !== req.get('host')) return res.status(403).json({ error: 'origin' }); } catch (e) { return res.status(403).json({ error: 'origin' }); } }
  next();
});
function nickOk(n) { return typeof n === 'string' && NICK_RE.test(n) && !RESERVED.has(n.toLowerCase()); }

/* ---- auth ---- */
app.get('/api/nickname-check', limit('nick', 60, 60e3), (req, res) => {
  const n = String(req.query.nickname || '').trim();
  if (!NICK_RE.test(n)) return res.json({ valid: false, available: false, reason: 'format' });
  if (RESERVED.has(n.toLowerCase())) return res.json({ valid: false, available: false, reason: 'reserved' });
  const taken = !!db.prepare('SELECT 1 FROM users WHERE nickname=?').get(n);
  res.json({ valid: true, available: !taken });
});

app.post('/api/signup', limit('signup', 10, 3600e3), (req, res) => {
  const { email, password, nickname } = req.body || {};
  const e = typeof email === 'string' ? email.trim() : '';
  const n = typeof nickname === 'string' ? nickname.trim() : '';
  if (!EMAIL_RE.test(e) || typeof password !== 'string' || password.length < 8 || password.length > 200 || !nickOk(n))
    return res.status(400).json({ error: 'invalid' });
  if (db.prepare('SELECT 1 FROM users WHERE nickname=?').get(n)) return res.status(409).json({ error: 'nickname' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(e)) return res.status(409).json({ error: 'email' });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const r = db.prepare('INSERT INTO users(email,nickname,salt,hash,created) VALUES(?,?,?,?,?)').run(e, n, salt, hashPw(password, salt), Date.now());
    startSession(res, r.lastInsertRowid);
    res.json({ ok: true, email: e, nickname: n });
  } catch (err) { /* race: UNIQUE constraint is the final guard */
    const m = String(err.message);
    res.status(409).json({ error: /nickname/i.test(m) ? 'nickname' : 'email' });
  }
});

app.post('/api/signin', limit('signin', 20, 15 * 60e3), (req, res) => {
  const { email, nickname, identifier, password } = req.body || {};
  const id = String(identifier || email || nickname || '').trim();
  if (!id || typeof password !== 'string' || password.length > 200) return res.status(400).json({ error: 'invalid' });
  const u = db.prepare('SELECT * FROM users WHERE email=? OR nickname=?').get(id, id);
  const salt = u ? u.salt : 'x'.repeat(32);
  const h = hashPw(password, salt); /* same work whether or not the user exists */
  if (!u || !safeEq(h, u.hash)) return res.status(401).json({ error: 'credentials' });
  startSession(res, u.id);
  res.json({ ok: true, email: u.email, nickname: u.nickname });
});

app.post('/api/signout', (req, res) => {
  const t = req.cookies && req.cookies.sid;
  if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(String(t));
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: 'auth' });
  res.json({ email: u.email, nickname: u.nickname });
});

/* password reset needs an email provider: not configured yet */
app.post('/api/request-reset', limit('reset', 5, 3600e3), (req, res) => res.status(501).json({ error: 'not-configured' }));

/* ---- skins (shared with everyone, owned by the uploader) ---- */
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function validSkinPng(buf) {
  if (buf.length < 33 || buf.length > 200 * 1024 || !buf.subarray(0, 8).equals(PNG_SIG)) return false;
  if (buf.toString('ascii', 12, 16) !== 'IHDR') return false;
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  return w === 64 && (h === 64 || h === 32);
}

app.get('/api/skins', (req, res) => {
  const me = currentUser(req);
  const rows = db.prepare('SELECT s.id,s.name,s.created,s.user_id,u.nickname FROM skins s JOIN users u ON u.id=s.user_id ORDER BY s.created DESC').all();
  res.set('Cache-Control', 'no-store');
  res.json(rows.map(r => ({ id: r.id, name: r.name, created: r.created, by: r.nickname, mine: !!me && me.id === r.user_id })));
});

app.post('/api/skins', limit('skin', 20, 3600e3), needUser, (req, res) => {
  const { name, png } = req.body || {};
  const nm = typeof name === 'string' ? name.replace(/[^\w \-]/g, '').trim().slice(0, 16) : '';
  const m = typeof png === 'string' && /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(png);
  if (!nm || !m) return res.status(400).json({ error: 'invalid' });
  const buf = Buffer.from(m[1], 'base64');
  if (!validSkinPng(buf)) return res.status(400).json({ error: 'png' });
  const n = db.prepare('SELECT COUNT(*) c FROM skins WHERE user_id=?').get(req.user.id).c;
  if (n >= 100) return res.status(429).json({ error: 'quota' });
  const id = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(path.join(SKIN_DIR, id + '.png'), buf);
  db.prepare('INSERT INTO skins(id,user_id,name,created) VALUES(?,?,?,?)').run(id, req.user.id, nm, Date.now());
  res.json({ ok: true, id });
});

app.post('/api/skins/delete', needUser, (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!/^[0-9a-f]{16}$/.test(id)) return res.status(400).json({ error: 'invalid' });
  const r = db.prepare('DELETE FROM skins WHERE id=? AND user_id=?').run(id, req.user.id);
  if (r.changes) fs.rmSync(path.join(SKIN_DIR, id + '.png'), { force: true });
  res.json({ ok: r.changes > 0 });
});

app.get('/skins/:id.png', (req, res) => {
  if (!/^[0-9a-f]{16}$/.test(req.params.id)) return res.sendStatus(404);
  const f = path.join(SKIN_DIR, req.params.id + '.png');
  if (!fs.existsSync(f)) return res.sendStatus(404);
  res.set('Content-Type', 'image/png').set('Cache-Control', 'public, max-age=31536000, immutable').sendFile(f);
});

/* ---- capes (shared with everyone, owned by the uploader) ---- */
function validCapePng(buf) {
  if (buf.length < 33 || buf.length > 100 * 1024 || !buf.subarray(0, 8).equals(PNG_SIG)) return false;
  if (buf.toString('ascii', 12, 16) !== 'IHDR') return false;
  return buf.readUInt32BE(16) === 64 && buf.readUInt32BE(20) === 32;
}
app.get('/api/capes', (req, res) => {
  const me = currentUser(req);
  const rows = db.prepare('SELECT c.id,c.name,c.created,c.user_id,u.nickname FROM capes c JOIN users u ON u.id=c.user_id ORDER BY c.created DESC').all();
  res.set('Cache-Control', 'no-store');
  res.json(rows.map(r => ({ id: r.id, name: r.name, created: r.created, by: r.nickname, mine: !!me && me.id === r.user_id })));
});
app.post('/api/capes', limit('cape', 20, 3600e3), needUser, (req, res) => {
  const { name, png } = req.body || {};
  const nm = typeof name === 'string' ? name.replace(/[^\w \-]/g, '').trim().slice(0, 20) : '';
  const m = typeof png === 'string' && /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(png);
  if (!nm || !m) return res.status(400).json({ error: 'invalid' });
  const buf = Buffer.from(m[1], 'base64');
  if (!validCapePng(buf)) return res.status(400).json({ error: 'png' });
  if (db.prepare('SELECT COUNT(*) c FROM capes WHERE user_id=?').get(req.user.id).c >= 100) return res.status(429).json({ error: 'quota' });
  const id = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(path.join(CAPE_DIR, id + '.png'), buf);
  db.prepare('INSERT INTO capes(id,user_id,name,created) VALUES(?,?,?,?)').run(id, req.user.id, nm, Date.now());
  res.json({ ok: true, id });
});
app.post('/api/capes/delete', needUser, (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!/^[0-9a-f]{16}$/.test(id)) return res.status(400).json({ error: 'invalid' });
  const r = db.prepare('DELETE FROM capes WHERE id=? AND user_id=?').run(id, req.user.id);
  if (r.changes) fs.rmSync(path.join(CAPE_DIR, id + '.png'), { force: true });
  res.json({ ok: r.changes > 0 });
});
app.get('/capes/:id.png', (req, res) => {
  if (!/^[0-9a-f]{16}$/.test(req.params.id)) return res.sendStatus(404);
  const f = path.join(CAPE_DIR, req.params.id + '.png');
  if (!fs.existsSync(f)) return res.sendStatus(404);
  res.set('Content-Type', 'image/png').set('Cache-Control', 'public, max-age=31536000, immutable').sendFile(f);
});

/* ---- schematics (file + preview picture, shared with everyone) ---- */
const SCH_EXT = /\.(litematic|schem|schematic|nbt|mcstructure|mcpack|zip)$/i;
const SCH_MAX = 12 * 1024 * 1024;
function imgKind(buf) {
  if (buf.length > 8 && buf.subarray(0, 8).equals(PNG_SIG)) return 'png';
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.length > 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  return null;
}
const MIME = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp' };

app.get('/api/schematics', (req, res) => {
  const me = currentUser(req);
  const rows = db.prepare('SELECT s.id,s.name,s.filename,s.size,s.created,s.user_id,u.nickname FROM schematics s JOIN users u ON u.id=s.user_id ORDER BY s.created ASC').all();
  res.set('Cache-Control', 'no-store');
  res.json(rows.map(r => ({ id: r.id, name: r.name, filename: r.filename, size: r.size, created: r.created, by: r.nickname, mine: !!me && me.id === r.user_id })));
});
app.post('/api/schematics', limit('sch', 15, 3600e3), needUser, (req, res) => {
  const { name, filename, file, thumb } = req.body || {};
  const nm = typeof name === 'string' ? name.replace(/[<>]/g, '').trim().slice(0, 40) : '';
  const fn = typeof filename === 'string' ? filename.replace(/[^\w.\- ]/g, '_').slice(0, 80) : '';
  const fm = typeof file === 'string' && /^[A-Za-z0-9+/=]+$/.test(file);
  const tm = typeof thumb === 'string' && /^data:image\/(?:png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(thumb);
  if (!nm || !fn || !SCH_EXT.test(fn) || !fm || !tm) return res.status(400).json({ error: 'invalid' });
  const fbuf = Buffer.from(file, 'base64'), tbuf = Buffer.from(tm[1], 'base64');
  if (fbuf.length < 8 || fbuf.length > SCH_MAX) return res.status(413).json({ error: 'size' });
  const kind = imgKind(tbuf);
  if (!kind || tbuf.length > 1024 * 1024) return res.status(400).json({ error: 'thumb' });
  if (db.prepare('SELECT COUNT(*) c FROM schematics WHERE user_id=?').get(req.user.id).c >= 30) return res.status(429).json({ error: 'quota' });
  const id = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(path.join(SCH_DIR, id + '.bin'), fbuf);
  fs.writeFileSync(path.join(SCH_DIR, id + '.' + kind), tbuf);
  db.prepare('INSERT INTO schematics(id,user_id,name,filename,thumb_ext,size,created) VALUES(?,?,?,?,?,?,?)').run(id, req.user.id, nm, fn, kind, fbuf.length, Date.now());
  res.json({ ok: true, id });
});
app.post('/api/schematics/delete', needUser, (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!/^[0-9a-f]{16}$/.test(id)) return res.status(400).json({ error: 'invalid' });
  const row = db.prepare('SELECT thumb_ext FROM schematics WHERE id=? AND user_id=?').get(id, req.user.id);
  if (!row) return res.json({ ok: false });
  db.prepare('DELETE FROM schematics WHERE id=?').run(id);
  fs.rmSync(path.join(SCH_DIR, id + '.bin'), { force: true });
  fs.rmSync(path.join(SCH_DIR, id + '.' + row.thumb_ext), { force: true });
  res.json({ ok: true });
});
app.get('/schematics/:id.png', (req, res) => {
  if (!/^[0-9a-f]{16}$/.test(req.params.id)) return res.sendStatus(404);
  const row = db.prepare('SELECT thumb_ext FROM schematics WHERE id=?').get(req.params.id);
  if (!row) return res.sendStatus(404);
  res.set('Content-Type', MIME[row.thumb_ext]).set('Cache-Control', 'public, max-age=31536000, immutable')
    .sendFile(path.join(SCH_DIR, req.params.id + '.' + row.thumb_ext));
});
app.get('/schematics/:id.bin', (req, res) => {
  if (!/^[0-9a-f]{16}$/.test(req.params.id)) return res.sendStatus(404);
  const f = path.join(SCH_DIR, req.params.id + '.bin');
  if (!fs.existsSync(f)) return res.sendStatus(404);
  res.set('Content-Type', 'application/octet-stream').set('Cache-Control', 'public, max-age=31536000, immutable').sendFile(f);
});

/* ---- the site itself ---- */
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', dotfiles: 'ignore' }));

setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()), 3600e3).unref();
app.listen(PORT, () => console.log('BrineMC on http://localhost:' + PORT));
