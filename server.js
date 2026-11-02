'use strict';
/* My Website server: serves public/BrineMC.html and shares skins between all devices.
   No dependencies. Run:  node server.js   (Node 18+)  */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public');
const DATA = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const SKIN_DIR = path.join(DATA, 'skins');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
/* sites allowed to call the API through a proxy (e.g. your Netlify address) */
const ALLOWED = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean)
  .map(x => { try { return new URL(x).host; } catch (e) { return x; } });
fs.mkdirSync(SKIN_DIR, { recursive: true });

const DB_FILE = path.join(DATA, 'db.json');
let db = { users: {}, sessions: {}, skins: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) {}
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}

const MAX_BODY = 300 * 1024, MAX_PNG = 100 * 1024, MAX_SKINS_PER_USER = 100, MAX_SKINS_TOTAL = 5000;
const SESSION_MS = 30 * 864e5;

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString('hex'); }
function send(res, code, obj, headers) {
  const body = JSON.stringify(obj === undefined ? {} : obj);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, headers));
  res.end(body);
}
function ip(req) {
  if (TRUST_PROXY && req.headers['x-nf-client-connection-ip']) return String(req.headers['x-nf-client-connection-ip']).trim();
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || '?';
}
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (a.length >= max) { hits.set(key, a); return true; }
  a.push(now); hits.set(key, a); return false;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some(t => now - t < 36e5)) hits.delete(k);
  for (const [k, s] of Object.entries(db.sessions)) if (s.exp < now) delete db.sessions[k]; }, 6e5).unref();

function cookies(req) {
  const o = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); });
  return o;
}
function sessionEmail(req) {
  const t = cookies(req).mw_sid; if (!t) return null;
  const s = db.sessions[sha(t)]; if (!s || s.exp < Date.now()) return null;
  return s.email;
}
function secure(req) { return !!req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https'); }
function startSession(req, res, email) {
  const t = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(t)] = { email, exp: Date.now() + SESSION_MS }; save();
  return 'mw_sid=' + t + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + (SESSION_MS / 1000) + (secure(req) ? '; Secure' : '');
}
function readJson(req) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { no(413); req.destroy(); } else ch.push(c); });
    req.on('end', () => { if (!n) return ok({}); try { const j = JSON.parse(Buffer.concat(ch).toString('utf8')); ok(j && typeof j === 'object' ? j : {}); } catch (e) { no(400); } });
    req.on('error', () => no(400));
  });
}
const validEmail = e => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

/* ---------- API ---------- */
async function api(req, res, url) {
  const p = url.pathname;
  if (req.method === 'POST') {            /* block cross-site posts */
    const o = req.headers.origin;
    if (o) { try { const oh = new URL(o).host; if (oh !== req.headers.host && !ALLOWED.includes(oh)) return send(res, 403, { error: 'origin' }); } catch (e) { return send(res, 403, { error: 'origin' }); } }
  }
  if (p === '/api/skins' && req.method === 'GET') {
    const me = sessionEmail(req);
    return send(res, 200, db.skins.slice().sort((a, b) => b.created - a.created).map(s => ({ id: s.id, name: s.name, created: s.created, mine: !!me && s.email === me })));
  }
  if (p === '/api/me' && req.method === 'GET') {
    const me = sessionEmail(req); return me ? send(res, 200, { email: me }) : send(res, 401, { error: 'signed out' });
  }
  if (req.method !== 'POST') return send(res, 404, { error: 'not found' });

  let body; try { body = await readJson(req); } catch (c) { return send(res, c === 413 ? 413 : 400, { error: 'bad body' }); }

  if (p === '/api/signup' || p === '/api/signin') {
    if (limited('auth:' + ip(req), 20, 15 * 6e4)) return send(res, 429, { error: 'too many attempts' });
    const email = String(body.email || '').trim().toLowerCase(), pw = body.password;
    if (!validEmail(email) || typeof pw !== 'string' || pw.length < (p === '/api/signup' ? 8 : 1) || pw.length > 200) return send(res, 400, { error: 'invalid' });
    if (p === '/api/signup') {
      if (db.users[email]) return send(res, 409, { error: 'exists' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[email] = { salt, hash: hashPw(pw, salt), created: Date.now() };
      return send(res, 200, { email }, { 'Set-Cookie': startSession(req, res, email) });
    }
    const u = db.users[email], salt = u ? u.salt : 'x'.repeat(32), h = Buffer.from(hashPw(pw, salt), 'hex');
    const good = u && crypto.timingSafeEqual(h, Buffer.from(u.hash, 'hex'));
    if (!good) return send(res, 401, { error: 'wrong' });
    return send(res, 200, { email }, { 'Set-Cookie': startSession(req, res, email) });
  }
  if (p === '/api/signout') {
    const t = cookies(req).mw_sid; if (t) { delete db.sessions[sha(t)]; save(); }
    return send(res, 200, {}, { 'Set-Cookie': 'mw_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }
  if (p === '/api/request-reset') return send(res, 501, { error: 'email sending is not configured' });

  if (p === '/api/skins') {
    const me = sessionEmail(req); if (!me) return send(res, 401, { error: 'sign in' });
    if (limited('up:' + me, 20, 36e5)) return send(res, 429, { error: 'too many uploads' });
    const name = String(body.name || '').replace(/[^\w \-]/g, '').trim().slice(0, 16);
    const m = /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(String(body.png || ''));
    if (!name || !m) return send(res, 400, { error: 'invalid' });
    const png = Buffer.from(m[1], 'base64');
    if (png.length < 33 || png.length > MAX_PNG || png.readUInt32BE(0) !== 0x89504e47 || png.readUInt32BE(4) !== 0x0d0a1a0a ||
        png.toString('latin1', 12, 16) !== 'IHDR' || png.readUInt32BE(16) !== 64 || png.readUInt32BE(20) !== 64) return send(res, 400, { error: 'must be a 64x64 png' });
    if (db.skins.length >= MAX_SKINS_TOTAL || db.skins.filter(s => s.email === me).length >= MAX_SKINS_PER_USER) return send(res, 429, { error: 'limit reached' });
    const id = crypto.randomBytes(8).toString('hex');
    fs.writeFileSync(path.join(SKIN_DIR, id + '.png'), png);
    db.skins.push({ id, name, email: me, created: Date.now() }); save();
    return send(res, 201, { id });
  }
  if (p === '/api/skins/delete') {
    const me = sessionEmail(req); if (!me) return send(res, 401, { error: 'sign in' });
    const i = db.skins.findIndex(s => s.id === body.id);
    if (i < 0) return send(res, 404, { error: 'not found' });
    if (db.skins[i].email !== me) return send(res, 403, { error: 'not yours' });
    const id = db.skins[i].id; db.skins.splice(i, 1); save();
    fs.unlink(path.join(SKIN_DIR, id + '.png'), () => {});
    return send(res, 200, {});
  }
  send(res, 404, { error: 'not found' });
}

/* ---------- static files ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon', '.glb': 'model/gltf-binary', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.woff2': 'font/woff2' };
function serve(req, res, url) {
  let p; try { p = decodeURIComponent(url.pathname); } catch (e) { res.writeHead(400); return res.end(); }
  const m = /^\/skins\/([a-f0-9]{16})\.png$/.exec(p);
  let file;
  if (m) file = path.join(SKIN_DIR, m[1] + '.png');
  else {
    if (p === '/') p = '/BrineMC.html';
    file = path.join(PUB, p);
    if (file !== PUB && !file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    const h = { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size, 'X-Content-Type-Options': 'nosniff' };
    h['Cache-Control'] = m ? 'public, max-age=31536000, immutable' : 'no-cache';
    res.writeHead(200, h);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api/')) api(req, res, url).catch(e => { console.error(e); if (!res.headersSent) send(res, 500, { error: 'server' }); });
  else if (req.method === 'GET' || req.method === 'HEAD') serve(req, res, url);
  else { res.writeHead(405); res.end(); }
}).listen(PORT, () => console.log('My Website running on http://localhost:' + PORT));
