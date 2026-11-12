const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'),
  cookieParser = require('cookie-parser'), rateLimit = require('express-rate-limit'), crypto = require('crypto');
const { DATABASE_URL, JWT_SECRET, ADMIN_PASSWORD, RESEND_API_KEY, FROM_EMAIL, BASE_URL } = process.env;
if (!DATABASE_URL || !JWT_SECRET || !ADMIN_PASSWORD) { console.error('Set DATABASE_URL, JWT_SECRET and ADMIN_PASSWORD'); process.exit(1); }
const pool = new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
const q = (s, a) => pool.query(s, a);
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '30mb', verify: (req, res, buf) => { if (req.originalUrl.startsWith('/api/pay/webhook')) req.rawBody = buf; } })); app.use(cookieParser());
const ck = (ms) => ({ httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: ms });
const sign = (o, exp) => jwt.sign(o, JWT_SECRET, { expiresIn: exp });
const who = (req, n) => { try { return jwt.verify(req.cookies[n], JWT_SECRET); } catch (e) { return null; } };
const needUser = (req, res, next) => { const t = who(req, 'sm_u'); if (!t) return res.status(401).json({ error: 'Please log in' }); req.uid = t.id; next(); };
const needAdmin = (req, res, next) => { const t = who(req, 'sm_a'); if (!t || t.r !== 'a') return res.status(401).json({ error: 'Admin login required' }); next(); };
const w = (f) => (req, res, next) => f(req, res, next).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const lim = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts, try again later' } });
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const fin = (p) => Math.round(p.price * (1 - p.disc / 100));
const getState = async () => (await q("select v from kv where k='state'")).rows[0]?.v || null;
const clean = (s) => { const c = JSON.parse(JSON.stringify(s)); if (c.set) delete c.set.pw; return c; };
const BREVO_API_KEY = process.env.BREVO_API_KEY, RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
const mailReady = () => !!(BREVO_API_KEY || RESEND_API_KEY);
// attachments: [{name, content(base64)}]. Returns true only if the provider accepted the email.
async function mail(to, subject, html, replyTo, attachments) {
  if (!to || !mailReady()) return false;
  const att = attachments && attachments.length ? attachments : undefined, fromName = process.env.FROM_NAME || 'Riot';
  try {
    if (BREVO_API_KEY) {
      const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ sender: { email: FROM_EMAIL, name: fromName }, to: [{ email: to }], subject, htmlContent: html, replyTo: replyTo ? { email: replyTo } : undefined, attachment: att }) });
      if (!r.ok) console.error('Brevo error', r.status, await r.text());
      return r.ok;
    }
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM_EMAIL || 'onboarding@resend.dev', to, subject, html, reply_to: replyTo, attachments: att && att.map((a) => ({ filename: a.name, content: a.content })) }) });
    if (!r.ok) console.error('Resend error', r.status, await r.text());
    return r.ok;
  } catch (e) { console.error('mail failed', e.message); return false; }
}
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));


/* ---------- marketplace helpers ---------- */
const TYPE_KEYS = ['excel', '3d', 'prompts', 'shortcuts', 'custom'];
const DEFAULT_TAXO = {
  excel: ['HR & Payroll', 'Finance & Accounting', 'Inventory Management', 'Business Management', 'Sales & Marketing', 'Project Management', 'Attendance & Time Office', 'Personal Finance', 'Education'],
  '3d': ['3D Keychains', 'Miniature Toys', 'Collectibles', 'Desk Accessories', 'Custom 3D Products'],
  prompts: ['Business & Marketing', 'Content Creation', 'Education & Learning', 'Productivity', 'Lifestyle', 'Technology & Coding', 'Creative Prompts'],
  shortcuts: ['Productivity', 'Automation', 'Photo Editing', 'Daily Utilities', 'Personal Assistant'],
  custom: ['Custom Prompt Packs']
};
const kindOf = (p) => p.kind || (p.type === '3d' ? 'physical' : 'digital');
// A product can only be sold when there is really something to deliver: a file/link (digital) or stock (physical).
const buyable = (p) => (kindOf(p) === 'physical' ? !!p.inStock : !!(p.hasFile || p.deliverUrl));
const dataImg = (u) => { const m = /^data:(image\/[\w+.-]+);base64,(.+)$/.exec(u || ''); return m ? { mime: m[1], buf: Buffer.from(m[2], 'base64') } : null; };
const saveImg = async (pid, n, u) => { const d = dataImg(u); if (!d) return false; await q('insert into images(pid,n,mime,data) values($1,$2,$3,$4) on conflict(pid,n) do update set mime=$3,data=$4', [pid, n, d.mime, d.buf]); return true; };
const saveState = (s) => q("insert into kv(k,v) values('state',$1) on conflict(k) do update set v=$1", [JSON.stringify(s)]);
const MIMES = { pdf: 'application/pdf', txt: 'text/plain; charset=utf-8', zip: 'application/zip', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', xls: 'application/vnd.ms-excel', csv: 'text/csv', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', shortcut: 'application/octet-stream', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', stl: 'model/stl' };
let statsCache = { t: 0, v: null };
async function stats() {
  if (statsCache.v && Date.now() - statsCache.t < 60000) return statsCache.v;
  const sold = {}, rate = {};
  (await q("select (i->>'pid')::int as pid, count(*)::int as n from orders o, jsonb_array_elements(o.items) i where o.status='Successful' group by 1")).rows.forEach((r) => { sold[r.pid] = r.n; });
  (await q('select pid, avg(rating)::float as a, count(*)::int as n from reviews group by pid')).rows.forEach((r) => { rate[r.pid] = { a: Math.round(r.a * 10) / 10, n: r.n }; });
  statsCache = { t: Date.now(), v: { sold, rate } }; return statsCache.v;
}
// brings older data in line with the marketplace: types, subcategories, images moved out of the big state document
async function migrate() {
  const s = await getState(); if (!s) return; let ch = false;
  if (!s.taxo) { s.taxo = JSON.parse(JSON.stringify(DEFAULT_TAXO)); ch = true; }
  const ren = { Finance: 'Finance & Accounting', Inventory: 'Inventory Management' };
  for (const p of s.products || []) {
    if (!p.type) { p.type = 'excel'; ch = true; }
    if (p.type === 'excel' && ren[p.cat]) { p.cat = ren[p.cat]; ch = true; }
    if (p.type === 'excel' && p.cat && !s.taxo.excel.includes(p.cat)) { s.taxo.excel.push(p.cat); ch = true; }
    if (dataImg(p.img)) { await saveImg(p.id, 0, p.img); p.imgv = Date.now(); delete p.img; ch = true; }
  }
  if (ch) await saveState(s);
}
const cleanShip = (x) => {
  x = x || {}; const t = (val, n) => String(val || '').trim().slice(0, n);
  const o = { name: t(x.name, 80), phone: t(x.phone, 16).replace(/[^\d+]/g, ''), line1: t(x.line1, 160), line2: t(x.line2, 120), city: t(x.city, 60), state: t(x.state, 60), pin: t(x.pin, 6) };
  if (!o.name || !/^(\+?91)?\d{10}$/.test(o.phone) || !o.line1 || !o.city || !o.state || !/^\d{6}$/.test(o.pin)) return null; return o;
};

/* ---------- public ---------- */
app.get('/api/public', w(async (req, res) => {
  const s = await getState(); const payMode = RAZORPAY_KEY_ID ? 'razorpay' : 'upi'; if (!s) return res.json({ ready: false, payMode });
  const st = await stats(), c = clean(s); delete c.coupons;
  c.products = c.products.filter((p) => p.pub).map((p) => {
    p.kind = kindOf(p); p.buyable = buyable(p); p.hasLink = !!p.deliverUrl; p.sold = st.sold[p.id] || 0; p.rating = (st.rate[p.id] || {}).a || 0; p.rc = (st.rate[p.id] || {}).n || 0;
    delete p.file; delete p.mailSubject; delete p.mailBody; delete p.deliverUrl; delete p.galAdd; delete p.galDel; return p;
  });
  c.ready = true; c.payMode = payMode; res.json(c);
}));
app.get('/api/img/:pid/:n', w(async (req, res) => {
  const pid = parseInt(req.params.pid, 10), n = parseInt(req.params.n, 10); if (!Number.isInteger(pid) || !Number.isInteger(n)) return res.sendStatus(404);
  const r = (await q('select mime,data from images where pid=$1 and n=$2', [pid, n])).rows[0]; if (!r) return res.sendStatus(404);
  res.set({ 'Content-Type': r.mime, 'Cache-Control': 'public, max-age=31536000, immutable' }).send(r.data);
}));
app.post('/api/register', lim, w(async (req, res) => {
  const { name, email, pw } = req.body || {};
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || !pw || pw.length < 6) return res.status(400).json({ error: 'Enter name, valid email and a 6+ character password' });
  try {
    const r = await q('insert into users(name,email,pw) values($1,$2,$3) returning id,name,email', [name.trim(), email.trim().toLowerCase(), await bcrypt.hash(pw, 10)]);
    res.cookie('sm_u', sign({ id: r.rows[0].id }, '7d'), ck(7 * 864e5)); res.json({ user: r.rows[0] });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' }); throw e; }
}));
app.post('/api/login', lim, w(async (req, res) => {
  const { email, pw } = req.body || {};
  const u = (await q('select * from users where email=$1', [String(email || '').trim().toLowerCase()])).rows[0];
  if (!u || !(await bcrypt.compare(String(pw || ''), u.pw))) return res.status(401).json({ error: 'Wrong email or password' });
  res.cookie('sm_u', sign({ id: u.id }, '7d'), ck(7 * 864e5)); res.json({ user: { id: u.id, name: u.name, email: u.email } });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('sm_u'); res.json({ ok: true }); });
app.get('/api/me', w(async (req, res) => {
  const t = who(req, 'sm_u'); if (!t) return res.json({ user: null });
  const u = (await q('select id,name,email,phone,joined from users where id=$1', [t.id])).rows[0]; res.json({ user: u || null });
}));
app.put('/api/me', needUser, w(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 80), phone = String((req.body || {}).phone || '').replace(/[^\d+]/g, '').slice(0, 16);
  if (!name) return res.status(400).json({ error: 'Enter your name' });
  const u = (await q('update users set name=$2, phone=$3 where id=$1 returning id,name,email,phone,joined', [req.uid, name, phone])).rows[0]; res.json({ user: u });
}));
app.post('/api/me/password', lim, needUser, w(async (req, res) => {
  const { old, pw } = req.body || {}; if (!pw || String(pw).length < 6) return res.status(400).json({ error: 'The new password needs at least 6 characters' });
  const u = (await q('select pw from users where id=$1', [req.uid])).rows[0];
  if (!u || !(await bcrypt.compare(String(old || ''), u.pw))) return res.status(400).json({ error: 'Your current password is not correct' });
  await q('update users set pw=$2 where id=$1', [req.uid, await bcrypt.hash(String(pw), 10)]); res.json({ ok: true });
}));
app.get('/api/wishlist', needUser, w(async (req, res) => res.json({ ids: (await q('select pid from wishlist where uid=$1 order by at desc', [req.uid])).rows.map((r) => r.pid) })));
app.put('/api/wishlist/:pid', needUser, w(async (req, res) => { const pid = parseInt(req.params.pid, 10); if (!Number.isInteger(pid)) return res.sendStatus(400); await q('insert into wishlist(uid,pid) values($1,$2) on conflict do nothing', [req.uid, pid]); res.json({ ok: true }); }));
app.delete('/api/wishlist/:pid', needUser, w(async (req, res) => { await q('delete from wishlist where uid=$1 and pid=$2', [req.uid, parseInt(req.params.pid, 10)]); res.json({ ok: true }); }));
const bought = async (uid, pid) => (await q("select 1 from orders where uid=$1 and status='Successful' and items @> $2::jsonb limit 1", [uid, JSON.stringify([{ pid }])])).rowCount > 0;
app.get('/api/reviews/:pid', w(async (req, res) => {
  const pid = parseInt(req.params.pid, 10), u = who(req, 'sm_u');
  const rows = (await q('select r.id,r.rating,r.body,r.at,r.uid,u.name from reviews r join users u on u.id=r.uid where r.pid=$1 order by r.id desc limit 100', [pid])).rows;
  const mine = u ? rows.find((r) => r.uid === u.id) : null;
  res.json({ reviews: rows.map((r) => ({ id: r.id, rating: r.rating, body: r.body, at: r.at, name: String(r.name).split(' ')[0] + (String(r.name).split(' ')[1] ? ' ' + String(r.name).split(' ')[1][0] + '.' : '') })), canReview: !!u && !mine && (await bought(u.id, pid)), mine: mine ? { rating: mine.rating, body: mine.body } : null });
}));
app.post('/api/reviews', needUser, w(async (req, res) => {
  const pid = parseInt((req.body || {}).pid, 10), rating = parseInt((req.body || {}).rating, 10), body = String((req.body || {}).body || '').trim().slice(0, 1000);
  if (!Number.isInteger(pid) || !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Choose a rating from 1 to 5 stars' });
  if (!(await bought(req.uid, pid))) return res.status(403).json({ error: 'Only customers who bought this product can review it' });
  await q('insert into reviews(pid,uid,rating,body) values($1,$2,$3,$4) on conflict(pid,uid) do update set rating=$3, body=$4, at=now()', [pid, req.uid, rating, body]); statsCache.t = 0; res.json({ ok: true });
}));
app.get('/api/downloads/mine', needUser, w(async (req, res) => res.json({ downloads: (await q("select d.at,d.oid,d.pid,(select i->>'name' from jsonb_array_elements(o.items) i where (i->>'pid')::int=d.pid limit 1) as name from dl_log d join orders o on o.id=d.oid where d.uid=$1 order by d.id desc limit 100", [req.uid])).rows })));
app.post('/api/coupon', lim, w(async (req, res) => {
  const s = await getState(); const c = ((s && s.coupons) || []).find((x) => x.code === String((req.body || {}).code || '').trim().toUpperCase());
  if (!c) return res.status(404).json({ error: 'Invalid coupon' }); res.json({ code: c.code, pct: c.pct });
}));
app.post('/api/contact', lim, w(async (req, res) => {
  const { name, email, msg } = req.body || {}; if (!msg) return res.status(400).json({ error: 'Write a message' });
  const s = await getState(); await mail(s && s.set && s.set.email, 'Support message from ' + esc(name), `<p>${esc(msg)}</p><p>${esc(name)} · ${esc(email)}</p>`, /^\S+@\S+$/.test(email || '') ? email : undefined);
  res.json({ ok: true });
}));


/* ---------- product videos (uploaded by admin, streamed with Range support) ---------- */
app.get('/api/video/:pid', w(async (req, res) => {
  const pid = parseInt(req.params.pid, 10); if (!Number.isInteger(pid)) return res.sendStatus(404);
  const m = (await q('select mime, octet_length(data) as n from videos where pid=$1', [pid])).rows[0]; if (!m) return res.sendStatus(404);
  const n = +m.n; let st = 0, en = n - 1, code = 200;
  const r = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
  if (r) {
    if (r[1] === '' && r[2] !== '') st = Math.max(0, n - +r[2]); else { if (r[1] !== '') st = +r[1]; if (r[2] !== '') en = Math.min(n - 1, +r[2]); }
    if (st > en || st >= n) { res.set('Content-Range', 'bytes */' + n); return res.status(416).end(); }
    en = Math.min(en, st + 3 * 1048576 - 1); code = 206;
  }
  const d = (await q('select substring(data from $2 for $3) as d from videos where pid=$1', [pid, st + 1, en - st + 1])).rows[0];
  if (!d) return res.sendStatus(404);
  res.status(code).set({ 'Content-Type': m.mime, 'Accept-Ranges': 'bytes', 'Content-Length': en - st + 1, 'Cache-Control': 'public, max-age=86400' });
  if (code === 206) res.set('Content-Range', `bytes ${st}-${en}/${n}`);
  res.end(d.d);
}));
app.put('/api/admin/video/:pid', needAdmin, express.raw({ type: () => true, limit: '40mb' }), w(async (req, res) => {
  const pid = parseInt(req.params.pid, 10), mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!Number.isInteger(pid)) return res.status(400).json({ error: 'Bad product' });
  if (!/^video\/(mp4|webm|quicktime|ogg)$/.test(mime)) return res.status(400).json({ error: 'Upload an MP4 or WebM video' });
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Empty file' });
  let nm = 'video'; try { nm = decodeURIComponent(String(req.headers['x-file-name'] || 'video')); } catch (e) {}
  await q('insert into videos(pid,name,mime,data) values($1,$2,$3,$4) on conflict(pid) do update set name=$2,mime=$3,data=$4', [pid, nm, mime, req.body]);
  res.json({ ok: true, size: req.body.length });
}));
app.delete('/api/admin/video/:pid', needAdmin, w(async (req, res) => { await q('delete from videos where pid=$1', [parseInt(req.params.pid, 10)]); res.json({ ok: true }); }));

/* ---------- customer orders & downloads ---------- */
app.get('/api/orders/mine', needUser, w(async (req, res) => res.json({ orders: (await q('select * from orders where uid=$1 and status<>\'Created\' order by id desc', [req.uid])).rows })));
const tokOk = (req, kind, oid) => { try { const k = jwt.verify(String(req.query.t || ''), JWT_SECRET); return k.k === kind && k.oid === oid; } catch (e) { return false; } };
app.get('/api/download/:oid/:pid', w(async (req, res) => {
  const oid = parseInt(req.params.oid, 10), pid = parseInt(req.params.pid, 10), u = who(req, 'sm_u');
  const o = Number.isInteger(oid) ? (await q('select * from orders where id=$1', [oid])).rows[0] : null;
  // access only after the payment is confirmed as Successful, never revoked, and only for the buyer (or their signed email link)
  if (!o || o.status !== 'Successful' || o.revoked || !o.items.some((i) => i.pid == pid) || !((u && u.id === o.uid) || tokOk(req, 'dl', oid))) return res.status(403).send('Not allowed');
  const f = (await q('select name,data from files where pid=$1', [pid])).rows[0];
  const log = () => q('insert into dl_log(uid,oid,pid) values($1,$2,$3)', [o.uid, oid, pid]).catch(() => {});
  if (!f) {
    const p = ((await getState()).products || []).find((x) => x.id == pid);
    if (p && p.deliverUrl && /^https:\/\//.test(p.deliverUrl)) { await q('update orders set dl_count=coalesce(dl_count,0)+1 where id=$1', [oid]); await log(); return res.redirect(p.deliverUrl); }
    return res.status(404).send('Nothing to download for this item');
  }
  await q('update orders set dl_count=coalesce(dl_count,0)+1 where id=$1', [oid]); await log();
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  res.set({ 'Content-Type': MIMES[ext] || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${f.name.replace(/[^\w.\- ]/g, '_')}"`, 'Cache-Control': 'private, no-store' });
  res.send(f.data);
}));

/* ---------- admin ---------- */
app.post('/api/admin/login', lim, (req, res) => {
  if (!crypto.timingSafeEqual(sha((req.body || {}).pw), sha(ADMIN_PASSWORD))) return res.status(401).json({ error: 'Wrong password' });
  res.cookie('sm_a', sign({ r: 'a' }, '12h'), ck(12 * 36e5)); res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { res.clearCookie('sm_a'); res.json({ ok: true }); });
app.get('/api/admin/state', needAdmin, w(async (req, res) => {
  const s = await getState(); const out = s ? clean(s) : {}; out.ready = !!s;
  out.orders = (await q('select * from orders where status<>\'Created\' order by id')).rows; out.users = (await q('select id,name,email,joined from users order by id')).rows; res.json(out);
}));
app.put('/api/admin/state', needAdmin, w(async (req, res) => {
  const b = req.body || {}; if (!Array.isArray(b.products) || !Array.isArray(b.cats) || !b.set) return res.status(400).json({ error: 'Invalid data' });
  const s = { cats: b.cats, catx: b.catx || {}, home: b.home || {}, set: b.set, products: b.products, coupons: b.coupons || [], taxo: b.taxo || JSON.parse(JSON.stringify(DEFAULT_TAXO)) }; delete s.set.pw;
  for (const k of TYPE_KEYS) if (!Array.isArray(s.taxo[k])) s.taxo[k] = [];
  const ids = [];
  for (const p of s.products) {
    if (!TYPE_KEYS.includes(p.type)) p.type = 'excel';
    if (p.type === 'excel' && p.cat === 'Finance') p.cat = 'Finance & Accounting';
    if (p.type === 'excel' && p.cat === 'Inventory') p.cat = 'Inventory Management';
    if (p.cat && !s.taxo[p.type].includes(p.cat)) s.taxo[p.type].push(p.cat);
    if (typeof p.file === 'string' && p.file.startsWith('data:')) {
      await q('insert into files(pid,name,data) values($1,$2,$3) on conflict(pid) do update set name=$2,data=$3', [p.id, p.fileName || 'file.xlsx', Buffer.from(p.file.split(',')[1], 'base64')]);
      p.hasFile = true;
    }
    delete p.file;
    if (dataImg(p.img)) { await saveImg(p.id, 0, p.img); if (!p.imgv) p.imgv = Date.now(); } delete p.img;
    p.gal = Array.isArray(p.gal) ? p.gal.filter(Number.isInteger) : [];
    for (const g of Array.isArray(p.galDel) ? p.galDel : []) { p.gal = p.gal.filter((x) => x !== g); await q('delete from images where pid=$1 and n=$2', [p.id, g]); }
    let next = Math.max(0, ...p.gal) + 1;
    for (const u of Array.isArray(p.galAdd) ? p.galAdd : []) { if (p.gal.length >= 8) break; if (await saveImg(p.id, next, u)) { p.gal.push(next); next++; } }
    delete p.galAdd; delete p.galDel;
    if (p.deliverUrl && !/^https:\/\//.test(p.deliverUrl)) delete p.deliverUrl;
    ids.push(p.id);
  }
  await q('delete from files where pid <> all($1::int[])', [ids]);
  await q('delete from videos where pid <> all($1::int[])', [ids]);
  await q('delete from images where pid <> all($1::int[])', [ids]);
  await saveState(s); res.json({ ok: true });
}));
app.get('/api/admin/starter', needAdmin, w(async (req, res) => {
  let n = 0; try { n = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, 'starter.json'), 'utf8')).products.length; } catch (e) {}
  const s = await getState(); res.json({ available: n > 0, count: n, loaded: ((s && s.products) || []).filter((p) => p.skey).length });
}));
// Loads the starter catalogue: real Excel files and prompt packs, plus clearly-marked sample listings for items that still need a real file or stock.
app.post('/api/admin/starter', needAdmin, w(async (req, res) => {
  let data; try { data = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, 'starter.json'), 'utf8')); } catch (e) { return res.status(404).json({ error: 'starter.json was not found next to server.js. Upload it to the main page of GitHub.' }); }
  const s = await getState(); if (!s) return res.status(400).json({ error: 'Save the store once from the admin panel first' });
  s.taxo = s.taxo || JSON.parse(JSON.stringify(DEFAULT_TAXO)); let maxId = Math.max(0, ...s.products.map((p) => p.id)), added = 0, skipped = 0;
  for (const it of data.products) {
    if (s.products.some((p) => p.skey === it.skey)) { skipped++; continue; }
    const id = ++maxId, { file, img, gal, fileName, ...meta } = it, p = { ...meta, id, pub: true, created: Date.now() + added, imgv: Date.now(), gal: [], hasFile: false };
    if (img) await saveImg(id, 0, img);
    for (const g of gal || []) { if (await saveImg(id, p.gal.length + 1, g)) p.gal.push(p.gal.length + 1); }
    if (file) { await q('insert into files(pid,name,data) values($1,$2,$3) on conflict(pid) do update set name=$2,data=$3', [id, fileName, Buffer.from(file, 'base64')]); p.hasFile = true; p.fileName = fileName; }
    s.products.push(p); added++;
  }
  await saveState(s); res.json({ ok: true, added, skipped });
}));
app.get('/api/admin/reviews', needAdmin, w(async (req, res) => res.json({ reviews: (await q('select r.id,r.pid,r.rating,r.body,r.at,u.name,u.email from reviews r join users u on u.id=r.uid order by r.id desc limit 200')).rows })));
app.delete('/api/admin/reviews/:id', needAdmin, w(async (req, res) => { await q('delete from reviews where id=$1', [parseInt(req.params.id, 10)]); statsCache.t = 0; res.json({ ok: true }); }));
app.patch('/api/admin/orders/:id/fulfil', needAdmin, w(async (req, res) => {
  const f = (req.body || {}).fulfil, tr = String((req.body || {}).track || '').slice(0, 200), id = parseInt(req.params.id, 10);
  if (!['Processing', 'Packed', 'Shipped', 'Delivered'].includes(f)) return res.status(400).json({ error: 'Bad status' });
  const o = (await q('update orders set fulfil=$2, track=$3 where id=$1 returning *', [id, f, tr])).rows[0]; if (!o) return res.sendStatus(404);
  await logEv('fulfil', id, 'Delivery status: ' + f + (tr ? ' · ' + tr : ''));
  if (['Shipped', 'Delivered'].includes(f)) { const u = (await q('select email,name from users where id=$1', [o.uid])).rows[0]; mail(u && u.email, 'Your order ' + refOf(id) + ' is ' + f.toLowerCase(), `<p>Hi ${esc(u && u.name)},</p><p>Your order <b>${refOf(id)}</b> is now <b>${f}</b>.${tr ? ' Tracking: <b>' + esc(tr) + '</b>.' : ''}</p>`); }
  res.json({ ok: true });
}));
app.patch('/api/admin/orders/:id', needAdmin, w(async (req, res) => {
  let st = (req.body || {}).status; if (st === 'Paid') st = 'Successful';
  if (!['Pending', 'Successful', 'Failed', 'Refunded'].includes(st)) return res.status(400).json({ error: 'Bad status' });
  const id = parseInt(req.params.id, 10), o = (await q('select * from orders where id=$1', [id])).rows[0]; if (!o) return res.status(404).json({ error: 'Not found' });
  if (st === 'Successful') {
    if (o.status === 'Refunded') await q("update orders set status='Successful', refunded_at=null where id=$1", [id]);
    else await markPaid(id, null, o.method || 'UPI (manual)', 'Marked Successful by admin');
  } else if (st === 'Refunded') {
    await q("update orders set status='Refunded', refunded_at=now(), refund_amt=coalesce(refund_amt,total), refund_id=coalesce(refund_id,'manual') where id=$1", [id]); await logEv('refund', id, 'Marked Refunded by admin');
  } else { await q('update orders set status=$2 where id=$1', [id, st]); await logEv('status', id, 'Status set to ' + st + ' by admin'); }
  res.json({ ok: true });
}));
app.post('/api/admin/orders/:id/refund', needAdmin, w(async (req, res) => {
  const id = parseInt(req.params.id, 10), o = (await q('select * from orders where id=$1', [id])).rows[0];
  if (!o || o.status !== 'Successful') return res.status(400).json({ error: 'Only successful payments can be refunded' });
  const amt = Math.min(o.total, Math.max(1, Math.round(+((req.body || {}).amount) || o.total))); let rid = 'manual';
  if (GATEWAY() && o.txn && /^pay_/.test(o.txn)) {
    try { rid = (await rzp('POST', '/payments/' + o.txn + '/refund', { amount: amt * 100, notes: { order: refOf(id) } })).id; }
    catch (e) { return res.status(502).json({ error: 'Gateway refund failed: ' + e.message }); }
  }
  await q('update orders set status=$2, refund_id=$3, refund_amt=$4, refunded_at=now() where id=$1', [id, amt >= o.total ? 'Refunded' : o.status, rid, amt]);
  await logEv('refund', id, 'Refund of ₹' + amt + ' (' + rid + ')'); res.json({ ok: true, refund: rid });
}));
app.post('/api/admin/orders/:id/access', needAdmin, w(async (req, res) => {
  const id = parseInt(req.params.id, 10), rv = !!(req.body || {}).revoked;
  await q('update orders set revoked=$2 where id=$1', [id, rv]); await logEv('access', id, rv ? 'Download access revoked' : 'Download access restored'); res.json({ ok: true });
}));
app.get('/api/admin/pay-status', needAdmin, w(async (req, res) => res.json({ gateway: GATEWAY(), mode: RAZORPAY_KEY_ID ? (/^rzp_test_/.test(RAZORPAY_KEY_ID) ? 'test' : 'live') : null, webhook: !!RAZORPAY_WEBHOOK_SECRET, mail: mailReady() })));
app.get('/api/admin/events', needAdmin, w(async (req, res) => res.json({ events: (await q('select * from events order by id desc limit 150')).rows })));

/* ---------- order emails (one per product, using the admin's draft) ---------- */
const fill = (t, v) => String(t || '').replace(/\{(\w+)\}/g, (m, k) => (k in v ? v[k] : m));
const toHtml = (t) => esc(t).replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1">$1</a>').replace(/\n/g, '<br>');
const DEFMAIL = 'Hi {name},\n\nThank you for your purchase! Your order #{order} for {product} is confirmed.\n\nYou can download it any time from My Orders: {link}\n\nNeed help? Just reply to this email.';
async function sendOrderEmails(oid) {
  const o = (await q('select o.*, u.email, u.name from orders o join users u on u.id=o.uid where o.id=$1', [oid])).rows[0]; if (!o || o.status !== 'Successful') return false;
  const s = await getState(); let ok = true, base = BASE_URL || '';
  const rlink = base + '/api/receipt/' + o.id + '?t=' + sign({ k: 'rc', oid: o.id }, '365d');
  for (const it of o.items) {
    const p = s.products.find((x) => x.id == it.pid); if (!p) continue;
    if (it.kind === 'physical') {
      const a = o.ship || {};
      ok = (await mail(o.email, 'Order ' + refOf(o.id) + ' confirmed: ' + p.name, `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.5"><p>Hi ${esc(o.name)},</p><p>Thank you! We received your payment for <b>${esc(p.name)}</b> (order <b>${refOf(o.id)}</b>, ₹${o.total}).</p><p>We will deliver to:<br>${esc(a.name)}, ${esc(a.line1)} ${esc(a.line2 || '')}, ${esc(a.city)}, ${esc(a.state)} ${esc(a.pin)}<br>Phone: ${esc(a.phone)}</p><p>We will email you the tracking details when it ships. <a href="${rlink}">View payment receipt</a></p></div>`, (s.set && s.set.email) || undefined)) && ok; continue;
    }
    const dlink = base + '/api/download/' + o.id + '/' + p.id + '?t=' + sign({ k: 'dl', oid: o.id }, '30d');
    const v = { name: o.name, product: p.name, order: refOf(o.id), link: base + '/#orders', download: dlink, receipt: rlink, txn: o.txn || '' };
    let att; if (p.mailAttach !== false) { const f = (await q('select name,data from files where pid=$1', [p.id])).rows[0]; if (f) att = [{ name: f.name, content: f.data.toString('base64') }]; }
    const foot = `<hr style="border:0;border-top:1px solid #ddd;margin:18px 0"><p style="font-size:14px;line-height:1.7;margin:0">Order <b>${refOf(o.id)}</b> · Amount paid <b>₹${o.total}</b>${o.txn ? ` · Transaction <b>${esc(o.txn)}</b>` : ''}</p><p style="margin:10px 0 0"><a href="${dlink}" style="display:inline-block;background:#107c41;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:bold">⬇ Download ${esc(p.name)}</a> &nbsp; <a href="${rlink}">View payment receipt</a></p>`;
    ok = (await mail(o.email, fill(p.mailSubject || 'Your {product} is ready to download', v), `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.5">${toHtml(fill(p.mailBody || DEFMAIL, v))}${foot}</div>`, (s.set && s.set.email) || undefined, att)) && ok;
  }
  return ok;
}
app.post('/api/admin/test-mail', needAdmin, w(async (req, res) => { const s = await getState(); const to = (s && s.set && s.set.email) || ''; res.json({ ok: await mail(to, 'Test email from your store', '<p>Email is working.</p>'), to }); }));
app.post('/api/admin/orders/:id/email', needAdmin, w(async (req, res) => res.json({ ok: await sendOrderEmails(req.params.id) })));

/* ---------- forgot password with email OTP ---------- */
const hashOtp = (e, c) => crypto.createHash('sha256').update(e + ':' + c + ':' + JWT_SECRET).digest('hex');
const em = (b) => String((b || {}).email || '').trim().toLowerCase();
app.post('/api/forgot', lim, w(async (req, res) => {
  const email = em(req.body); if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email' });
  if (!mailReady()) return res.status(503).json({ error: 'Email service is not set up yet. Please contact support.' });
  const u = (await q('select name from users where email=$1', [email])).rows[0];
  if (u) {
    const code = String(crypto.randomInt(100000, 1000000));
    await q("insert into otps(email,h,exp,tries) values($1,$2,now()+interval '10 minutes',0) on conflict(email) do update set h=$2, exp=now()+interval '10 minutes', tries=0", [email, hashOtp(email, code)]);
    const ok = await mail(email, 'Your password reset OTP', `<p>Hi ${esc(u.name)},</p><p>Your one-time password (OTP) is:</p><p style="font-size:28px;letter-spacing:6px"><b>${code}</b></p><p>It expires in 10 minutes. If you did not ask for this, ignore this email.</p>`);
    if (!ok) return res.status(503).json({ error: 'Could not send the email. Please try again later.' });
  }
  res.json({ ok: true });
}));
app.post('/api/verify-otp', lim, w(async (req, res) => {
  const email = em(req.body), otp = String((req.body || {}).otp || '').trim();
  const r = (await q('select * from otps where email=$1', [email])).rows[0];
  if (!r || new Date(r.exp) < new Date() || r.tries >= 5) return res.status(400).json({ error: 'Code expired. Please request a new OTP.' });
  if (r.h !== hashOtp(email, otp)) { await q('update otps set tries=tries+1 where email=$1', [email]); return res.status(400).json({ error: 'Wrong OTP. Try again.' }); }
  await q('delete from otps where email=$1', [email]); res.json({ token: sign({ r: 'reset', email }, '15m') });
}));
app.post('/api/reset-password', lim, w(async (req, res) => {
  let t; try { t = jwt.verify((req.body || {}).token, JWT_SECRET); } catch (e) { return res.status(400).json({ error: 'Session expired. Please start again.' }); }
  const pw = (req.body || {}).pw; if (t.r !== 'reset' || !pw || pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  await q('update users set pw=$1 where email=$2', [await bcrypt.hash(pw, 10), t.email]); res.json({ ok: true });
}));

/* ---------- checkout, server-side payment verification, webhooks, receipts ---------- */
const GATEWAY = () => !!(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);
const refOf = (id) => 'RIOT-' + String(id).padStart(6, '0');
const rzp = async (method, path, body) => {
  const r = await fetch('https://api.razorpay.com/v1' + path, { method, headers: { Authorization: 'Basic ' + Buffer.from(RAZORPAY_KEY_ID + ':' + RAZORPAY_KEY_SECRET).toString('base64'), 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error((d.error && d.error.description) || 'Razorpay error'); return d;
};
const logEv = (kind, oid, note, eid) => q('insert into events(eid,kind,oid,note) values($1,$2,$3,$4) on conflict(eid) do nothing', [eid || null, kind, oid || null, note || '']).catch((e) => console.error('event log failed', e.message));
const same = (a, b) => { a = String(a || ''); b = String(b || ''); return a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); };
function priceCart(s, ids, coupon) {
  const ps = [...new Set(ids || [])].map((i) => s.products.find((p) => p.id == i && p.pub)).filter(Boolean);
  const items = ps.map((p) => ({ pid: p.id, name: p.name, price: fin(p), kind: kindOf(p) })), unavailable = ps.filter((p) => !buyable(p)).map((p) => p.name);
  let total = items.reduce((a, i) => a + i.price, 0);
  const c = (s.coupons || []).find((x) => x.code === String(coupon || '').toUpperCase()); if (c) total -= Math.round(total * c.pct / 100);
  return { items, total, code: c ? c.code : '', unavailable };
}

// The ONLY place an order becomes Successful. Atomic + idempotent: runs the delivery email exactly once, never on Refunded orders.
async function markPaid(oid, txn, method, note) {
  let r;
  try { r = await q("update orders set status='Successful', txn=coalesce($2,txn), method=coalesce($3,method), paid_at=now(), fail_reason=null, pay=coalesce($4,pay) where id=$1 and status not in ('Successful','Refunded') returning id", [oid, txn || null, method || null, txn ? 'RZP ' + txn : null]); }
  catch (e) { if (e.code === '23505') { await logEv('duplicate', oid, 'Transaction ' + txn + ' is already recorded on another order. Ignored.'); return false; } throw e; }
  if (!r.rowCount) return false;
  await logEv('paid', oid, note || ('Payment confirmed' + (txn ? ' · ' + txn : '')));
  sendOrderEmails(oid).catch(console.error); return true;
}
async function markFailed(oid, reason) {
  const r = await q("update orders set status='Failed', fail_reason=$2 where id=$1 and status in ('Created','Pending','Failed')", [oid, String(reason || 'Payment failed').slice(0, 300)]);
  if (r.rowCount) await logEv('failed', oid, reason || 'Payment failed');
}
// Ask the gateway itself what happened to a payment, and only then update the order.
async function settle(o, payId) {
  let p = await rzp('GET', '/payments/' + encodeURIComponent(payId));
  if (p.order_id !== o.rzp || p.amount !== o.total * 100 || (p.currency && p.currency !== 'INR')) { await logEv('mismatch', o.id, 'Payment ' + payId + ' does not match this order. Ignored.'); return; }
  if (p.status === 'authorized') { try { p = await rzp('POST', '/payments/' + p.id + '/capture', { amount: p.amount, currency: 'INR' }); } catch (e) { p = await rzp('GET', '/payments/' + p.id); } }
  if (p.status === 'captured') await markPaid(o.id, p.id, String(p.method || 'upi').toUpperCase(), 'Verified with the gateway · ' + p.id);
  else if (p.status === 'failed') await markFailed(o.id, p.error_description);
  else await q("update orders set status='Pending' where id=$1 and status='Created'", [o.id]);
}
const statusOf = async (oid) => (await q('select * from orders where id=$1', [oid])).rows[0];
const view = (o) => ({ oid: o.id, ref: refOf(o.id), status: o.status, total: o.total, txn: o.txn, method: o.method, paidAt: o.paid_at, items: o.items, reason: o.fail_reason, revoked: o.revoked });

app.post('/api/checkout/start', needUser, w(async (req, res) => {
  const s = await getState(), { items, total, code, unavailable } = priceCart(s, (req.body || {}).ids, (req.body || {}).coupon);
  if (!items.length) return res.status(400).json({ error: 'Your cart is empty' });
  if (unavailable.length) return res.status(409).json({ error: unavailable.join(', ') + (unavailable.length > 1 ? ' are' : ' is') + ' not available to buy yet.' });
  const phys = items.some((i) => i.kind === 'physical'), ship = phys ? cleanShip((req.body || {}).ship) : null;
  if (phys && !ship) return res.status(400).json({ error: 'Please enter your delivery address: name, 10-digit phone, address, city, state and 6-digit PIN code.' });
  if (total < 1) return res.status(400).json({ error: 'The amount is too small to pay online' });
  const owned = new Set((await q("select items from orders where uid=$1 and status='Successful' and not coalesce(revoked,false)", [req.uid])).rows.flatMap((r) => r.items.map((i) => i.pid)));
  const dup = items.filter((i) => owned.has(i.pid)); if (dup.length) return res.status(409).json({ error: 'You already own ' + dup.map((d) => d.name).join(', ') + '. Download it from My Orders.' });
  const gw = GATEWAY();
  // reuse a recent unpaid order for the same basket, so retries never create duplicate orders
  let o = (await q("select * from orders where uid=$1 and status='Created' and total=$2 and coupon=$3 and items=$4::jsonb and date>now()-interval '30 minutes' order by id desc limit 1", [req.uid, total, code, JSON.stringify(items)])).rows[0];
  if (!o) o = (await q("insert into orders(uid,items,total,coupon,status,ship,fulfil) values($1,$2,$3,$4,'Created',$5,$6) returning *", [req.uid, JSON.stringify(items), total, code, ship ? JSON.stringify(ship) : null, phys ? 'Processing' : null])).rows[0];
  else if (phys) await q('update orders set ship=$2 where id=$1', [o.id, JSON.stringify(ship)]);
  if (gw && !o.rzp) {
    let z;
    try { z = await rzp('POST', '/orders', { amount: total * 100, currency: 'INR', receipt: refOf(o.id), notes: { order: refOf(o.id) } }); }
    catch (e) {
      console.error('Razorpay order creation failed:', e.message);
      await q("delete from orders where id=$1 and status='Created' and rzp is null", [o.id]);
      await logEv('gateway_error', null, 'Could not create a Razorpay order: ' + e.message + ' (check RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in Render)');
      return res.status(502).json({ error: 'We could not start the payment (' + e.message + '). Please try again in a moment.' });
    }
    await q('update orders set rzp=$1, pay=$2 where id=$3', [z.id, 'RZP order ' + z.id, o.id]); o.rzp = z.id;
  }
  const user = (await q('select name,email from users where id=$1', [req.uid])).rows[0];
  res.json({ oid: o.id, ref: refOf(o.id), total, items, mode: gw ? 'gateway' : 'manual', key: gw ? RAZORPAY_KEY_ID : undefined, test: gw && /^rzp_test_/.test(RAZORPAY_KEY_ID), rzp: o.rzp || null, amount: total * 100, name: (s.set && s.set.name) || 'Store', user });
}));
// Client returns from the gateway: the signature is checked AND the gateway is asked directly. The browser's word is never enough.
app.post('/api/pay/verify', needUser, w(async (req, res) => {
  if (!GATEWAY()) return res.status(400).json({ error: 'Online payment is not set up' });
  const { oid, payment_id, order_id, signature } = req.body || {};
  const o = (await q('select * from orders where id=$1 and uid=$2 and rzp=$3', [parseInt(oid, 10) || 0, req.uid, String(order_id || '')])).rows[0]; if (!o) return res.status(404).json({ error: 'Order not found' });
  const exp = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(order_id + '|' + payment_id).digest('hex');
  if (!same(exp, signature)) return res.status(400).json({ error: 'Payment could not be verified' });
  try { await settle(o, payment_id); } catch (e) { console.error('verify lookup failed', e.message); return res.status(502).json({ error: 'We could not confirm this payment with the gateway yet. Please check again in a moment.' }); }
  res.json(view(await statusOf(o.id)));
}));
app.post('/api/pay/failed', needUser, w(async (req, res) => {
  const o = (await q('select * from orders where id=$1 and uid=$2', [parseInt((req.body || {}).oid, 10) || 0, req.uid])).rows[0]; if (!o) return res.status(404).json({ error: 'Order not found' });
  await markFailed(o.id, (req.body || {}).reason); res.json({ ok: true });
}));
app.post('/api/pay/cancelled', needUser, w(async (req, res) => {
  const o = (await q('select id,status from orders where id=$1 and uid=$2', [parseInt((req.body || {}).oid, 10) || 0, req.uid])).rows[0];
  if (o && ['Created', 'Pending'].includes(o.status)) await logEv('cancelled', o.id, 'Customer closed the payment window without paying');
  res.json({ ok: true });
}));
app.get('/api/pay/status/:oid', needUser, w(async (req, res) => {
  let o = (await q('select * from orders where id=$1 and uid=$2', [parseInt(req.params.oid, 10) || 0, req.uid])).rows[0]; if (!o) return res.status(404).json({ error: 'Order not found' });
  if (GATEWAY() && o.rzp && ['Created', 'Pending'].includes(o.status)) {
    try { const l = await rzp('GET', '/orders/' + o.rzp + '/payments'), ok = (l.items || []).find((x) => x.status === 'captured' || x.status === 'authorized'); if (ok) { await settle(o, ok.id); o = await statusOf(o.id); } }
    catch (e) { console.error('reconcile failed', e.message); }
  }
  res.json(view(o));
}));
// Manual UPI (static QR / UPI ID): stays Pending until the admin verifies the money in the bank and marks it Successful.
app.post('/api/checkout/utr', needUser, w(async (req, res) => {
  const { oid, utr } = req.body || {}; if (!/^\d{12}$/.test(utr || '')) return res.status(400).json({ error: 'Enter the 12-digit UPI transaction (UTR) number' });
  const o = (await q('select * from orders where id=$1 and uid=$2', [parseInt(oid, 10) || 0, req.uid])).rows[0]; if (!o) return res.status(404).json({ error: 'Order not found' });
  if (o.rzp) return res.status(400).json({ error: 'This order is paid through the payment gateway' });
  if (!['Created', 'Pending', 'Failed'].includes(o.status)) return res.status(409).json({ error: 'This order was already processed' });
  try { await q("update orders set pay=$1, status='Pending', method='UPI (manual)' where id=$2", ['UPI UTR ' + utr, o.id]); }
  catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'This transaction number was already used' }); throw e; }
  await logEv('utr', o.id, 'Customer submitted UTR ' + utr + '. Awaiting admin verification.');
  const s = await getState(); mail(s && s.set && s.set.email, 'Order ' + refOf(o.id) + ' awaiting verification', `<p>Order ${refOf(o.id)}, ₹${o.total}, UTR ${esc(utr)}. Check your UPI account, then mark it Successful in Admin → Orders.</p>`);
  res.json({ ok: true, ref: refOf(o.id) });
}));
// Gateway webhook: signed by the gateway, verified here, safe to receive more than once.
app.post('/api/pay/webhook', w(async (req, res) => {
  if (!RAZORPAY_WEBHOOK_SECRET) return res.status(503).json({ error: 'Webhook secret is not set' });
  const exp = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(req.rawBody || Buffer.from('')).digest('hex');
  if (!same(exp, req.headers['x-razorpay-signature'])) return res.status(400).json({ error: 'Bad signature' });
  const ev = req.body || {}, pl = ev.payload || {}, pay = pl.payment && pl.payment.entity, rf = pl.refund && pl.refund.entity, ord = pl.order && pl.order.entity, eid = String(req.headers['x-razorpay-event-id'] || '') || null;
  if (eid && (await q('select 1 from events where eid=$1', [eid])).rowCount) return res.json({ ok: true, duplicate: true });
  let o = null, note = 'received'; const orderId = (pay && pay.order_id) || (ord && ord.id);
  if (orderId) o = (await q('select * from orders where rzp=$1', [orderId])).rows[0];
  if (!o && rf) o = (await q('select * from orders where txn=$1', [rf.payment_id])).rows[0];
  if (o) {
    if ((ev.event === 'payment.captured' || ev.event === 'order.paid') && pay) {
      // never trust the message alone: ask the gateway directly about this payment (status, order, amount, currency) before unlocking anything
      if (pay.amount === o.total * 100) { await settle(o, pay.id); note = 'verified with the gateway'; } else note = 'amount mismatch, ignored';
    } else if (ev.event === 'payment.authorized' && pay) { await settle(o, pay.id).catch((e) => console.error(e.message)); note = 'processed'; }
    else if (ev.event === 'payment.failed' && pay) { await markFailed(o.id, pay.error_description); note = 'failed recorded'; }
    else if ((ev.event === 'refund.processed' || ev.event === 'refund.created') && rf) {
      const full = rf.amount >= o.total * 100;
      await q('update orders set status=$2, refund_id=$3, refund_amt=$4, refunded_at=now() where id=$1', [o.id, full ? 'Refunded' : o.status, rf.id, Math.round(rf.amount / 100)]); note = full ? 'refund recorded' : 'partial refund recorded';
    }
  }
  await logEv('webhook:' + ev.event, o && o.id, note, eid); res.json({ ok: true });
}));

/* ---------- digital payment receipt (printable / save as PDF) ---------- */
app.get('/api/receipt/:oid', w(async (req, res) => {
  const oid = parseInt(req.params.oid, 10), u = who(req, 'sm_u'), a = who(req, 'sm_a');
  const o = Number.isInteger(oid) ? (await q('select o.*, u.name as uname, u.email as uemail from orders o join users u on u.id=o.uid where o.id=$1', [oid])).rows[0] : null;
  if (!o || !((a && a.r === 'a') || (u && u.id === o.uid) || tokOk(req, 'rc', oid))) return res.status(403).send('Not allowed');
  if (!['Successful', 'Refunded'].includes(o.status)) return res.status(404).send('A receipt is available after the payment is successful.');
  const st = ((await getState()) || {}).set || {}, sub = o.items.reduce((x, i) => x + i.price, 0), disc = sub - o.total, inr = (n) => '₹' + Number(n).toLocaleString('en-IN');
  const when = new Date(o.paid_at || o.date).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' }) + ' IST';
  res.set('Cache-Control', 'private, no-store').type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Receipt ${refOf(o.id)}</title><style>
body{font-family:Arial,Helvetica,sans-serif;background:#eef1f0;margin:0;padding:24px;color:#18211d}.r{max-width:660px;margin:auto;background:#fff;border-radius:14px;padding:34px;box-shadow:0 8px 30px #0001}
.h{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;border-bottom:2px solid #107c41;padding-bottom:16px}h1{margin:0;font-size:24px;color:#107c41}.m{color:#5b6b63;font-size:13px;line-height:1.6}
.b{display:inline-block;padding:3px 12px;border-radius:99px;font-size:12px;font-weight:700;background:#dff5e8;color:#0b6b36}.b.x{background:#e3e8ff;color:#3a4cb3}
.g{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:20px 0;font-size:14px}.g span{color:#5b6b63;display:block;font-size:12px;margin-bottom:2px}.g b{word-break:break-all}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{text-align:left;padding:10px 6px;border-bottom:1px solid #e3e8e5;font-size:14px}.n{text-align:right}
.t{display:flex;justify-content:space-between;font-size:14px;padding:5px 6px}.t.f{font-size:19px;font-weight:700;border-top:2px solid #18211d;margin-top:6px;padding-top:10px}
button{background:#107c41;color:#fff;border:0;border-radius:8px;padding:11px 20px;font-size:14px;cursor:pointer;margin-top:22px}.fo{margin-top:22px;font-size:12px;color:#5b6b63;line-height:1.6}
@media print{body{background:#fff;padding:0}.r{box-shadow:none}button{display:none}}</style></head><body><div class="r">
<div class="h"><div><h1>${esc(st.name || 'Store')}</h1><div class="m">${esc(st.addr)}<br>${esc(st.email)} · ${esc(st.phone)}</div></div><div style="text-align:right"><b style="font-size:16px">PAYMENT RECEIPT</b><div class="m">Receipt no. RCT-${String(o.id).padStart(6, '0')}</div><span class="b ${o.status === 'Refunded' ? 'x' : ''}">${o.status === 'Refunded' ? 'REFUNDED' : 'PAID'}</span></div></div>
<div class="g"><div><span>Order ID</span><b>${refOf(o.id)}</b></div><div><span>Date &amp; time</span><b>${esc(when)}</b></div><div><span>Transaction ID</span><b>${esc(o.txn || '—')}</b></div><div><span>Payment method</span><b>${esc(o.method || 'UPI')}</b></div><div><span>Billed to</span><b>${esc(o.uname)}</b><div class="m">${esc(o.uemail)}</div></div><div><span>Paid to</span><b>${esc(st.name || 'Store')}</b></div></div>
<table><tr><th>Item</th><th class="n">Amount</th></tr>${o.items.map((i) => `<tr><td>${esc(i.name)}<div class="m">Digital product · instant download</div></td><td class="n">${inr(i.price)}</td></tr>`).join('')}</table>
<div class="t"><span>Subtotal</span><span>${inr(sub)}</span></div>${disc > 0 ? `<div class="t"><span>Coupon ${esc(o.coupon)}</span><span>−${inr(disc)}</span></div>` : ''}<div class="t f"><span>Total paid</span><span>${inr(o.total)}</span></div>
${o.status === 'Refunded' || o.refund_amt ? `<div class="t"><span>Refunded${o.refund_id ? ' (' + esc(o.refund_id) + ')' : ''}</span><span>${inr(o.refund_amt || o.total)}</span></div>` : ''}
<div class="fo">This is a computer-generated receipt for a digital product delivered electronically. For help, contact ${esc(st.email)}.</div><button onclick="window.print()">🖨 Print / Save as PDF</button></div></body></html>`);
}));

app.get('/admin', (req, res) => { res.set('X-Robots-Tag', 'noindex'); res.sendFile(require('path').join(__dirname, 'public', 'index.html')); });
app.use(express.static('public'));
app.use((e, req, res, next) => { if (e && e.status === 413) return res.status(413).json({ error: 'File is too large' }); console.error(e); res.status(500).json({ error: 'Server error' }); });
(async () => {
  await q(`create table if not exists kv(k text primary key, v jsonb not null);
  create table if not exists users(id serial primary key, name text, email text unique, pw text, joined timestamptz default now());
  create table if not exists orders(id serial primary key, uid int references users(id), items jsonb, total int, coupon text default '', status text default 'Pending', pay text unique, date timestamptz default now());
  create table if not exists files(pid int primary key, name text, data bytea);
  create table if not exists otps(email text primary key, h text, exp timestamptz, tries int default 0);
  alter table orders add column if not exists rzp text;
  alter table orders add column if not exists txn text;
  alter table orders add column if not exists method text;
  alter table orders add column if not exists paid_at timestamptz;
  alter table orders add column if not exists fail_reason text;
  alter table orders add column if not exists refund_id text;
  alter table orders add column if not exists refund_amt int;
  alter table orders add column if not exists refunded_at timestamptz;
  alter table orders add column if not exists revoked boolean default false;
  alter table orders add column if not exists dl_count int default 0;
  update orders set status='Successful' where status='Paid';
  create unique index if not exists orders_txn_u on orders(txn) where txn is not null;
  create unique index if not exists orders_rzp_u on orders(rzp) where rzp is not null;
  create table if not exists events(id serial primary key, eid text unique, kind text, oid int, note text, at timestamptz default now());
  create table if not exists videos(pid int primary key, name text, mime text, data bytea);
  create table if not exists images(pid int, n int, mime text, data bytea, primary key(pid,n));
  alter table images alter column data set storage external;
  create table if not exists reviews(id serial primary key, pid int, uid int references users(id), rating int, body text, at timestamptz default now(), unique(pid,uid));
  create table if not exists wishlist(uid int references users(id), pid int, at timestamptz default now(), primary key(uid,pid));
  create table if not exists dl_log(id serial primary key, uid int, oid int, pid int, at timestamptz default now());
  alter table orders add column if not exists ship jsonb;
  alter table orders add column if not exists fulfil text;
  alter table orders add column if not exists track text;
  alter table users add column if not exists phone text;
  alter table videos alter column data set storage external;`);
  await migrate();
  app.listen(process.env.PORT || 3000, () => console.log('Store running'));
})().catch((e) => { console.error(e); process.exit(1); });
