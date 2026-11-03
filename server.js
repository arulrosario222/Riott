const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'),
  cookieParser = require('cookie-parser'), rateLimit = require('express-rate-limit'), crypto = require('crypto');
const { DATABASE_URL, JWT_SECRET, ADMIN_PASSWORD, RESEND_API_KEY, FROM_EMAIL, BASE_URL } = process.env;
if (!DATABASE_URL || !JWT_SECRET || !ADMIN_PASSWORD) { console.error('Set DATABASE_URL, JWT_SECRET and ADMIN_PASSWORD'); process.exit(1); }
const pool = new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
const q = (s, a) => pool.query(s, a);
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '30mb' })); app.use(cookieParser());
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
async function mail(to, subject, html, replyTo) {
  if (!RESEND_API_KEY || !to) return;
  try { await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM_EMAIL || 'onboarding@resend.dev', to, subject, html, reply_to: replyTo }) }); } catch (e) { console.error('mail failed', e.message); }
}
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* ---------- public ---------- */
app.get('/api/public', w(async (req, res) => {
  const s = await getState(); if (!s) return res.json({ ready: false });
  const c = clean(s); delete c.coupons; c.products = c.products.filter((p) => p.pub).map((p) => { delete p.file; return p; }); c.ready = true; res.json(c);
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
  const u = (await q('select id,name,email from users where id=$1', [t.id])).rows[0]; res.json({ user: u || null });
}));
app.post('/api/coupon', lim, w(async (req, res) => {
  const s = await getState(); const c = ((s && s.coupons) || []).find((x) => x.code === String((req.body || {}).code || '').trim().toUpperCase());
  if (!c) return res.status(404).json({ error: 'Invalid coupon' }); res.json({ code: c.code, pct: c.pct });
}));
app.post('/api/contact', lim, w(async (req, res) => {
  const { name, email, msg } = req.body || {}; if (!msg) return res.status(400).json({ error: 'Write a message' });
  const s = await getState(); await mail(s && s.set && s.set.email, 'Support message from ' + esc(name), `<p>${esc(msg)}</p><p>${esc(name)} · ${esc(email)}</p>`, /^\S+@\S+$/.test(email || '') ? email : undefined);
  res.json({ ok: true });
}));

/* ---------- customer orders & downloads ---------- */
app.post('/api/orders', needUser, w(async (req, res) => {
  const { ids, coupon, utr } = req.body || {};
  if (!/^\d{12}$/.test(utr || '')) return res.status(400).json({ error: 'Enter the 12-digit UPI transaction (UTR) number' });
  const s = await getState();
  const items = [...new Set(ids || [])].map((i) => s.products.find((p) => p.id == i && p.pub)).filter(Boolean).map((p) => ({ pid: p.id, name: p.name, price: fin(p) }));
  if (!items.length) return res.status(400).json({ error: 'Your cart is empty' });
  let total = items.reduce((a, i) => a + i.price, 0);
  const c = (s.coupons || []).find((x) => x.code === String(coupon || '').toUpperCase()); if (c) total -= Math.round(total * c.pct / 100);
  try {
    const r = await q('insert into orders(uid,items,total,coupon,pay) values($1,$2,$3,$4,$5) returning *', [req.uid, JSON.stringify(items), total, c ? c.code : '', 'UPI UTR ' + utr]);
    mail(s.set && s.set.email, 'New order #' + r.rows[0].id + ' awaiting verification', `<p>Order #${r.rows[0].id}, ₹${total}, UTR ${utr}. Verify in your UPI app, then mark it Paid in Admin.</p>`);
    res.json({ order: r.rows[0] });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'This transaction number was already used' }); throw e; }
}));
app.get('/api/orders/mine', needUser, w(async (req, res) => res.json({ orders: (await q('select * from orders where uid=$1 order by id desc', [req.uid])).rows })));
app.get('/api/download/:oid/:pid', needUser, w(async (req, res) => {
  const o = (await q('select * from orders where id=$1 and uid=$2', [req.params.oid, req.uid])).rows[0];
  if (!o || o.status !== 'Paid' || !o.items.some((i) => i.pid == req.params.pid)) return res.status(403).send('Not allowed');
  const f = (await q('select name,data from files where pid=$1', [req.params.pid])).rows[0]; if (!f) return res.status(404).send('File not uploaded yet');
  res.set({ 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Content-Disposition': `attachment; filename="${f.name.replace(/[^\w.\- ]/g, '_')}"`, 'Cache-Control': 'private, no-store' });
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
  out.orders = (await q('select * from orders order by id')).rows; out.users = (await q('select id,name,email,joined from users order by id')).rows; res.json(out);
}));
app.put('/api/admin/state', needAdmin, w(async (req, res) => {
  const b = req.body || {}; if (!Array.isArray(b.products) || !Array.isArray(b.cats) || !b.set) return res.status(400).json({ error: 'Invalid data' });
  const s = { cats: b.cats, catx: b.catx || {}, home: b.home || {}, set: b.set, products: b.products, coupons: b.coupons || [] }; delete s.set.pw;
  const ids = [];
  for (const p of s.products) {
    if (typeof p.file === 'string' && p.file.startsWith('data:')) {
      await q('insert into files(pid,name,data) values($1,$2,$3) on conflict(pid) do update set name=$2,data=$3', [p.id, p.fileName || 'file.xlsx', Buffer.from(p.file.split(',')[1], 'base64')]);
      p.hasFile = true;
    }
    delete p.file; ids.push(p.id);
  }
  await q('delete from files where pid <> all($1::int[])', [ids]);
  await q("insert into kv(k,v) values('state',$1) on conflict(k) do update set v=$1", [JSON.stringify(s)]); res.json({ ok: true });
}));
app.patch('/api/admin/orders/:id', needAdmin, w(async (req, res) => {
  const st = (req.body || {}).status; if (!['Pending', 'Paid', 'Refunded'].includes(st)) return res.status(400).json({ error: 'Bad status' });
  const old = (await q('select o.status,u.email,u.name from orders o join users u on u.id=o.uid where o.id=$1', [req.params.id])).rows[0]; if (!old) return res.status(404).json({ error: 'Not found' });
  await q('update orders set status=$1 where id=$2', [st, req.params.id]);
  if (st === 'Paid' && old.status !== 'Paid') mail(old.email, 'Payment confirmed – your Excel files are ready', `<p>Hi ${esc(old.name)}, your payment for order #${req.params.id} is confirmed.</p><p><a href="${esc(BASE_URL || '')}/#orders">Open My Orders to download</a></p>`);
  res.json({ ok: true });
}));

app.use(express.static('public'));
(async () => {
  await q(`create table if not exists kv(k text primary key, v jsonb not null);
  create table if not exists users(id serial primary key, name text, email text unique, pw text, joined timestamptz default now());
  create table if not exists orders(id serial primary key, uid int references users(id), items jsonb, total int, coupon text default '', status text default 'Pending', pay text unique, date timestamptz default now());
  create table if not exists files(pid int primary key, name text, data bytea);`);
  app.listen(process.env.PORT || 3000, () => console.log('Store running'));
})().catch((e) => { console.error(e); process.exit(1); });
