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
const BREVO_API_KEY = process.env.BREVO_API_KEY, RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const mailReady = () => !!(BREVO_API_KEY || RESEND_API_KEY);
// attachments: [{name, content(base64)}]. Returns true only if the provider accepted the email.
async function mail(to, subject, html, replyTo, attachments) {
  if (!to || !mailReady()) return false;
  const att = attachments && attachments.length ? attachments : undefined, fromName = process.env.FROM_NAME || 'SheetMart';
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

/* ---------- public ---------- */
app.get('/api/public', w(async (req, res) => {
  const s = await getState(); const payMode = RAZORPAY_KEY_ID ? 'razorpay' : 'upi'; if (!s) return res.json({ ready: false, payMode });
  const c = clean(s); delete c.coupons; c.products = c.products.filter((p) => p.pub).map((p) => { delete p.file; delete p.mailSubject; delete p.mailBody; return p; }); c.ready = true; c.payMode = payMode; res.json(c);
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
app.get('/api/orders/mine', needUser, w(async (req, res) => res.json({ orders: (await q('select * from orders where uid=$1 and status<>\'Created\' order by id desc', [req.uid])).rows })));
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
  out.orders = (await q('select * from orders where status<>\'Created\' order by id')).rows; out.users = (await q('select id,name,email,joined from users order by id')).rows; res.json(out);
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
  await q('delete from videos where pid <> all($1::int[])', [ids]);
  await q("insert into kv(k,v) values('state',$1) on conflict(k) do update set v=$1", [JSON.stringify(s)]); res.json({ ok: true });
}));
app.patch('/api/admin/orders/:id', needAdmin, w(async (req, res) => {
  const st = (req.body || {}).status; if (!['Pending', 'Paid', 'Refunded'].includes(st)) return res.status(400).json({ error: 'Bad status' });
  const old = (await q('select o.status,u.email,u.name from orders o join users u on u.id=o.uid where o.id=$1', [req.params.id])).rows[0]; if (!old) return res.status(404).json({ error: 'Not found' });
  await q('update orders set status=$1 where id=$2', [st, req.params.id]);
  if (st === 'Paid' && old.status !== 'Paid') sendOrderEmails(req.params.id).catch(console.error);
  res.json({ ok: true });
}));

/* ---------- order emails (one per product, using the admin's draft) ---------- */
const fill = (t, v) => String(t || '').replace(/\{(\w+)\}/g, (m, k) => (k in v ? v[k] : m));
const toHtml = (t) => esc(t).replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1">$1</a>').replace(/\n/g, '<br>');
const DEFMAIL = 'Hi {name},\n\nThank you for your purchase! Your order #{order} for {product} is confirmed.\n\nYou can download it any time from My Orders: {link}\n\nNeed help? Just reply to this email.';
async function sendOrderEmails(oid) {
  const o = (await q('select o.*, u.email, u.name from orders o join users u on u.id=o.uid where o.id=$1', [oid])).rows[0]; if (!o) return false;
  const s = await getState(); let ok = true;
  for (const it of o.items) {
    const p = s.products.find((x) => x.id == it.pid); if (!p) continue;
    const v = { name: o.name, product: p.name, order: String(o.id), link: (BASE_URL || '') + '/#orders' };
    let att; if (p.mailAttach !== false) { const f = (await q('select name,data from files where pid=$1', [p.id])).rows[0]; if (f) att = [{ name: f.name, content: f.data.toString('base64') }]; }
    ok = (await mail(o.email, fill(p.mailSubject || 'Your {product} is ready to download', v), `<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.5">${toHtml(fill(p.mailBody || DEFMAIL, v))}</div>`, (s.set && s.set.email) || undefined, att)) && ok;
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

/* ---------- automatic UPI payments through Razorpay (GPay, PhonePe, Paytm, QR...) ---------- */
const rz = async (path, body) => {
  const r = await fetch('https://api.razorpay.com/v1' + path, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(RAZORPAY_KEY_ID + ':' + RAZORPAY_KEY_SECRET).toString('base64'), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const d = await r.json(); if (!r.ok) throw new Error((d.error && d.error.description) || 'Razorpay error'); return d;
};
function priceCart(s, ids, coupon) {
  const items = [...new Set(ids || [])].map((i) => s.products.find((p) => p.id == i && p.pub)).filter(Boolean).map((p) => ({ pid: p.id, name: p.name, price: fin(p) }));
  let total = items.reduce((a, i) => a + i.price, 0);
  const c = (s.coupons || []).find((x) => x.code === String(coupon || '').toUpperCase()); if (c) total -= Math.round(total * c.pct / 100);
  return { items, total, code: c ? c.code : '' };
}
app.post('/api/pay/create', needUser, w(async (req, res) => {
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) return res.status(400).json({ error: 'Online payment is not set up' });
  const s = await getState(); const { items, total, code } = priceCart(s, req.body.ids, req.body.coupon);
  if (!items.length || total < 1) return res.status(400).json({ error: 'Your cart is empty or the amount is too small' });
  const o = await rz('/orders', { amount: total * 100, currency: 'INR', receipt: 'sm_' + Date.now() });
  const r = await q("insert into orders(uid,items,total,coupon,status,pay,rzp) values($1,$2,$3,$4,'Created',$5,$6) returning id", [req.uid, JSON.stringify(items), total, code, 'RZP order ' + o.id, o.id]);
  const user = (await q('select name,email from users where id=$1', [req.uid])).rows[0];
  res.json({ oid: r.rows[0].id, key: RAZORPAY_KEY_ID, rzp: o.id, amount: total * 100, name: (s.set && s.set.name) || 'Store', user });
}));
app.post('/api/pay/verify', needUser, w(async (req, res) => {
  const { oid, payment_id, order_id, signature } = req.body || {};
  const o = (await q('select * from orders where id=$1 and uid=$2 and rzp=$3', [oid, req.uid, order_id])).rows[0]; if (!o) return res.status(404).json({ error: 'Order not found' });
  const exp = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(order_id + '|' + payment_id).digest('hex'), got = String(signature || '');
  if (exp.length !== got.length || !crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(got))) return res.status(400).json({ error: 'Payment could not be verified' });
  if (o.status !== 'Paid') { await q("update orders set status='Paid', pay=$1 where id=$2", ['RZP ' + payment_id, oid]); sendOrderEmails(oid).catch(console.error); }
  res.json({ ok: true });
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
  create table if not exists videos(pid int primary key, name text, mime text, data bytea);
  alter table videos alter column data set storage external;`);
  app.listen(process.env.PORT || 3000, () => console.log('Store running'));
})().catch((e) => { console.error(e); process.exit(1); });
