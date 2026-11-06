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
app.get('/api/orders/mine', needUser, w(async (req, res) => res.json({ orders: (await q('select * from orders where uid=$1 and status<>\'Created\' order by id desc', [req.uid])).rows })));
const tokOk = (req, kind, oid) => { try { const k = jwt.verify(String(req.query.t || ''), JWT_SECRET); return k.k === kind && k.oid === oid; } catch (e) { return false; } };
app.get('/api/download/:oid/:pid', w(async (req, res) => {
  const oid = parseInt(req.params.oid, 10), pid = parseInt(req.params.pid, 10), u = who(req, 'sm_u');
  const o = Number.isInteger(oid) ? (await q('select * from orders where id=$1', [oid])).rows[0] : null;
  // access only after the payment is confirmed as Successful, never revoked, and only for the buyer (or their signed email link)
  if (!o || o.status !== 'Successful' || o.revoked || !o.items.some((i) => i.pid == pid) || !((u && u.id === o.uid) || tokOk(req, 'dl', oid))) return res.status(403).send('Not allowed');
  const f = (await q('select name,data from files where pid=$1', [pid])).rows[0]; if (!f) return res.status(404).send('File not uploaded yet');
  await q('update orders set dl_count=coalesce(dl_count,0)+1 where id=$1', [oid]);
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
  const items = [...new Set(ids || [])].map((i) => s.products.find((p) => p.id == i && p.pub)).filter(Boolean).map((p) => ({ pid: p.id, name: p.name, price: fin(p) }));
  let total = items.reduce((a, i) => a + i.price, 0);
  const c = (s.coupons || []).find((x) => x.code === String(coupon || '').toUpperCase()); if (c) total -= Math.round(total * c.pct / 100);
  return { items, total, code: c ? c.code : '' };
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
  const s = await getState(), { items, total, code } = priceCart(s, (req.body || {}).ids, (req.body || {}).coupon);
  if (!items.length) return res.status(400).json({ error: 'Your cart is empty' });
  if (total < 1) return res.status(400).json({ error: 'The amount is too small to pay online' });
  const owned = new Set((await q("select items from orders where uid=$1 and status='Successful' and not coalesce(revoked,false)", [req.uid])).rows.flatMap((r) => r.items.map((i) => i.pid)));
  const dup = items.filter((i) => owned.has(i.pid)); if (dup.length) return res.status(409).json({ error: 'You already own ' + dup.map((d) => d.name).join(', ') + '. Download it from My Orders.' });
  const gw = GATEWAY();
  // reuse a recent unpaid order for the same basket, so retries never create duplicate orders
  let o = (await q("select * from orders where uid=$1 and status='Created' and total=$2 and coupon=$3 and items=$4::jsonb and date>now()-interval '30 minutes' order by id desc limit 1", [req.uid, total, code, JSON.stringify(items)])).rows[0];
  if (!o) o = (await q("insert into orders(uid,items,total,coupon,status) values($1,$2,$3,$4,'Created') returning *", [req.uid, JSON.stringify(items), total, code])).rows[0];
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
  alter table videos alter column data set storage external;`);
  app.listen(process.env.PORT || 3000, () => console.log('Store running'));
})().catch((e) => { console.error(e); process.exit(1); });
