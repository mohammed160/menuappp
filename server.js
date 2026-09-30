/* Dynamic menu server: public menu + admin dashboard + high-quality image uploads */
const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const ROOT = __dirname;
const envPath = path.join(ROOT, '.env');
if (fs.existsSync(envPath)) {
  try {
    fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(l => {
      const line = l.trim();
      if (!line || line.startsWith('#')) return;
      const idx = line.indexOf('=');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        let v = line.slice(idx + 1).trim();
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
        if (!process.env[k]) process.env[k] = v;
      }
    });
  } catch {}
}

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('menu-secret:' + ADMIN_PASSWORD).digest('hex');
const PUBLIC = path.join(ROOT, 'public');
const UPLOADS = path.join(PUBLIC, 'uploads');
try { fs.mkdirSync(UPLOADS, { recursive: true }); } catch {}

const SUPABASE_URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

/* ---------- tiny cookie session (HMAC-signed, httpOnly) ---------- */
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const makeToken = () => { const exp = String(Date.now() + 12 * 3600 * 1000); return exp + '.' + sign(exp); };
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const cookie = (req, name) => (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(([k]) => k === name)?.[1];
const requireAuth = (req, res, next) => validToken(cookie(req, 'adm')) ? next() : res.status(401).json({ error: 'Not signed in' });

const attempts = new Map();
function limited(ip) { const now = Date.now(), a = attempts.get(ip); if (!a || now - a.t > 15 * 60e3) { attempts.set(ip, { n: 0, t: now }); return false; } return a.n >= 10; }

app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  if (limited(ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const given = Buffer.from(String((req.body || {}).password || '')), real = Buffer.from(ADMIN_PASSWORD);
  const ok = given.length === real.length && crypto.timingSafeEqual(given, real);
  if (!ok) { attempts.get(ip).n++; return res.status(401).json({ error: 'Wrong password' }); }
  attempts.delete(ip);
  res.setHeader('Set-Cookie', `adm=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { res.setHeader('Set-Cookie', 'adm=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/admin/me', requireAuth, (req, res) => res.json({ ok: true }));

/* ---------- helpers ---------- */
const str = (v, max = 120) => String(v ?? '').trim().slice(0, max);
const num = v => { const n = Number(v); return Number.isFinite(n) && n >= 0 && n < 100000 ? Math.round(n * 100) / 100 : undefined; };
const prices = o => { const r = {}; for (const k of ['M', 'L', 'F', 'Regular']) { const n = num(o?.[k]); if (o && o[k] !== '' && o[k] != null && n !== undefined) r[k] = n; } return r; };
const IMG = /^\/(uploads|images)\/[\w./-]+$/;
function image(i) {
  if (!i || !IMG.test(i.src || '')) return null;
  const ok = u => (IMG.test(u || '') ? u : i.src);
  return { src: i.src, md: ok(i.md), th: ok(i.th), w: num(i.w), h: num(i.h), cutout: !!i.cutout, legacy: !!i.legacy };
}
const id = (v, fallback) => (str(v, 60).toLowerCase().replace(/[^a-z0-9-]/g, '') || fallback);
const list = (a, f) => (Array.isArray(a) ? a.slice(0, 300).map(f) : []);

const httpUrl = v => { try { const u = new URL(String(v || '').trim()); return /^https?:$/.test(u.protocol) ? u.href.slice(0, 300) : ''; } catch { return ''; } };
const waNumber = v => { let d = String(v || '').replace(/[^\d]/g, ''); if (d.startsWith('00')) d = d.slice(2); if (/^01[0125]\d{8}$/.test(d)) d = '20' + d.slice(1); return d.slice(0, 15); };
const bad = msg => { const e = new Error(msg); e.status = 400; return e; };

/* strict = true on save (throws a readable error); false on read (just fills defaults) */
function cleanSettings(S = {}, strict = false) {
  const P = S.payments || {};
  const D = S.delivery || {};
  const rawZones = Array.isArray(D.zones) ? D.zones.slice(0, 200) : [];
  const seenIds = new Set();
  const zones = [];
  for (let i = 0; i < rawZones.length; i++) {
    const z = rawZones[i] || {};
    const name = str(z.name, 60);
    const en = str(z.en, 60);
    if (strict && !name) throw bad('اكتب اسم لكل منطقة توصيل');
    let zid = str(z.id, 60).toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!zid || seenIds.has(zid)) {
      zid = 'zone-' + crypto.randomBytes(3).toString('hex');
      while (seenIds.has(zid)) zid = 'zone-' + crypto.randomBytes(3).toString('hex');
    }
    seenIds.add(zid);
    zones.push({ id: zid, name, en, fee: num(z.fee) ?? 0, enabled: z.enabled !== false });
  }

  const DEFAULT_BRANCHES = [
    { id: 'branch-kafr-eldawar', name: 'فرع 1 كفرالدوار', en: 'Branch 1 Kafr El-Dawar', whatsapp: '', enabled: true },
    { id: 'branch-alex-smouha', name: 'فرع 2 الاسكندرية سموحة', en: 'Branch 2 Alexandria Smouha', whatsapp: '', enabled: true }
  ];
  const rawBranches = Array.isArray(S.branches) ? S.branches.slice(0, 50) : (S.branches === undefined ? DEFAULT_BRANCHES : []);
  const seenBIds = new Set();
  const branches = [];
  for (let i = 0; i < rawBranches.length; i++) {
    const b = rawBranches[i] || {};
    const name = str(b.name, 80);
    const en = str(b.en, 80);
    if (strict && !name) throw bad('اكتب اسم لكل فرع');
    let bid = str(b.id, 60).toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!bid || seenBIds.has(bid)) {
      bid = 'branch-' + crypto.randomBytes(3).toString('hex');
      while (seenBIds.has(bid)) bid = 'branch-' + crypto.randomBytes(3).toString('hex');
    }
    seenBIds.add(bid);
    branches.push({ id: bid, name, en, whatsapp: waNumber(b.whatsapp), enabled: b.enabled !== false });
  }

  const out = {
    currency: str(S.currency, 8) || 'EGP',
    restaurant: str(S.restaurant),
    whatsapp: waNumber(S.whatsapp),
    logo: image(S.logo),
    theme: ['auto', 'light', 'dark'].includes(S.theme) ? S.theme : 'auto',
    branches,
    delivery: { enabled: D.enabled !== false, fee: num(D.fee) ?? 0, zones },
    takeaway: { enabled: S.takeaway?.enabled !== false },
    payments: {
      cod: { enabled: P.cod?.enabled !== false },
      instapay: { enabled: !!P.instapay?.enabled, handle: str(P.instapay?.handle, 80), link: httpUrl(P.instapay?.link) },
      wallet: { enabled: !!P.wallet?.enabled, label: str(P.wallet?.label, 40) || 'Mobile wallet', number: str(P.wallet?.number, 20).replace(/[^\d+]/g, ''), holder: str(P.wallet?.holder, 60), link: httpUrl(P.wallet?.link) }
    }
  };
  if (!out.delivery.enabled && !out.takeaway.enabled) out.delivery.enabled = true;
  if (strict && out.delivery.enabled && zones.length > 0 && !zones.some(z => z.enabled)) {
    throw bad('فعّل منطقة توصيل واحدة على الأقل');
  }
  if (strict && branches.length > 0 && !branches.some(b => b.enabled)) {
    throw bad('فعّل فرعاً واحداً على الأقل');
  }
  const p = out.payments;
  if (p.instapay.enabled && !p.instapay.handle && !p.instapay.link) { if (strict) throw bad('انستا باي: اكتب عنوان انستا باي أو رابط التحويل'); p.instapay.enabled = false; }
  if (p.wallet.enabled && !p.wallet.number && !p.wallet.link) { if (strict) throw bad('المحفظة: اكتب رقم المحفظة أو رابط التحويل'); p.wallet.enabled = false; }
  if (!p.cod.enabled && !p.instapay.enabled && !p.wallet.enabled) { if (strict) throw bad('لازم تفعّل طريقة دفع واحدة على الأقل'); p.cod.enabled = true; }
  if (strict && S.whatsapp && out.whatsapp.length < 10) throw bad('رقم الواتساب غير صحيح');
  return out;
}

/* ---------- menu: convert DB rows <-> API format ---------- */

function rowToPizza(row) {
  return {
    id: row.id, en: row.en_name, ar: row.ar_name, group: row.group_name,
    p: row.price_json, s: row.stuffed_json, image: row.image_json,
    hidden: row.hidden, soldOut: row.sold_out
  };
}
function rowToPasta(row) {
  return {
    id: row.id, en: row.en_name, ar: row.ar_name, group: row.group_name,
    p: row.price_json, sauce: row.sauce_color, images: row.pasta_images,
    hidden: row.hidden, soldOut: row.sold_out
  };
}
function rowToSide(row) {
  return {
    id: row.id, en: row.en_name, ar: row.ar_name,
    price: row.price_json?.price ?? 0, col: row.side_column, hl: row.side_highlight,
    image: row.image_json, hidden: row.hidden, soldOut: row.sold_out
  };
}
function rowToExtra(row) {
  return {
    id: row.id, en: row.en_name, ar: row.ar_name,
    price: row.price_json?.price ?? 0, cat: row.extra_category,
    hidden: row.hidden, soldOut: row.sold_out
  };
}
function rowToDrink(row) {
  return {
    id: row.id, en: row.en_name, ar: row.ar_name,
    price: row.price_json?.price ?? 0, image: row.image_json,
    hidden: row.hidden, soldOut: row.sold_out
  };
}

async function readMenu() {
  if (!supabase) throw new Error('Database not configured');

  const [{ data: settingsRow }, { data: items }] = await Promise.all([
    supabase.from('app_settings').select('*').eq('id', 'singleton').maybeSingle(),
    supabase.from('menu_items').select('*').order('sort_order')
  ]);

  const S = settingsRow || {};
  const settings = cleanSettings({
    currency: S.currency,
    restaurant: S.restaurant_name,
    whatsapp: S.whatsapp,
    logo: S.logo,
    theme: S.theme,
    branches: S.branches,
    delivery: S.delivery,
    takeaway: S.takeaway,
    payments: S.payments
  }, false);

  const pizzas = (items || []).filter(r => r.category === 'pizza').map(rowToPizza);
  const pasta = (items || []).filter(r => r.category === 'pasta').map(rowToPasta);
  const sides = (items || []).filter(r => r.category === 'side').map(rowToSide);
  const extras = (items || []).filter(r => r.category === 'extra').map(rowToExtra);
  const drinks = (items || []).filter(r => r.category === 'drink').map(rowToDrink);

  return { version: S.version || Date.now(), settings, pizzas, pasta, sides, extras, drinks };
}

/* ---------- menu API ---------- */
app.get('/api/menu', async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const menu = await readMenu();
    res.json(menu);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load menu' }); }
});
app.get('/api/admin/menu', requireAuth, async (req, res) => {
  try {
    const menu = await readMenu();
    res.json(menu);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load menu' }); }
});

app.put('/api/admin/menu', requireAuth, async (req, res) => {
  try {
    const m = clean(req.body || {});
    if (m.pizzas.some(x => !x.en) || m.pasta.some(x => !x.en) || m.sides.some(x => !x.en) || m.extras.some(x => !x.en) || m.drinks.some(x => !x.en))
      return res.status(400).json({ error: 'Every item needs an English name.' });

    await saveMenuToDB(m);
    collectGarbage(m);
    res.json(m);
  } catch (e) { if (e.status === 400) return res.status(400).json({ error: e.message }); console.error(e); res.status(500).json({ error: 'Could not save' }); }
});

function clean(m) {
  return {
    version: Date.now(),
    settings: cleanSettings(m.settings, true),
    pizzas: list(m.pizzas, (x, i) => ({
      id: id(x.id, 'pizza-' + i), en: str(x.en), ar: str(x.ar), group: ['signature', 'classic', 'premium'].includes(x.group) ? x.group : 'classic',
      p: prices(x.p), s: x.s && Object.keys(prices(x.s)).length ? prices(x.s) : null, image: image(x.image), hidden: !!x.hidden, soldOut: !!x.soldOut
    })),
    pasta: list(m.pasta, (x, i) => ({
      id: id(x.id, 'pasta-' + i), en: str(x.en), ar: str(x.ar), group: x.group === 'premium' ? 'premium' : 'regular', p: prices(x.p),
      sauce: /^#[0-9a-f]{6}$/i.test(x.sauce || '') ? x.sauce : '#e0a21b',
      images: { penne: image(x.images?.penne), fettuccine: image(x.images?.fettuccine) }, hidden: !!x.hidden, soldOut: !!x.soldOut
    })),
    sides: list(m.sides, (x, i) => ({ id: id(x.id, 'side-' + i), en: str(x.en), ar: str(x.ar), price: num(x.price) ?? 0, col: x.col === 'R' ? 'R' : 'L', hl: !!x.hl, image: image(x.image), hidden: !!x.hidden, soldOut: !!x.soldOut })),
    extras: list(m.extras, (x, i) => ({ id: id(x.id, 'extra-' + i), en: str(x.en), ar: str(x.ar), price: num(x.price) ?? 0, cat: ['toppings', 'cheese', 'sauces'].includes(x.cat) ? x.cat : 'toppings', hidden: !!x.hidden, soldOut: !!x.soldOut })),
    drinks: list(m.drinks, (x, i) => ({ id: id(x.id, 'drink-' + i), en: str(x.en), ar: str(x.ar), price: num(x.price) ?? 0, image: image(x.image), hidden: !!x.hidden, soldOut: !!x.soldOut }))
  };
}

async function saveMenuToDB(m) {
  const settingsData = {
    id: 'singleton',
    currency: m.settings.currency,
    restaurant_name: m.settings.restaurant,
    whatsapp: m.settings.whatsapp,
    logo: m.settings.logo,
    theme: m.settings.theme,
    branches: m.settings.branches,
    delivery: m.settings.delivery,
    takeaway: m.settings.takeaway,
    payments: m.settings.payments,
    version: m.version,
    updated_at: new Date().toISOString()
  };

  const rows = [];
  m.pizzas.forEach((x, i) => rows.push({
    id: x.id, category: 'pizza', en_name: x.en, ar_name: x.ar, group_name: x.group,
    price_json: x.p, stuffed_json: x.s, image_json: x.image, sort_order: i,
    hidden: x.hidden, sold_out: x.soldOut, updated_at: new Date().toISOString()
  }));
  m.pasta.forEach((x, i) => rows.push({
    id: x.id, category: 'pasta', en_name: x.en, ar_name: x.ar, group_name: x.group,
    price_json: x.p, sauce_color: x.sauce, pasta_images: x.images, sort_order: i,
    hidden: x.hidden, sold_out: x.soldOut, updated_at: new Date().toISOString()
  }));
  m.sides.forEach((x, i) => rows.push({
    id: x.id, category: 'side', en_name: x.en, ar_name: x.ar,
    price_json: { price: x.price }, side_column: x.col, side_highlight: x.hl,
    image_json: x.image, sort_order: i, hidden: x.hidden, sold_out: x.soldOut,
    updated_at: new Date().toISOString()
  }));
  m.extras.forEach((x, i) => rows.push({
    id: x.id, category: 'extra', en_name: x.en, ar_name: x.ar,
    price_json: { price: x.price }, extra_category: x.cat, sort_order: i,
    hidden: x.hidden, sold_out: x.soldOut, updated_at: new Date().toISOString()
  }));
  m.drinks.forEach((x, i) => rows.push({
    id: x.id, category: 'drink', en_name: x.en, ar_name: x.ar,
    price_json: { price: x.price }, image_json: x.image, sort_order: i,
    hidden: x.hidden, sold_out: x.soldOut, updated_at: new Date().toISOString()
  }));

  const newRowIds = new Set(rows.map(r => r.id));

  const { data: existing } = await supabase.from('menu_items').select('id');
  const existingIds = (existing || []).map(r => r.id);
  const toDelete = existingIds.filter(id => !newRowIds.has(id));

  if (toDelete.length > 0) {
    const { error: delErr } = await supabase.from('menu_items').delete().in('id', toDelete);
    if (delErr) throw delErr;
  }

  for (const row of rows) {
    const { error } = await supabase.from('menu_items').upsert(row);
    if (error) throw error;
  }

  const { error: sErr } = await supabase.from('app_settings').upsert(settingsData);
  if (sErr) throw sErr;
}

/* ---------- high-quality image pipeline ---------- */
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => (/^image\/(jpeg|png|webp)$/.test(file.mimetype) ? cb(null, true) : cb(new Error('Use a JPG, PNG or WebP image'))) });

app.post('/api/admin/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, async err => {
    if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'File is larger than 25 MB' : err.message });
    if (!req.file) return res.status(400).json({ error: 'No file received' });
    try {
      const base = sharp(req.file.buffer, { failOn: 'none' }).rotate();
      const meta = await sharp(req.file.buffer).metadata();
      if (!meta.width || !meta.height) throw new Error('Not a valid image');
      let cutout = false;
      if (meta.hasAlpha) { const st = await sharp(req.file.buffer).stats(); cutout = !!(st.channels[3] && st.channels[3].min < 250); }
      const name = crypto.randomBytes(8).toString('hex');
      const sizes = { src: [2000, 92], md: [900, 88], th: [400, 82] };
      const out = {};
      for (const [k, [w, q]] of Object.entries(sizes)) {
        const file = `${name}-${k}.webp`;
        const info = await base.clone().resize({ width: w, withoutEnlargement: true }).webp({ quality: q, alphaQuality: 100, effort: 5 }).toFile(path.join(UPLOADS, file));
        out[k] = '/uploads/' + file;
        if (k === 'src') { out.w = info.width; out.h = info.height; out.bytes = info.size; }
      }
      res.json({ ...out, cutout, origW: meta.width, origH: meta.height });
    } catch (e) { console.error(e); res.status(400).json({ error: 'Could not read this image. Try a JPG or PNG.' }); }
  });
});

function collectGarbage(menu) {
  const used = new Set(); const walk = o => { if (o && typeof o === 'object') Object.values(o).forEach(v => typeof v === 'string' && v.startsWith('/uploads/') ? used.add(path.basename(v)) : walk(v)); };
  walk(menu);
  try { for (const f of fs.readdirSync(UPLOADS)) { const p = path.join(UPLOADS, f); if (!used.has(f) && Date.now() - fs.statSync(p).mtimeMs > 3600e3) fs.unlink(p, () => {}); } } catch {}
}

/* ---------- orders backend ---------- */
const orderAttempts = new Map();
function orderLimited(ip) {
  const now = Date.now(), a = orderAttempts.get(ip);
  if (!a || now - a.t > 10 * 60e3) {
    orderAttempts.set(ip, { n: 1, t: now });
    return false;
  }
  if (a.n >= 8) return true;
  a.n++;
  return false;
}

const VALID_STATUSES = ['new', 'preparing', 'out_for_delivery', 'delivered', 'cancelled'];

function rowToOrder(row) {
  return {
    id: row.id,
    number: row.number,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    status: row.status,
    history: row.history || [],
    type: row.type,
    customer: row.customer || {},
    lines: row.lines || [],
    subtotal: Number(row.subtotal),
    deliveryFee: Number(row.delivery_fee),
    total: Number(row.total),
    currency: row.currency,
    payment: row.payment,
    paymentLabel: row.payment_label,
    note: row.note,
    adjusted: row.adjusted,
    cancelReason: row.cancel_reason || ''
  };
}

app.post('/api/orders', async (req, res) => {
  const ip = req.ip;
  if (orderLimited(ip)) {
    return res.status(429).json({ error: 'Too many orders. Please try again later. · طلبات كثيرة جداً، يرجى المحاولة لاحقاً.' });
  }
  if (JSON.stringify(req.body || {}).length > 100 * 1024) {
    return res.status(400).json({ error: 'Order data too large · حجم بيانات الطلب كبير جداً' });
  }

  try {
    const b = req.body || {};
    const type = b.type === 'takeaway' ? 'takeaway' : 'delivery';
    const cust = b.customer || {};
    const name = str(cust.name, 60);
    const phone = waNumber(cust.phone);
    const address = str(cust.address, 240);
    const note = str(b.note, 300);
    const payment = ['cod', 'instapay', 'wallet'].includes(b.payment) ? b.payment : 'cod';

    if (name.length < 2) return res.status(400).json({ error: 'Please enter your name · اكتب اسمك' });
    if (phone.length < 9 || phone.length > 15) return res.status(400).json({ error: 'Enter a valid mobile number · اكتب رقم موبايل صحيح' });

    const menu = await readMenu();
    const S = menu.settings;

    if (type === 'delivery' && !S.delivery?.enabled) {
      return res.status(400).json({ error: 'Delivery is not available · التوصيل غير متاح حالياً' });
    }
    if (type === 'takeaway' && !S.takeaway?.enabled) {
      return res.status(400).json({ error: 'Takeaway is not available · الاستلام من المطعم غير متاح حالياً' });
    }
    if (!S.payments?.[payment]?.enabled) {
      return res.status(400).json({ error: 'Selected payment method is not available · طريقة الدفع غير متاحة' });
    }

    let zone = null;
    if (type === 'delivery') {
      if (address.length < 8) return res.status(400).json({ error: 'Please write your full address · اكتب العنوان بالتفصيل' });
      const zones = (S.delivery?.zones || []).filter(z => z.enabled !== false);
      if (zones.length > 0) {
        zone = zones.find(z => z.id === cust.zoneId);
        if (!zone) return res.status(400).json({ error: 'Please choose your area · اختر منطقتك' });
      }
    }

    let branch = null;
    const branches = (S.branches || []).filter(br => br.enabled !== false);
    if (branches.length > 0) {
      branch = branches.find(br => br.id === cust.branchId);
      if (!branch) return res.status(400).json({ error: 'Please choose a branch · اختر فرع المطعم' });
    }

    const rawLines = Array.isArray(b.lines) ? b.lines.slice(0, 60) : [];
    if (!rawLines.length) return res.status(400).json({ error: 'Your cart is empty · السلة فارغة' });

    let adjusted = false;
    const orderLines = [];

    for (const rawLine of rawLines) {
      const qty = Math.max(1, Math.min(99, Number(rawLine.qty) || 1));
      const key = str(rawLine.key, 200);
      const keyParts = key.split('|')[0].split(':');
      let basePrice = 0;
      let itemEn = '', itemAr = '';

      if (keyParts[0] === 'pizza') {
        const pizza = menu.pizzas.find(p => p.id === keyParts[1]);
        if (!pizza || pizza.hidden || pizza.soldOut) {
          return res.status(400).json({ error: `Item unavailable: ${rawLine.en || keyParts[1]} · هذا الصنف غير متاح` });
        }
        itemEn = pizza.en; itemAr = pizza.ar;
        if (pizza.group === 'premium' || keyParts[2] === 'R') {
          basePrice = pizza.p.Regular;
        } else {
          const sz = keyParts[2];
          const isStuffed = keyParts[3] === '1';
          if (isStuffed && pizza.s && pizza.s[sz] !== undefined) basePrice = pizza.s[sz];
          else basePrice = pizza.p[sz];
        }
        if (basePrice === undefined || isNaN(basePrice)) {
          return res.status(400).json({ error: `Invalid size for ${pizza.en} · المقاس غير متاح` });
        }
      } else if (keyParts[0] === 'pasta') {
        const pasta = menu.pasta.find(p => p.id === keyParts[1]);
        if (!pasta || pasta.hidden || pasta.soldOut) {
          return res.status(400).json({ error: `Item unavailable: ${rawLine.en || keyParts[1]} · هذا الصنف غير متاح` });
        }
        itemEn = pasta.en; itemAr = pasta.ar;
        const sz = keyParts[3];
        basePrice = pasta.p[sz];
        if (basePrice === undefined || isNaN(basePrice)) {
          return res.status(400).json({ error: `Invalid size for ${pasta.en} · المقاس غير متاح` });
        }
      } else if (keyParts[0] === 'd') {
        const sec = keyParts[1];
        const sectionList = menu[sec];
        if (!Array.isArray(sectionList)) {
          return res.status(400).json({ error: 'Unknown category · قسم غير معروف' });
        }
        const item = sectionList.find(x => x.id === keyParts[2]);
        if (!item || item.hidden || item.soldOut) {
          return res.status(400).json({ error: `Item unavailable: ${rawLine.en || keyParts[2]} · هذا الصنف غير متاح` });
        }
        itemEn = item.en; itemAr = item.ar;
        basePrice = item.price;
      } else {
        return res.status(400).json({ error: 'Unknown item in cart · صنف غير معروف في السلة' });
      }

      const rawExtras = Array.isArray(rawLine.extras) ? rawLine.extras.slice(0, 30) : [];
      let extrasTotal = 0;
      const extrasList = [];

      for (const ex of rawExtras) {
        const extraItem = menu.extras.find(x => x.id === ex.id);
        if (!extraItem || extraItem.hidden || extraItem.soldOut) {
          return res.status(400).json({ error: `Extra unavailable: ${ex.en || ex.id} · هذه الإضافة غير متاحة` });
        }
        extrasTotal += extraItem.price;
        extrasList.push({ id: extraItem.id, en: extraItem.en, ar: extraItem.ar || '', price: extraItem.price });
      }

      const serverUnit = Math.round((basePrice + extrasTotal) * 100) / 100;
      if (num(rawLine.unit) !== serverUnit) {
        adjusted = true;
      }

      orderLines.push({
        en: str(itemEn || rawLine.en, 80),
        ar: str(itemAr || rawLine.ar, 80),
        detailAr: str(rawLine.detailAr, 120),
        detailMsg: str(rawLine.detailMsg, 120),
        qty,
        unit: serverUnit,
        note: str(rawLine.note, 140),
        extras: extrasList
      });
    }

    const subtotal = Math.round(orderLines.reduce((s, l) => s + l.unit * l.qty, 0) * 100) / 100;
    let deliveryFee = 0;
    if (type === 'delivery') {
      if (zone) deliveryFee = zone.fee;
      else deliveryFee = S.delivery?.fee || 0;
    }
    const total = Math.round((subtotal + deliveryFee) * 100) / 100;

    const { data: counter } = await supabase.from('order_counter').select('next_number').eq('id', 'singleton').maybeSingle();
    const orderNumber = counter?.next_number || 1001;
    const orderId = crypto.randomBytes(5).toString('hex');
    const now = new Date().toISOString();

    let paymentLabel = 'كاش عند الاستلام';
    if (payment === 'instapay') paymentLabel = 'انستا باي';
    else if (payment === 'wallet') paymentLabel = S.payments?.wallet?.label || 'محفظة إلكترونية';

    const customerObj = {
      name,
      phone,
      address: type === 'delivery' ? address : '',
      ...(zone ? { zoneId: zone.id, zoneName: zone.name } : {}),
      ...(branch ? { branchId: branch.id, branchName: branch.name, branchWhatsapp: branch.whatsapp } : {})
    };

    const orderRow = {
      id: orderId,
      number: orderNumber,
      status: 'new',
      type,
      customer: customerObj,
      lines: orderLines,
      subtotal,
      delivery_fee: deliveryFee,
      total,
      currency: S.currency || 'EGP',
      payment,
      payment_label: paymentLabel,
      note,
      history: [{ status: 'new', at: now }],
      cancel_reason: '',
      adjusted,
      created_at: now,
      updated_at: now
    };

    const { error: insertErr } = await supabase.from('orders').insert(orderRow);
    if (insertErr) throw insertErr;

    await supabase.from('order_counter').update({ next_number: orderNumber + 1 }).eq('id', 'singleton');

    res.json(rowToOrder(orderRow));
  } catch (e) {
    console.error('Order error:', e);
    res.status(500).json({ error: 'Could not place order · تعذر إنشاء الطلب' });
  }
});

app.get('/api/admin/orders', requireAuth, async (req, res) => {
  try {
    const { status, q, from, to } = req.query;
    let query = supabase.from('orders').select('*', { count: 'exact' }).order('created_at', { ascending: false });

    if (q) {
      const ql = String(q).trim();
      query = query.or(`customer.ilike.%${ql}%,note.ilike.%${ql}%`);
    }
    if (status === 'active') {
      query = query.in('status', ['new', 'preparing', 'out_for_delivery']);
    } else if (status && status !== 'all') {
      query = query.eq('status', status);
    }
    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to);

    const limitNum = Math.min(300, Math.max(1, Number(req.query.limit) || 100));
    query = query.limit(limitNum);

    const { data, error } = await query;
    if (error) throw error;

    const orders = (data || []).map(rowToOrder);

    const counts = { new: 0, preparing: 0, out_for_delivery: 0, delivered: 0, cancelled: 0, active: 0 };
    for (const o of orders) {
      if (counts[o.status] !== undefined) counts[o.status]++;
      if (['new', 'preparing', 'out_for_delivery'].includes(o.status)) counts.active++;
    }

    if (q) {
      const ql = String(q).trim().toLowerCase();
      const filtered = orders.filter(o =>
        String(o.number).includes(ql) ||
        (o.customer?.name || '').toLowerCase().includes(ql) ||
        (o.customer?.phone || '').includes(ql)
      );
      return res.json({ orders: filtered, counts, serverTime: new Date().toISOString() });
    }

    res.json({ orders, counts, serverTime: new Date().toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load orders' });
  }
});

app.patch('/api/admin/orders/:id', requireAuth, async (req, res) => {
  try {
    const { status, cancelReason } = req.body || {};
    if (!VALID_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status · حالة غير صحيحة' });

    const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
    if (!existing) return res.status(404).json({ error: 'Order not found · الطلب غير موجود' });

    if (existing.type === 'takeaway' && status === 'out_for_delivery') {
      return res.status(400).json({ error: 'Takeaway orders cannot be out for delivery · طلبات التيك أواي لا تخرج مع المندوب' });
    }

    const now = new Date().toISOString();
    const cr = cancelReason !== undefined ? str(cancelReason, 200) : (existing.cancel_reason || '');
    const history = [...(existing.history || []), { status, at: now, ...(cr ? { reason: cr } : {}) }];

    const { data, error } = await supabase.from('orders').update({
      status, updated_at: now, cancel_reason: cr, history
    }).eq('id', req.params.id).select('*').maybeSingle();

    if (error) throw error;
    res.json(rowToOrder(data));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not update order' });
  }
});

app.delete('/api/admin/orders/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('orders').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not delete order' });
  }
});

/* ---------- static ---------- */
app.use('/uploads', express.static(UPLOADS, { maxAge: '365d', immutable: true }));
app.use('/admin', (req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex'); next(); });
app.use(express.static(PUBLIC, { extensions: ['html'], setHeaders: (res, p) => { if (/\.(html|js|css)$/.test(p)) res.setHeader('Cache-Control', 'no-cache'); } }));
app.get(['/admin', '/dashboard'], (req, res) => res.sendFile(path.join(PUBLIC, 'admin', 'index.html')));

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`\n  Menu:       http://localhost:${PORT}\n  Dashboard:  http://localhost:${PORT}/admin`);
    if (!process.env.ADMIN_PASSWORD) console.log('\n  ⚠  Using the default password "admin123". Set your own:  ADMIN_PASSWORD=yourpassword npm start\n');
  });
}

module.exports = app;
