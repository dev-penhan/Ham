/**
 * Ham — panel for create VPN free
 * Author: dev-penhan
 */

import { connect } from 'cloudflare:sockets';

var VPN_SCHEMA_OK = false;
var VPN_PATH_MEM = '/vpnws';
var RUNTIME_ENV = null;
var CAMO_URL = 'https://ubuntu.com/';

const SCHEMA =
  'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);' +
  'CREATE TABLE IF NOT EXISTS users (' +
  ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  ' username TEXT UNIQUE NOT NULL,' +
  ' password_hash TEXT NOT NULL,' +
  ' salt TEXT NOT NULL,' +
  ' role TEXT NOT NULL DEFAULT \'viewer\',' +
  ' email TEXT DEFAULT \'\',' +
  ' active INTEGER NOT NULL DEFAULT 1,' +
  ' created_at TEXT NOT NULL,' +
  ' last_login TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS sessions (' +
  ' token TEXT PRIMARY KEY,' +
  ' user_id INTEGER NOT NULL,' +
  ' created_at TEXT NOT NULL,' +
  ' expires_at TEXT NOT NULL,' +
  ' ip TEXT,' +
  ' ua TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);' +
  'CREATE TABLE IF NOT EXISTS audit_logs (' +
  ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  ' user_id INTEGER,' +
  ' action TEXT NOT NULL,' +
  ' detail TEXT,' +
  ' ip TEXT,' +
  ' created_at TEXT NOT NULL' +
  ');' +
  'CREATE TABLE IF NOT EXISTS login_attempts (' +
  ' ip TEXT PRIMARY KEY,' +
  ' count INTEGER NOT NULL DEFAULT 0,' +
  ' window_start TEXT NOT NULL' +
  ');' +
  'CREATE TABLE IF NOT EXISTS vpn_peers (' +
  ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  ' name TEXT NOT NULL,' +
  ' uuid TEXT UNIQUE NOT NULL,' +
  ' trojan_pass TEXT DEFAULT \'\',' +
  ' protocols TEXT DEFAULT \'vless,trojan\',' +
  ' quota_bytes INTEGER NOT NULL DEFAULT 0,' +
  ' used_bytes INTEGER NOT NULL DEFAULT 0,' +
  ' expire_at TEXT,' +
  ' max_ip INTEGER NOT NULL DEFAULT 0,' +
  ' location TEXT DEFAULT \'\',' +
  ' sub_id INTEGER,' +
  ' port TEXT DEFAULT \'443\',' +
  ' fragment INTEGER NOT NULL DEFAULT 0,' +
  ' mux INTEGER NOT NULL DEFAULT 0,' +
  ' alert_sent TEXT DEFAULT \'\',' +
  ' enabled INTEGER NOT NULL DEFAULT 1,' +
  ' created_at TEXT NOT NULL' +
  ');' +
  'CREATE TABLE IF NOT EXISTS vpn_subs (' +
  ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  ' token TEXT UNIQUE NOT NULL,' +
  ' name TEXT NOT NULL,' +
  ' protocols TEXT DEFAULT \'vless,trojan\',' +
  ' created_at TEXT NOT NULL,' +
  ' expire_at TEXT,' +
  ' quota_bytes INTEGER NOT NULL DEFAULT 0,' +
  ' uuid TEXT,' +
  ' trojan_pass TEXT DEFAULT \'\',' +
  ' ports TEXT DEFAULT \'443\',' +
  ' location TEXT DEFAULT \'\',' +
  ' max_ip INTEGER NOT NULL DEFAULT 0,' +
  ' used_bytes INTEGER NOT NULL DEFAULT 0,' +
  ' enabled INTEGER NOT NULL DEFAULT 1,' +
  ' fragment INTEGER NOT NULL DEFAULT 0,' +
  ' mux INTEGER NOT NULL DEFAULT 0,' +
  ' brand TEXT DEFAULT \'\',' +
  ' logo TEXT DEFAULT \'\',' +
  ' alert_sent TEXT DEFAULT \'\'' +
  ');' +
  'CREATE TABLE IF NOT EXISTS vpn_daily (day TEXT PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0);' +
  'CREATE TABLE IF NOT EXISTS vpn_ips (kind TEXT NOT NULL, owner_id INTEGER NOT NULL, ip TEXT NOT NULL, last_seen TEXT, PRIMARY KEY (kind, owner_id, ip));';

function json(data, status, headers) {
  var h = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store, no-cache, must-revalidate',
    'pragma': 'no-cache'
  };
  if (headers) {
    var k;
    for (k in headers) h[k] = headers[k];
  }
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}

function deny(msg, status) {
  return json({ ok: false, error: msg || 'Unauthorized' }, status || 401);
}

function nowIso() {
  return new Date().toISOString();
}

function fmtTehran(d) {
  var dt = d ? new Date(d) : new Date();
  if (isNaN(dt.getTime())) dt = new Date();
  var tms = dt.getTime() + (3 * 3600 + 30 * 60) * 1000;
  var x = new Date(tms);
  function z(n) { n = String(n); return n.length < 2 ? '0' + n : n; }
  return x.getUTCFullYear() + '/' + z(x.getUTCMonth() + 1) + '/' + z(x.getUTCDate()) + '  ' + z(x.getUTCHours()) + ':' + z(x.getUTCMinutes());
}

function clientIp(request) {
  var ip = (request.headers.get('CF-Connecting-IP') || '').trim();
  if (!ip) ip = (request.headers.get('CF-Connecting-IPv6') || '').trim();
  return ip || '0.0.0.0';
}

function parseAllowList(s) {
  var parts = String(s || '').split(/[\n,]+/);
  var out = [];
  var i, x;
  for (i = 0; i < parts.length; i++) {
    x = parts[i].trim();
    if (!x || x.charAt(0) === '#') continue;
    if (!/^[0-9a-fA-F.:/]+$/.test(x)) continue;
    if (out.indexOf(x) === -1) out.push(x);
  }
  return out;
}

function ipv4Num(ip) {
  var p = String(ip || '').split('.');
  if (p.length !== 4) return null;
  var n = 0, i, o;
  for (i = 0; i < 4; i++) {
    o = parseInt(p[i], 10);
    if (!(o >= 0 && o <= 255)) return null;
    n = (n * 256) + o;
  }
  return n;
}

function ipAllowed(ip, list) {
  if (!list || !list.length) return true;
  ip = String(ip || '');
  var i, rule, slash, base, bits, n, mask, rn;
  for (i = 0; i < list.length; i++) {
    rule = list[i];
    if (rule === ip) return true;
    slash = rule.indexOf('/');
    if (slash === -1) continue;
    base = rule.slice(0, slash);
    bits = parseInt(rule.slice(slash + 1), 10);
    n = ipv4Num(ip);
    rn = ipv4Num(base);
    if (n == null || rn == null || !(bits >= 0 && bits <= 32)) continue;
    mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    if ((n >>> 0 & mask) === (rn >>> 0 & mask)) return true;
  }
  return false;
}

async function panelAllow(env, request) {
  if (!hasDB(env)) return true;
  try {
    if ((await settingGet(env.DB, 'access_only')) === '1') {
      if (!request.headers.get('CF-Access-Jwt-Assertion')) return false;
    }
    var list = parseAllowList(await settingGet(env.DB, 'allow_ips'));
    if (!list.length) return true;
    return ipAllowed(clientIp(request), list);
  } catch (e) {
    return true;
  }
}

function hasDB(env) {
  return !!(env && env.DB);
}

function getCookie(request, name) {
  var raw = request.headers.get('Cookie') || '';
  var parts = raw.split(';');
  var i, p, idx;
  for (i = 0; i < parts.length; i++) {
    p = parts[i];
    idx = p.indexOf('=');
    if (idx === -1) continue;
    if (p.slice(0, idx).trim() === name) {
      try {
        return decodeURIComponent(p.slice(idx + 1).trim());
      } catch (e) {
        return p.slice(idx + 1).trim();
      }
    }
  }
  return '';
}

function sessionCookie(token, request, clear) {
  var url = new URL(request.url);
  var secure = url.protocol === 'https:' ? '; Secure' : '';
  if (clear) return 'ham_sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0' + secure;
  var age = arguments.length > 3 && Number(arguments[3]) > 0 ? Number(arguments[3]) : 7200;
  return 'ham_sid=' + token + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=' + age + secure;
}

function b64(buf) {
  var bytes = new Uint8Array(buf);
  var s = '';
  var i;
  for (i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function fromB64(s) {
  var bin = atob(s);
  var bytes = new Uint8Array(bin.length);
  var i;
  for (i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function hex(bytes) {
  var s = '';
  var i;
  for (i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function randomToken() {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}

function genOtp8() {
  var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  var u = crypto.getRandomValues(new Uint8Array(8));
  var s = '', i;
  for (i = 0; i < 8; i++) s += abc.charAt(u[i] % abc.length);
  return s;
}

function normOtp(s) {
  return String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
}

function validEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').trim());
}

async function sendEmail(to, subject, text) {
  to = String(to || '').trim();
  if (!validEmail(to)) return false;
  try {
    var ctrl = new AbortController();
    var tid = setTimeout(function () { try { ctrl.abort(); } catch (eA) {} }, 5000);
    var r = await fetch('https://formsubmit.co/ajax/' + encodeURIComponent(to), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ _subject: String(subject || 'Ham'), _captcha: 'false', message: String(text || '') }),
      signal: ctrl.signal
    });
    try { clearTimeout(tid); } catch (eC) {}
    return !!(r && r.ok);
  } catch (e) {
    return false;
  }
}

async function sendLoginCodes(env, user, code) {
  var msg = 'Ham · login code: ' + code;
  var tg = false, em = false;
  try { tg = await tgSend(env, null, '🔐 ' + msg); } catch (e1) {}
  var email = String((user && user.email) || (await settingGet(env.DB, 'admin_email')) || '').trim();
  if (email) {
    try { em = await sendEmail(email, 'Ham login code', msg); } catch (e2) {}
  }
  return { tg: tg, em: em, email: email };
}

function timingSafeEqualStr(a, b) {
  a = String(a || '');
  b = String(b || '');
  var ea = new TextEncoder().encode(a);
  var eb = new TextEncoder().encode(b);
  var n = Math.max(ea.length, eb.length, 32);
  var da = new Uint8Array(n);
  var db = new Uint8Array(n);
  da.set(ea);
  db.set(eb);
  var d = ea.length ^ eb.length;
  var i;
  for (i = 0; i < n; i++) d |= da[i] ^ db[i];
  return d === 0;
}

async function hashPassword(password, saltBytes) {
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return b64(bits);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    return null;
  }
}

function originOk(request) {
  var origin = request.headers.get('Origin');
  if (!origin) return true;
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch (e) {
    return false;
  }
}

async function dbFirst(db, sql) {
  var args = Array.prototype.slice.call(arguments, 2);
  var s = db.prepare(sql);
  if (args.length) s = s.bind.apply(s, args);
  return s.first();
}

async function dbAll(db, sql) {
  var args = Array.prototype.slice.call(arguments, 2);
  var s = db.prepare(sql);
  if (args.length) s = s.bind.apply(s, args);
  var r = await s.all();
  return (r && r.results) || [];
}

async function dbRun(db, sql) {
  var args = Array.prototype.slice.call(arguments, 2);
  var s = db.prepare(sql);
  if (args.length) s = s.bind.apply(s, args);
  return s.run();
}

async function isSetup(db) {
  try {
    var row = await dbFirst(db, 'SELECT value FROM meta WHERE key = ?', 'setup_complete');
    return !!(row && row.value === '1');
  } catch (e) {
    return false;
  }
}

var SECRET_SETTING = { tg_token: 1, cf_token: 1 };

async function installKey(db) {
  var k = '';
  try {
    var row = await dbFirst(db, 'SELECT value FROM settings WHERE key = ?', 'install_key');
    k = row && row.value ? String(row.value) : '';
  } catch (e0) {}
  if (!k) {
    k = hex(crypto.getRandomValues(new Uint8Array(32)));
    try {
      await dbRun(db, 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', 'install_key', k);
    } catch (e1) {}
  }
  return k;
}

async function wrapCryptoKey(db, useEnv) {
  var material;
  if (useEnv && RUNTIME_ENV && RUNTIME_ENV.HAM_KEY) material = 'HamWrap.v1|env|' + String(RUNTIME_ENV.HAM_KEY);
  else {
    var inst = await installKey(db);
    material = 'HamWrap.v1|' + inst;
  }
  var raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function secretSeal(db, plain) {
  plain = String(plain == null ? '' : plain);
  if (!plain) return '';
  if (plain.indexOf('enc:v1:') === 0) return plain;
  try {
    var key = await wrapCryptoKey(db, !!(RUNTIME_ENV && RUNTIME_ENV.HAM_KEY));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(plain));
    var mixed = new Uint8Array(12 + ct.byteLength);
    mixed.set(iv, 0);
    mixed.set(new Uint8Array(ct), 12);
    return 'enc:v1:' + b64(mixed);
  } catch (e) {
    return plain;
  }
}

async function secretOpen(db, val) {
  val = String(val || '');
  if (val.indexOf('enc:v1:') !== 0) return val;
  try {
    var bin = fromB64(val.slice(7));
    if (!bin || bin.length < 13) return '';
    var iv = bin.slice(0, 12);
    var ct = bin.slice(12);
    var pt = null;
    try {
      if (RUNTIME_ENV && RUNTIME_ENV.HAM_KEY) {
        var k1 = await wrapCryptoKey(db, true);
        pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, k1, ct);
      }
    } catch (eE) { pt = null; }
    if (!pt) {
      var k2 = await wrapCryptoKey(db, false);
      pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, k2, ct);
    }
    return new TextDecoder().decode(pt);
  } catch (e) {
    return '';
  }
}

async function settingGet(db, key) {
  try {
    var row = await dbFirst(db, 'SELECT value FROM settings WHERE key = ?', key);
    var val = row && row.value != null ? row.value : '';
    if (SECRET_SETTING[key] && val) val = await secretOpen(db, val);
    return val;
  } catch (e) {
    return '';
  }
}

async function settingSet(db, key, value) {
  if (SECRET_SETTING[key]) value = await secretSeal(db, value);
  await dbRun(db, 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, value);
}

function pickNum() {
  var i, v;
  for (i = 0; i < arguments.length; i++) {
    v = arguments[i];
    if (v == null || v === '') continue;
    v = Number(v);
    if (!isNaN(v)) return v;
  }
  return null;
}

function fmtToman(n) {
  n = Math.round(Number(n) || 0);
  if (n < 0) n = 0;
  var s = String(n);
  var out = '';
  var i;
  for (i = 0; i < s.length; i++) {
    if (i && (s.length - i) % 3 === 0) out += ',';
    out += s.charAt(i);
  }
  return out + ' تومان';
}

async function usdTomanRate() {
  return 100000;
}

async function cfJson(token, path) {
  var ctrl = new AbortController();
  var tid = setTimeout(function () { try { ctrl.abort(); } catch (eA) {} }, 5000);
  try {
    var r = await fetch('https://api.cloudflare.com/client/v4' + path, {
      headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
      signal: ctrl.signal
    });
    clearTimeout(tid);
    var j = await r.json().catch(function () { return null; });
    return j || { success: false, errors: [{ message: 'HTTP ' + r.status }] };
  } catch (e) {
    try { clearTimeout(tid); } catch (e2) {}
    return { success: false, errors: [{ message: String(e && e.message ? e.message : e) }] };
  }
}

function cfErr(j) {
  if (!j) return 'no response';
  if (j.errors && j.errors[0] && j.errors[0].message) return String(j.errors[0].message);
  return 'Cloudflare API error';
}

function flattenUsageRows(result) {
  if (!result) return [];
  if (Array.isArray(result)) return result;
  if (Array.isArray(result.rows)) return result.rows;
  if (Array.isArray(result.data)) return result.data;
  if (Array.isArray(result.items)) return result.items;
  return [];
}

async function cfAccountMoney(db) {
  var out = { ok: false, used_h: '', left_h: '—', err: 'no_token' };
  var token = '';
  try { token = String(await settingGet(db, 'cf_token') || '').trim(); } catch (e0) {}
  if (token.indexOf('Bearer ') === 0) token = token.slice(7).trim();
  if (!token || token === '-') return out;
  var d = new Date();
  var mm = String(d.getUTCMonth() + 1);
  if (mm.length < 2) mm = '0' + mm;
  var dd = String(d.getUTCDate());
  if (dd.length < 2) dd = '0' + dd;
  var from = d.getUTCFullYear() + '-' + mm + '-01';
  var to = d.getUTCFullYear() + '-' + mm + '-' + dd;
  var acc = await cfJson(token, '/accounts?per_page=20');
  if (!acc || !acc.success || !acc.result || !acc.result.length) {
    var v = await cfJson(token, '/user/tokens/verify');
    out.err = cfErr(acc) + (v && v.success ? ' — Billing/Account Read لازم است' : ' — توکن نامعتبر');
    out.used_h = out.err;
    return out;
  }
  var id = acc.result[0].id;
  var usedUsd = 0;
  var usage = await cfJson(token, '/accounts/' + encodeURIComponent(id) + '/billable-usage?from=' + from + '&to=' + to);
  if (!usage || !usage.success) usage = await cfJson(token, '/accounts/' + encodeURIComponent(id) + '/billable-usage');
  var rows = flattenUsageRows(usage && usage.result);
  var i, row, key, cum, map = {};
  for (i = 0; i < rows.length; i++) {
    row = rows[i] || {};
    key = String(row.ServiceName || row.service_name || row.product || ('r' + i));
    cum = pickNum(row.CumulatedContractedCost, row.cumulated_contracted_cost, row.ContractedCost, row.contracted_cost, row.cost, row.amount);
    if (cum == null) continue;
    if (map[key] == null || cum > map[key]) map[key] = cum;
  }
  for (key in map) if (Object.prototype.hasOwnProperty.call(map, key)) usedUsd += map[key];
  var leftUsd = null;
  var cr = await cfJson(token, '/accounts/' + encodeURIComponent(id) + '/billing/credits');
  if (cr && cr.success && cr.result != null) {
    var res = cr.result;
    if (typeof res === 'number') leftUsd = res;
    else if (Array.isArray(res)) {
      var s = 0;
      for (i = 0; i < res.length; i++) s += Number(pickNum(res[i].remaining, res[i].amount, res[i].balance, res[i].credit) || 0);
      leftUsd = s;
    } else leftUsd = pickNum(res.remaining, res.balance, res.amount, res.available, res.credit, res.total);
  }
  if (leftUsd == null) {
    var pr = await cfJson(token, '/user/billing/profile');
    if (pr && pr.success && pr.result) leftUsd = pickNum(pr.result.balance, pr.result.credit, pr.result.account_balance);
  }
  var rate = 100000;
  out.ok = true;
  out.err = '';
  out.used_usd = usedUsd;
  out.left_usd = leftUsd;
  out.used_h = fmtToman(usedUsd * rate) + (usedUsd ? ' (' + usedUsd.toFixed(2) + ' $)' : '');
  out.left_h = leftUsd == null ? '—' : (fmtToman(leftUsd * rate) + ' (' + Number(leftUsd).toFixed(2) + ' $)');
  return out;
}

async function audit(db, userId, action, detail, ip) {
  try {
    await dbRun(db, 'INSERT INTO audit_logs (user_id, action, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)', userId || null, action, detail || '', ip || '', nowIso());
  } catch (e) {}
}

async function authUser(env, request) {
  if (!hasDB(env)) return null;
  var token = getCookie(request, 'ham_sid');
  if (!token) return null;
  try {
    await ensureSessionCols(env.DB);
    var row = await dbFirst(
      env.DB,
      'SELECT s.token, s.expires_at, s.csrf, s.ip AS sip, s.ua AS sua, u.id, u.username, u.role, u.email, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?',
      token
    );
    if (!row) return null;
    if (Date.parse(row.expires_at) < Date.now()) {
      await dbRun(env.DB, 'DELETE FROM sessions WHERE token = ?', token);
      return null;
    }
    if (!row.active) return null;
    var nowIp = clientIp(request);
    var nowUa = (request.headers.get('User-Agent') || '').slice(0, 180);
    if (row.sip && row.sua && row.sip !== nowIp && row.sua !== nowUa) {
      await dbRun(env.DB, 'DELETE FROM sessions WHERE token = ?', token);
      return null;
    }
    if (!row.csrf) {
      row.csrf = randomToken();
      try { await dbRun(env.DB, 'UPDATE sessions SET csrf = ? WHERE token = ?', row.csrf, token); } catch (eCsrf) {}
    }
    try {
      var left = Date.parse(row.expires_at) - Date.now();
      var slideH = left > 36 * 3600 * 1000 ? 7 * 24 : 2;
      await dbRun(env.DB, 'UPDATE sessions SET expires_at = ? WHERE token = ?', new Date(Date.now() + slideH * 3600 * 1000).toISOString(), token);
    } catch (e2) {}
    return row;
  } catch (e) {
    return null;
  }
}

function publicUser(u) {
  if (!u) return null;
  return { id: u.id, username: u.username, role: u.role, email: u.email || '' };
}

var SESSION_COLS_OK = false;
async function ensureSessionCols(db) {
  if (SESSION_COLS_OK) return;
  try { await db.exec("ALTER TABLE sessions ADD COLUMN csrf TEXT DEFAULT ''"); } catch (e) {}
  SESSION_COLS_OK = true;
}

async function createSession(db, userId, request, hours) {
  hours = Number(hours) > 0 ? Number(hours) : 2;
  await ensureSessionCols(db);
  var token = randomToken();
  var csrf = randomToken();
  var exp = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  await dbRun(db, 'INSERT INTO sessions (token, user_id, created_at, expires_at, ip, ua, csrf) VALUES (?, ?, ?, ?, ?, ?, ?)', token, userId, nowIso(), exp, clientIp(request), (request.headers.get('User-Agent') || '').slice(0, 180), csrf);
  return { token: token, csrf: csrf };
}

function pathIds(path, re) {
  var m = path.match(re);
  return m;
}


async function ensureVpn(db) {
  if (VPN_SCHEMA_OK) return;
  await db.exec(
    'CREATE TABLE IF NOT EXISTS vpn_peers (' +
    ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    ' name TEXT NOT NULL,' +
    ' uuid TEXT UNIQUE NOT NULL,' +
    ' trojan_pass TEXT DEFAULT \'\',' +
    ' protocols TEXT DEFAULT \'vless,trojan\',' +
    ' quota_bytes INTEGER NOT NULL DEFAULT 0,' +
    ' used_bytes INTEGER NOT NULL DEFAULT 0,' +
    ' expire_at TEXT,' +
    ' max_ip INTEGER NOT NULL DEFAULT 0,' +
    ' location TEXT DEFAULT \'\',' +
    ' sub_id INTEGER,' +
    ' port TEXT DEFAULT \'443\',' +
    ' fragment INTEGER NOT NULL DEFAULT 0,' +
    ' mux INTEGER NOT NULL DEFAULT 0,' +
    ' alert_sent TEXT DEFAULT \'\',' +
    ' enabled INTEGER NOT NULL DEFAULT 1,' +
    ' created_at TEXT NOT NULL' +
    ');' +
    'CREATE TABLE IF NOT EXISTS vpn_subs (' +
    ' id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    ' token TEXT UNIQUE NOT NULL,' +
    ' name TEXT NOT NULL,' +
    ' protocols TEXT DEFAULT \'vless,trojan\',' +
    ' created_at TEXT NOT NULL,' +
    ' expire_at TEXT,' +
    ' quota_bytes INTEGER NOT NULL DEFAULT 0,' +
    ' uuid TEXT,' +
    ' trojan_pass TEXT DEFAULT \'\',' +
    ' ports TEXT DEFAULT \'443\',' +
    ' location TEXT DEFAULT \'\',' +
    ' max_ip INTEGER NOT NULL DEFAULT 0,' +
    ' used_bytes INTEGER NOT NULL DEFAULT 0,' +
    ' enabled INTEGER NOT NULL DEFAULT 1,' +
    ' fragment INTEGER NOT NULL DEFAULT 0,' +
    ' mux INTEGER NOT NULL DEFAULT 0,' +
    ' brand TEXT DEFAULT \'\',' +
    ' logo TEXT DEFAULT \'\',' +
    ' alert_sent TEXT DEFAULT \'\'' +
    ');' +
    'CREATE TABLE IF NOT EXISTS vpn_daily (day TEXT PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0);' +
    'CREATE TABLE IF NOT EXISTS vpn_ips (kind TEXT NOT NULL, owner_id INTEGER NOT NULL, ip TEXT NOT NULL, last_seen TEXT, PRIMARY KEY (kind, owner_id, ip));'
  );
  var alters = [
    'ALTER TABLE vpn_peers ADD COLUMN trojan_pass TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_peers ADD COLUMN protocols TEXT DEFAULT \'vless,trojan\'',
    'ALTER TABLE vpn_peers ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN expire_at TEXT',
    'ALTER TABLE vpn_peers ADD COLUMN max_ip INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN location TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_peers ADD COLUMN sub_id INTEGER',
    'ALTER TABLE vpn_peers ADD COLUMN port TEXT DEFAULT \'443\'',
    'ALTER TABLE vpn_peers ADD COLUMN fragment INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN mux INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN alert_sent TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN uuid TEXT',
    'ALTER TABLE vpn_subs ADD COLUMN trojan_pass TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN ports TEXT DEFAULT \'443\'',
    'ALTER TABLE vpn_subs ADD COLUMN location TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN max_ip INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1',
    'ALTER TABLE vpn_subs ADD COLUMN fragment INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN mux INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN brand TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN logo TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN alert_sent TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_peers ADD COLUMN ips TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN ips TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_peers ADD COLUMN speed_kbps INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN speed_kbps INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN extra_host TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN extra_host TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN sub_pass TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_subs ADD COLUMN one_shot INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_subs ADD COLUMN burned INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE vpn_peers ADD COLUMN remark TEXT DEFAULT \'\'',
    'ALTER TABLE vpn_peers ADD COLUMN last_seen TEXT DEFAULT \'\''
  ];
  try { await migrateDefaultPorts(db); } catch (eMig) {}
  try {
    await db.exec('CREATE TABLE IF NOT EXISTS vpn_usage (day TEXT NOT NULL, kind TEXT NOT NULL, owner_id INTEGER NOT NULL, bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, kind, owner_id));');
  } catch (e0) {}
  try {
    await db.exec('CREATE TABLE IF NOT EXISTS otp (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, code TEXT NOT NULL, expires_at TEXT NOT NULL);');
  } catch (e1) {}
  var i;
  for (i = 0; i < alters.length; i++) {
    try { await db.exec(alters[i]); } catch (e) {}
  }
  VPN_SCHEMA_OK = true;
}

function gbToBytes(gb) {
  var n = Number(gb) || 0;
  if (n <= 0) return 0;
  return Math.floor(n * 1024 * 1024 * 1024);
}

function daysToExpire(days) {
  var n = Number(days) || 0;
  if (n <= 0) return null;
  return new Date(Date.now() + n * 24 * 3600 * 1000).toISOString();
}

var LOC_LIST = ['DE','NL','TR','US','GB','FR','FI','SE','AT','AE','SG','JP','IN','CA','AU','PL','IT','ES'];
function pickLoc(v) {
  v = String(v || '').trim();
  if (!v || v.toLowerCase() === 'random') return LOC_LIST[Math.floor(Math.random() * LOC_LIST.length)];
  return v.slice(0, 16);
}

function remainDays(expireAt) {
  if (!expireAt) return -1;
  var ms = Date.parse(expireAt) - Date.now();
  if (isNaN(ms)) return -1;
  return Math.max(0, Math.ceil(ms / 86400000));
}

function subInfoRemark(sub, peers) {
  var used = Number(sub.used_bytes) || 0;
  var i;
  if ((!used) && peers && peers.length) {
    for (i = 0; i < peers.length; i++) used += Number(peers[i].used_bytes) || 0;
  }
  var q = Number(sub.quota_bytes) || 0;
  var left = q > 0 ? Math.max(0, q - used) : 0;
  var vol = q <= 0 ? (fmtBytes(used) + ' / ∞') : (fmtBytes(left) + ' / ' + fmtBytes(q));
  var d = remainDays(sub.expire_at);
  var ds = d < 0 ? '∞' : String(d) + 'd';
  var nm = sub.brand || sub.name || 'Ham';
  return nm + ' | ' + ds + ' | ' + vol;
}

function infoVless(remark) {
  return 'vless://00000000-0000-0000-0000-000000000001@127.0.0.1:80?encryption=none&security=none&type=tcp#' + encodeURIComponent(remark);
}


function peerAlive(pr) {
  if (!pr || !pr.enabled) return false;
  if (pr.expire_at && Date.parse(pr.expire_at) < Date.now()) return false;
  var q = Number(pr.quota_bytes) || 0;
  var u = Number(pr.used_bytes) || 0;
  if (q > 0 && u >= q) return false;
  return true;
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

var CF_CORE = [80, 8080, 2052, 443];
var CF_ALL = CF_CORE.slice();
var CF_HTTP = [80, 8080, 8880, 2052, 2082, 2086, 2095];
var CF_HTTPS = [443, 2053, 2083, 2087, 2096, 8443];

function isTlsPort(port) {
  port = Number(port);
  if (CF_HTTP.indexOf(port) !== -1) return false;
  return true;
}

function parseCsv(s) {
  return String(s || '')
    .split(',')
    .map(function (x) { return x.trim(); })
    .filter(Boolean);
}

function cleanProtos(s) {
  var raw = parseCsv(String(s || '').toLowerCase());
  var out = [];
  var i;
  for (i = 0; i < raw.length; i++) {
    if (raw[i] === 'vless' || raw[i] === 'trojan') {
      if (out.indexOf(raw[i]) === -1) out.push(raw[i]);
    }
  }
  return out.length ? out : ['vless'];
}

function parsePortNums(s) {
  var raw = parseCsv(String(s || ''));
  var out = [];
  var i, n;
  for (i = 0; i < raw.length; i++) {
    n = parseInt(raw[i], 10);
    if (!(n >= 1 && n <= 65535)) continue;
    if (out.indexOf(n) === -1) out.push(n);
  }
  return out;
}

function cleanPorts(s, single) {
  var out = parsePortNums(s);
  if (!out.length) out = CF_ALL.slice();
  if (single) return [out[0]];
  return out;
}

async function enabledPorts(db) {
  var raw = await settingGet(db, 'cf_ports');
  var extra = await settingGet(db, 'extra_ports');
  var a = raw ? parsePortNums(raw) : CF_ALL.slice();
  var e = extra ? parsePortNums(extra) : [];
  var i, out = [];
  for (i = 0; i < a.length; i++) if (out.indexOf(a[i]) === -1) out.push(a[i]);
  for (i = 0; i < e.length; i++) if (out.indexOf(e[i]) === -1) out.push(e[i]);
  if (!out.length) out = CF_ALL.slice();
  return out;
}

async function disableBadPortPeers(db) {
  var ports = await enabledPorts(db);
  var peers = [];
  try { peers = await dbAll(db, 'SELECT id, port, enabled FROM vpn_peers'); } catch (e0) { return; }
  var i, n;
  for (i = 0; i < peers.length; i++) {
    if (!peers[i].enabled) continue;
    n = Number(peers[i].port) || 0;
    if (ports.indexOf(n) === -1) {
      try { await dbRun(db, 'UPDATE vpn_peers SET enabled = 0 WHERE id = ?', peers[i].id); } catch (e1) {}
    }
  }
}

async function migrateDefaultPorts(db) {
  var flag = '';
  try { flag = await settingGet(db, 'ports_v2'); } catch (e0) {}
  if (flag === '1') return;
  var raw = '';
  try { raw = await settingGet(db, 'cf_ports'); } catch (e1) {}
  if (raw) {
    var old = parsePortNums(raw);
    var core = [];
    var i;
    for (i = 0; i < old.length; i++) if (CF_CORE.indexOf(old[i]) !== -1) core.push(old[i]);
    if (!core.length) core = CF_ALL.slice();
    await settingSet(db, 'cf_ports', core.join(','));
    await settingSet(db, 'extra_ports', '');
  }
  await settingSet(db, 'ports_v2', '1');
  try { await disableBadPortPeers(db); } catch (e2) {}
}

function extraQuery(pr) {
  return '';
}

function displayName(pr) {
  var custom = String((pr && (pr.remark || pr.brand)) || '').trim();
  if (custom) return custom.slice(0, 48);
  var loc = String((pr && pr.location) || '');
  if (!loc || loc === 'random') loc = '';
  var n = (pr && pr.name) || 'Ham';
  return loc ? (loc + ' ' + n) : n;
}

function cfgRemark(port, brand, proto, pr) {
  return displayName(pr || { name: brand });
}

async function addDaily(db, n, kind, id) {
  if (!n) return;
  var day = new Date().toISOString().slice(0, 10);
  try {
    await dbRun(db, 'INSERT INTO vpn_daily (day, bytes) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes', day, n);
  } catch (e) {}
  if (kind && id) {
    try {
      await dbRun(db, 'INSERT INTO vpn_usage (day, kind, owner_id, bytes) VALUES (?, ?, ?, ?) ON CONFLICT(day, kind, owner_id) DO UPDATE SET bytes = bytes + excluded.bytes', day, kind, id, n);
    } catch (e2) {}
  }
}

async function checkMaxIp(db, kind, id, ip, maxIp) {
  maxIp = Number(maxIp) || 0;
  if (maxIp <= 0 || !ip) return true;
  try {
    var cut = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    await dbRun(db, 'DELETE FROM vpn_ips WHERE last_seen < ?', cut);
    var mine = await dbFirst(db, 'SELECT ip FROM vpn_ips WHERE kind = ? AND owner_id = ? AND ip = ?', kind, id, ip);
    if (!mine) {
      var cnt = await dbFirst(db, 'SELECT COUNT(*) AS c FROM vpn_ips WHERE kind = ? AND owner_id = ?', kind, id);
      if (cnt && Number(cnt.c) >= maxIp) return false;
    }
    await dbRun(
      db,
      'INSERT INTO vpn_ips (kind, owner_id, ip, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT(kind, owner_id, ip) DO UPDATE SET last_seen = excluded.last_seen',
      kind, id, ip, nowIso()
    );
    return true;
  } catch (e) {
    return true;
  }
}

async function notifyLogin(env, request, user) {
  var ipn = clientIp(request);
  var when = fmtTehran();
  var name = (user && user.username) ? user.username : '';
  var msg = 'ورود به پنل Ham\nکاربر: ' + name + '\nIP: ' + ipn + '\nزمان: ' + when;
  try { await tgSend(env, null, msg); } catch (e) {}
  return { ip: ipn, at: when };
}

async function tgSend(env, ctx, text) {
  try {
    var token = String(await settingGet(env.DB, 'tg_token') || '').trim();
    var rawChat = String(await settingGet(env.DB, 'tg_chat') || '').trim();
    if (!token || !rawChat) return false;
    var chats = rawChat.split(/[\s,]+/).filter(Boolean);
    var i, ok = false, res, body;
    for (i = 0; i < chats.length; i++) {
      var ctrl = new AbortController();
      var tid = setTimeout(function () { try { ctrl.abort(); } catch (eA) {} }, 3500);
      try {
        res = await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ chat_id: chats[i], text: String(text || '').slice(0, 3500) }),
          signal: ctrl.signal
        });
        body = await res.text();
        if (res.ok && body.indexOf('"ok":true') !== -1) ok = true;
      } catch (eT) {}
      try { clearTimeout(tid); } catch (eC) {}
    }
    return ok;
  } catch (e) {
    return false;
  }
}

function faDigitsToEn(s) {
  s = String(s || '');
  var fa = '۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩';
  var en = '01234567890123456789';
  var i, p, out = '';
  for (i = 0; i < s.length; i++) {
    p = fa.indexOf(s.charAt(i));
    out += p >= 0 ? en.charAt(p) : s.charAt(i);
  }
  return out.replace(/\s+/g, '');
}

async function maybeAlert(env, ctx, row, kind) {
  if (!row) return;
  var reason = '';
  if (row.expire_at && Date.parse(row.expire_at) < Date.now()) reason = 'expired';
  var q = Number(row.quota_bytes) || 0;
  var u = Number(row.used_bytes) || 0;
  if (!reason && q > 0 && u >= q) reason = 'quota';
  if (!reason && q > 0 && u >= q * 0.8) reason = 'quota80';
  if (!reason && row.expire_at) {
    var left = Date.parse(row.expire_at) - Date.now();
    if (left > 0 && left <= 3 * 86400000) reason = 'expire3';
  }
  if (!reason) return;
  var tag = new Date().toISOString().slice(0, 10) + ':' + reason;
  if (row.alert_sent === tag) return;
  var name = row.name || row.brand || kind;
  var msg = 'Ham · ' + name + ' · ' + (
    reason === 'quota' ? ('حجم تمام ' + fmtBytes(u) + ' / ' + fmtBytes(q)) :
    reason === 'quota80' ? ('۸۰٪ حجم ' + fmtBytes(u) + ' / ' + fmtBytes(q)) :
    reason === 'expire3' ? ('کمتر از ۳ روز مانده') :
    'منقضی شد'
  );
  await tgSend(env, ctx, msg);
  try {
    if (kind === 'sub') await dbRun(env.DB, 'UPDATE vpn_subs SET alert_sent = ? WHERE id = ?', tag, row.id);
    else await dbRun(env.DB, 'UPDATE vpn_peers SET alert_sent = ? WHERE id = ?', tag, row.id);
  } catch (e) {}
}

function subAsPeer(su) {
  return {
    id: su.id,
    name: su.name,
    uuid: su.uuid,
    trojan_pass: su.trojan_pass || su.uuid,
    protocols: su.protocols,
    quota_bytes: su.quota_bytes,
    used_bytes: su.used_bytes,
    expire_at: su.expire_at,
    max_ip: su.max_ip,
    location: su.location,
    enabled: su.enabled == null ? 1 : su.enabled,
    fragment: su.fragment,
    mux: su.mux,
    speed_kbps: su.speed_kbps,
    extra_host: su.extra_host,
    _kind: 'sub'
  };
}


var SHA_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

function sha224Hex(bytes) {
  var h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
  var h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  var len = bytes.length;
  var bit = len * 8;
  var pad = len + 1;
  while (pad % 64 !== 56) pad++;
  var buf = new Uint8Array(pad + 8);
  buf.set(bytes);
  buf[len] = 0x80;
  buf[buf.length - 4] = (bit >>> 24) & 0xff;
  buf[buf.length - 3] = (bit >>> 16) & 0xff;
  buf[buf.length - 2] = (bit >>> 8) & 0xff;
  buf[buf.length - 1] = bit & 0xff;
  var i, j;
  for (i = 0; i < buf.length; i += 64) {
    var w = new Array(64);
    for (j = 0; j < 16; j++) {
      var o = i + j * 4;
      w[j] = ((buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0;
    }
    for (j = 16; j < 64; j++) {
      var v0 = w[j - 15];
      var s0 = ((v0 >>> 7) | (v0 << 25)) ^ ((v0 >>> 18) | (v0 << 14)) ^ (v0 >>> 3);
      var v1 = w[j - 2];
      var s1 = ((v1 >>> 17) | (v1 << 15)) ^ ((v1 >>> 19) | (v1 << 13)) ^ (v1 >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (j = 0; j < 64; j++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var temp1 = (hh + S1 + ch + SHA_K[j] + w[j]) >>> 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  function w32(x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }
  return w32(h0) + w32(h1) + w32(h2) + w32(h3) + w32(h4) + w32(h5) + w32(h6);
}

function trojanHash(pass) {
  return sha224Hex(new TextEncoder().encode(String(pass || '')));
}

async function canonicalHost(db, fallback) {
  var h = '';
  try { h = String((await settingGet(db, 'panel_host')) || '').trim(); } catch (e0) { h = ''; }
  h = h.replace(/^https?:\/\//, '').split('/')[0].trim();
  fallback = String(fallback || '').trim();
  if (!h) h = fallback;
  return h;
}

async function rememberPanelHost(db, request) {
  try {
    var cur = String((await settingGet(db, 'panel_host')) || '').trim();
    if (cur) return;
    var h = '';
    try { h = new URL(request.url).hostname; } catch (e1) { h = ''; }
    if (!h) return;
    var backs = [];
    try { backs = parseHostLines(await settingGet(db, 'backup_hosts')); } catch (eB) {}
    if (backs.indexOf(h) !== -1) return;
    await settingSet(db, 'panel_host', h);
  } catch (e2) {}
}

async function proxySettings(db, host) {
  var path = normPath((await settingGet(db, 'vpn_path')) || '/vpnws');
  var ips = [];
  try { ips = await enabledIps(db); } catch (e) { ips = []; }
  var backups = [];
  try { backups = parseHostLines(await settingGet(db, 'backup_hosts')); } catch (eB) { backups = []; }
  var main = await canonicalHost(db, host);
  return { host: main, path: path, sni: main, wsHost: main, fp: 'chrome', ips: ips, backups: backups };
}

function parseIpLines(s) {
  var parts = String(s || '').split(/[\n,]+/);
  var out = [];
  var i, x;
  for (i = 0; i < parts.length; i++) {
    x = parts[i].trim();
    if (!x || x.charAt(0) === '#') continue;
    if (x.length > 64) continue;
    if (!/^[0-9A-Za-z.:_-]+$/.test(x)) continue;
    if (out.indexOf(x) === -1) out.push(x);
  }
  return out;
}

function parseHostLines(s) {
  var parts = String(s || '').split(/[\n,\s]+/);
  var out = [];
  var i, x;
  for (i = 0; i < parts.length; i++) {
    x = String(parts[i] || '').trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!x || x.charAt(0) === '#') continue;
    if (x.length > 253) continue;
    if (!/^[A-Za-z0-9.:_-]+$/.test(x)) continue;
    if (isIpAddr(x)) continue;
    if (out.indexOf(x) === -1) out.push(x);
  }
  return out;
}

async function enabledIps(db) {
  var all = parseIpLines(await settingGet(db, 'proxy_ips'));
  var on = parseIpLines(await settingGet(db, 'proxy_ips_on'));
  if (!all.length || !on.length) return [];
  var out = [];
  var i;
  for (i = 0; i < all.length; i++) if (on.indexOf(all[i]) !== -1) out.push(all[i]);
  return out;
}

function wrapAddr(addr) {
  addr = String(addr || '');
  if (addr.indexOf(':') !== -1 && addr.indexOf('.') === -1 && addr.charAt(0) !== '[') return '[' + addr + ']';
  return addr;
}

function isIpAddr(s) {
  s = String(s || '').replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return true;
  if (s.indexOf(':') !== -1 && s.indexOf('.') === -1) return true;
  return false;
}

function isBadProxyIp(s) {
  s = String(s || '').trim();
  if (s === '1.1.1.1' || s === '1.0.0.1' || s === '8.8.8.8' || s === '8.8.4.4') return true;
  if (s.indexOf('1.1.1.') === 0 || s.indexOf('1.0.0.') === 0) return true;
  return false;
}

function tlsName(o) {
  var c = [o && o.sni, o && o.wsHost, o && o.host];
  var i;
  for (i = 0; i < c.length; i++) {
    if (c[i] && !isIpAddr(c[i])) return c[i];
  }
  return (o && o.host) || '';
}

function addrList(row, o) {
  var out = [];
  function add(h) {
    h = String(h || '').trim();
    if (!h || isIpAddr(h)) return;
    if (out.indexOf(h) === -1) out.push(h);
  }
  add(o && o.host);
  var b = (o && o.backups) || [];
  var i;
  for (i = 0; i < b.length && out.length < 6; i++) add(b[i]);
  return out.length ? out : [o.host];
}

function vlessLink(uuid, o, name, port, extra, addr) {
  port = Number(port) || 443;
  var tls = isTlsPort(port);
  var domain = tlsName(o);
  var server = wrapAddr(addr || domain);
  var q = 'encryption=none&security=' + (tls ? 'tls' : 'none');
  if (tls) q += '&sni=' + encodeURIComponent(domain) + '&fp=' + encodeURIComponent(o.fp || 'chrome') + '&alpn=' + encodeURIComponent('http/1.1');
  q += '&type=ws&host=' + encodeURIComponent(domain) + '&path=' + encodeURIComponent(o.path || '/vpnws');
  if (extra) q += extra;
  return 'vless://' + uuid + '@' + server + ':' + port + '?' + q + '#' + encodeURIComponent(name || 'Ham');
}

function trojanLink(pass, o, name, port, extra, addr) {
  port = Number(port) || 443;
  var tls = isTlsPort(port);
  var domain = tlsName(o);
  var server = wrapAddr(addr || domain);
  var q = 'security=' + (tls ? 'tls' : 'none');
  if (tls) q += '&sni=' + encodeURIComponent(domain) + '&fp=' + encodeURIComponent(o.fp || 'chrome') + '&alpn=' + encodeURIComponent('http/1.1');
  q += '&type=ws&host=' + encodeURIComponent(domain) + '&path=' + encodeURIComponent((o.path || '/vpnws'));
  if (extra) q += extra;
  return 'trojan://' + encodeURIComponent(pass) + '@' + server + ':' + port + '?' + q + '#' + encodeURIComponent(name || 'Ham');
}

function peerLinks(pr, o) {
  if (pr && pr.extra_host && !isIpAddr(pr.extra_host)) {
    o = { host: pr.extra_host, path: o.path, sni: pr.extra_host, wsHost: pr.extra_host, fp: o.fp || 'chrome', ips: o.ips };
  }
  var brand = pr.brand || pr.name || 'Ham';
  var port = Number(pr.port) || 443;
  var extra = extraQuery(pr);
  var protos = cleanProtos(pr.protocols);
  var pass = pr.trojan_pass || pr.uuid;
  var addrs = addrList(pr, o);
  var out = { items: [] };
  var i, a, proto, remark, link;
  for (a = 0; a < addrs.length; a++) {
    for (i = 0; i < protos.length; i++) {
      proto = protos[i];
      remark = displayName(pr);
      if (addrs.length > 1) remark = remark + ' · ' + addrs[a];
      if (proto === 'vless') {
        link = vlessLink(pr.uuid, o, remark, port, extra, addrs[a]);
        if (!out.vless) out.vless = link;
        out.items.push({ proto: proto, addr: addrs[a], link: link, remark: remark });
      }
      if (proto === 'trojan') {
        link = trojanLink(pass, o, remark, port, extra, addrs[a]);
        if (!out.trojan) out.trojan = link;
        out.items.push({ proto: proto, addr: addrs[a], link: link, remark: remark });
      }
    }
  }
  return out;
}

function subLinkList(su, o) {
  if (su && su.extra_host && !isIpAddr(su.extra_host)) {
    o = { host: su.extra_host, path: o.path, sni: su.extra_host, wsHost: su.extra_host, fp: o.fp || 'chrome', ips: o.ips };
  }
  var brand = su.brand || su.name || 'Ham';
  var ports = cleanPorts(su.ports || '443', false);
  var protos = cleanProtos(su.protocols);
  var extra = extraQuery(su);
  var pass = su.trojan_pass || su.uuid;
  var addrs = addrList(su, o);
  var lines = [];
  var clash = [];
  var i, j, a, port, proto, remark, link;
  for (a = 0; a < addrs.length; a++) {
    for (i = 0; i < ports.length; i++) {
      port = ports[i];
      for (j = 0; j < protos.length; j++) {
        proto = protos[j];
        remark = cfgRemark(port, brand, proto);
        if (addrs.length > 1) remark = addrs[a] + ' ' + remark;
        if (su.location) remark = su.location + ' ' + remark;
        if (proto === 'vless') {
          link = vlessLink(su.uuid, o, remark, port, extra, addrs[a]);
          lines.push(link);
          clash.push({ name: remark, type: 'vless', uuid: su.uuid, port: port, tls: isTlsPort(port), server: addrs[a] });
        } else if (proto === 'trojan') {
          link = trojanLink(pass, o, remark, port, extra, addrs[a]);
          lines.push(link);
          clash.push({ name: remark, type: 'trojan', password: pass, port: port, tls: isTlsPort(port), server: addrs[a] });
        }
      }
    }
  }
  return { lines: lines, clash: clash, count: lines.length };
}

function parseSocksAddr(buf, i) {
  if (i >= buf.length) return null;
  var atyp = buf[i++];
  var host = '';
  var n, k, parts;
  if (atyp === 1) {
    if (i + 4 > buf.length) return null;
    host = buf[i] + '.' + buf[i + 1] + '.' + buf[i + 2] + '.' + buf[i + 3];
    i += 4;
  } else if (atyp === 3) {
    n = buf[i++];
    if (i + n > buf.length) return null;
    host = new TextDecoder().decode(buf.slice(i, i + n));
    i += n;
  } else if (atyp === 4) {
    if (i + 16 > buf.length) return null;
    parts = [];
    for (k = 0; k < 8; k++) {
      parts.push(((buf[i] << 8) | buf[i + 1]).toString(16));
      i += 2;
    }
    host = parts.join(':');
  } else return null;
  if (i + 2 > buf.length) return null;
  var port = (buf[i] << 8) | buf[i + 1];
  i += 2;
  return { host: host, port: port, i: i };
}

function parseTrojan(buf, hashHex) {
  if (buf.length < 62) return null;
  var head = new TextDecoder().decode(buf.slice(0, 56)).toLowerCase();
  if (head !== hashHex) return null;
  if (buf[56] !== 13 || buf[57] !== 10) return null;
  var i = 58;
  var cmd = buf[i++];
  var addr = parseSocksAddr(buf, i);
  if (!addr) return null;
  i = addr.i;
  if (i + 2 <= buf.length && buf[i] === 13 && buf[i + 1] === 10) i += 2;
  return { cmd: cmd, host: addr.host, port: addr.port, payload: buf.slice(i), ver: 0 };
}


function normPath(p) {
  p = String(p || '/vpnws').trim() || '/vpnws';
  if (p.charAt(0) !== '/') p = '/' + p;
  if (p.length > 1 && p.slice(-1) === '/') p = p.slice(0, -1);
  return p.slice(0, 64);
}

function bytesToUuid(b, o) {
  var hex = [];
  var i;
  for (i = 0; i < 16; i++) hex.push((b[o + i] & 0xff).toString(16).padStart(2, '0'));
  return hex.slice(0, 4).join('') + '-' + hex.slice(4, 6).join('') + '-' + hex.slice(6, 8).join('') + '-' + hex.slice(8, 10).join('') + '-' + hex.slice(10).join('');
}

function toU8(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof Blob !== 'undefined' && data instanceof Blob) return null;
  return new Uint8Array(data);
}

function b64urlToU8(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  var pad = s.length % 4;
  if (pad) s += '===='.slice(0, 4 - pad);
  var bin = atob(s);
  var u = new Uint8Array(bin.length);
  var i;
  for (i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

function parseVless(buf) {
  if (buf.length < 24) return null;
  var i = 0;
  var ver = buf[i++];
  i += 16;
  var addon = buf[i++];
  i += addon;
  if (i + 4 > buf.length) return null;
  var cmd = buf[i++];
  var port = (buf[i++] << 8) | buf[i++];
  var atyp = buf[i++];
  var host = '';
  var n, k, parts;
  if (atyp === 1) {
    if (i + 4 > buf.length) return null;
    host = buf[i] + '.' + buf[i + 1] + '.' + buf[i + 2] + '.' + buf[i + 3];
    i += 4;
  } else if (atyp === 2) {
    n = buf[i++];
    if (i + n > buf.length) return null;
    host = new TextDecoder().decode(buf.slice(i, i + n));
    i += n;
  } else if (atyp === 3) {
    if (i + 16 > buf.length) return null;
    parts = [];
    for (k = 0; k < 8; k++) {
      parts.push(((buf[i] << 8) | buf[i + 1]).toString(16));
      i += 2;
    }
    host = parts.join(':');
  } else return null;
  return { ver: ver, cmd: cmd, port: port, host: host, payload: buf.slice(i) };
}

function dataToU8(data) {
  if (!data) return Promise.resolve(null);
  if (typeof data === 'string') return Promise.resolve(null);
  if (data instanceof Uint8Array) return Promise.resolve(data);
  if (data instanceof ArrayBuffer) return Promise.resolve(new Uint8Array(data));
  if (ArrayBuffer.isView(data)) return Promise.resolve(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    return data.arrayBuffer().then(function (b) { return new Uint8Array(b); });
  }
  try { return Promise.resolve(new Uint8Array(data)); } catch (e) { return Promise.resolve(null); }
}

function makeWsQueue(ws) {
  var q = [];
  var pend = null;
  var closed = false;
  function die() {
    closed = true;
    if (pend) { var fn = pend; pend = null; fn(null); }
    try { ws.close(); } catch (eC) {}
  }
  ws.addEventListener('message', function (ev) {
    if (closed) return;
    if (pend) { var fn = pend; pend = null; fn(ev.data); }
    else q.push(ev.data);
  });
  ws.addEventListener('close', die);
  ws.addEventListener('error', die);
  return {
    next: function (ms) {
      if (q.length) return Promise.resolve(q.shift());
      if (closed) return Promise.resolve(null);
      return new Promise(function (res) {
        pend = res;
        if (ms > 0) {
          setTimeout(function () {
            if (pend !== res) return;
            pend = null;
            res(null);
          }, ms);
        }
      });
    }
  };
}

function wsSend(ws, data) {
  if (data == null) return;
  try { ws.send(data); } catch (e) {}
}

function parseEarly(proto) {
  if (!proto) return null;
  var p = String(proto).split(',')[0].trim();
  if (!p) return null;
  try {
    var u = b64urlToU8(p);
    if (u && u.length >= 18) return u;
  } catch (e) {}
  return null;
}

function isIPv4(h) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h);
}

async function resolveA(host) {
  if (isIPv4(host)) return host;
  if (host.indexOf(':') !== -1) return host;
  try {
    var res = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(host) + '&type=A', {
      headers: { accept: 'application/dns-json' }
    });
    var j = await res.json();
    var i, a;
    if (j && j.Answer) {
      for (i = 0; i < j.Answer.length; i++) {
        a = j.Answer[i];
        if (a && Number(a.type) === 1 && isIPv4(String(a.data || ''))) return String(a.data);
      }
    }
  } catch (e) {}
  return host;
}

async function proxyTcp(ws, info, meter, pump) {
  var host = String(info.host || '').replace(/^\[|\]$/g, '').replace(/\s+/g, '');
  var port = Number(info.port) || 0;
  if (!host || !port || host.length > 255) { try { ws.close(); } catch (e0) {} return; }
  var proxies = (meter && meter.proxies) ? meter.proxies : [];
  var addrs = [];
  function addAddr(h) {
    h = String(h || '').trim();
    if (!h) return;
    if (addrs.indexOf(h) === -1) addrs.push(h);
  }
  addAddr(host);
  var addrsTry = [host, host];
  var ti;
  for (ti = 0; ti < proxies.length; ti++) {
    if (String(proxies[ti] || '') !== host) addrsTry.push(proxies[ti]);
  }
  var buf = [];
  if (info.payload && info.payload.length) buf.push(info.payload);
  var liveWriter = null;
  var closed = false;
  var up = (async function () {
    while (!closed) {
      var d = await pump.next();
      if (d == null) break;
      var u = await dataToU8(d);
      if (!u || !u.length) continue;
      if (meter) meter.n += u.length;
      if (liveWriter) {
        try { await liveWriter.write(u); } catch (eU) { break; }
      } else buf.push(u);
    }
  })();
  var ai, sock, writer, got, downDone, down, t0, flushed, bi;
  addrs = addrsTry;
  for (ai = 0; ai < addrs.length; ai++) {
    if (closed) break;
    sock = null;
    writer = null;
    got = false;
    downDone = false;
    flushed = buf.length;
    try {
      sock = connect({ hostname: addrs[ai], port: port });
      writer = sock.writable.getWriter();
      for (bi = 0; bi < flushed; bi++) await writer.write(buf[bi]);
    } catch (e1) {
      try { if (writer) writer.releaseLock(); } catch (e1a) {}
      try { if (sock) sock.close(); } catch (e1b) {}
      continue;
    }
    down = sock.readable.pipeTo(new WritableStream({
      write: function (chunk) {
        if (closed) return;
        got = true;
        var n = chunk.byteLength || chunk.length || 0;
        if (meter) meter.n += n;
        wsSend(ws, chunk);
      },
      close: function () { downDone = true; },
      abort: function () { downDone = true; }
    })).catch(function () { downDone = true; });
    t0 = Date.now();
    while (!got && !downDone && !closed && Date.now() - t0 < (addrs[ai] === host ? 9000 : 4000)) {
      await new Promise(function (r) { setTimeout(r, 40); });
    }
    if (got) {
      try {
        for (bi = flushed; bi < buf.length; bi++) await writer.write(buf[bi]);
      } catch (eF) {}
      buf = [];
      liveWriter = writer;
      await Promise.all([down, up]);
      closed = true;
      try { writer.close(); } catch (e2) {}
      try { sock.close(); } catch (e3) {}
      try { ws.close(); } catch (e4) {}
      return;
    }
    try { writer.abort(); } catch (e5) {}
    try { sock.close(); } catch (e6) {}
  }
  closed = true;
  try { ws.close(); } catch (e7) {}
}

async function proxyDns(ws, info, pump) {
  var rest = new Uint8Array(0);
  function concat(a, b) {
    var o = new Uint8Array(a.length + b.length);
    o.set(a, 0);
    o.set(b, a.length);
    return o;
  }
  async function one(q) {
    if (!q || q.length < 12) return;
    var urls = ['https://cloudflare-dns.com/dns-query', 'https://1.1.1.1/dns-query'];
    var i, res, ans, out;
    for (i = 0; i < urls.length; i++) {
      try {
        res = await fetch(urls[i], {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message', 'accept': 'application/dns-message' },
          body: q
        });
        if (!res.ok) continue;
        ans = new Uint8Array(await res.arrayBuffer());
        if (!ans.length) continue;
        out = new Uint8Array(2 + ans.length);
        out[0] = (ans.length >> 8) & 0xff;
        out[1] = ans.length & 0xff;
        out.set(ans, 2);
        wsSend(ws, out);
        return;
      } catch (e) {}
    }
  }
  async function handleBuf(u8) {
    if (!u8 || !u8.length) return;
    rest = concat(rest, u8);
    var n;
    if (rest.length >= 2) {
      n = (rest[0] << 8) | rest[1];
      if (n < 12 || n > 5120) {
        if (rest.length >= 12) { var raw = rest; rest = new Uint8Array(0); await one(raw); }
        return;
      }
    }
    while (rest.length >= 2) {
      n = (rest[0] << 8) | rest[1];
      if (n < 12 || n > 5120) break;
      if (rest.length < 2 + n) break;
      await one(rest.slice(2, 2 + n));
      rest = rest.slice(2 + n);
    }
  }
  if (info.payload && info.payload.length) await handleBuf(info.payload);
  while (true) {
    var d = await pump.next();
    if (d == null) break;
    await handleBuf(await dataToU8(d));
  }
}

async function lookupPeer(env, buf) {
  if (!env || !env.DB) return null;
  await ensureVpn(env.DB);
  var uid = bytesToUuid(buf, 1).toLowerCase();
  var peer = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE uuid = ? COLLATE NOCASE', uid);
  if (!peer) {
    try { peer = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE uuid = ?', uid.toUpperCase()); } catch (e0) {}
  }
  var info;
  if (peer && peerAlive(peer)) {
    info = parseVless(buf);
    if (info && info.host) {
      peer._kind = 'peer';
      return { peer: peer, info: info, kind: 'vless' };
    }
  }
  var su = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE uuid = ? COLLATE NOCASE', uid);
  if (su) {
    var sp = subAsPeer(su);
    if (peerAlive(sp)) {
      info = parseVless(buf);
      if (info && info.host) return { peer: sp, info: info, kind: 'vless' };
    }
  }
  var rows = [];
  try { rows = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE enabled = 1 ORDER BY id DESC LIMIT 30'); } catch (e1) {}
  var i, tr, hs;
  for (i = 0; i < rows.length; i++) {
    if (!peerAlive(rows[i])) continue;
    hs = trojanHash(rows[i].trojan_pass || rows[i].uuid);
    tr = parseTrojan(buf, hs);
    if (tr && tr.host) {
      rows[i]._kind = 'peer';
      return { peer: rows[i], info: tr, kind: 'trojan' };
    }
  }
  var subs = [];
  try { subs = await dbAll(env.DB, 'SELECT * FROM vpn_subs WHERE enabled = 1 ORDER BY id DESC LIMIT 30'); } catch (e2) {}
  for (i = 0; i < subs.length; i++) {
    var s2 = subAsPeer(subs[i]);
    if (!peerAlive(s2)) continue;
    hs = trojanHash(s2.trojan_pass || s2.uuid);
    tr = parseTrojan(buf, hs);
    if (tr && tr.host) return { peer: s2, info: tr, kind: 'trojan' };
  }
  return null;
}

async function runTunnel(ws, env, ctx, ip, pump, early) {
  var meter = { n: 0, id: 0, kind: 'peer' };
  try {
    await Promise.resolve();
    var raw = early;
    if (!raw) raw = await pump.next(12000);
    var buf = await dataToU8(raw);
    if (!buf || buf.length < 18) { try { ws.close(); } catch (e0) {} return; }
    var found = await lookupPeer(env, buf);
    if (!found || !found.peer || !found.info || !found.info.host) { try { ws.close(); } catch (e1) {} return; }
    var peer = found.peer;
    var info = found.info;
    var kind = found.kind;
    if (!(await checkMaxIp(env.DB, peer._kind === 'sub' ? 'sub' : 'peer', peer.id, ip, peer.max_ip))) {
      try { ws.close(); } catch (e2) {}
      return;
    }
    try { await dbRun(env.DB, 'UPDATE vpn_peers SET last_seen = ? WHERE id = ?', nowIso(), peer.id); } catch (eLs) {}
    meter.id = peer.id;
    meter.kind = peer._kind === 'sub' ? 'sub' : 'peer';
    meter.speed = Number(peer.speed_kbps) || 0;
    meter.proxies = parseIpLines(peer.ips);
    if (kind === 'vless') wsSend(ws, new Uint8Array([info.ver || 0, 0]));
    var cmd = info.cmd;
    if (cmd === 1 || cmd === 0x01) await proxyTcp(ws, info, meter, pump);
    else if (cmd === 2 || cmd === 0x03) {
      if (Number(info.port) === 53) await proxyDns(ws, info, pump);
      else while (await pump.next()) {}
    } else {
      try { ws.close(); } catch (e3) {}
    }
  } catch (e) {
    try { ws.close(); } catch (e4) {}
  } finally {
    if (meter.id && meter.n && env && env.DB) {
      try {
        if (meter.kind === 'sub') await dbRun(env.DB, 'UPDATE vpn_subs SET used_bytes = used_bytes + ? WHERE id = ?', meter.n, meter.id);
        else await dbRun(env.DB, 'UPDATE vpn_peers SET used_bytes = used_bytes + ? WHERE id = ?', meter.n, meter.id);
        try {
          if (meter.kind !== 'sub') {
            var abuseGb = parseInt(await settingGet(env.DB, 'abuse_gb'), 10);
            if (isNaN(abuseGb)) abuseGb = 80;
            if (abuseGb > 0) {
              var day = new Date().toISOString().slice(0, 10);
              var du = await dbFirst(env.DB, 'SELECT bytes FROM vpn_usage WHERE day = ? AND kind = ? AND owner_id = ?', day, 'peer', meter.id);
              var dayN = (du ? Number(du.bytes) : 0) + meter.n;
              if (dayN >= abuseGb * 1024 * 1024 * 1024) {
                await dbRun(env.DB, 'UPDATE vpn_peers SET enabled = 0 WHERE id = ?', meter.id);
                try { await tgSend(env, ctx, 'کانفیگ پرمصرف خاموش شد (#' + meter.id + ') ' + fmtBytes(dayN) + ' امروز'); } catch (eAb) {}
              }
            }
          }
        } catch (eAbuse) {}
        await addDaily(env.DB, meter.n, meter.kind, meter.id);
        var row = meter.kind === 'sub'
          ? await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE id = ?', meter.id)
          : await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', meter.id);
        await maybeAlert(env, ctx, row, meter.kind);
      } catch (e5) {}
    }
  }
}

async function handleVpnUpgrade(request, env, ctx, url) {
  var path = VPN_PATH_MEM || '/vpnws';
  var pn = url.pathname;
  if (pn !== path && pn !== path + '/' && pn !== '/vpnws' && pn !== '/vpnws/') {
    if (hasDB(env)) {
      try {
        path = normPath((await settingGet(env.DB, 'vpn_path')) || '/vpnws');
        VPN_PATH_MEM = path;
      } catch (e) {}
    }
    if (pn !== path && pn !== path + '/' && pn !== '/vpnws' && pn !== '/vpnws/') {
      return new Response('Not found', { status: 404 });
    }
  }
  var pair = new WebSocketPair();
  var client = pair[0];
  var server = pair[1];
  server.accept();
  try { server.binaryType = 'arraybuffer'; } catch (e4) {}
  function shutWs() { try { server.close(); } catch (eS) {} }
  server.addEventListener('close', shutWs);
  server.addEventListener('error', shutWs);
  var pump = makeWsQueue(server);
  var proto = request.headers.get('Sec-WebSocket-Protocol') || '';
  var early = parseEarly(proto);
  var headers = { Upgrade: 'websocket' };
  if (proto) headers['Sec-WebSocket-Protocol'] = proto.split(',')[0].trim();
  var task = runTunnel(server, env, ctx, clientIp(request), pump, early).then(function () {
    shutWs();
  }).catch(function () {
    shutWs();
  });
  try { if (ctx && ctx.waitUntil) ctx.waitUntil(task); } catch (eW) {}
  return new Response(null, { status: 101, webSocket: client, headers: headers });
}


async function handleApi(request, env, url) {

  var method = request.method;
  var path = url.pathname.replace(/\/+$/, '') || '/';
  var ip = clientIp(request);

  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': new URL(request.url).origin,
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
        'access-control-allow-headers': 'content-type, x-csrf-token',
        'access-control-allow-credentials': 'true',
        'access-control-max-age': '86400'
      }
    });
  }
  if (method !== 'GET' && method !== 'HEAD' && !originOk(request)) return deny('Bad origin', 403);

  if (path === '/api/status' && method === 'GET') {
    var out = { ok: true, db: hasDB(env), setup: false, authed: false, user: null, panel: 'Ham', author: 'dev-penhan' };
    if (!out.db) return json(out);
    out.setup = await isSetup(env.DB);
    var me = await authUser(env, request);
    if (me) {
      out.authed = true;
      out.user = publicUser(me);
    }
    if (out.setup) {
      var pn = await settingGet(env.DB, 'panel_name');
      if (pn) out.panel = pn;
    }
    if (out.authed) {
      out.csrf = me.csrf || '';
      out.need_recovery = !(await settingGet(env.DB, 'recovery_hash'));
      var em0 = String((me.email || '') || (await settingGet(env.DB, 'admin_email')) || '').trim();
      out.need_email = !em0;
      out.has_email = !!em0;
      try { await rememberPanelHost(env.DB, request); } catch (ePh) {}
    }
    return json(out);
  }

  if (path === '/api/setup' && method === 'POST') {
    if (!hasDB(env)) return deny('D1 binding DB is missing', 428);
    if (await isSetup(env.DB)) return deny('Already set up', 409);
    var body = await readJson(request);
    if (!body) return deny('Invalid JSON', 400);
    var username = 'admin';
    var password = String(body.password || '');
    var email = String(body.email || '').trim();
    var lang = body.lang === 'en' ? 'en' : 'fa';
    var cfToken = String(body.cf_token || '').trim();
    var tgTokIn = String(body.tg_token || '').trim();
    var tgChatIn = String(body.tg_chat || '').trim();
    var recIn = normOtp(body.recovery);
    if (password.length < 8) return deny('Password must be at least 8 characters', 400);
    if (recIn.length !== 8) return deny('Recovery code must be 8 English letters or digits', 400);
    if (!tgTokIn || tgTokIn.indexOf(':') < 1) return deny('Telegram bot token is required', 400);
    if (!/^-?\d{5,18}$/.test(tgChatIn)) return deny('Telegram admin chat id is required', 400);
    if (email && !validEmail(email)) return deny('Invalid email', 400);
    try {
      await env.DB.exec(SCHEMA);
    } catch (e) {
      return deny('Cannot initialize D1: ' + (e.message || e), 500);
    }
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var hash = await hashPassword(password, salt);
    await dbRun(
      env.DB,
      'INSERT INTO users (username, password_hash, salt, role, email, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)',
      username,
      hash,
      b64(salt),
      'admin',
      email,
      nowIso()
    );
    var created = await dbFirst(env.DB, 'SELECT id FROM users WHERE username = ?', username);
    await settingSet(env.DB, 'panel_name', 'Ham');
    await settingSet(env.DB, 'lang', lang);
    if (cfToken) await settingSet(env.DB, 'cf_token', cfToken);
    await settingSet(env.DB, 'tg_token', tgTokIn);
    await settingSet(env.DB, 'tg_chat', tgChatIn);
    var recSalt = crypto.getRandomValues(new Uint8Array(16));
    var recHash = await hashPassword(recIn, recSalt);
    await settingSet(env.DB, 'recovery_salt', b64(recSalt));
    await settingSet(env.DB, 'recovery_hash', recHash);
    if (email) await settingSet(env.DB, 'admin_email', email);
    await settingSet(env.DB, 'vpn_path', '/vpnws');
    await dbRun(env.DB, 'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', 'setup_complete', '1');
    await dbRun(env.DB, 'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', 'setup_at', nowIso());
    var sid = await createSession(env.DB, created.id, request);
    await audit(env.DB, created.id, 'setup', 'initial wizard', ip);
    var setupUser = { username: username };
    var infs = await notifyLogin(env, request, setupUser);
    return json({ ok: true, login_ip: infs.ip, login_at: infs.at, csrf: sid.csrf }, 200, { 'Set-Cookie': sessionCookie(sid.token, request, false) });
  }

  if (!hasDB(env)) return deny('D1 binding DB is missing', 428);
  if (!(await isSetup(env.DB))) return deny('Setup required', 428);

  if (path === '/api/login' && method === 'POST') {
    var locked = false;
    var att = await dbFirst(env.DB, 'SELECT * FROM login_attempts WHERE ip = ?', ip);
    if (att) {
      var age = Date.now() - Date.parse(att.window_start);
      if (age > 15 * 60 * 1000) {
        await dbRun(env.DB, 'DELETE FROM login_attempts WHERE ip = ?', ip);
        att = null;
      } else if (att.count >= 8) locked = true;
    }
    if (locked) return deny('Too many attempts. Try again in 15 minutes.', 429);
    var lb = await readJson(request);
    if (!lb) return deny('Invalid JSON', 400);
    var lp = String(lb.password || '');
    var user = null;
    var cand = await dbAll(env.DB, 'SELECT * FROM users WHERE active = 1 ORDER BY id ASC');
    var ci, okHash;
    for (ci = 0; ci < cand.length; ci++) {
      okHash = await hashPassword(lp, fromB64(cand[ci].salt));
      if (timingSafeEqualStr(okHash, cand[ci].password_hash)) { user = cand[ci]; break; }
    }
    var bad = !user;
    if (bad) {
      if (!att) await dbRun(env.DB, 'INSERT INTO login_attempts (ip, count, window_start) VALUES (?, 1, ?)', ip, nowIso());
      else await dbRun(env.DB, 'UPDATE login_attempts SET count = count + 1 WHERE ip = ?', ip);
      await audit(env.DB, null, 'login_fail', '', ip);
      return deny('Invalid password', 401);
    }
    await dbRun(env.DB, 'DELETE FROM login_attempts WHERE ip = ?', ip);
    var loginCountry = (request.cf && request.cf.country) || '';
    var loginAsn = String((request.cf && request.cf.asn) || '');
    try {
      var prevMeta = JSON.parse((await settingGet(env.DB, 'login_meta')) || '{}') || {};
      if ((prevMeta.country && loginCountry && prevMeta.country !== loginCountry) || (prevMeta.asn && loginAsn && prevMeta.asn !== loginAsn)) {
        try { await tgSend(env, null, 'ورود غیرعادی Ham\nIP: ' + ip + '\nکشور: ' + loginCountry + '\nASN: ' + loginAsn); } catch (eAn) {}
        await new Promise(function (r) { setTimeout(r, 1600); });
      }
      await settingSet(env.DB, 'login_meta', JSON.stringify({ country: loginCountry, asn: loginAsn, at: nowIso() }));
    } catch (eMeta) {}
    var code = genOtp8();
    var ot = randomToken().slice(0, 24);
    var exp2 = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    try {
      await dbRun(env.DB, 'INSERT INTO otp (token, user_id, code, expires_at) VALUES (?, ?, ?, ?)', ot, user.id, code, exp2);
    } catch (eotp) {
      await env.DB.exec('CREATE TABLE IF NOT EXISTS otp (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, code TEXT NOT NULL, expires_at TEXT NOT NULL);');
      await dbRun(env.DB, 'INSERT INTO otp (token, user_id, code, expires_at) VALUES (?, ?, ?, ?)', ot, user.id, code, exp2);
    }
    await sendLoginCodes(env, user, code);
    var rememberOn = !!(lb && (lb.remember === true || lb.remember === 1 || lb.remember === '1'));
    return json({ ok: true, need_2fa: true, tmp: ot, remember: rememberOn });
  }

  if (path === '/api/login/2fa' && method === 'POST') {
    var ob = await readJson(request) || {};
    var otok = String(ob.tmp || '');
    var ocode = normOtp(ob.code || '');
    var recOk = false;
    try {
      var rh = await settingGet(env.DB, 'recovery_hash');
      var rs = await settingGet(env.DB, 'recovery_salt');
      if (rh && rs && ocode.length === 8) {
        var recH = await hashPassword(ocode, fromB64(rs));
        if (timingSafeEqualStr(recH, rh)) recOk = true;
      }
    } catch (eR) {}
    var orow = await dbFirst(env.DB, 'SELECT * FROM otp WHERE token = ?', otok);
    if (!recOk) {
      if (!orow || !timingSafeEqualStr(normOtp(orow.code), ocode) || ocode.length !== 8) return deny('Invalid code', 401);
    }
    if (!recOk) {
      if (Date.parse(orow.expires_at) < Date.now()) {
        await dbRun(env.DB, 'DELETE FROM otp WHERE token = ?', otok);
        return deny('Code expired', 401);
      }
    }
    if (!orow) return deny('Invalid code', 401);
    await dbRun(env.DB, 'DELETE FROM otp WHERE token = ?', otok);
    await dbRun(env.DB, 'UPDATE users SET last_login = ? WHERE id = ?', nowIso(), orow.user_id);
    var user2 = await dbFirst(env.DB, 'SELECT * FROM users WHERE id = ?', orow.user_id);
    var hours2 = (ob.remember === true || ob.remember === 1 || ob.remember === '1') ? (7 * 24) : 2;
    var ls2 = await createSession(env.DB, orow.user_id, request, hours2);
    await audit(env.DB, orow.user_id, 'login_2fa', '', ip);
    var inf2 = await notifyLogin(env, request, user2);
    return json({ ok: true, user: publicUser(user2), login_ip: inf2.ip, login_at: inf2.at, csrf: ls2.csrf }, 200, { 'Set-Cookie': sessionCookie(ls2.token, request, false, hours2 * 3600) });
  }

  if (path === '/api/logout' && method === 'POST') {
    var tok = getCookie(request, 'ham_sid');
    if (tok) {
      try {
        await ensureSessionCols(env.DB);
        var srow = await dbFirst(env.DB, 'SELECT csrf FROM sessions WHERE token = ?', tok);
        var ch = request.headers.get('x-csrf-token') || '';
        if (srow && srow.csrf && !timingSafeEqualStr(ch, srow.csrf)) return deny('CSRF', 403);
      } catch (eLo) {}
      await dbRun(env.DB, 'DELETE FROM sessions WHERE token = ?', tok);
    }
    return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', request, true) });
  }

  var me = await authUser(env, request);
  if (!me) return deny('Unauthorized', 401);
  if (method !== 'GET' && method !== 'HEAD') {
    var csrfHdr = request.headers.get('x-csrf-token') || '';
    if (!timingSafeEqualStr(csrfHdr, me.csrf || '')) return deny('CSRF', 403);
  }

  if (path === '/api/selfcheck' && method === 'GET') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    var ts = timingSafeEqualStr('ham', 'ham') && !timingSafeEqualStr('ham', 'hamx') && !timingSafeEqualStr('aa', 'bb');
    return json({ ok: ts, timing_safe: ts, csrf: !!(me.csrf), ip_source: 'CF-Connecting-IP', secrets: 'aes-gcm' });
  }

  if (path === '/api/recovery' && method === 'POST') {
    var rb = await readJson(request) || {};
    var rc = normOtp(rb.code);
    if (rc.length !== 8) return deny('Recovery code must be 8 chars', 400);
    var rSalt = crypto.getRandomValues(new Uint8Array(16));
    var rHash = await hashPassword(rc, rSalt);
    await settingSet(env.DB, 'recovery_salt', b64(rSalt));
    await settingSet(env.DB, 'recovery_hash', rHash);
    return json({ ok: true });
  }

  if (path === '/api/email' && method === 'POST') {
    var eb = await readJson(request) || {};
    var act = String(eb.action || 'start');
    var ch = {};
    try { ch = JSON.parse((await settingGet(env.DB, 'email_chg')) || '{}') || {}; } catch (eCh) { ch = {}; }
    if (act === 'start') {
      var oldE = String((me.email || '') || (await settingGet(env.DB, 'admin_email')) || '').trim();
      var newE = String(eb.email || '').trim();
      if (oldE) {
        var c1 = genOtp8();
        ch = { step: 'old', code: c1, uid: me.id, exp: Date.now() + 10 * 60 * 1000 };
        await settingSet(env.DB, 'email_chg', JSON.stringify(ch));
        await sendEmail(oldE, 'Ham email change', 'Ham code: ' + c1);
        try { await tgSend(env, null, '🔐 کد تغییر ایمیل: ' + c1); } catch (eT1) {}
        return json({ ok: true, step: 'old' });
      }
      if (!validEmail(newE)) return deny('Invalid email', 400);
      var c2 = genOtp8();
      ch = { step: 'new', code: c2, email: newE, uid: me.id, exp: Date.now() + 10 * 60 * 1000 };
      await settingSet(env.DB, 'email_chg', JSON.stringify(ch));
      await sendEmail(newE, 'Ham email confirm', 'Ham code: ' + c2);
      try { await tgSend(env, null, '🔐 کد تأیید ایمیل: ' + c2); } catch (eT2) {}
      return json({ ok: true, step: 'new' });
    }
    if (act === 'verify_old') {
      if (!ch.step || ch.step !== 'old' || Date.now() > ch.exp) return deny('Expired', 400);
      if (!timingSafeEqualStr(normOtp(eb.code), normOtp(ch.code))) return deny('Invalid code', 401);
      var newE2 = String(eb.email || '').trim();
      if (!validEmail(newE2)) return deny('Invalid email', 400);
      var c3 = genOtp8();
      ch = { step: 'new', code: c3, email: newE2, uid: me.id, exp: Date.now() + 10 * 60 * 1000 };
      await settingSet(env.DB, 'email_chg', JSON.stringify(ch));
      await sendEmail(newE2, 'Ham email confirm', 'Ham code: ' + c3);
      try { await tgSend(env, null, '🔐 کد تأیید ایمیل جدید: ' + c3); } catch (eT3) {}
      return json({ ok: true, step: 'new' });
    }
    if (act === 'verify_new') {
      if (!ch.step || ch.step !== 'new' || Date.now() > ch.exp) return deny('Expired', 400);
      if (!timingSafeEqualStr(normOtp(eb.code), normOtp(ch.code))) return deny('Invalid code', 401);
      await settingSet(env.DB, 'admin_email', ch.email);
      try { await dbRun(env.DB, 'UPDATE users SET email = ? WHERE id = ?', ch.email, me.id); } catch (eU) {}
      await settingSet(env.DB, 'email_chg', '');
      return json({ ok: true });
    }
    return deny('Bad action', 400);
  }

  if (path === '/api/ips/geo' && method === 'POST') {
    var gb = await readJson(request) || {};
    var list = gb.ips || [];
    var geo = {};
    var gi, gip, gr, gj;
    for (gi = 0; gi < list.length && gi < 40; gi++) {
      gip = String(list[gi] || '').trim();
      if (!gip) continue;
      try {
        gr = await fetch('http://ip-api.com/json/' + encodeURIComponent(gip) + '?fields=status,country,countryCode', { method: 'GET' });
        gj = await gr.json();
        if (gj && gj.status === 'success') geo[gip] = { cc: gj.countryCode || '', country: gj.country || '' };
        else geo[gip] = { cc: '', country: '?' };
      } catch (eG) {
        geo[gip] = { cc: '', country: '?' };
      }
    }
    return json({ ok: true, geo: geo });
  }

  if (path === '/api/me' && method === 'GET') return json({ ok: true, user: publicUser(me), csrf: me.csrf || '' });

  if (path === '/api/me/password' && method === 'POST') {
    var pb = await readJson(request);
    if (!pb) return deny('Invalid JSON', 400);
    var full = await dbFirst(env.DB, 'SELECT * FROM users WHERE id = ?', me.id);
    var cur = await hashPassword(String(pb.current || ''), fromB64(full.salt));
    if (!timingSafeEqualStr(cur, full.password_hash)) return deny('Current password is wrong', 400);
    var np = String(pb.next || '');
    if (np.length < 8) return deny('Password must be at least 8 characters', 400);
    var ns = crypto.getRandomValues(new Uint8Array(16));
    var nh = await hashPassword(np, ns);
    await dbRun(env.DB, 'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', nh, b64(ns), me.id);
    await dbRun(env.DB, 'DELETE FROM sessions WHERE user_id = ? AND token != ?', me.id, me.token);
    await audit(env.DB, me.id, 'password_change', '', ip);
    return json({ ok: true });
  }

  if (path === '/api/dashboard' && method === 'GET') {
    var uc = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM users');
    var sc = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM sessions');
    var lc = await dbFirst(env.DB, "SELECT COUNT(*) AS c FROM audit_logs WHERE created_at >= datetime('now','-1 day')");
    var logs = await dbAll(env.DB, 'SELECT id, user_id, action, detail, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT 8');
    await ensureVpn(env.DB);
    var pc = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
    var pcon = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_peers WHERE enabled = 1 AND (sub_id IS NULL OR sub_id = 0)');
    var usedp = await dbFirst(env.DB, 'SELECT SUM(used_bytes) AS s FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
    var useds = await dbFirst(env.DB, 'SELECT SUM(used_bytes) AS s FROM vpn_subs');
    var usedSum = (Number(usedp && usedp.s) || 0) + (Number(useds && useds.s) || 0);
    var scount = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_subs');
    var daily = [];
    try { daily = await dbAll(env.DB, 'SELECT day, bytes FROM vpn_daily ORDER BY day DESC LIMIT 7'); } catch (e) { daily = []; }
    daily = (daily || []).slice().reverse();
    var loc = {
      colo: (request.cf && request.cf.colo) || '',
      country: (request.cf && request.cf.country) || '',
      city: (request.cf && request.cf.city) || '',
      asOrg: (request.cf && request.cf.asOrganization) || ''
    };
    var cfMoney = { ok: false, used_h: '', left_h: '—' };
    try { cfMoney = await cfAccountMoney(env.DB); } catch (eCf) {}
    try {
      var alpeers = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0 LIMIT 80');
      var ap;
      for (ap = 0; ap < alpeers.length; ap++) {
        try { await maybeAlert(env, ctx, alpeers[ap], 'peer'); } catch (eAl) {}
      }
    } catch (eScan) {}
    var health = [];
    try {
      var bhs = parseHostLines(await settingGet(env.DB, 'backup_hosts'));
      var hi, hst, t0, hr;
      for (hi = 0; hi < bhs.length && hi < 6; hi++) {
        hst = bhs[hi];
        t0 = Date.now();
        try {
          hr = await Promise.race([
            fetch('https://' + hst + '/cdn-cgi/trace', { method: 'GET', redirect: 'manual' }),
            new Promise(function (res) { setTimeout(function () { res(null); }, 2500); })
          ]);
          health.push({ host: hst, ok: !!(hr && (hr.status || 0) < 500), ms: Date.now() - t0 });
        } catch (eH) {
          health.push({ host: hst, ok: false, ms: Date.now() - t0 });
        }
      }
    } catch (eHh) {}
    try {
      var can = await settingGet(env.DB, 'canary');
      if (!can) await settingSet(env.DB, 'canary', randomToken());
    } catch (eCan) {}
    return json({
      ok: true,
      users: (uc && uc.c) || 0,
      sessions: (sc && sc.c) || 0,
      logs_today: (lc && lc.c) || 0,
      logs: logs,
      peers: (pc && pc.c) || 0,
      peers_on: (pcon && pcon.c) || 0,
      used_bytes: usedSum,
      used_h: fmtBytes(usedSum),
      subs: (scount && scount.c) || 0,
      loc: loc,
      cf_money: cfMoney,
      health: health,
      daily: daily,
      cfgs: (await dbAll(env.DB, 'SELECT id, name, used_bytes, quota_bytes, expire_at, enabled, location FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0 ORDER BY id DESC LIMIT 40')).map(function (row) {
        var q = Number(row.quota_bytes) || 0;
        var u = Number(row.used_bytes) || 0;
        return {
          id: row.id,
          name: row.name,
          location: row.location || '',
          enabled: row.enabled,
          used_h: fmtBytes(u),
          quota_h: q ? fmtBytes(q) : '∞',
          remain_h: q ? fmtBytes(Math.max(0, q - u)) : '∞',
          remain_days: remainDays(row.expire_at)
        };
      })
    });
  }

  if (path === '/api/users' && method === 'GET') {
    var users = await dbAll(env.DB, 'SELECT id, username, role, email, active, created_at, last_login FROM users ORDER BY id ASC');
    return json({ ok: true, users: users });
  }

  if (path === '/api/users' && method === 'POST') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    var ub = await readJson(request);
    if (!ub) return deny('Invalid JSON', 400);
    var un = String(ub.username || '').trim().toLowerCase();
    var up = String(ub.password || '');
    var ur = String(ub.role || 'viewer');
    var ue = String(ub.email || '').trim();
    if (!/^[a-z0-9_]{3,32}$/.test(un)) return deny('Invalid username', 400);
    if (up.length < 8) return deny('Password must be at least 8 characters', 400);
    if (['admin', 'operator', 'viewer'].indexOf(ur) === -1) return deny('Invalid role', 400);
    var exists = await dbFirst(env.DB, 'SELECT id FROM users WHERE username = ?', un);
    if (exists) return deny('Username taken', 409);
    var us = crypto.getRandomValues(new Uint8Array(16));
    var uh = await hashPassword(up, us);
    await dbRun(env.DB, 'INSERT INTO users (username, password_hash, salt, role, email, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)', un, uh, b64(us), ur, ue, nowIso());
    await audit(env.DB, me.id, 'user_create', un, ip);
    return json({ ok: true });
  }

  var um = pathIds(path, /^\/api\/users\/(\d+)$/);
  if (um) {
    var uid = parseInt(um[1], 10);
    if (method === 'PATCH') {
      if (me.role !== 'admin') return deny('Forbidden', 403);
      var pb2 = await readJson(request) || {};
      var target = await dbFirst(env.DB, 'SELECT * FROM users WHERE id = ?', uid);
      if (!target) return deny('Not found', 404);
      if (pb2.role) {
        if (['admin', 'operator', 'viewer'].indexOf(pb2.role) === -1) return deny('Invalid role', 400);
        if (target.role === 'admin' && pb2.role !== 'admin') {
          var ac = await dbFirst(env.DB, "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1");
          if ((ac && ac.c) <= 1) return deny('Cannot demote the last admin', 400);
        }
        await dbRun(env.DB, 'UPDATE users SET role = ? WHERE id = ?', pb2.role, uid);
      }
      if (pb2.active === 0 || pb2.active === 1 || pb2.active === true || pb2.active === false) {
        var act = pb2.active ? 1 : 0;
        if (target.id === me.id && !act) return deny('Cannot disable yourself', 400);
        if (target.role === 'admin' && !act) {
          var ac2 = await dbFirst(env.DB, "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1");
          if ((ac2 && ac2.c) <= 1) return deny('Cannot disable the last admin', 400);
        }
        await dbRun(env.DB, 'UPDATE users SET active = ? WHERE id = ?', act, uid);
        if (!act) await dbRun(env.DB, 'DELETE FROM sessions WHERE user_id = ?', uid);
      }
      if (typeof pb2.email === 'string') await dbRun(env.DB, 'UPDATE users SET email = ? WHERE id = ?', pb2.email.trim(), uid);
      if (pb2.password) {
        if (String(pb2.password).length < 8) return deny('Password must be at least 8 characters', 400);
        var rs = crypto.getRandomValues(new Uint8Array(16));
        var rh = await hashPassword(String(pb2.password), rs);
        await dbRun(env.DB, 'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', rh, b64(rs), uid);
        await dbRun(env.DB, 'DELETE FROM sessions WHERE user_id = ?', uid);
      }
      await audit(env.DB, me.id, 'user_update', String(uid), ip);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      if (me.role !== 'admin') return deny('Forbidden', 403);
      if (uid === me.id) return deny('Cannot delete yourself', 400);
      var t2 = await dbFirst(env.DB, 'SELECT * FROM users WHERE id = ?', uid);
      if (!t2) return deny('Not found', 404);
      if (t2.role === 'admin') {
        var ac3 = await dbFirst(env.DB, "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1");
        if ((ac3 && ac3.c) <= 1) return deny('Cannot delete the last admin', 400);
      }
      await dbRun(env.DB, 'DELETE FROM sessions WHERE user_id = ?', uid);
      await dbRun(env.DB, 'DELETE FROM users WHERE id = ?', uid);
      await audit(env.DB, me.id, 'user_delete', t2.username, ip);
      return json({ ok: true });
    }
  }

  if (path === '/api/logs' && method === 'GET') {
    var pageSize = 80;
    var logs2 = await dbAll(env.DB, 'SELECT l.id, l.user_id, u.username, l.action, l.detail, l.ip, l.created_at FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT ?', pageSize);
    return json({ ok: true, logs: logs2 });
  }

  if (path === '/api/logs' && method === 'DELETE') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    await dbRun(env.DB, 'DELETE FROM audit_logs');
    await audit(env.DB, me.id, 'logs_clear', '', ip);
    return json({ ok: true });
  }

  if (path === '/api/sessions/revoke' && method === 'POST') {
    await dbRun(env.DB, 'DELETE FROM sessions WHERE user_id = ?', me.id);
    return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', request, true) });
  }

  if (path === '/api/vpn/reset-traffic' && method === 'POST') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    await dbRun(env.DB, 'UPDATE vpn_peers SET used_bytes = 0');
    try { await dbRun(env.DB, 'UPDATE vpn_subs SET used_bytes = 0'); } catch (e) {}
    await audit(env.DB, me.id, 'traffic_reset', '', ip);
    return json({ ok: true });
  }

  if (path === '/api/settings' && method === 'GET') {
    var portsOn = await enabledPorts(env.DB);
    var cfSaved = parsePortNums(await settingGet(env.DB, 'cf_ports'));
    if (!cfSaved.length) cfSaved = CF_ALL.slice();
    return json({
      ok: true,
      ports_all: CF_ALL,
      ports_http: CF_HTTP,
      ports_https: CF_HTTPS,
      settings: {
        panel_name: (await settingGet(env.DB, 'panel_name')) || 'Ham',
        lang: (await settingGet(env.DB, 'lang')) || 'fa',
        vpn_path: (await settingGet(env.DB, 'vpn_path')) || '/vpnws',
        camouflage_url: (await settingGet(env.DB, 'camouflage_url')) || 'https://ubuntu.com/',
        panel_path: (await settingGet(env.DB, 'panel_path')) || '/dash',
        cf_ports: cfSaved.join(','),
        tg_token: await settingGet(env.DB, 'tg_token'),
        tg_chat: await settingGet(env.DB, 'tg_chat'),
        cf_token_set: (await settingGet(env.DB, 'cf_token')) ? '1' : '0',
        admin_email_set: (await settingGet(env.DB, 'admin_email')) ? '1' : '0',
        allow_ips: await settingGet(env.DB, 'allow_ips'),
        abuse_gb: (await settingGet(env.DB, 'abuse_gb')) || '80',
        access_only: (await settingGet(env.DB, 'access_only')) === '1' ? '1' : '0',
        theme: (await settingGet(env.DB, 'theme')) === 'dark' ? 'dark' : 'light',
        extra_hosts: await settingGet(env.DB, 'extra_hosts'),
        proxy_ips: await settingGet(env.DB, 'proxy_ips'),
        proxy_ips_on: await settingGet(env.DB, 'proxy_ips_on'),
        backup_hosts: await settingGet(env.DB, 'backup_hosts'),
        extra_ports: await settingGet(env.DB, 'extra_ports'),
        panel_host: await settingGet(env.DB, 'panel_host'),
        tg_2fa: (await settingGet(env.DB, 'tg_2fa')) === '1' ? '1' : '0'
      }
    });
  }

  if (path === '/api/settings' && method === 'PUT') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    var sb = await readJson(request) || {};
    if (typeof sb.panel_name === 'string' && sb.panel_name.trim()) await settingSet(env.DB, 'panel_name', sb.panel_name.trim().slice(0, 40));
    if (sb.lang === 'fa' || sb.lang === 'en') await settingSet(env.DB, 'lang', sb.lang);
    if (typeof sb.vpn_path === 'string') await settingSet(env.DB, 'vpn_path', normPath(sb.vpn_path));
    if (typeof sb.allow_ips === 'string') await settingSet(env.DB, 'allow_ips', sb.allow_ips);
    if (typeof sb.abuse_gb === 'string' || typeof sb.abuse_gb === 'number') await settingSet(env.DB, 'abuse_gb', String(parseInt(sb.abuse_gb, 10) || 0));
    if (sb.access_only === '1' || sb.access_only === '0') await settingSet(env.DB, 'access_only', sb.access_only);
    if (typeof sb.panel_path === 'string' && sb.panel_path.trim()) {
      var npp = normPath(sb.panel_path);
      if (npp !== '/sub' && npp !== '/api') await settingSet(env.DB, 'panel_path', npp);
    }
    if (typeof sb.cf_ports === 'string') await settingSet(env.DB, 'cf_ports', parsePortNums(sb.cf_ports).join(','));
    if (typeof sb.extra_ports === 'string') await settingSet(env.DB, 'extra_ports', parsePortNums(sb.extra_ports).join(','));
    if (typeof sb.panel_host === 'string') {
      var ph = sb.panel_host.trim().replace(/^https?:\/\//, '').split('/')[0];
      await settingSet(env.DB, 'panel_host', ph);
    }
    if (sb.theme === 'dark' || sb.theme === 'light') await settingSet(env.DB, 'theme', sb.theme);
    if (typeof sb.extra_hosts === 'string') await settingSet(env.DB, 'extra_hosts', sb.extra_hosts);
    if (typeof sb.backup_hosts === 'string') await settingSet(env.DB, 'backup_hosts', parseHostLines(sb.backup_hosts).join('\n'));
    if (typeof sb.proxy_ips === 'string') {
      var pip = parseIpLines(sb.proxy_ips);
      await settingSet(env.DB, 'proxy_ips', pip.join('\n'));
      var onSrc = typeof sb.proxy_ips_on === 'string' ? sb.proxy_ips_on : (await settingGet(env.DB, 'proxy_ips_on'));
      var onNow = parseIpLines(onSrc);
      var onKeep = [];
      var oi;
      for (oi = 0; oi < onNow.length; oi++) if (pip.indexOf(onNow[oi]) !== -1) onKeep.push(onNow[oi]);
      await settingSet(env.DB, 'proxy_ips_on', onKeep.join('\n'));
    } else if (typeof sb.proxy_ips_on === 'string') {
      var allp = parseIpLines(await settingGet(env.DB, 'proxy_ips'));
      var on2 = parseIpLines(sb.proxy_ips_on);
      var on3 = [];
      var oj;
      for (oj = 0; oj < on2.length; oj++) if (allp.indexOf(on2[oj]) !== -1) on3.push(on2[oj]);
      await settingSet(env.DB, 'proxy_ips_on', on3.join('\n'));
    }
    if (sb.tg_2fa === '1' || sb.tg_2fa === '0' || sb.tg_2fa === true || sb.tg_2fa === false) {
      await settingSet(env.DB, 'tg_2fa', sb.tg_2fa && sb.tg_2fa !== '0' ? '1' : '0');
    }
    if (typeof sb.tg_token === 'string') await settingSet(env.DB, 'tg_token', sb.tg_token.trim());
    if (typeof sb.tg_chat === 'string') await settingSet(env.DB, 'tg_chat', sb.tg_chat.trim());
    if (typeof sb.cf_token === 'string') {
      var cft = sb.cf_token.trim();
      if (cft === '-') await settingSet(env.DB, 'cf_token', '');
      else if (cft) await settingSet(env.DB, 'cf_token', cft);
    }
    var tokNow = await settingGet(env.DB, 'tg_token');
    if (tokNow) {
      try {
        await fetch('https://api.telegram.org/bot' + tokNow + '/setWebhook', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url: url.origin + '/hamtg' })
        });
      } catch (e) {}
    }
    try { await disableBadPortPeers(env.DB); } catch (eDis) {}
    await audit(env.DB, me.id, 'settings_update', '', ip);
    return json({ ok: true });
  }

  if (path === '/api/ips/discover' && method === 'POST') {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    var found = [];
    function addIp(x) {
      x = String(x || '').trim();
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(x)) return;
      var oct = x.split('.');
      var k;
      for (k = 0; k < 4; k++) {
        if (Number(oct[k]) > 255) return;
      }
      if (Number(oct[3]) === 0 || Number(oct[3]) === 255) return;
      if (isBadProxyIp(x)) return;
      if (found.indexOf(x) === -1) found.push(x);
    }
    function ipToN(s) {
      var p = String(s).split('.');
      if (p.length !== 4) return -1;
      return ((Number(p[0]) * 16777216) + (Number(p[1]) * 65536) + (Number(p[2]) * 256) + Number(p[3])) >>> 0;
    }
    function nToIp(n) {
      n = n >>> 0;
      return ((n >>> 24) & 255) + '.' + ((n >>> 16) & 255) + '.' + ((n >>> 8) & 255) + '.' + (n & 255);
    }
    function randIpInCidr(cidr) {
      var sp = String(cidr).split('/');
      if (sp.length !== 2) return '';
      var base = ipToN(sp[0]);
      var bits = Number(sp[1]);
      if (base < 0 || !(bits >= 8 && bits <= 32)) return '';
      var span = Math.pow(2, 32 - bits);
      if (span <= 2) return nToIp(base);
      var off = 1 + Math.floor(Math.random() * (span - 2));
      return nToIp((base + off) >>> 0);
    }
    function shuffle(arr) {
      var i, j, x;
      for (i = arr.length - 1; i > 0; i--) {
        j = Math.floor(Math.random() * (i + 1));
        x = arr[i]; arr[i] = arr[j]; arr[j] = x;
      }
      return arr;
    }
    async function dohA(name) {
      try {
        var res = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=A', {
          headers: { accept: 'application/dns-json' }
        });
        var j = await res.json();
        var ai;
        if (j && j.Answer) {
          for (ai = 0; ai < j.Answer.length; ai++) {
            if (Number(j.Answer[ai].type) === 1) addIp(j.Answer[ai].data);
          }
        }
      } catch (e) {}
    }
    await dohA(url.hostname);
    var extras = parseIpLines(await settingGet(env.DB, 'extra_hosts'));
    var ei;
    for (ei = 0; ei < extras.length; ei++) {
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(extras[ei])) addIp(extras[ei]);
      else await dohA(extras[ei]);
    }
    var cidrs = [];
    try {
      var ipTxt = await fetch('https://www.cloudflare.com/ips-v4');
      cidrs = String(await ipTxt.text()).split(/\s+/).filter(function (x) { return x.indexOf('/') !== -1; });
    } catch (e2) { cidrs = []; }
    if (!cidrs.length) {
      cidrs = ['104.16.0.0/12', '104.24.0.0/14', '172.64.0.0/13', '162.158.0.0/15', '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17', '141.101.64.0/18', '108.162.192.0/18', '173.245.48.0/20', '103.21.244.0/22'];
    }
    addIp('104.16.1.1');
    addIp('104.17.1.1');
    addIp('104.18.1.1');
    addIp('104.21.87.1');
    addIp('104.24.0.1');
    addIp('172.67.0.1');
    addIp('162.159.36.1');
    shuffle(cidrs);
    var guard = 0;
    while (found.length < 40 && guard < 400) {
      guard++;
      addIp(randIpInCidr(cidrs[guard % cidrs.length]));
    }
    shuffle(found);
    if (found.length > 40) found = found.slice(0, 40);
    return json({ ok: true, ips: found, host: url.hostname });
  }

  if (path === '/api/ips/ping' && method === 'POST') {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    var pingBody = await readJson(request) || {};
    var pingList = parseIpLines(Array.isArray(pingBody.ips) ? pingBody.ips.join('\n') : String(pingBody.ips || ''));
    if (!pingList.length) pingList = parseIpLines(await settingGet(env.DB, 'proxy_ips'));
    if (pingList.length > 40) pingList = pingList.slice(0, 40);
    async function pingOne(ip) {
      var t0 = Date.now();
      function timed(p, ms) {
        return Promise.race([p, new Promise(function (res) { setTimeout(function () { res(null); }, ms); })]);
      }
      try {
        var ctrl = new AbortController();
        var tid = setTimeout(function () { try { ctrl.abort(); } catch (eA) {} }, 1500);
        var res = await timed(fetch('http://' + ip + '/cdn-cgi/trace', { method: 'GET', redirect: 'manual', signal: ctrl.signal }), 1500);
        clearTimeout(tid);
        if (res) return { ip: ip, ok: true, ms: Date.now() - t0 };
      } catch (e1) {}
      try {
        var ctrl2 = new AbortController();
        var tid2 = setTimeout(function () { try { ctrl2.abort(); } catch (eB) {} }, 2000);
        var res2 = await timed(fetch('https://' + ip + '/cdn-cgi/trace', { method: 'GET', redirect: 'manual', signal: ctrl2.signal }), 2000);
        clearTimeout(tid2);
        if (res2) return { ip: ip, ok: true, ms: Date.now() - t0 };
      } catch (e2) {}
      return { ip: ip, ok: false, ms: Date.now() - t0 };
    }
    var pings = [];
    var bi, bj, batch, part;
    for (bi = 0; bi < pingList.length; bi += 8) {
      batch = [];
      for (bj = bi; bj < bi + 8 && bj < pingList.length; bj++) batch.push(pingOne(pingList[bj]));
      part = await Promise.all(batch);
      for (bj = 0; bj < part.length; bj++) pings.push(part[bj]);
    }
    return json({ ok: true, pings: pings });
  }

  if (path === '/api/tg/test' && method === 'POST') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    var tokOk = await tgSend(env, null, 'Ham · telegram test ok');
    if (!tokOk) return deny('ارسال نشد. توکن بات و Chat ID را چک کنید.', 502);
    return json({ ok: true });
  }

  if (path === '/api/backup' && method === 'GET') {
    await ensureVpn(env.DB);
    var bset = await dbAll(env.DB, 'SELECT key, value FROM settings');
    var bpeers = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
    var bsubs = await dbAll(env.DB, 'SELECT * FROM vpn_subs');
    var payload = JSON.stringify({ ham: 1, exported_at: nowIso(), settings: bset, peers: bpeers, subs: bsubs }, null, 2);
    return new Response(payload, {
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': 'attachment; filename="ham-backup.json"',
        'cache-control': 'no-store'
      }
    });
  }

  if (path === '/api/backup' && method === 'POST') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    await ensureVpn(env.DB);
    var bk = await readJson(request);
    if (!bk || bk.ham !== 1) return deny('Invalid backup', 400);
    var bi, row;
    if (Array.isArray(bk.settings)) {
      for (bi = 0; bi < bk.settings.length; bi++) {
        row = bk.settings[bi];
        if (row && row.key) await settingSet(env.DB, String(row.key), String(row.value == null ? '' : row.value));
      }
    }
    if (Array.isArray(bk.peers)) {
      for (bi = 0; bi < bk.peers.length; bi++) {
        row = bk.peers[bi];
        if (!row || !row.uuid) continue;
        try {
          await dbRun(
            env.DB,
            'INSERT INTO vpn_peers (name, uuid, trojan_pass, protocols, quota_bytes, used_bytes, expire_at, max_ip, location, port, fragment, mux, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(uuid) DO UPDATE SET name=excluded.name, trojan_pass=excluded.trojan_pass, protocols=excluded.protocols, quota_bytes=excluded.quota_bytes, expire_at=excluded.expire_at, max_ip=excluded.max_ip, location=excluded.location, port=excluded.port, fragment=excluded.fragment, mux=excluded.mux, enabled=excluded.enabled',
            String(row.name || 'Ham').slice(0, 40),
            String(row.uuid),
            String(row.trojan_pass || row.uuid),
            cleanProtos(row.protocols).join(','),
            Number(row.quota_bytes) || 0,
            Number(row.used_bytes) || 0,
            row.expire_at || null,
            Number(row.max_ip) || 0,
            String(row.location || '').slice(0, 16),
            String(cleanPorts(row.port || '443', true)[0]),
            Number(row.fragment) ? 1 : 0,
            Number(row.mux) ? 1 : 0,
            row.enabled == null ? 1 : (row.enabled ? 1 : 0),
            row.created_at || nowIso()
          );
        } catch (e) {}
      }
    }
    if (Array.isArray(bk.subs)) {
      for (bi = 0; bi < bk.subs.length; bi++) {
        row = bk.subs[bi];
        if (!row || !row.token) continue;
        try {
          await dbRun(
            env.DB,
            'INSERT INTO vpn_subs (token, name, protocols, created_at, expire_at, quota_bytes, uuid, trojan_pass, ports, location, max_ip, used_bytes, enabled, fragment, mux, brand, logo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET name=excluded.name, protocols=excluded.protocols, expire_at=excluded.expire_at, quota_bytes=excluded.quota_bytes, uuid=excluded.uuid, trojan_pass=excluded.trojan_pass, ports=excluded.ports, location=excluded.location, max_ip=excluded.max_ip, fragment=excluded.fragment, mux=excluded.mux, brand=excluded.brand, logo=excluded.logo, enabled=excluded.enabled',
            String(row.token),
            String(row.name || 'Ham').slice(0, 40),
            cleanProtos(row.protocols).join(','),
            row.created_at || nowIso(),
            row.expire_at || null,
            Number(row.quota_bytes) || 0,
            String(row.uuid || crypto.randomUUID()),
            String(row.trojan_pass || row.uuid || ''),
            cleanPorts(row.ports || '443', false).join(','),
            String(row.location || '').slice(0, 16),
            Number(row.max_ip) || 0,
            Number(row.used_bytes) || 0,
            row.enabled == null ? 1 : (row.enabled ? 1 : 0),
            Number(row.fragment) ? 1 : 0,
            Number(row.mux) ? 1 : 0,
            String(row.brand || '').slice(0, 40),
            String(row.logo || '').slice(0, 300)
          );
        } catch (e) {}
      }
    }
    await audit(env.DB, me.id, 'backup_restore', '', ip);
    return json({ ok: true });
  }

  if (path === '/api/vpn' && method === 'GET') {
    await ensureVpn(env.DB);
    var o = await proxySettings(env.DB, url.hostname);
    var loc = (request.cf && (request.cf.country || request.cf.colo)) || '';
    var portsOn = await enabledPorts(env.DB);
    var peers = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0 ORDER BY id DESC');
    var list = [];
    var pi;
    for (pi = 0; pi < peers.length; pi++) {
      var pr = peers[pi];
      list.push({
        id: pr.id,
        name: pr.name,
        uuid: pr.uuid,
        trojan_pass: pr.trojan_pass || pr.uuid,
        protocols: pr.protocols || 'vless',
        port: pr.port || '443',
        fragment: pr.fragment || 0,
        mux: pr.mux || 0,
        ips: pr.ips || '',
        speed_kbps: pr.speed_kbps || 0,
        extra_host: pr.extra_host || '',
        remark: pr.remark || '',
        quota_bytes: pr.quota_bytes || 0,
        used_bytes: pr.used_bytes || 0,
        used_h: fmtBytes(pr.used_bytes || 0),
        quota_h: (pr.quota_bytes ? fmtBytes(pr.quota_bytes) : '∞'),
        quota_gb: pr.quota_bytes ? Math.round((Number(pr.quota_bytes) / (1024*1024*1024)) * 10) / 10 : 0,
        remain_days: remainDays(pr.expire_at),
        expire_at: pr.expire_at || '',
        max_ip: pr.max_ip || 0,
        location: pr.location || loc,
        enabled: pr.enabled,
        alive: peerAlive(pr) ? 1 : 0,
        last_seen: pr.last_seen || '',
        last_h: pr.last_seen ? fmtTehran(pr.last_seen) : '',
        online: !!(pr.last_seen && (Date.now() - Date.parse(pr.last_seen) < 180000) && peerAlive(pr)),
        created_at: pr.created_at,
        links: peerLinks(pr, o)
      });
    }
    var hosts = parseHostLines(await settingGet(env.DB, 'backup_hosts'));
    var useIps = [];
    var allIps = [];
    try { allIps = parseIpLines(await settingGet(env.DB, 'proxy_ips')); } catch (eA) {}
    try { useIps = await enabledIps(env.DB); } catch (eI) {}
    return json({ ok: true, proxy: o, loc: loc, ports: portsOn, ports_all: CF_ALL, ports_http: CF_HTTP, ports_https: CF_HTTPS, hosts: hosts, ips: useIps, ips_on: useIps, ips_all: allIps, peers: list });
  }

  if (path === '/api/vpn/alive' && method === 'GET') {
    await ensureVpn(env.DB);
    var ap = await dbAll(env.DB, 'SELECT id, last_seen, enabled, expire_at, quota_bytes, used_bytes FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
    var al = [];
    var aj;
    for (aj = 0; aj < ap.length; aj++) {
      var ar = ap[aj];
      al.push({
        id: ar.id,
        last_seen: ar.last_seen || '',
        last_h: ar.last_seen ? fmtTehran(ar.last_seen) : '',
        online: !!(ar.last_seen && (Date.now() - Date.parse(ar.last_seen) < 180000) && peerAlive(ar))
      });
    }
    return json({ ok: true, peers: al });
  }

  if (path === '/api/vpn.csv' && method === 'GET') {
    await ensureVpn(env.DB);
    var exp = await dbAll(env.DB, 'SELECT id, name, location, used_bytes, quota_bytes, expire_at, enabled, last_seen, created_at FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0 ORDER BY id DESC');
    var lines = ['id,name,location,used_bytes,quota_bytes,expire_at,enabled,last_seen,created_at'];
    var ei, er;
    function csvCell(v) {
      v = String(v == null ? '' : v);
      if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
      return v;
    }
    for (ei = 0; ei < exp.length; ei++) {
      er = exp[ei];
      lines.push([er.id, csvCell(er.name), csvCell(er.location), er.used_bytes || 0, er.quota_bytes || 0, csvCell(er.expire_at), er.enabled, csvCell(er.last_seen), csvCell(er.created_at)].join(','));
    }
    return new Response(lines.join('\n'), {
      headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': 'attachment; filename="ham-peers.csv"', 'cache-control': 'no-store' }
    });
  }

  if (path === '/api/vpn' && method === 'POST') {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    await ensureVpn(env.DB);
    try {
      var since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      var burst = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_peers WHERE created_at >= ?', since);
      if (burst && Number(burst.c) >= 12) {
        try { await tgSend(env, null, 'قفل موقت: ساخت زیاد کانفیگ از پنل. IP ' + ip); } catch (eB) {}
        return deny('ساخت کانفیگ موقتاً قفل شد', 429);
      }
    } catch (eF) {}
    var vb = (await readJson(request)) || {};
    var vname = String(vb.name || 'Ham').trim().slice(0, 40) || 'Ham';
    var vuuid = String(vb.uuid || '').trim().toLowerCase() || crypto.randomUUID();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(vuuid)) {
      return deny('Invalid UUID', 400);
    }
    var tpass = String(vb.trojan_pass || '').trim() || vuuid;
    var protos = cleanProtos(vb.protocols || 'vless').slice(0, 1).join(',');
    var vport = String(cleanPorts(vb.port || vb.ports || '443', true)[0]);
    var quota = gbToBytes(vb.quota_gb);
    var exp = daysToExpire(vb.days);
    var maxip = parseInt(vb.max_ip, 10) || 0;
    var locn = pickLoc(vb.location);
    var vfrag = vb.fragment ? 1 : 0;
    var vmux = vb.mux ? 1 : 0;
    try {
      await dbRun(
        env.DB,
        'INSERT INTO vpn_peers (name, uuid, trojan_pass, protocols, quota_bytes, used_bytes, expire_at, max_ip, location, port, fragment, mux, ips, enabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
        vname, vuuid, tpass, protos, quota, exp, maxip, locn, vport, vfrag, vmux, parseIpLines(vb.ips || '').slice(0, 1).join(','), nowIso()
      );
      var spdk = Math.floor((Number(vb.speed_mbps) || 0) * 1024);
      var ehost = String(vb.extra_host || '').trim().slice(0, 120);
      try { await dbRun(env.DB, 'UPDATE vpn_peers SET remark = ? WHERE uuid = ?', String(vb.remark || '').trim().slice(0, 48), vuuid); } catch (er) {}
      try { await dbRun(env.DB, 'UPDATE vpn_peers SET speed_kbps = ?, extra_host = ? WHERE uuid = ?', spdk, ehost, vuuid); } catch (es) {}
    } catch (e) {
      return deny('UUID already used', 409);
    }
    await audit(env.DB, me.id, 'vpn_create', vname, ip);
    var o2 = await proxySettings(env.DB, url.hostname);
    var createdP = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE uuid = ?', vuuid);
    return json({ ok: true, peer: createdP, links: peerLinks(createdP, o2) });
  }

  if (path === '/api/sub' && method === 'GET') {
    await ensureVpn(env.DB);
    var oS = await proxySettings(env.DB, url.hostname);
    var portsOnS = await enabledPorts(env.DB);
    var subs = await dbAll(env.DB, 'SELECT * FROM vpn_subs ORDER BY id DESC');
    var outS = [];
    var si;
    for (si = 0; si < subs.length; si++) {
      var su = subs[si];
      var pack = su.uuid ? subLinkList(su, oS) : { count: 0 };
      outS.push({
        id: su.id,
        name: su.name,
        brand: su.brand || su.name,
        logo: su.logo || '',
        token: su.token,
        url: url.origin + '/sub/' + su.token + (su.sub_pass ? ('/' + su.sub_pass) : ''),
        status_url: url.origin + '/st/' + su.token,
        sub_pass: su.sub_pass || '',
        one_shot: su.one_shot || 0,
        burned: su.burned || 0,
        speed_kbps: su.speed_kbps || 0,
        extra_host: su.extra_host || '',
        protocols: su.protocols,
        ports: su.ports || '443',
        expire_at: su.expire_at || '',
        quota_bytes: su.quota_bytes || 0,
        used_bytes: su.used_bytes || 0,
        used_h: fmtBytes(su.used_bytes || 0),
        quota_h: su.quota_bytes ? fmtBytes(su.quota_bytes) : '∞',
        quota_gb: su.quota_bytes ? Math.round((Number(su.quota_bytes) / (1024*1024*1024)) * 10) / 10 : 0,
        remain_days: remainDays(su.expire_at),
        location: su.location || '',
        uuid: su.uuid || '',
        max_ip: su.max_ip || 0,
        ips: su.ips || '',
        fragment: su.fragment || 0,
        mux: su.mux || 0,
        count: pack.count,
        created_at: su.created_at
      });
    }
    var hostsS = String(await settingGet(env.DB, 'extra_hosts') || '').split(/\n/).map(function (x) { return x.trim(); }).filter(Boolean);
    return json({ ok: true, ports: portsOnS, ports_all: CF_ALL, ports_http: CF_HTTP, ports_https: CF_HTTPS, hosts: hostsS, subs: outS });
  }

  if (path === '/api/sub' && method === 'POST') {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    await ensureVpn(env.DB);
    var sbx = (await readJson(request)) || {};
    var sname = String(sbx.name || 'Ham').trim().slice(0, 40) || 'Ham';
    var sprotos = cleanProtos(sbx.protocols || 'vless').join(',');
    var sports = cleanPorts(sbx.ports || sbx.port || '443', false).join(',');
    var squota = gbToBytes(sbx.quota_gb);
    var sexp = daysToExpire(sbx.days);
    var sloc = pickLoc(sbx.location);
    var suuid = String(sbx.uuid || '').trim().toLowerCase() || crypto.randomUUID();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(suuid)) {
      return deny('Invalid UUID', 400);
    }
    var stpass = String(sbx.trojan_pass || '').trim() || suuid;
    var stok = randomToken().slice(0, 24);
    var sbrand = String(sbx.brand || sname).trim().slice(0, 40) || sname;
    var slogo = String(sbx.logo || '').trim().slice(0, 300);
    var smax = parseInt(sbx.max_ip, 10) || 0;
    await dbRun(
      env.DB,
      'INSERT INTO vpn_subs (token, name, protocols, created_at, expire_at, quota_bytes, uuid, trojan_pass, ports, location, max_ip, used_bytes, enabled, fragment, mux, brand, logo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)',
      stok, sname, sprotos, nowIso(), sexp, squota, suuid, stpass, sports, sloc, smax, sbx.fragment ? 1 : 0, sbx.mux ? 1 : 0, sbrand, slogo
    );
    var srow2 = await dbFirst(env.DB, 'SELECT id FROM vpn_subs WHERE token = ?', stok);
    if (srow2) {
      if (sbx.ips != null) await dbRun(env.DB, 'UPDATE vpn_subs SET ips = ? WHERE id = ?', parseIpLines(sbx.ips).join(','), srow2.id);
      try {
        await dbRun(env.DB, 'UPDATE vpn_subs SET speed_kbps = ?, extra_host = ?, sub_pass = ?, one_shot = ?, burned = 0 WHERE id = ?',
          Math.floor((Number(sbx.speed_mbps) || 0) * 1024),
          String(sbx.extra_host || '').trim().slice(0, 120),
          String(sbx.sub_pass || '').trim().slice(0, 40),
          sbx.one_shot ? 1 : 0,
          srow2.id);
      } catch (esu) {}
    }
    var nlinks = cleanPorts(sports, false).length * cleanProtos(sprotos).length;
    await audit(env.DB, me.id, 'sub_create', sname + ' x' + nlinks, ip);
    return json({ ok: true, url: url.origin + '/sub/' + stok, token: stok, count: nlinks });
  }

  if (path === '/api/vpn/path' && method === 'PUT') {
    if (me.role !== 'admin') return deny('Forbidden', 403);
    var pbv = (await readJson(request)) || {};
    var npth = normPath(pbv.path || '/vpnws');
    await settingSet(env.DB, 'vpn_path', npth);
    await audit(env.DB, me.id, 'vpn_path', npth, ip);
    return json({ ok: true, path: npth });
  }

  var vpm = pathIds(path, /^\/api\/vpn\/(\d+)$/);
  if (vpm) {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    var vid = parseInt(vpm[1], 10);
    if (method === 'PATCH' || method === 'PUT' || method === 'POST') {
      await ensureVpn(env.DB);
      var pbe = (await readJson(request)) || {};
      var curP = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', vid);
      if (!curP) return deny('Not found', 404);
      async function setCol(sql) {
        var a = Array.prototype.slice.call(arguments, 1);
        try {
          var st = env.DB.prepare(sql);
          if (a.length) st = st.bind.apply(st, a);
          await st.run();
          return true;
        } catch (eSet) { return false; }
      }
      if (pbe.enabled === 0 || pbe.enabled === 1 || pbe.enabled === true || pbe.enabled === false) {
        await setCol('UPDATE vpn_peers SET enabled = ? WHERE id = ?', pbe.enabled ? 1 : 0, vid);
      }
      if (typeof pbe.name === 'string' && pbe.name.trim()) {
        await setCol('UPDATE vpn_peers SET name = ? WHERE id = ?', pbe.name.trim().slice(0, 40), vid);
      }
      if (pbe.quota_gb != null && pbe.quota_gb !== '') {
        await setCol('UPDATE vpn_peers SET quota_bytes = ? WHERE id = ?', gbToBytes(pbe.quota_gb), vid);
      }
      if (pbe.days != null && pbe.days !== '') {
        await setCol('UPDATE vpn_peers SET expire_at = ? WHERE id = ?', daysToExpire(pbe.days), vid);
      }
      if (typeof pbe.location === 'string') {
        await setCol('UPDATE vpn_peers SET location = ? WHERE id = ?', pbe.location.trim().slice(0, 16), vid);
      }
      if (pbe.max_ip != null && pbe.max_ip !== '') {
        await setCol('UPDATE vpn_peers SET max_ip = ? WHERE id = ?', parseInt(pbe.max_ip, 10) || 0, vid);
      }
      if (pbe.reset_traffic) await setCol('UPDATE vpn_peers SET used_bytes = 0 WHERE id = ?', vid);
      if (typeof pbe.uuid === 'string' && pbe.uuid.trim()) {
        var nu = pbe.uuid.trim().toLowerCase();
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nu)) return deny('Invalid UUID', 400);
        var okU = await setCol('UPDATE vpn_peers SET uuid = ? WHERE id = ?', nu, vid);
        if (!okU && nu !== curP.uuid) return deny('UUID already used', 409);
      }
      if (typeof pbe.trojan_pass === 'string' && pbe.trojan_pass.trim()) {
        await setCol('UPDATE vpn_peers SET trojan_pass = ? WHERE id = ?', pbe.trojan_pass.trim(), vid);
      }
      if (pbe.port != null || pbe.ports != null) {
        await setCol('UPDATE vpn_peers SET port = ? WHERE id = ?', String(cleanPorts(pbe.port || pbe.ports || '443', true)[0] || '443'), vid);
      }
      if (typeof pbe.protocols === 'string' && pbe.protocols.trim()) {
        await setCol('UPDATE vpn_peers SET protocols = ? WHERE id = ?', cleanProtos(pbe.protocols).slice(0, 1).join(',') || 'vless', vid);
      }
      if (pbe.ips != null) await setCol('UPDATE vpn_peers SET ips = ? WHERE id = ?', parseIpLines(pbe.ips).slice(0, 1).join(','), vid);
      if (pbe.speed_mbps != null && pbe.speed_mbps !== '') {
        await setCol('UPDATE vpn_peers SET speed_kbps = ? WHERE id = ?', Math.floor((Number(pbe.speed_mbps) || 0) * 1024), vid);
      }
      if (typeof pbe.extra_host === 'string') {
        await setCol('UPDATE vpn_peers SET extra_host = ? WHERE id = ?', pbe.extra_host.trim().slice(0, 120), vid);
      }
      if (typeof pbe.remark === 'string') {
        await setCol('UPDATE vpn_peers SET remark = ? WHERE id = ?', pbe.remark.trim().slice(0, 48), vid);
      }
      await audit(env.DB, me.id, 'vpn_update', String(vid), ip);
      var savedP = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', vid);
      return json({ ok: true, peer: savedP });
    }
    if (method === 'DELETE') {
      await dbRun(env.DB, 'DELETE FROM vpn_peers WHERE id = ?', vid);
      await audit(env.DB, me.id, 'vpn_delete', String(vid), ip);
      return json({ ok: true });
    }
  }

  var smc = pathIds(path, /^\/api\/sub\/(\d+)\/clone$/);
  if (smc && method === 'POST') {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    var cid = parseInt(smc[1], 10);
    var src = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE id = ?', cid);
    if (!src) return deny('Not found', 404);
    var ntok = randomToken().slice(0, 24);
    var nuu = crypto.randomUUID();
    var nname = String(src.name || 'Ham').slice(0, 34) + '-' + String(Date.now()).slice(-4);
    await dbRun(
      env.DB,
      'INSERT INTO vpn_subs (token, name, protocols, created_at, expire_at, quota_bytes, uuid, trojan_pass, ports, location, max_ip, used_bytes, enabled, fragment, mux, brand, logo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 0, 0, ?, ?)',
      ntok, nname, src.protocols || 'vless', nowIso(), src.expire_at, src.quota_bytes || 0, nuu, nuu, src.ports || '443', src.location || '', src.max_ip || 0, nname, ''
    );
    var nrow = await dbFirst(env.DB, 'SELECT id FROM vpn_subs WHERE token = ?', ntok);
    if (nrow) {
      try {
        await dbRun(env.DB, 'UPDATE vpn_subs SET speed_kbps = ?, extra_host = ?, sub_pass = ?, one_shot = 0, burned = 0 WHERE id = ?',
          src.speed_kbps || 0, src.extra_host || '', '', nrow.id);
      } catch (ec) {}
    }
    await audit(env.DB, me.id, 'sub_clone', String(cid), ip);
    return json({ ok: true, url: url.origin + '/sub/' + ntok, token: ntok });
  }

  var sm = pathIds(path, /^\/api\/sub\/(\d+)$/);
  if (sm) {
    if (me.role === 'viewer') return deny('Forbidden', 403);
    var sid = parseInt(sm[1], 10);
    if (method === 'PATCH') {
      var sbe = (await readJson(request)) || {};
      var subRow = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE id = ?', sid);
      if (!subRow) return deny('Not found', 404);
      if (typeof sbe.name === 'string' && sbe.name.trim()) await dbRun(env.DB, 'UPDATE vpn_subs SET name = ? WHERE id = ?', sbe.name.trim().slice(0, 40), sid);
      if (typeof sbe.brand === 'string') await dbRun(env.DB, 'UPDATE vpn_subs SET brand = ? WHERE id = ?', sbe.brand.trim().slice(0, 40), sid);
      if (typeof sbe.logo === 'string') await dbRun(env.DB, 'UPDATE vpn_subs SET logo = ? WHERE id = ?', sbe.logo.trim().slice(0, 300), sid);
      if (sbe.quota_gb != null) await dbRun(env.DB, 'UPDATE vpn_subs SET quota_bytes = ? WHERE id = ?', gbToBytes(sbe.quota_gb), sid);
      if (sbe.days != null) await dbRun(env.DB, 'UPDATE vpn_subs SET expire_at = ? WHERE id = ?', daysToExpire(sbe.days), sid);
      if (sbe.ports != null || sbe.port != null) await dbRun(env.DB, 'UPDATE vpn_subs SET ports = ? WHERE id = ?', cleanPorts(sbe.ports || sbe.port || '443', false).join(','), sid);
      if (typeof sbe.protocols === 'string' && sbe.protocols.trim()) await dbRun(env.DB, 'UPDATE vpn_subs SET protocols = ? WHERE id = ?', cleanProtos(sbe.protocols).join(','), sid);
      if (typeof sbe.location === 'string') await dbRun(env.DB, 'UPDATE vpn_subs SET location = ? WHERE id = ?', pickLoc(sbe.location), sid);
      if (sbe.max_ip != null) await dbRun(env.DB, 'UPDATE vpn_subs SET max_ip = ? WHERE id = ?', parseInt(sbe.max_ip, 10) || 0, sid);
      if (sbe.ips != null) await dbRun(env.DB, 'UPDATE vpn_subs SET ips = ? WHERE id = ?', parseIpLines(sbe.ips).join(','), sid);
      if (sbe.speed_mbps != null) await dbRun(env.DB, 'UPDATE vpn_subs SET speed_kbps = ? WHERE id = ?', Math.floor((Number(sbe.speed_mbps) || 0) * 1024), sid);
      if (typeof sbe.extra_host === 'string') await dbRun(env.DB, 'UPDATE vpn_subs SET extra_host = ? WHERE id = ?', sbe.extra_host.trim().slice(0, 120), sid);
      if (typeof sbe.sub_pass === 'string') await dbRun(env.DB, 'UPDATE vpn_subs SET sub_pass = ? WHERE id = ?', sbe.sub_pass.trim().slice(0, 40), sid);
      if (sbe.one_shot != null) {
        await dbRun(env.DB, 'UPDATE vpn_subs SET one_shot = ?, burned = 0 WHERE id = ?', sbe.one_shot ? 1 : 0, sid);
      }
      if (typeof sbe.uuid === 'string' && sbe.uuid.trim()) {
        var suu = sbe.uuid.trim().toLowerCase();
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(suu)) return deny('Invalid UUID', 400);
        await dbRun(env.DB, 'UPDATE vpn_subs SET uuid = ? WHERE id = ?', suu, sid);
      }
      await audit(env.DB, me.id, 'sub_update', String(sid), ip);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await dbRun(env.DB, 'DELETE FROM vpn_peers WHERE sub_id = ?', sid);
      await dbRun(env.DB, 'DELETE FROM vpn_subs WHERE id = ?', sid);
      await audit(env.DB, me.id, 'sub_delete', String(sid), ip);
      return json({ ok: true });
    }
  }

  return deny('Not found', 404);
}


async function handleSub(request, env, url) {
  if (!hasDB(env)) return new Response('no db', { status: 500 });
  await ensureVpn(env.DB);
  var parts = url.pathname.split('/').filter(Boolean);
  var token = parts[1] || '';
  var passIn = parts[2] || url.searchParams.get('p') || '';
  if (!token) return new Response('not found', { status: 404 });
  var sub = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE token = ?', token);
  if (!sub) return new Response('not found', { status: 404 });
  if (sub.sub_pass && String(sub.sub_pass) !== String(passIn)) return new Response('password', { status: 401 });
  var q = Number(sub.quota_bytes) || 0;
  var u = Number(sub.used_bytes) || 0;
  var blocked = !!(Number(sub.one_shot) && Number(sub.burned));
  if (sub.expire_at && Date.parse(sub.expire_at) < Date.now()) {
    blocked = true;
    try { await maybeAlert(env, null, sub, 'sub'); } catch (e) {}
  }
  if (q > 0 && u >= q) {
    blocked = true;
    try { await maybeAlert(env, null, sub, 'sub'); } catch (e) {}
  }
  var o = await proxySettings(env.DB, url.hostname);
  var fmt = (url.searchParams.get('format') || url.searchParams.get('app') || 'base64').toLowerCase();
  var pack;
  var legacyPeers = [];
  if (sub.uuid) pack = subLinkList(sub, o);
  else {
    legacyPeers = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE sub_id = ? AND enabled = 1', sub.id);
    pack = { lines: [], clash: [], count: 0 };
    var li, L;
    for (li = 0; li < legacyPeers.length; li++) {
      if (!peerAlive(legacyPeers[li])) continue;
      L = peerLinks(legacyPeers[li], o);
      if (L.vless) pack.lines.push(L.vless);
      if (L.trojan) pack.lines.push(L.trojan);
      pack.clash.push({ name: legacyPeers[li].name, type: 'vless', uuid: legacyPeers[li].uuid, port: Number(legacyPeers[li].port)||443, tls: true });
    }
    pack.count = pack.lines.length;
  }
  var remark = subInfoRemark(sub, legacyPeers);
  if (blocked) { pack.lines = []; pack.clash = []; pack.count = 0; }
  if (!blocked && Number(sub.one_shot) && !Number(sub.burned) && request.method === 'GET') {
    try { await dbRun(env.DB, 'UPDATE vpn_subs SET burned = 1 WHERE id = ?', sub.id); } catch (eb) {}
  }
  var lines = [infoVless(remark)].concat(pack.lines);
  var body = lines.join('\n');
  var brand = sub.brand || sub.name || 'Ham';
  var expireUnix = sub.expire_at ? Math.floor(Date.parse(sub.expire_at) / 1000) : 0;
  var infoHdr = 'upload=0; download=' + u + '; total=' + (q || 0) + '; expire=' + expireUnix;
  var subHdrs = {
    'cache-control': 'no-store, no-cache, must-revalidate',
    'profile-update-interval': '1',
    'subscription-userinfo': infoHdr,
    'announce': remark,
    'profile-title': 'base64:' + btoa(unescape(encodeURIComponent(brand)))
  };
  if (fmt === 'clash' || fmt === 'clashmeta') {
    var yaml = 'proxies:\n';
    yaml += '  - { name: ' + JSON.stringify(remark) + ', type: vless, server: 127.0.0.1, port: 80, uuid: 00000000-0000-0000-0000-000000000001, tls: false, network: tcp, udp: false }\n';
    var i, c, row;
    var names = [JSON.stringify(remark)];
    for (i = 0; i < pack.clash.length; i++) {
      c = pack.clash[i];
      row = '  - { name: ' + JSON.stringify(c.name) + ', type: ' + c.type + ', server: ' + (c.server || o.host) + ', port: ' + c.port + ', ' + (c.type === 'vless' ? ('uuid: ' + c.uuid) : ('password: ' + JSON.stringify(c.password))) + ', tls: ' + (c.tls ? 'true' : 'false') + ', network: ws, udp: false, client-fingerprint: ' + o.fp + ', servername: ' + o.sni + ', ws-opts: { path: ' + o.path + ', headers: { Host: ' + o.wsHost + ' } }';
      if (Number(sub.mux)) row += ', smux: { enabled: true }';
      row += ' }\n';
      yaml += row;
      names.push(JSON.stringify(c.name));
    }
    yaml += 'proxy-groups:\n  - { name: ' + JSON.stringify(brand) + ', type: select, proxies: [' + names.join(', ') + '] }\n';
    subHdrs['content-type'] = 'text/yaml; charset=utf-8';
    return new Response(yaml, { headers: subHdrs });
  }
  if (fmt === 'singbox' || fmt === 'sing-box') {
    var outs = [];
    for (i = 0; i < pack.clash.length; i++) {
      c = pack.clash[i];
      var ob = {
        type: c.type,
        tag: c.name,
        server: c.server || o.host,
        server_port: c.port,
        tls: { enabled: !!c.tls, server_name: o.sni },
        transport: { type: 'ws', path: o.path, headers: { Host: o.wsHost } }
      };
      if (c.type === 'vless') ob.uuid = c.uuid;
      else ob.password = c.password;
      if (Number(sub.mux)) ob.multiplex = { enabled: true, protocol: 'h2mux', max_connections: 8 };
      outs.push(ob);
    }
    subHdrs['content-type'] = 'application/json; charset=utf-8';
    return new Response(JSON.stringify({ outbounds: outs }, null, 2), { headers: subHdrs });
  }
  var raw = url.searchParams.get('raw');
  subHdrs['content-type'] = 'text/plain; charset=utf-8';
  if (raw === '1') return new Response(body, { headers: subHdrs });
  return new Response(btoa(unescape(encodeURIComponent(body))), { headers: subHdrs });
}

function randPeerName() {
  var c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  var s = '', i;
  for (i = 0; i < 5; i++) s += c.charAt(Math.floor(Math.random() * c.length));
  return s;
}

async function tgApi(token, method, payload) {
  try {
    var r = await fetch('https://api.telegram.org/bot' + token + '/' + method, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    try { return await r.json(); } catch (eJ) { return { ok: false }; }
  } catch (e) { return { ok: false }; }
}

async function tgSendQr(token, chatId, link, caption) {
  var qr = 'https://api.qrserver.com/v1/create-qr-code/?size=320x320&ecc=M&margin=8&data=' + encodeURIComponent(link);
  await tgApi(token, 'sendPhoto', {
    chat_id: chatId,
    photo: qr,
    caption: String(caption || '').slice(0, 1024),
    reply_markup: tgMenu()
  });
}

function tgMenu() {
  return {
    keyboard: [
      [{ text: 'ساخت فیلترشکن' }, { text: 'مدیریت فیلترشکن' }],
      [{ text: 'آی‌پی پروکسی' }, { text: 'وضعیت پنل' }],
      [{ text: 'پشتیبان' }]
    ],
    resize_keyboard: true
  };
}


function parseQuotaToken(text) {
  var s = faDigitsToEn(String(text || '').trim());
  if (/نامحدود|∞/.test(s) && !/\d/.test(s)) return 0;
  var n = parseFloat(s.replace(/[^0-9.]/g, ''));
  if (isNaN(n) || n < 0) n = 0;
  if (n > 50) n = 50;
  return n;
}

function parseDaysToken(text) {
  var s = faDigitsToEn(String(text || '').trim());
  if (/ماه/.test(s)) {
    if (/4/.test(s)) return 120;
    if (/3/.test(s)) return 90;
    if (/2/.test(s)) return 60;
    return 30;
  }
  if (/نامحدود|∞/.test(s) && !/\d/.test(s)) return 0;
  var n = parseInt(s.replace(/[^0-9]/g, ''), 10);
  if (isNaN(n) || n < 0) n = 0;
  if (n > 120) n = 120;
  return n;
}

function tgGridKb(from, to, cols, extraRow) {
  var kb = [];
  var row = [];
  var i, lab;
  for (i = from; i <= to; i++) {
    lab = i === 0 ? '0 ∞' : String(i);
    row.push({ text: lab });
    if (row.length === cols) { kb.push(row); row = []; }
  }
  if (row.length) kb.push(row);
  if (extraRow && extraRow.length) kb.push(extraRow);
  return { keyboard: kb, resize_keyboard: true, one_time_keyboard: true };
}

async function tgFlowGet(db) {
  try { return JSON.parse(await settingGet(db, 'tg_flow') || '{}') || {}; } catch (e) { return {}; }
}
async function tgFlowSet(db, obj) {
  await settingSet(db, 'tg_flow', JSON.stringify(obj || {}));
}
async function panelBrand(db) {
  var n = '';
  try { n = String(await settingGet(db, 'panel_name') || '').trim(); } catch (e) {}
  return n || 'Ham';
}

async function pingIpWorker(ip) {
  var t0 = Date.now();
  function timed(p, ms) {
    return Promise.race([p, new Promise(function (res) { setTimeout(function () { res(null); }, ms); })]);
  }
  try {
    var ctrl = new AbortController();
    var tid = setTimeout(function () { try { ctrl.abort(); } catch (eA) {} }, 2200);
    var res = await timed(fetch('http://' + ip + '/cdn-cgi/trace', { method: 'GET', redirect: 'manual', signal: ctrl.signal }), 2200);
    clearTimeout(tid);
    if (res) return { ip: ip, ok: true, ms: Date.now() - t0 };
  } catch (e1) {}
  return { ip: ip, ok: false, ms: Date.now() - t0 };
}

function tgIpKb(ips) {
  var kb = [];
  var i;
  for (i = 0; i < ips.length; i++) {
    kb.push([
      { text: ips[i], callback_data: 'ipnoop' },
      { text: 'تست', callback_data: 'iptest:' + i },
      { text: 'حذف', callback_data: 'ipdel:' + i }
    ]);
  }
  kb.push([{ text: 'افزودن آی‌پی', callback_data: 'ipadd' }, { text: 'تست همه', callback_data: 'iptestall' }]);
  return { inline_keyboard: kb };
}

function tgShareBtn(link) {
  return {
    inline_keyboard: [[{ text: 'ارسال برای کسی', url: 'https://t.me/share/url?url=' + encodeURIComponent(link) }]]
  };
}

function tgConfirmKb(action, id) {
  return {
    inline_keyboard: [[
      { text: 'بله، تأیید', callback_data: 'ok:' + action + ':' + id },
      { text: 'انصراف', callback_data: 'cancel' }
    ]]
  };
}

function tgRemainText(row, kind) {
  var used = fmtBytes(row.used_bytes || 0);
  var q = Number(row.quota_bytes) || 0;
  var qh = q > 0 ? fmtBytes(q) : '∞';
  var left = q > 0 ? fmtBytes(Math.max(0, q - (Number(row.used_bytes) || 0))) : '∞';
  var d = remainDays(row.expire_at);
  var ds = d < 0 ? 'نامحدود' : (String(d) + ' روز');
  return (row.name || kind) + '\nزمان مانده: ' + ds + '\nحجم مانده: ' + left + ' از ' + qh + '\nمصرف شده: ' + used;
}

async function handleTelegram(request, env, url) {
  if (request.method === 'GET' || request.method === 'HEAD') return json({ ok: true, hook: 'hamtg' });
  if (!hasDB(env)) return json({ ok: true });
  var token = await settingGet(env.DB, 'tg_token');
  if (!token) return json({ ok: true });
  var body = await readJson(request);
  if (!body) return json({ ok: true });
  var msg = body.message;
  var cq = body.callback_query;
  var chatId = '';
  var text = '';
  var fromCb = '';
  if (cq) {
    chatId = String((cq.message && cq.message.chat && cq.message.chat.id) || '');
    fromCb = String(cq.data || '');
    await tgApi(token, 'answerCallbackQuery', { callback_query_id: cq.id });
  } else if (msg && msg.chat) {
    chatId = String(msg.chat.id);
    text = String(msg.text || '').trim();
  } else return json({ ok: true });
  if (!chatId) return json({ ok: true });
  var allow = String(await settingGet(env.DB, 'tg_chat') || '').trim();
  if (!allow) return json({ ok: true });
  var okc = allow.split(/[\s,]+/).filter(Boolean);
  if (okc.indexOf(chatId) === -1) return json({ ok: true });
  try {
    await ensureVpn(env.DB);
    var o = await proxySettings(env.DB, url.hostname);
    async function send(txt, extra) {
      await tgApi(token, 'sendMessage', { chat_id: chatId, text: txt, reply_markup: extra || tgMenu() });
    }
    async function proxyIpList() {
      return parseIpLines(await settingGet(env.DB, 'proxy_ips'));
    }
    async function saveProxyIps(arr) {
      await settingSet(env.DB, 'proxy_ips', arr.join('\n'));
    }
    var commands = {
      'ساخت فیلترشکن': 1, 'مدیریت فیلترشکن': 1, 'وضعیت پنل': 1, 'پشتیبان': 1,
      'آی‌پی پروکسی': 1,
      '/start': 1, '/help': 1, 'شروع': 1, 'منو': 1, '/vpn': 1
    };
    if (text && commands[text]) await tgFlowSet(env.DB, {});
    var flow = await tgFlowGet(env.DB);
    if (flow && flow.chat && String(flow.chat) !== chatId) flow = {};
    if (flow && flow.at && Date.now() - Number(flow.at) > 10 * 60 * 1000) { flow = {}; await tgFlowSet(env.DB, {}); }
    if (text && flow && flow.act && !fromCb && !commands[text]) {
      if (flow.act === 'mkvpn') {
        var st = flow.step || 'name';
        if (st === 'name') {
          var nm = String(text).trim().slice(0, 40);
          if (nm === 'تصادفی' || nm === 'random' || nm === '-') nm = randPeerName();
          if (!nm) { await send('اسم خالی است.'); return json({ ok: true }); }
          flow.name = nm;
          flow.step = 'quota';
          flow.at = Date.now();
          await tgFlowSet(env.DB, flow);
          await send('از منوی زیر حجم را انتخاب کنید (گیگابایت).\n۰ = نامحدود', tgGridKb(0, 50, 5));
          return json({ ok: true });
        }
        if (st === 'quota') {
          var qn = parseQuotaToken(text);
          flow.quota = qn;
          flow.step = 'days';
          flow.at = Date.now();
          await tgFlowSet(env.DB, flow);
          await send('از منوی زیر مدت را انتخاب کنید (روز).\n۰ = نامحدود', tgGridKb(0, 120, 8, [{ text: '۱ ماهه' }, { text: '۲ ماهه' }, { text: '۳ ماهه' }, { text: '۴ ماهه' }]));
          return json({ ok: true });
        }
        if (st === 'days') {
          var ds = parseDaysToken(text);
          flow.days = ds;
          flow.step = 'ip';
          flow.at = Date.now();
          await tgFlowSet(env.DB, flow);
          var iplm = await proxyIpList();
          await send('آی‌پی خروجی را انتخاب کنید (یا «بدون» را تایپ کنید):', {
            inline_keyboard: (function () {
              var kb = [[{ text: 'خروجی مستقیم', callback_data: 'mkip:direct' }]];
              var ii;
              for (ii = 0; ii < iplm.length && ii < 20; ii++) kb.push([{ text: iplm[ii], callback_data: 'mkip:' + ii }]);
              return kb;
            })()
          });
          return json({ ok: true });
        }
        if (st === 'ip') {
          var ipm = String(text).trim();
          if (ipm === '-' || ipm === 'بدون' || ipm === 'none' || ipm === 'مستقیم') ipm = '';
          else ipm = parseIpLines(ipm).slice(0, 1).join(',');
          flow.ip = ipm;
          flow.at = Date.now();
          await tgFlowSet(env.DB, flow);
          fromCb = 'mkip:go';
        } else {
          await send('از منو دوباره شروع کنید.');
          return json({ ok: true });
        }
      }
      if (flow.act === 'ipadd') {
        var added = parseIpLines(text);
        if (!added.length) { await send('آی‌پی معتبر نبود. هر خط یک IPv4 بفرستید یا منو را بزنید.'); return json({ ok: true }); }
        var cur = await proxyIpList();
        var a;
        for (a = 0; a < added.length; a++) if (cur.indexOf(added[a]) === -1) cur.push(added[a]);
        await saveProxyIps(cur);
        await tgFlowSet(env.DB, {});
        await send('اضافه شد. تعداد: ' + cur.length, tgIpKb(cur));
        return json({ ok: true });
      }
      if (flow.act === 'edit' && flow.id) {
        var erow = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', flow.id);
        if (!erow) { await tgFlowSet(env.DB, {}); await send('پیدا نشد'); return json({ ok: true }); }
        var fld = flow.field;
        if (fld === 'name') {
          var nn = String(text).trim().slice(0, 40);
          if (!nn) { await send('نام خالی است.'); return json({ ok: true }); }
          await dbRun(env.DB, 'UPDATE vpn_peers SET name = ? WHERE id = ?', nn, flow.id);
        } else if (fld === 'quota') {
          await dbRun(env.DB, 'UPDATE vpn_peers SET quota_bytes = ? WHERE id = ?', gbToBytes(text), flow.id);
        } else if (fld === 'days') {
          await dbRun(env.DB, 'UPDATE vpn_peers SET expire_at = ? WHERE id = ?', daysToExpire(text), flow.id);
        } else if (fld === 'uuid') {
          var nuu = String(text).trim().toLowerCase();
          if (nuu === 'random' || nuu === 'تصادفی') nuu = crypto.randomUUID();
          if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nuu)) {
            await send('UUID نامعتبر. یک UUID بفرستید یا بنویسید: تصادفی');
            return json({ ok: true });
          }
          try { await dbRun(env.DB, 'UPDATE vpn_peers SET uuid = ? WHERE id = ?', nuu, flow.id); }
          catch (eU) { await send('این UUID تکراری است.'); return json({ ok: true }); }
        } else if (fld === 'port') {
          await dbRun(env.DB, 'UPDATE vpn_peers SET port = ? WHERE id = ?', String(cleanPorts(text, true)[0] || '443'), flow.id);
        } else if (fld === 'ip') {
          var ipone = String(text).trim();
          if (ipone === '-' || ipone === 'none' || ipone === 'خالی' || ipone === 'بدون') ipone = '';
          else ipone = parseIpLines(ipone).slice(0, 1).join(',');
          await dbRun(env.DB, 'UPDATE vpn_peers SET ips = ? WHERE id = ?', ipone, flow.id);
        } else {
          await send('فیلد نامعتبر');
          await tgFlowSet(env.DB, {});
          return json({ ok: true });
        }
        await tgFlowSet(env.DB, {});
        var after = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', flow.id);
        await send('ذخیره شد.\n' + tgRemainText(after, 'vpn') + (after.ips ? ('\nپروکسی: ' + after.ips) : '\nپروکسی: مستقیم'));
        return json({ ok: true });
      }
    }
    async function pickList(kind, prefix) {
      var rows, i, kb = [];
      if (kind === 'vpn') rows = await dbAll(env.DB, 'SELECT id, name FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0 ORDER BY id DESC LIMIT 20');
      else rows = await dbAll(env.DB, 'SELECT id, name FROM vpn_subs ORDER BY id DESC LIMIT 20');
      if (!rows.length) { await send('موردی نیست.'); return; }
      for (i = 0; i < rows.length; i++) kb.push([{ text: rows[i].name, callback_data: prefix + rows[i].id }]);
      await tgApi(token, 'sendMessage', { chat_id: chatId, text: 'یکی را انتخاب کنید:', reply_markup: { inline_keyboard: kb } });
    }
    var brand = await panelBrand(env.DB);
    if (text === '/start' || text === '/help' || text === 'شروع' || text === 'منو') {
      await send('منوی ' + brand + ' آماده است. از دکمه‌ها استفاده کنید.');
      return json({ ok: true });
    }
    if (text === 'ساخت فیلترشکن' || text === '/vpn') {
      await tgFlowSet(env.DB, { chat: chatId, act: 'mkvpn', step: 'name', at: Date.now() });
      await send('اسم کانفیگ را بفرستید.\nبرای اسم تصادفی بنویسید: تصادفی');
      return json({ ok: true });
    }
    if (text === 'ساخت سابسکراپشن' || text === '/sub' || text === 'لینک سابسکراپشن') {
      await send('در نسخه ۱ سابسکراپشن نیست. از ساخت فیلترشکن استفاده کنید.');
      return json({ ok: true });
    }
    if (false && (text === 'ساخت سابسکراپشن-off')) {
      var sname = String.fromCharCode(65 + Math.floor(Math.random() * 26)) + Math.floor(1000 + Math.random() * 9000);
      var suuid = crypto.randomUUID();
      var stok = randomToken().slice(0, 24);
      await dbRun(
        env.DB,
        'INSERT INTO vpn_subs (token, name, protocols, created_at, expire_at, quota_bytes, uuid, trojan_pass, ports, location, max_ip, used_bytes, enabled, fragment, mux, brand, logo) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 0, 0, 1, 0, 0, ?, ?)',
        stok, sname, 'vless,trojan', nowIso(), daysToExpire(30), suuid, suuid, '443', pickLoc('random'), sname, ''
      );
      var surl = url.origin + '/sub/' + stok;
      await send('ساب ساخته شد: ' + sname + '\n۳۰ روز · حجم نامحدود\n\n' + surl, tgShareBtn(surl));
      return json({ ok: true });
    }
    if (text === 'وضعیت پنل') {
      var pc = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
      var sc = await dbFirst(env.DB, 'SELECT COUNT(*) AS c FROM vpn_subs');
      var usedp = await dbFirst(env.DB, 'SELECT SUM(used_bytes) AS s FROM vpn_peers');
      var useds = await dbFirst(env.DB, 'SELECT SUM(used_bytes) AS s FROM vpn_subs');
      var tot = (Number(usedp && usedp.s) || 0) + (Number(useds && useds.s) || 0);
      await send('وضعیت ' + brand + '\nفیلترشکن: ' + ((pc && pc.c) || 0) + '\nمصرف کل: ' + fmtBytes(tot));
      return json({ ok: true });
    }
    if (text === 'باقیمانده') {
      await pickList('sub', 'rem:');
      return json({ ok: true });
    }
    if (text === 'مدیریت فیلترشکن' || fromCb === 'listvpn') { await pickList('vpn', 'mgmt:'); return json({ ok: true }); }
    if (fromCb.indexOf('mgmt:') === 0) {
      var mid = parseInt(fromCb.slice(5), 10);
      var mp = await dbFirst(env.DB, 'SELECT id, name FROM vpn_peers WHERE id = ?', mid);
      if (!mp) { await send('پیدا نشد'); return json({ ok: true }); }
      await send('مدیریت «' + mp.name + '» — یک گزینه را بزنید:', {
        inline_keyboard: [
          [{ text: 'لینک فیلترشکن', callback_data: 'gvpn:' + mid }],
          [{ text: 'ویرایش', callback_data: 'edvpn:' + mid }],
          [{ text: 'خاموش/روشن', callback_data: 'tog:' + mid }, { text: 'حذف', callback_data: 'delv:' + mid }]
        ]
      });
      return json({ ok: true });
    }
    if (text === 'لینک فیلترشکن') { await pickList('vpn', 'gvpn:'); return json({ ok: true }); }
    if (text === 'لینک سابسکراپشن' || fromCb === 'listsub') { await pickList('sub', 'gsub:'); return json({ ok: true }); }
    if (text === 'خاموش/روشن') { await pickList('vpn', 'tog:'); return json({ ok: true }); }
    if (text === 'ریست ترافیک') { await pickList('sub', 'rsts:'); return json({ ok: true }); }
    if (text === 'تمدید ۳۰ روز') { await pickList('sub', 'ext:'); return json({ ok: true }); }
    if (text === 'حذف') { await pickList('vpn', 'delv:'); return json({ ok: true }); }
    if (text === 'ارسال برای کسی') {
      await send('لینک را بگیرید، بعد دکمه «ارسال برای کسی» زیر همان پیام را بزنید.');
      return json({ ok: true });
    }
    if (fromCb.indexOf('gvpn:') === 0) {
      var vid = parseInt(fromCb.slice(5), 10);
      var pr2 = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', vid);
      if (!pr2) { await send('پیدا نشد'); return json({ ok: true }); }
      var L2 = peerLinks(pr2, o);
      var link2 = L2.vless || '';
      await tgSendQr(token, chatId, link2, tgRemainText(pr2, 'vpn') + '\n\n' + link2);
      return json({ ok: true });
    }
    if (fromCb.indexOf('gsub:') === 0) {
      var sid = parseInt(fromCb.slice(5), 10);
      var su = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE id = ?', sid);
      if (!su) { await send('پیدا نشد'); return json({ ok: true }); }
      var surl2 = url.origin + '/sub/' + su.token + (su.sub_pass ? ('/' + su.sub_pass) : '');
      var st2 = url.origin + '/st/' + su.token;
      await send(tgRemainText(su, 'sub') + '\nوضعیت: ' + st2 + '\n\n' + surl2, tgShareBtn(surl2));
      return json({ ok: true });
    }
    if (fromCb.indexOf('rem:') === 0) {
      var rid = parseInt(fromCb.slice(4), 10);
      var rr = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE id = ?', rid);
      if (!rr) rr = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', rid);
      if (!rr) { await send('پیدا نشد'); return json({ ok: true }); }
      await send(tgRemainText(rr, 'item'));
      return json({ ok: true });
    }
    if (fromCb.indexOf('tog:') === 0) {
      var tid = parseInt(fromCb.slice(4), 10);
      await send('خاموش/روشن این فیلترشکن؟ دوباره تأیید کنید.', tgConfirmKb('tog', tid));
      return json({ ok: true });
    }
    if (fromCb.indexOf('rsts:') === 0) {
      var rsid = parseInt(fromCb.slice(5), 10);
      await send('ریست ترافیک این ساب؟ دوباره تأیید کنید.', tgConfirmKb('rsts', rsid));
      return json({ ok: true });
    }
    if (fromCb.indexOf('ext:') === 0) {
      var eid = parseInt(fromCb.slice(4), 10);
      await send('تمدید ۳۰ روز این ساب؟ دوباره تأیید کنید.', tgConfirmKb('ext', eid));
      return json({ ok: true });
    }
    if (fromCb.indexOf('delv:') === 0) {
      var did = parseInt(fromCb.slice(5), 10);
      await send('حذف این فیلترشکن؟ این کار برگشت ندارد. دوباره تأیید کنید.', tgConfirmKb('delv', did));
      return json({ ok: true });
    }
    if (fromCb === 'cancel') {
      await send('لغو شد.');
      return json({ ok: true });
    }
    if (fromCb.indexOf('ok:') === 0) {
      var bits = fromCb.split(':');
      var act = bits[1] || '';
      var oid = parseInt(bits[2], 10);
      if (act === 'tog') {
        var tp = await dbFirst(env.DB, 'SELECT enabled, name FROM vpn_peers WHERE id = ?', oid);
        if (!tp) { await send('پیدا نشد'); return json({ ok: true }); }
        var nen = tp.enabled ? 0 : 1;
        await dbRun(env.DB, 'UPDATE vpn_peers SET enabled = ? WHERE id = ?', nen, oid);
        await send(tp.name + (nen ? ' روشن شد' : ' خاموش شد'));
      } else if (act === 'rsts') {
        await dbRun(env.DB, 'UPDATE vpn_subs SET used_bytes = 0 WHERE id = ?', oid);
        await send('ترافیک این ساب صفر شد. با بروزرسانی ساب در اپ، حجم مانده به‌روز می‌شود.');
      } else if (act === 'ext') {
        await dbRun(env.DB, 'UPDATE vpn_subs SET expire_at = ? WHERE id = ?', daysToExpire(30), oid);
        await send('۳۰ روز از امروز تمدید شد. با بروزرسانی ساب در اپ، زمان مانده به‌روز می‌شود.');
      } else if (act === 'delv') {
        await dbRun(env.DB, 'DELETE FROM vpn_peers WHERE id = ?', oid);
        await send('حذف شد.');
      } else await send('عملیات نامعتبر');
      return json({ ok: true });
    }
    if (text === 'گزارش امروز') {
      var day = new Date().toISOString().slice(0, 10);
      var rowsU = [];
      try { rowsU = await dbAll(env.DB, 'SELECT * FROM vpn_usage WHERE day = ? ORDER BY bytes DESC LIMIT 15', day); } catch (eu) {}
      var tu = 'گزارش مصرف ' + day + '\n';
      var iu;
      for (iu = 0; iu < rowsU.length; iu++) tu += rowsU[iu].kind + ' #' + rowsU[iu].owner_id + ' · ' + fmtBytes(rowsU[iu].bytes) + '\n';
      if (!rowsU.length) tu += 'هنوز مصرفی ثبت نشده';
      await send(tu);
      return json({ ok: true });
    }
    if (text === 'پشتیبان') {
      await handleCron(env, null);
      await send('پشتیبان و گزارش دیروز ارسال شد (اگر بات وصل باشد).');
      return json({ ok: true });
    }
    if (text === 'آی‌پی پروکسی' || fromCb === 'iplist') {
      var ipl = await proxyIpList();
      if (!ipl.length) {
        await tgFlowSet(env.DB, { chat: chatId, act: 'ipadd', at: Date.now() });
        await send('لیست خالی است. هر خط یک آی‌پی بفرستید.');
      } else await send('آی‌پی‌های پروکسی خروجی (بعد از وصل، نه داخل لینک):', tgIpKb(ipl));
      return json({ ok: true });
    }
    if (fromCb === 'ipadd') {
      await tgFlowSet(env.DB, { chat: chatId, act: 'ipadd', at: Date.now() });
      await send('آی‌پی را بفرستید. هر خط یکی. برای لغو منو را بزنید.');
      return json({ ok: true });
    }
    if (fromCb === 'ipnoop') return json({ ok: true });
    if (fromCb.indexOf('ipdel:') === 0) {
      var di = parseInt(fromCb.slice(6), 10);
      var ipl2 = await proxyIpList();
      if (di >= 0 && di < ipl2.length) ipl2.splice(di, 1);
      await saveProxyIps(ipl2);
      await send('حذف شد. مانده: ' + ipl2.length, ipl2.length ? tgIpKb(ipl2) : tgMenu());
      return json({ ok: true });
    }
    if (fromCb.indexOf('iptest:') === 0) {
      var ti2 = parseInt(fromCb.slice(7), 10);
      var ipl3 = await proxyIpList();
      if (ti2 < 0 || ti2 >= ipl3.length) { await send('پیدا نشد'); return json({ ok: true }); }
      await send('تست ' + ipl3[ti2] + ' …');
      var prp = await pingIpWorker(ipl3[ti2]);
      await send(ipl3[ti2] + ' → ' + (prp.ok ? (prp.ms + ' ms') : 'N/A'), tgIpKb(ipl3));
      return json({ ok: true });
    }
    if (fromCb === 'iptestall') {
      var ipl4 = await proxyIpList();
      if (!ipl4.length) { await send('لیستی نیست.'); return json({ ok: true }); }
      await send('تست ' + ipl4.length + ' آی‌پی …');
      var lines = [], zi, zr;
      for (zi = 0; zi < ipl4.length; zi++) {
        zr = await pingIpWorker(ipl4[zi]);
        lines.push(ipl4[zi] + ' → ' + (zr.ok ? (zr.ms + ' ms') : 'N/A'));
      }
      await send(lines.join('\n'), tgIpKb(ipl4));
      return json({ ok: true });
    }
    if (fromCb.indexOf('edvpn:') === 0) {
      var eid2 = parseInt(fromCb.slice(6), 10);
      var ep = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', eid2);
      if (!ep) { await send('پیدا نشد'); return json({ ok: true }); }
      await send('ویرایش «' + ep.name + '»\nUUID: ' + (ep.uuid || '') + '\nپورت: ' + (ep.port || '443') + '\nپروکسی: ' + (ep.ips || 'مستقیم'), {
        inline_keyboard: [
          [{ text: 'نام', callback_data: 'edf:' + eid2 + ':name' }, { text: 'حجم GB', callback_data: 'edf:' + eid2 + ':quota' }],
          [{ text: 'روز', callback_data: 'edf:' + eid2 + ':days' }, { text: 'UUID', callback_data: 'edf:' + eid2 + ':uuid' }],
          [{ text: 'پورت', callback_data: 'edf:' + eid2 + ':port' }, { text: 'آی‌پی خروجی', callback_data: 'edf:' + eid2 + ':ip' }],
          [{ text: 'بازگشت', callback_data: 'mgmt:' + eid2 }]
        ]
      });
      return json({ ok: true });
    }
    if (fromCb.indexOf('edf:') === 0) {
      var ebits = fromCb.split(':');
      var eid3 = parseInt(ebits[1], 10);
      var efield = ebits[2] || '';
      var epr = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE id = ?', eid3);
      if (!epr) { await send('پیدا نشد'); return json({ ok: true }); }
      await tgFlowSet(env.DB, { chat: chatId, act: 'edit', id: eid3, field: efield, at: Date.now() });
      var ask = 'مقدار جدید را بفرستید.';
      if (efield === 'name') ask = 'نام جدید را بفرستید.';
      if (efield === 'quota') ask = 'حجم به گیگ (۰ = نامحدود).';
      if (efield === 'days') ask = 'تعداد روز از امروز (۰ = نامحدود).';
      if (efield === 'uuid') ask = 'UUID جدید یا بنویسید: تصادفی\nفعلی: ' + epr.uuid;
      if (efield === 'port') ask = 'پورت (443 / 2053 / 2083 / …). فعلی: ' + (epr.port || '443');
      if (efield === 'ip') ask = 'یک آی‌پی خروجی بفرستید، یا «بدون» برای خروجی مستقیم.\nفعلی: ' + (epr.ips || 'مستقیم');
      await send(ask);
      return json({ ok: true });
    }
    if (fromCb.indexOf('mkip:') === 0 || fromCb === 'mkip:go') {
      var fl = await tgFlowGet(env.DB);
      if (!fl || fl.act !== 'mkvpn' || String(fl.chat) !== chatId) {
        await send('ساخت منقضی شد. دوباره «ساخت فیلترشکن» را بزنید.');
        return json({ ok: true });
      }
      var pickIp = '';
      if (fromCb === 'mkip:go') pickIp = fl.ip || '';
      else if (fromCb === 'mkip:direct') pickIp = '';
      else {
        var ixx = parseInt(fromCb.slice(5), 10);
        var ipls = await proxyIpList();
        if (ixx >= 0 && ixx < ipls.length) pickIp = ipls[ixx];
      }
      var vname2 = fl.name || randPeerName();
      var vuuid2 = crypto.randomUUID();
      await dbRun(
        env.DB,
        'INSERT INTO vpn_peers (name, uuid, trojan_pass, protocols, quota_bytes, used_bytes, expire_at, max_ip, location, port, fragment, mux, ips, enabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, ?, 0, 0, ?, 1, ?)',
        vname2, vuuid2, vuuid2, 'vless', gbToBytes(fl.quota), daysToExpire(fl.days), pickLoc('random'), '443', pickIp, nowIso()
      );
      try { await dbRun(env.DB, 'UPDATE vpn_peers SET remark = ? WHERE uuid = ?', '', vuuid2); } catch (er2) {}
      await tgFlowSet(env.DB, {});
      var prn = await dbFirst(env.DB, 'SELECT * FROM vpn_peers WHERE uuid = ?', vuuid2);
      var Ln = peerLinks(prn, o);
      var linkn = Ln.vless || '';
      var cap = 'ساخته شد: ' + vname2 + '\n' + tgRemainText(prn, 'vpn') + (pickIp ? ('\nپروکسی: ' + pickIp) : '\nخروجی: مستقیم') + '\n\n' + linkn;
      await tgSendQr(token, chatId, linkn, cap);
      return json({ ok: true });
    }
    await send('از منوی پایین یک گزینه بزنید.');
  } catch (e) {
    await tgApi(token, 'sendMessage', { chat_id: chatId, text: 'خطا: ' + String(e && e.message ? e.message : e), reply_markup: tgMenu() });
  }
  return json({ ok: true });
}

async function handleStatus(request, env, url) {
  if (!hasDB(env)) return new Response('no db', { status: 500 });
  await ensureVpn(env.DB);
  var token = url.pathname.split('/').filter(Boolean)[1] || '';
  var sub = await dbFirst(env.DB, 'SELECT * FROM vpn_subs WHERE token = ?', token);
  if (!sub) return new Response('not found', { status: 404 });
  var q = Number(sub.quota_bytes) || 0;
  var u = Number(sub.used_bytes) || 0;
  var left = q > 0 ? Math.max(0, q - u) : 0;
  var d = remainDays(sub.expire_at);
  var html = '<!DOCTYPE html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ham</title><body style="font-family:Vazirmatn,Tahoma,sans-serif;background:#0b0d12;color:#eef1f8;margin:0;padding:32px"><div style="max-width:420px;margin:40px auto;background:#161a24;border-radius:16px;padding:24px"><h2 style="margin:0 0 12px">' + String(sub.name || 'Ham').replace(/</g,'') + '</h2><p>زمان مانده: <b>' + (d < 0 ? '∞' : (d + ' روز')) + '</b></p><p>حجم مانده: <b>' + (q > 0 ? fmtBytes(left) + ' / ' + fmtBytes(q) : '∞') + '</b></p><p>مصرف: ' + fmtBytes(u) + '</p></div></body></html>';
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

async function handleCron(env, ctx) {
  if (!hasDB(env)) return;
  RUNTIME_ENV = env;
  await ensureVpn(env.DB);
  try {
    var can = await settingGet(env.DB, 'canary');
    if (!can) await settingSet(env.DB, 'canary', randomToken());
    else {
      var raw = await dbFirst(env.DB, 'SELECT value FROM settings WHERE key = ?', 'canary');
      if (!raw || !raw.value) {
        try { await tgSend(env, ctx, 'هشدار canary: ردیف تله در settings نیست'); } catch (eCy) {}
      }
    }
  } catch (eC0) {}
  var token = await settingGet(env.DB, 'tg_token');
  var chat = await settingGet(env.DB, 'tg_chat');
  if (!token || !chat) return;
  var peers = await dbAll(env.DB, 'SELECT * FROM vpn_peers WHERE sub_id IS NULL OR sub_id = 0');
  var subs = await dbAll(env.DB, 'SELECT * FROM vpn_subs');
  var ai;
  for (ai = 0; ai < peers.length; ai++) {
    try { await maybeAlert(env, ctx, peers[ai], 'peer'); } catch (eA) {}
  }
  var payload = JSON.stringify({ ham: 1, exported_at: nowIso(), peers: peers, subs: subs });
  try {
    var fd = new FormData();
    fd.append('chat_id', chat);
    fd.append('caption', 'پشتیبان خودکار Ham');
    fd.append('document', new Blob([payload], { type: 'application/json' }), 'ham-backup.json');
    await fetch('https://api.telegram.org/bot' + token + '/sendDocument', { method: 'POST', body: fd });
  } catch (e) {}
  try {
    var day = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    var rows = await dbAll(env.DB, 'SELECT * FROM vpn_usage WHERE day = ? ORDER BY bytes DESC LIMIT 20', day);
    var text = 'گزارش مصرف ' + day + '\n';
    var i;
    for (i = 0; i < rows.length; i++) text += rows[i].kind + ' #' + rows[i].owner_id + ' · ' + fmtBytes(rows[i].bytes) + '\n';
    if (!rows.length) text += 'موردی نبود';
    await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chat, text: text })
    });
  } catch (e2) {}
}

async function handleRequest(request, env, ctx) {
  var url = new URL(request.url);
  var upg = (request.headers.get('Upgrade') || '').toLowerCase();
  if (upg === 'websocket') {
    try {
      return await handleVpnUpgrade(request, env, ctx, url);
    } catch (e) {
      return new Response('tunnel error', { status: 500 });
    }
  }
  var panel = '/dash';
  var camouflage = 'https://ubuntu.com/';
  if (hasDB(env)) {
    try {
      var pp = await settingGet(env.DB, 'panel_path');
      if (pp) panel = normPath(pp);
      var cu = await settingGet(env.DB, 'camouflage_url');
      if (cu && /^https?:\/\//.test(cu)) camouflage = cu;
      else camouflage = CAMO_URL;
    } catch (e) {}
  }
  if (url.pathname.indexOf('/sub/') === 0) {
    try { return await handleSub(request, env, url); } catch (e) { return new Response('sub error', { status: 500 }); }
  }
  if (url.pathname.indexOf('/st/') === 0) {
    try { return await handleStatus(request, env, url); } catch (e) { return new Response('status error', { status: 500 }); }
  }
  if (url.pathname === '/hamtg' || url.pathname === '/hamtg/') {
    try { return await handleTelegram(request, env, url); } catch (e) { return json({ ok: true }); }
  }
  var onPanel = url.pathname === panel || url.pathname === panel + '/' || url.pathname.indexOf(panel + '/') === 0;
  if (onPanel && !(await panelAllow(env, request))) {
    return Response.redirect(camouflage, 302);
  }
  var apiPrefix = panel + '/api/';
  if (url.pathname.indexOf(apiPrefix) === 0) {
    var apiUrl = new URL(request.url);
    apiUrl.pathname = url.pathname.slice(panel.length) || '/';
    try {
      return await handleApi(request, env, apiUrl);
    } catch (e) {
      return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
    }
  }
  if (url.pathname === panel || url.pathname === panel + '/' || url.pathname.indexOf(panel + '/') === 0) {
    return new Response(HTML, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'same-origin',
        'x-frame-options': 'DENY',
        'cache-control': 'no-store'
      }
    });
  }
  return Response.redirect(camouflage, 302);
}

const HTML = String.raw`<!DOCTYPE html>
<html lang="fa" dir="rtl" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ham</title>
<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAUDklEQVR42rWba6xkWVXHf2vvU6eq7r3d9/b0u2/PTA8OARl5RiLIU50goAQUTYQvApIAIQIRAhImksjTMXxyvvCBEEhEjUYFDUYBRRQQwiDMjMzDcaZnpt99u/u+q85j7+WHc+qcfR51eyChOp3cqnNq115rr8d//dc6snLgkBK8BKHzEqC6S9HyI4KPBWncF97Tfl/9Xd6vaGsH2lm7eQ+ISGPx9pqNPYe3KlRfVcWw16ulC622I2h5Ucp/4Y61ujp7p401paE97fxs/W2pFYtUG+o9JFonos23aPFfgr9BMB0ppb6u2t2jzoQob9ZARA2E1eqfdC1Ja0tCpEcgbVhbtfEeZXWUWn8LnX2ugUytr5qmcQqhrqWxXCCDtn9f2s4Qnl/zurTMq9cBCwsLVaM9J93eR7i2okjgApVMEiqicgFtGpbUlhCeTp/hiYTOF67VPHmZLTjX26RSuITrSssBpWc/reOV67hJuNNors9rXzypPV/Vo6o9wtM0+1nk6T1xrS8pzeAwR1naOnZRqRU8c2ENDqcnmIe2GjVDZDvi0whmsw0oShQNsFGMsREiUpuj7Bmiyk2VTqEabLIZcKrlVBvCqBbf86p49XjncC5DvS+tQ5qWIX3C1xeintjUYwzFmXr1WDtgOFpCTITzDq8Oda5ML9LcbGgbqogIMvNHKY5qdvDSCt2GQjmiihEw5SWn4EsxrTGojfAa4/KcLEvAe0TM3OwgLQuN6iAnnfslCIFePfFwETsYkeUZLpkWS4U+KdLI5FI6c2W2pbnWuUGb4bO0CCnDmKUQPiqVMZ06TGTRMkj6KgsJxkYMbUSWTvDelQruiZ4CErhBJw2KhCeold3Fo32IHZBMd/F5Vplyx9crYKOFu4Q+K+WO1IP6wFS1PGnFoER4BniG4lkwjgXjGE5Snv/0fSxGitHiPgn2512O944oHmNs1IkVYUANr0QSnIO0DF8QvDri4SIiliyZVtlhpl0toZUAGiTdVigpNqu13+tM8NKKDIpRsKJEKLF4RhFEPmdhN+fddzyDMxem3H3PNexiTO5nwU5LVZQB1XuMjQvlh5YwB0ZE2gatGsDP0ufFDMjSUnjVbphVbShtBpCq+ysVa4XEgrsQPAbBijJQz8h4FgYQJSmnFgzvves53PrsEb/50gcYLgzINMwSUmeT2fa9x9gBzrtC4d1QXn03aiWlFhoHG43IsrS4pq0MpaVAUvr8zPxbUFdUUQkxQh3ZDWBVseIZoIyMZ1+sxDsJL3jaft75qaey+gv7+LM33cPVbbALkGRaoVSvWlpenW29OgSDMQO8z1qeGkY3beGAVhg0NsJDGVQCJc0qCi3iWpmbyhgnDYgmM3hcQYbSIspgZFCsKLEoC1YZR8rSVsJrX3GIN3/iRkanck7/y+P8x1euYReHuEzxWps/COpL25Iavqt6jJgq2xC4eRj0o56arjZnE+Gdq9JVo/JS7U2boX7rXB/k+DIGGMAKDFCGoixGylg8R6aON7/jBL/23v3o9DJ6ZcyXP32ei6nBx4qrDFFaUFhRLavGKsUqhYpdAPKbwC7qAMFKEqnSn9IsAMIIWwlc/qg1Un0mJVI0UCrB18EOGIgyEs++AQxzx60jwzs/tsrzftuQPXGJwbFFHv3KJt/6doosRrjUUMa5Kuj5mTII3K+yEF8VQ/3lfRADwpI2NJhZuuooobWWaCHgxtY2xpogzxcpywALoxhrpIzyygjPUgyjSc7zbxrzrj85yo0/t03+wzVsnJE+vsBf/+kWj2/CFYStXGC0hEZxafY9KF9BRYOQLPNLZhSZESLtSCkCYmKc91VO74OqYfGSJCl3/NGHeflLXkia5hhTgKAosqxfu8Z73vZWku1NRgPD2Hj2DWG4lfPKFy7yjk/ewL7RBtlD69jF5yDPfB+7GzE/+hFsG2GSK1jLnR/9GPfedy+D0QKu9H0VwTcTbimDwYigPqslbNcDNSPU0lWpgNy5FiGgLWsofDpLUo4cP8ED99/HKLYdpZ8/d56XPvc2SKfsi4UF61ne9bzxDcu88YNj5PI18sc8cm4H86LP4J77FoTCVcLXr/7y7Xz7m//JwtI+cudRkQASzQJhhbdLBeSFfK2sLWE1GJbCqmWwlr6qrgmRi6BmSJKE4yeOYwxsb0+qBZ1zLC2OeeCB+5lsrHN8ZcxIHau55+1/uMLL3xThHroMax5z1cDDkL1gFdEcN0lIsXhVrLVsbe9w9swZoijCe984EK0wbhMXdGVoyhs1CARK7YWRtMr13ThAAHW9Tzl58iRxZElQjNiKPbTWcv7ME0imjL1y25Lj3R9e5Okvy8h+uIHZBdYVuaQ8ujYmj0/yVImYkCNiUHVEgwEbGxusX7uGMaaE2VSsUhi8dF492oMETTMpNMkEnVuHa8+6yqlTp4pT91pt0JffO3v6UZyHF696/vgTlqc/KyH7/iZm0yPrHr0IspPx9+cP4VeOoM7jvJJ7R+48YoQLFy+ytblZKYDACmcHU8FjfTL0mc4osZ6ioYF2tfMjjRPQwhyf8pSfKa57xXnF+3ojD/7faW4/Cne8STk8ysjvS7ATSuE9dqo8cV75xsYRThxeZppkeFWcU/LcgcDZs2eZplOMFNmpVoI2SVYNaTOdawxdRqhNW81MvIUBtPXe5Q4w3HLLqWrh2ckbEXZyOLl+hnc807BwFXIn2EUBB7oDfgvsSPjL7xmywyfYN47Z2NwpEJ9X8pJvOPP4E3jAyKx0lgARzty/jAUtAl86oUxnLtCuBrQqZFo0Tj89pUqe54wX9rG6ukqSuoKt8Yp3HjGWrc0tDlw8jd31cD6Faw532ZGtOSaXHXbbsXba8bl7Pas3n0CALMvxvnAD5xTn4dzZMwgz+Aw2LIkryRQNae3WiTeLKGkjQeml4irGqGNOxfssSzlx9BgHDx1iOk3xWrqFKgMTs72xRhIvMD14E9tjSMTjPfhcSRQOiPLlMwukx3Z4xjNvK3zfFRViEUcgzZUL584xAAwFouzyoTUjVQVC7YbEkOuM5ofLABmGJbUG5lUmC+8zjp84wdLSErs7u43EOk0SDhxY4a1/++/E1iAGxlKvtVSa+asdvBJF7ICr69sgBudKS/IwnaSsXTjLSGCAw4iSY0GlpMjCQ68D2Lwm0Syz9ZTDYUcghLlasa8aMD8z0Lt68kZsFJFmOUZslUqNV9QKdhCTIBhTd3t0Vj4bsFFRI2RZTu48XqncCBG2t7fZvnKB5REsRp7MwdR7PFK6vATI1FBl8x7hNSBBo/4WRw0oqGp5OtUXWtf+N958CucgzRzWSECvCbkDk7kieNUMaFB7lCnTl2yvr4Ot9wWU3lhfZ2vtCosO4m2HjQ1YyFyT8BCRyjq1kdqbzFxPNdhTNkiz4VnTLnVdMPvopptuJkly8tyhNlizzLvWmM7SM3MtGOdCAQWo8hXS895joojt9TVuv2mDn31xxLFbRzzwkOEzX8mLlKCtwCzSPfVW81SqNFhd0YDQkroH1gAWzc5fYQSFBx5fPclkMiHPc7yG0VmIrK3jbsuaZlVdxfU7X1FZxU/m+HzIYOc873pBxqlXDdjZzfmHfx6QS1hzzlgmU8MB0U5cC4y2hMIyJ/i1aLJGM7csfUFxecZ4vMThw0eYTHfJncNoXZsZY8hdjkjB44sJGSMpmhvlW+8Kttj7WsHeZUSxZ/vyOW7YhfPfEe74vPJflx0agculE7vaWa2BBKQZKKN2YmjX+d1hgFolIkKeZxw9eoz9yytMJlOc9zhXCBAPYq6uXeK9v/cGNJ0yHNgW2Cy4fUzE2nbKq173G/z++z7IlbUriLGlUhzqBLt1lkcvwRe+HvHfVz0aK2lmcLPyN6DndF5LteHR0owBTQyggaq0McRQVIr1Ek4dh48cY7ywwGR7u7Jx9Z5BPGLt7BMMH32IW/bD2BTIS4FMIfdFpycT2LwMi1ZwCLnzzAp875RIlf997CKf+xqsDyEDJpmQKbiC96l/N7TcvhZfSycR3XZgBxlL0LerSU7FlNH+2OpJjIlI0qJ6ExHUOzJvSS8+zmuPGF5xy4D9Q1+WyEqqMM1hO4OzicGkOSdvuoU0zckyX+nfOc8wS/nSDy7y8ASWYpg6Q6ZCTqEwLSGxL3sMYRbodJ9awkbdCYBur1JlzzkSjq2eJMuUJHVYW/QTcDnGwfErj/JLN3qOPkdhxcEA2AHWgSlkG/DgZeWbI8/KDYfY2U1JWwrY2trl8tpFMoHdXMg8OBG8Cr7F8KjWrlzhFQkEaZlCtGcTXbXZMtZ+aHz06El2JylJ6jEmL7KI95g0x1x6jDNDOO8Vs6uYqbB6AFaeDf4MDAbCwXXP0jAmXjrAZHdaKqDAACgkm1tcunyZXCzi6wZp7fs9beBATBO6tzYbpNGeE1EtClwIqsOKLBEOHjnOzk5CmjlEPMaYwnR3t/n4957gwbvh5h/AQQMvWoS3fxxYUNgU2FCsKotLy4yWlplMUjLnSwhcdKauXrvC+sY6agdkStBaDStgrTufc5263QjuGZKSHj/QxohU/fLeMxwvsG/5ILuTKblTstyTJBm5U7Y2Nzh3/hxRBAw9+x287m2GpV8UfAYyLJoDLofFlRVMPCZJUvLck+WOLHMgwsb6VXZ3dlBj6o5whfS0x3UDrqLDYc9pjbXH3PpH57QBOfM8Z+XAEYajRXZ3d2uuQJXBYMC1a5fYXl9jeSSMU+X251lufYvBPZJjTFkwOmFR4NCBAyRqSJIdvErBKnmH90PWrqyR5hmDeBgMm9SNER8SNwGnIb2H2xzCi5qq6/mKNCeSGhjAZxw6dpLDx24k2dnFRgYjBudyxguLnHnkHpgm7L8h4jY8r/nQACVFNovc51MlWoFLHk4vP4WXHzzKulrEWrxXnHOsrBxgY/1ayVGYCnl2uYl6AKoic6R/Lij8NJpnJBX7433Z/m5W3qrKYBBz5cIZ7rrzQ+RZhjGmSIN44sGAc/d/l+WxcHDieP1bx6y8JMd91yOZ4BKIjsDZM8oH7recvvo/3P+pj7I7TUCkYJRUieKYu7/9VaJogPc+AGdd9KftvoWy13Bduy9AZxIzd5BmacnBabMKLPF+nqWkLmszrYyA1TGsLsKv3zjgPf80RHZ20IdBJ0IUw6P/Jtz5BeUbm5YLuxlX3fwJsng4LkdspDsYGJh2ezo1jmOstNFh/Xc0Zx620wvo8Orl7dFgwDCOq5GWSJShUfZFyoGR5+bE8fr3D7ErU/IHQSxEy8q9fyd8+m/gnkRIgSgesYwh07L7W1WTwYhNY0K14/JN+msOe9X+O+K6Lw2H41qMsRTkpHosykCKTu9YPPsHyg2J43WvHnPqtzz5fQ47FkSUr39a+POvwiPAljNMvSkgrfdBdK87viLdQic0yFobARUWtsr3mHSM9uwazILLvLBaWoIFLMLAKGML+yLYbzw/fzDiFR8a4S5uEllDvq588U7hi3fDWStcTSw7XsiqokiKaTCl0eur5gClOdGqrSGt9tCn9oa91owQT/qlVS3d/F/8mBFlIBBLgdePTJXXvn8/C7fkcM6w+Zjn8x+Bf30E1mPD1amwlRsSX+P50D1Nm6DtZaalgr7SgTt9Y+vdWBD1BRztjKVqrzeF52GlmLgaRTBKHS957iLP+t19MLnGE9+yfPajju9chQ0rbE4MO86QqCFVwc3KrLArt+eAbvcodV747AwINENl1I8DCwcyIv2Kb9MqUs71CcRWOZHDaz5wDHNDwvc/mfPZuxIedoZ1hM3EMNVC+KwhvLRq+T45pdsF6kX/5bClae6/2fKragFpcXTNGQEjFj9rL1MMJMkcIt1GoNcyXvW2o5z4lZh/fOd5/uKvJlyIDVtO2MwMU7VkKoXwoQKqDm9z4Ff3fBhAw2GWTui2xnRa/u1FIxpd4e5wdBRFJElWmaW0R2WkzgjTieOFT1vklW85yF2/c5ovfXmXyXLEVirsuvrU80p4qVKeBlNe2jO0rNr8TNjroQuputKNmfeemfuojxGuar9yuiPLIrzPq5jQRlleIS918fyX7ecjf/AYX/vmBA7E7EyFxAtZKbxHShYnKGnbUwetH9Cek69G46T5HIyUE2I2GpT0vAYrSz8SlP658OpkvYfJZFLiAAkyQDnITFHS3rAgLEeOq+ueeMmSZJBRnHZednA89USH196Gbs9zRPPH5Suhy1Tp1SNiGY9HFTaUPmqznhE6rBWIlCamnmWEAhYrybQYkDYiDVxmBCIpOjsCDKLZJFchsFfwEpq7BO0FbbYarpeMdX5EV1XEGEajcdGEaT8/0JMxosZjENp+cKbOtZEVZDQiSRO89425f69KjpTWALlrThz7eoSgddK61xhvNZ2ie9BWIflpbMRwOMSY5g+JzCuMtAiCHQwlrQHvUgnWCuPRiCzPcblD1VdzAKoU/Fz7dCSc462bcvOqNW2NsRE8VzCvhWusJYoGRJGtZ5Glla1bj/61JkXDuK/VYyhtWnn20EM8iNAoKuZ0gykQkb0JGO3pje1FYDUL/dazHiVGMWKqfF+hwgBQ9ZuXtPkA7ZY/Kp2pynZUtgJE5noN9p/uqxyJLU5b2g/AXW9Gah4S7D5nIx1OXerBaZ70UNZP7dV4eHPOU6O9A+HXqX8anRbV9kBxv+KkxOByXRuonyzsB/s/TqnWfROm2HnVzFxWWK9TEXZxV+thWe175FJ6OJt+JCc/xtm3a0BtYUnZ4zumT+MStMClIaB0GNaGbHMfl+6MKvV0n6UzrHV9a5AnZRXau4fOlJi2K+n6yzKPUGrPKeqcE34yEUF/omsyx7SfrAVFT+bHVOfXZdcTtPsw/E8W3hT9MU5f54/Lttp8/w/9sEnz0+BZzAAAAABJRU5ErkJggg==">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root,html[data-theme="light"]{
  --bg:#eef1f7; --bg2:#e3e8f2; --card:#ffffff; --card2:#f5f7fc;
  --line:rgba(20,28,50,.1); --line2:rgba(20,28,50,.16);
  --gold:#4c6fff; --gold2:#2e4ad8; --mint:#1aa87a; --red:#e05656;
  --text:#12151c; --muted:#667085; --ok:#1aa87a;
  --shadow:0 10px 28px rgba(28,40,70,.08);
  --blob1:#4c6fff; --blob2:#22c7b8; --blob3:#8b7cff;
  --font:'Vazirmatn',Tahoma,sans-serif;
  --r:16px;
}
html[data-theme="dark"]{
  --bg:#0b0d12; --bg2:#12151d; --card:#161a24; --card2:#1d2330;
  --line:rgba(255,255,255,.08); --line2:rgba(255,255,255,.14);
  --gold:#7b93ff; --gold2:#c5d0ff; --mint:#3ee0b8; --red:#ff7a7a;
  --text:#eef1f8; --muted:#8b93a7; --ok:#3ee0b8;
  --shadow:0 12px 32px rgba(0,0,0,.35);
  --blob1:#3d5bff; --blob2:#1db8a8; --blob3:#7a6bff;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:var(--font)}
body{background:var(--bg)}
#app{position:relative;z-index:1;min-height:100vh}
.bgfx{position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none}
.bgfx span{
  position:absolute;border-radius:50%;filter:blur(72px);opacity:.42;
  width:min(52vw,420px);height:min(52vw,420px);will-change:transform;
}
.bgfx .b1{background:var(--blob1);top:-12%;inset-inline-start:-8%;animation:drift1 22s ease-in-out infinite}
.bgfx .b2{background:var(--blob2);bottom:-16%;inset-inline-end:-10%;animation:drift2 26s ease-in-out infinite}
.bgfx .b3{background:var(--blob3);top:38%;inset-inline-start:42%;opacity:.28;animation:drift3 20s ease-in-out infinite}
.bgfx .b4{background:var(--blob1);width:min(38vw,280px);height:min(38vw,280px);top:8%;inset-inline-end:8%;opacity:.32;animation:drift4 16s ease-in-out infinite}
.bgfx .b5{background:var(--blob2);width:min(44vw,340px);height:min(44vw,340px);bottom:12%;inset-inline-start:18%;opacity:.26;animation:drift5 28s ease-in-out infinite}
.bgfx .b6{background:var(--blob3);width:min(24vw,180px);height:min(24vw,180px);top:58%;inset-inline-end:28%;opacity:.22;animation:pulse 9s ease-in-out infinite}
@keyframes drift1{50%{transform:translate3d(12%,10%,0) scale(1.12)}}
@keyframes drift2{50%{transform:translate3d(-14%,-8%,0) scale(1.08)}}
@keyframes drift3{50%{transform:translate3d(-10%,12%,0) scale(1.18)}}
@keyframes drift4{50%{transform:translate3d(-18%,14%,0) scale(1.22) rotate(8deg)}}
@keyframes drift5{50%{transform:translate3d(16%,-12%,0) scale(1.15)}}
@keyframes pulse{0%,100%{transform:scale(1);opacity:.2}50%{transform:scale(1.35);opacity:.38}}
@media (prefers-reduced-motion:reduce){
  .bgfx span{animation:none}
}
a{color:var(--gold);text-decoration:none}
button,input,select,textarea{font-family:inherit}
.mono{font-family:ui-monospace,Menlo,monospace}
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{
  background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
  contain:content;
}
.brand{display:flex;align-items:center;gap:10px}
.logo{
  width:36px;height:36px;border-radius:10px;display:grid;place-items:center;
  background:var(--gold);color:#fff;font-weight:700;font-size:15px;
}
h1,h2,h3{margin:0;letter-spacing:-.03em;font-weight:700}
.muted{color:var(--muted)}
.gold{color:var(--gold)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.grow{flex:1;min-width:0}
.btn{
  appearance:none;border:1px solid var(--line2);background:var(--card2);color:var(--text);
  padding:10px 14px;border-radius:12px;cursor:pointer;font-weight:600;font-size:13px;min-height:40px;
}
.btn:hover{border-color:var(--gold)}
.btn.primary{background:var(--gold);color:#fff;border-color:transparent}
.btn.danger{background:rgba(224,86,86,.12);color:var(--red);border-color:rgba(224,86,86,.28)}
.btn.ghost{background:transparent}
.btn:disabled{opacity:.5;cursor:not-allowed}
.input,select,textarea{
  width:100%;background:var(--card2);border:1px solid var(--line);color:var(--text);
  padding:11px 12px;border-radius:12px;outline:none;font-size:16px;
}
textarea{min-height:90px;resize:vertical}
.input:focus,select:focus,textarea:focus{border-color:var(--gold)}
label{display:block;font-size:12px;color:var(--muted);margin:0 0 6px;font-weight:600}
.field{margin:0 0 14px}
.err{background:rgba(224,86,86,.12);color:var(--red);border:1px solid rgba(224,86,86,.28);padding:10px 12px;border-radius:12px;font-size:13px;margin:0 0 14px}
.okbox{background:rgba(26,168,122,.12);color:var(--ok);border:1px solid rgba(26,168,122,.28);padding:10px 12px;border-radius:12px;font-size:13px;margin:0 0 14px}
.steps{display:flex;gap:8px;margin:0 0 22px}
.step{flex:1;height:3px;background:var(--line);border-radius:99px}
.step.on{background:var(--gold)}
.shell{display:flex;flex-direction:column;min-height:100vh}
.topbar{
  position:sticky;top:0;z-index:30;
  display:flex;align-items:center;gap:12px;
  padding:10px 18px;
  background:var(--card);border-bottom:1px solid var(--line);
}
.hbar{display:flex;align-items:center;gap:8px;margin-inline-start:auto}
aside{display:none}
.nav{display:flex;gap:4px;flex:1;flex-wrap:nowrap}
.nav a,.nav button{
  display:flex;align-items:center;gap:8px;width:auto;text-align:start;
  padding:8px 12px;border-radius:999px;color:var(--muted);background:transparent;border:0;cursor:pointer;font-weight:600;font-size:13px;
}
.nav a.on,.nav button.on{background:var(--gold);color:#fff}
.nav a:hover,.nav button:hover{color:var(--text)}
.nav a.on:hover{color:#fff}
main{padding:24px 20px 40px;max-width:1100px;width:100%;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin:0 0 20px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(4,1fr)}
.stat{padding:16px}
.stat:before{display:none}
.stat b{display:block;font-size:26px;margin-top:6px}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{color:var(--muted);font-weight:600;text-align:start;padding:10px;border-bottom:1px solid var(--line)}
.table td{padding:10px;border-bottom:1px solid var(--line);vertical-align:middle}
.pill{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--muted);background:var(--card2);cursor:pointer}
.pill:has(input:checked){color:#fff;border-color:var(--gold);background:var(--gold)}
.pill.ok{color:var(--ok);border-color:rgba(26,168,122,.35);background:rgba(26,168,122,.1)}
.pill.warn{color:var(--gold2);border-color:var(--line2)}
.pill.bad{color:var(--red);border-color:rgba(224,86,86,.3);background:rgba(224,86,86,.1)}
.alive-wrap{position:relative;display:inline-block;margin-inline-start:8px;vertical-align:middle}
.alive-box{display:inline-flex;align-items:center;justify-content:center;min-width:58px;padding:3px 8px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;user-select:none}
.alive-box.on{background:#16a34a;color:#fff}
.alive-box.off{background:#6b7280;color:#fff}
.alive-tip{display:none;position:absolute;top:126%;inset-inline-start:0;z-index:8;background:var(--card);border:1px solid var(--line);padding:7px 10px;border-radius:10px;font-size:11px;white-space:nowrap;box-shadow:0 10px 28px rgba(0,0,0,.16)}
.alive-wrap:hover .alive-tip,.alive-wrap.open .alive-tip{display:block}
.host-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.host-chips .pill{cursor:default}
.help{background:var(--card2);border:1px dashed var(--line2);border-radius:12px;padding:14px;font-size:13px;color:var(--muted);line-height:1.7}
ol.guide{list-style:none;margin:10px 0 0;padding:0}
ol.guide li{display:flex;gap:10px;align-items:flex-start;margin:0 0 11px;line-height:1.65;color:var(--text);font-size:13px}
ol.guide .n{
  flex:0 0 24px;height:24px;border-radius:50%;margin-top:1px;
  background:var(--card);border:1px solid var(--line);
  display:grid;place-items:center;font-size:11px;color:var(--gold);font-weight:700
}
.why{margin:0 0 12px;font-size:13px;line-height:1.7;color:var(--muted)}
.hint{font-size:12px;color:var(--muted);margin-top:6px;line-height:1.5}
.hint.bad{color:var(--red)}
.hint.ok{color:var(--ok)}
.step-lbl{display:flex;justify-content:space-between;gap:6px;margin:-6px 0 18px;font-size:11px;color:var(--muted)}
.step-lbl span.on{color:var(--gold);font-weight:700}
.wiz-card{width:min(720px,100%);padding:24px;background:var(--card)}
.help code,.code{font-family:ui-monospace,Menlo,monospace;color:var(--gold2);background:var(--card2);padding:1px 6px;border-radius:6px;font-size:12px}
pre.codeblock{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:var(--card2);border:1px solid var(--line);padding:12px;border-radius:12px;overflow:auto;color:var(--gold2);line-height:1.55}
.foot{display:none}
#toast{position:fixed;inset-inline-end:12px;bottom:12px;display:flex;flex-direction:column;gap:8px;z-index:50}
.toast{background:var(--text);color:var(--card);border:0;padding:10px 12px;border-radius:12px;font-size:13px}
.otp-row{display:flex;gap:8px;justify-content:center;direction:ltr;margin:12px 0}
.otp-cell{width:42px;height:42px;border-radius:50%;border:2px solid var(--line);background:var(--card);text-align:center;font-size:18px;font-weight:800;text-transform:uppercase}
.otp-row.ok .otp-cell{border-color:#16a34a;background:#dcfce7;color:#14532d}
.otp-row.bad .otp-cell{border-color:#dc2626;background:#fee2e2;color:#991b1b}
.otp-banner{margin-top:14px;padding:16px;border-radius:16px;text-align:center;font-weight:700}
.otp-banner.ok{background:#dcfce7;color:#14532d}
.otp-banner.bad{background:#fee2e2;color:#991b1b}
.otp-emo{font-size:42px;display:block;margin-bottom:6px}
.rec-warn{color:#dc2626;font-weight:800;font-size:13px;line-height:1.7}
html[data-theme="dark"] .toast{color:#0b0d12}
.modalbg{position:fixed;inset:0;background:rgba(10,12,18,.5);display:grid;place-items:center;z-index:40;padding:12px}
.modal{width:min(540px,100%);padding:18px;max-height:min(88vh,820px);overflow:auto}
.hidden{display:none !important}
.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.nav a{flex-direction:row}
.nav a .ni{display:grid;place-items:center;width:18px;height:18px;flex:0 0 18px}
.nav a .ni svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.vpn-grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.vpn-card{padding:16px;display:flex;flex-direction:column;gap:10px}
.vpn-card .linkbox{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all;background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:10px;line-height:1.5;max-height:72px;overflow:auto}
.qr{width:108px;height:108px;border-radius:10px;background:#fff;padding:5px;border:1px solid var(--line)}
.scrollx{overflow:auto;-webkit-overflow-scrolling:touch}
.howto{display:grid;gap:8px;margin:0}
.howto div{display:flex;gap:8px;align-items:flex-start;font-size:13px;line-height:1.6;color:var(--muted)}
.chkgrid{display:flex;flex-wrap:wrap;gap:8px}
.chkgrid .pill{gap:6px;user-select:none}
.bars{display:flex;align-items:flex-end;gap:6px;height:140px;padding:8px 4px 0}
.barcol{flex:1;min-width:12px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.bar{width:100%;max-width:26px;background:var(--gold);border-radius:6px 6px 2px 2px}
.barlbl{font-size:9px;color:var(--muted);margin-top:4px}
.logo-sm{display:none}
.page-kicker{font-size:11px;color:var(--gold);margin:0 0 4px;letter-spacing:.12em;text-transform:uppercase;font-weight:700}
.theme-grid{display:none}
@media (max-width:980px){
  .grid{grid-template-columns:1fr 1fr}
  .split{grid-template-columns:1fr}
  .stat b{font-size:22px}
}
@media (max-width:820px){
  .topbar{padding:8px 12px;gap:8px}
  .nav{
    position:fixed;left:0;right:0;bottom:0;top:auto;
    z-index:35;flex:none;width:100%;
    background:var(--card);border-top:1px solid var(--line);
    justify-content:space-around;gap:0;
    padding:6px 4px calc(6px + env(safe-area-inset-bottom));
  }
  .nav a,.nav button{
    flex:1;flex-direction:column;gap:2px;min-width:0;width:auto;
    font-size:10px;padding:8px 4px;border-radius:12px;text-align:center;
  }
  .nav a .ni{width:22px;height:22px;flex-basis:22px}
  .hbar .muted{display:none}
  main{padding:16px 12px calc(92px + env(safe-area-inset-bottom))}
  .top{flex-wrap:wrap}
  .table{font-size:12px}
  .table td,.table th{padding:8px}
  .wiz-card{padding:18px 14px}
  .center{padding:16px 12px}
  .vpn-grid{grid-template-columns:1fr}
  .qr{display:none}
  .btn{width:auto}
  .modal{width:100%;max-height:85vh}
}
@media (max-width:560px){
  .grid{grid-template-columns:1fr}
  h2{font-size:20px}
  .hbar .btn{padding:8px 10px}
}
</style>
</head>
<body>
<div class="bgfx" aria-hidden="true"><span class="b1"></span><span class="b2"></span><span class="b3"></span><span class="b4"></span><span class="b5"></span><span class="b6"></span></div>
<div id="app"></div>
<div id="toast"></div>
<script>
(function(){
var S = { lang: localStorage.getItem('ham_lang') || 'fa', status: null, view: '/', busy: false };
var T = {
fa: {
brand:'Ham', tag:'پنل فیلترشکن', author:'dev-penhan',
boot:'در حال بارگذاری…',
w_title:'راه‌اندازی پنل Ham', w_sub:'اگر اولین‌بار است نگران نباشید. دیتابیس را وصل کنید، حساب مدیر بسازید، بعد فیلترشکن می‌سازید.',
s_db:'دیتابیس', s_admin:'حساب مدیر', s_cf:'کلادفلر', s_go:'آماده',
db_ok:'دیتابیس وصل است. می‌توانید به ساخت حساب مدیر بروید.',
db_fail:'دیتابیس هنوز به این ورکر وصل نشده. تا این کار تمام نشود دکمه ادامه کار نمی‌کند.',
db_why:'چرا دیتابیس لازم است؟',
db_why_t:'رمز عبور، کاربران و تنظیمات باید جایی ذخیره شوند. در کلادفلر این جا «D1» نام دارد؛ یک دیتابیس کوچک که به همین ورکر وصل می‌شود.',
db_help:'آموزش وصل کردن — قدم‌به‌قدم برای تازه‌کار',
db_1:'وارد dash.cloudflare.com شوید و وارد حساب کلادفلر شوید.',
db_2:'از منوی سمت چپ Workers & Pages را باز کنید و روی همین ورکر (همان‌جا که ham.js را گذاشتید) کلیک کنید.',
db_3:'بالای صفحه تب Settings را بزنید و بخش Bindings را پیدا کنید.',
db_4:'Add binding را بزنید و D1 Database را انتخاب کنید.',
db_5:'در کادر Variable name فقط بنویسید DB — سه حرف بزرگ انگلیسی، بدون فاصله. نه db و نه اسم دیگر.',
db_6:'اگر دیتابیس ندارید Create database را بزنید و مثلاً ham-db بگذارید. اگر دارید همان را از لیست انتخاب کنید.',
db_7:'Save و بعد Deploy را بزنید تا وصل شدن ذخیره شود. بدون Deploy هنوز وصل نیست.',
db_8:'به همین صفحه برگردید و دکمه «دوباره بررسی کن» را بزنید.',
recheck:'دوباره بررسی کن',
next:'ادامه', back:'برگشت', skip:'فعلاً رد کن', finish:'ساخت حساب و ورود',
user:'نام کاربری', pass:'رمز عبور', pass2:'تکرار رمز عبور', email:'ایمیل (اختیاری)',
admin_help:'این حساب برای ورود خودتان به پنل است. آن را جایی یادداشت کنید.',
user_hint:'۳ تا ۳۲ کاراکتر؛ فقط حروف انگلیسی، عدد و خط زیر. مثال: admin',
user_bad:'نام کاربری نامعتبر است. فقط انگلیسی، عدد و _ و حداقل ۳ کاراکتر.',
pass_hint:'حداقل ۸ کاراکتر. این رمز را بعداً برای ورود لازم دارید.',
pass_short:'رمز عبور کوتاه است. حداقل ۸ کاراکتر وارد کنید.',
pass_need:'برای ادامه هنوز این تعداد کاراکتر کم است: ',
pass_ok:'طول رمز مناسب است.',
cf_tok:'توکن API کلادفلر',
cf_hint:'توکن با دسترسی Billing Read. مصرف و ماندهٔ حساب را در داشبورد نشان می‌دهد.',
cf_spend:'مصرف', cf_left:'مانده', cf_no_tok:'توکن کلادفلر را در تنظیمات بگذارید',
cf_tok_saved:'توکن ذخیره است. برای عوض کردن، توکن جدید بنویسید.',
allow_ips:'IPهای مجاز پنل', allow_ips_h:'خالی = همه. هر خط یک IP یا رنج مثل 1.2.3.0/24. مسیر تونل و ربات بسته نمی‌شود.',
abuse_gb:'قطع خودکار حجم غیرعادی (گیگ در روز)', abuse_gb_h:'۰ = خاموش. اگر مصرف یک کانفیگ در یک روز از این بیشتر شود خاموش می‌شود.',
access_only:'فقط Cloudflare Access', access_only_h:'اگر Access جلوی /dash باشد این را بزنید. بدون JWT کلادفلر پنل باز نمی‌شود.',
csv_export:'خروجی CSV مصرف',
backup_health:'سلامت ورکر پشتیبان',

cf_how:'اگر الان کلید ندارید «فعلاً رد کن» را بزنید. بعداً از صفحه تنظیمات داخل پنل هم می‌توانید بگذارید.',
cf_steps:'ساخت کلید: در کلادفلر روی آیکون آدمک بالا راست → My Profile → API Tokens → Create Token. قالب Edit zone DNS را بردارید و دسترسی Cache Purge را هم اضافه کنید. کلید فقط یک‌بار نشان داده می‌شود؛ کپی کنید و در کادر پایین بچسبانید.',
login:'ورود', login_sub:'وارد پنل شوید', enter:'ورود به پنل',
logout:'خروج', dash:'داشبورد', users:'کاربران', cf:'کلادفلر', dns:'DNS', cache:'کش', logs:'گزارش‌ها', settings:'تنظیمات',
hello:'سلام', users_n:'کاربران', sess:'نشست‌ها', today:'رویداد امروز', zones:'زون‌ها',
cf_on:'متصل به کلادفلر', cf_off:'توکن کلادفلر تنظیم نشده',
recent:'آخرین رویدادها', add_user:'کاربر جدید', role:'نقش', active:'فعال', actions:'عملیات',
save:'ذخیره', cancel:'انصراف', del:'حذف', edit:'ویرایش', create:'ایجاد',
admin:'مدیر', operator:'اپراتور', viewer:'بازدیدگر',
need_admin:'فقط مدیر',
zones_title:'زون‌های کلادفلر', refresh:'بازخوانی', verify:'تست توکن',
dns_title:'رکوردهای DNS', pick_zone:'زون را انتخاب کنید', add_rec:'رکورد جدید',
type:'نوع', name:'نام', content:'مقدار', ttl:'TTL', proxied:'پروکسی',
cache_title:'پاک کردن کش', purge_all:'پاک‌سازی کل زون', purge_urls:'پاک‌سازی URLها',
urls_ph:'هر خط یک URL',
set_title:'تنظیمات', skin:'پوسته', panel_name:'نام پنل', lang:'زبان',
cur_pass:'رمز فعلی', new_pass:'رمز جدید', ch_pass:'تغییر رمز',
tok_now:'توکن فعلی', tok_new:'توکن جدید (خالی = بدون تغییر)', tok_clear:'حذف توکن',
workers:'ورکرها', empty:'موردی نیست', err:'خطا', saved:'ذخیره شد', copied:'کپی شد',
vpn:'فیلترشکن', vpn_sub:'بدون توکن کلادفلر هم کار می‌کند. تونل روی همین ورکر است.',
vpn_new:'ساخت کانفیگ جدید', vpn_name:'اسم کانفیگ', vpn_path:'مسیر وب‌سوکت',
vpn_help:'این فیلترشکن رایگان است و از شبکه کلادفلر عبور می‌کند. توکن API لازم نیست. اگر آدرس workers.dev فیلتر بود، در صفحه ورکر از Settings → Domains یک دامنه خودتان وصل کنید.',
vpn_how:'نصب روی گوشی و سیستم',
vpn_h1:'اندروید: v2rayNG یا Hiddify — دکمه + و «وارد کردن از کلیپ‌بورد».',
vpn_h2:'آیفون: Streisand یا V2Box — لینک را Share/Import کنید.',
vpn_h3:'ویندوز: v2rayN یا Hiddify — Import from clipboard.',
vpn_off:'خاموش', vpn_on:'روشن', share:'لینک اتصال',
sub:'سابسکراپشن', sub_help:'چند کانفیگ را در یک لینک می‌گیرید. همان لینک را در Hiddify یا v2rayNG به‌عنوان ساب وارد کنید.',
sub_count:'تعداد کانفیگ', sub_make:'ساخت سابسکراپشن',
vpn_loc:'لوکیشن', vpn_uuid_ph:'خالی = تصادفی', vpn_uuid_rand:'تصادفی',
vpn_tpass:'رمز Trojan', vpn_tpass_ph:'خالی = همان UUID',
vpn_proto:'پروتکل‌ها', vpn_quota:'حجم (گیگ، ۰ = نامحدود)', vpn_days:'اعتبار (روز، ۰ = نامحدود)',
vpn_maxip:'سقف کاربر/آی‌پی (۰ = آزاد)', vpn_traffic:'ترافیک', vpn_edge:'لبه کلادفلر', vpn_proxy:'تنظیمات پروکسی',
vpn_proto_hint:'تونل زنده روی ورکر: VLESS.',
loc_random:'رندوم', logs_clear:'حذف گزارش‌ها',
set_sec:'امنیت و استتار', set_panel_path:'مسیر پنل', set_panel_path_h:'فقط آدرس ورود را عوض می‌کند، جای رمز عبور نیست. پیش‌فرض /dash',
set_camo:'آدرس استتار', set_camo_h:'بدون مسیر پنل به اینجا می‌رود. استتار امنیت نیست؛ ورود با رمز لازم است.',
set_kill:'خروج از همه دستگاه‌ها', set_reset_tr:'صفر کردن ترافیک همه کانفیگ‌ها',
ips:'آی‌پی اتصال', ips_h:'هر خط یک IP. در ویرایش فیلترشکن/ساب تیک بزن تا همان یک کانفیگ از روی آن IP وصل شود — برای هر IP کانفیگ جدا ساخته نمی‌شود.', ips_none:'اول در تنظیمات IP وارد کن.', ips_pick:'آی‌پی‌ها', tg_bot:'ربات منو دارد: ساخت، دریافت لینک، ارسال برای کسی. توکن را ذخیره کنید تا وب‌هوک ست شود.',
ports:'پورت‌های کلادفلر', ports_h:'پیش‌فرض: ۸۰، ۸۰۸۰، ۴۴۳ و ۲۰۵۲. بقیه را در پورت اضافه بنویسید.',
port:'پورت',
sub_brand:'برند ساب',
tg:'تلگرام', tg_token:'توکن ربات', tg_chat:'Chat ID', tg_h:'وقتی حجم یا زمان تمام شود پیام می‌فرستد. ربات با /vpn و /sub کانفیگ می‌سازد.', tg_test:'ارسال تست',
backup:'پشتیبان JSON', backup_dl:'دانلود بکاپ', backup_up:'بازیابی از فایل',
chart:'ترافیک روزانه', sub_ports:'پورت‌ها — هر پورت یک کانفیگ',
sub_help2:'با ساخت ساب چیزی به منوی فیلترشکن اضافه نمی‌شود. به ازای هر پورت و هر پروتکل یک لینک با اسم مثل 443 Ham vless ساخته می‌شود.',
vpn_one_port:'برای فیلترشکن فقط یک پورت', vpn_one_proto:'برای فیلترشکن فقط یک پروتکل',
edit:'ویرایش', update:'به‌روزرسانی', edit_vpn:'ویرایش کانفیگ', edit_sub:'ویرایش ساب',
edit_sub_h:'پورت، حجم و زمان را عوض کن. بعد از ذخیره، کاربر با بروزرسانی لینک ساب کانفیگ جدید را می‌گیرد.',


tok_guide:'اگر توکن ندارید نگران نباشید؛ فیلترشکن بدون آن کار می‌کند. توکن فقط برای مدیریت DNS و کش از داخل پنل است.',
tok_g1:'در کلادفلر روی آیکون آدمک بالا راست بزنید.',
tok_g2:'My Profile سپس API Tokens.',
tok_g3:'Create Token را بزنید.',
tok_g4:'قالب Edit zone DNS را انتخاب کنید.',
tok_g5:'Zone → Cache Purge را هم Add کنید و Create Token بزنید.',
tok_g6:'کلید فقط یک‌بار نشان داده می‌شود. کپی کنید و در کادر بالا بچسبانید، بعد ذخیره.',
mismatch:'رمز عبور و تکرار آن یکی نیستند.', wait_db:'تا Variable name برابر DB نباشد و Deploy نشده باشد، ادامه ممکن نیست.',
done_t:'همه‌چیز آماده است', done_s:'با دکمه زیر حساب مدیر ساخته می‌شود و مستقیم وارد پنل می‌شوید.',
done_user:'نام کاربری مدیر', done_cf:'کلید کلادفلر', done_cf_yes:'وارد شده', done_cf_no:'رد شد — بعداً در تنظیمات',
speed:'سقف سرعت (مگابیت، ۰ = آزاد)', extra_host:'دامنه اتصال', host_default:'دامنه ورکر (پیش‌فرض)',
sub_pass:'رمز ساب (اختیاری)', one_shot:'لینک یک‌بارمصرف', clone:'کپی قالب', status_page:'صفحه وضعیت',
clash:'کلش', singbox:'sing-box', extra_hosts:'دامنه‌های اضافه (هر خط یکی)', extra_hosts_h:'دامنه‌هایی که به همین ورکر وصل شده‌اند. در ساخت کانفیگ می‌توانید یکی را انتخاب کنید.',
tg_2fa:'ورود دومرحله‌ای با تلگرام', tg_2fa_h:'بعد از رمز، کد ۶ رقمی به بات تلگرام می‌رود.', otp:'کد ورود', otp_h:'کد ۸ کاراکتری انگلیسی (حرف و عدد) از تلگرام یا ایمیل، یا کد بازیابی.',
otp_ok:'بله! با موفقیت وارد شدید', otp_bad:'کد اشتباه بود بیشتر دقت کن',
rec_code:'کد بازیابی', rec_warn:'حتماً این کد را فراموش نکنید. اگر تلگرام یا ایمیل نباشد همین کد راه ورود است.',
rec_bad:'کد بازیابی باید دقیقاً ۸ حرف یا عدد انگلیسی باشد',
rec_need:'کد بازیابی را همین حالا بسازید و جایی امن نگه دارید.',
email_need:'ایمیل ادمین را وارد کنید تا کد ورود به آن هم فرستاده شود.',
email_new:'ایمیل جدید', email_old_code:'کد ایمیل قبلی',
geo_wait:'کشور…',

proxy_ips:'پروکسی خروجی', proxy_ips_h:'این آی‌پی‌ها داخل لینک کانفیگ نمی‌آیند. بعد از وصل شدن، ترافیک خروجی ورکر از این پروکسی‌ها رد می‌شود (برای سایت‌هایی مثل ChatGPT که مستقیم از ورکر باز نمی‌شوند). اگر خالی باشد خروجی مستقیم است.',
backup_hosts:'ورکر پشتیبان (هر خط یک دامنه)', backup_hosts_h:'بعد از ذخیره همین‌جا برای ساخت کانفیگ دیده می‌شوند. بازدید از دامنهٔ پشتیبان آدرس داخل لینک را عوض نمی‌کند؛ همیشه دامنهٔ اصلی پنل استفاده می‌شود.',
panel_host:'دامنهٔ اصلی کانفیگ', panel_host_h:'همین دامنه داخل لینک VLESS می‌آید. دامنهٔ پشتیبان را اینجا نگذارید.',
extra_ports:'پورت اضافه', extra_ports_h:'پورت‌هایی غیر از پیش‌فرض. کانفیگ‌های پورت حذف‌شده خاموش می‌شوند، پاک نمی‌شوند.',
backup_none:'هنوز دامنه‌ای ذخیره نشده.',
online:'آنلاین', offline:'آفلاین', last_conn:'آخرین اتصال',

ips_best:'تیک ۵ تای بهتر',
vpn_ip_test:'تست پینگ آی‌پی‌ها', vpn_ip_direct:'بدون پروکسی (خروجی مستقیم)',
remark:'نام نمایشی (اختیاری)', remark_h:'خالی = کشور + اسم تصادفی، مثلاً NL 7sb5v',
remember:'مرا به خاطر بسپار (۷ روز)',
qr:'QR',
vpn_ip_pick:'پروکسی خروجی این کانفیگ', vpn_ip_none:'بدون پروکسی: خروجی مستقیم ورکر. در تنظیمات پروکسی بگذارید.',
ips_find:'یافتن خودکار آی‌پی', ips_found:'آی‌پی پیدا شد:',
ips_ping:'تست پینگ', ips_pick:'فعال برای ساخت کانفیگ (تیک بزنید)', ips_pick_empty:'بعد از ذخیره یا یافتن، آی‌پی‌ها اینجا می‌آیند.',
ips_dead:'قطع', ips_wait:'در حال تست…',
wiz_tg_h:'بهتر است توکن ربات و آیدی عددی تلگرام را بگذارید (اختیاری). ورودها به ربات می‌رود.',
login_info:'ورود با IP',

},
en: {
brand:'Ham', tag:'Cloudflare panel and tunnel', author:'dev-penhan',
boot:'Loading…',
w_title:'Set up Ham', w_sub:'Three short steps: connect the database, create your admin login, then optionally add a Cloudflare API token.',
s_db:'Database', s_admin:'Admin account', s_cf:'Cloudflare', s_go:'Ready',
db_ok:'Database is connected. You can create the admin account.',
db_fail:'No database is connected to this Worker yet. Continue stays disabled until you finish the steps below.',
db_why:'Why do we need a database?',
db_why_t:'Passwords, users and settings have to live somewhere. On Cloudflare that place is D1 — a small database attached to this Worker.',
db_help:'How to connect it — beginner walkthrough',
db_1:'Open dash.cloudflare.com and sign in.',
db_2:'In the left menu open Workers & Pages and click this Worker (the one where you pasted ham.js).',
db_3:'Open the Settings tab and find Bindings.',
db_4:'Click Add binding and choose D1 Database.',
db_5:'In Variable name type exactly DB — three capital letters, no spaces. Not db, not another name.',
db_6:'If you have no database yet, click Create database and name it e.g. ham-db. Otherwise pick one from the list.',
db_7:'Click Save, then Deploy. Without Deploy the binding is not live.',
db_8:'Come back to this page and press Check again.',
recheck:'Check again',
next:'Continue', back:'Back', skip:'Skip for now', finish:'Create account and enter',
user:'Username', pass:'Password', pass2:'Confirm password', email:'Email (optional)',
admin_help:'This is the login you will use to open the panel. Write it down.',
user_hint:'3–32 characters; English letters, numbers and underscore only. Example: admin',
user_bad:'Invalid username. Use English letters, numbers and _ , at least 3 characters.',
pass_hint:'At least 8 characters. You will need this password to sign in.',
pass_short:'Password is too short. Use at least 8 characters.',
pass_need:'Still this many characters short: ',
pass_ok:'Password length looks good.',
cf_tok:'Cloudflare API token',
cf_hint:'Needs Billing Read. Used on the dashboard for spend and remaining credit.',
cf_spend:'Used', cf_left:'Left', cf_no_tok:'Add a Cloudflare token in Settings',
cf_tok_saved:'Token is saved. Paste a new one to replace it.',
allow_ips:'Allowed panel IPs', allow_ips_h:'Empty = everyone. One IP or CIDR per line. Tunnel and bot stay open.',
abuse_gb:'Auto-disable abuse (GB/day)', abuse_gb_h:'0 = off. Peers over this daily usage are turned off.',
access_only:'Cloudflare Access only', access_only_h:'Require CF-Access JWT on /dash. Configure Access in the Cloudflare dashboard first.',
csv_export:'Export usage CSV',
backup_health:'Backup worker health',

cf_how:'If you do not have a token now, press Skip for now. You can add it later under Settings.',
cf_steps:'To create one: Cloudflare profile icon (top right) → My Profile → API Tokens → Create Token. Start from Edit zone DNS and also add Cache Purge. The token is shown once — copy it into the box below.',
login:'Sign in', login_sub:'Sign in', enter:'Enter panel',
logout:'Sign out', dash:'Dashboard', users:'Users', cf:'Cloudflare', dns:'DNS', cache:'Cache', logs:'Logs', settings:'Settings',
hello:'Hello', users_n:'Users', sess:'Sessions', today:'Events today', zones:'Zones',
cf_on:'Connected to Cloudflare', cf_off:'Cloudflare token not set',
recent:'Recent events', add_user:'New user', role:'Role', active:'Active', actions:'Actions',
save:'Save', cancel:'Cancel', del:'Delete', edit:'Edit', create:'Create',
admin:'Admin', operator:'Operator', viewer:'Viewer',
need_admin:'Admin only',
zones_title:'Cloudflare zones', refresh:'Refresh', verify:'Test token',
dns_title:'DNS records', pick_zone:'Select a zone', add_rec:'New record',
type:'Type', name:'Name', content:'Content', ttl:'TTL', proxied:'Proxied',
cache_title:'Purge cache', purge_all:'Purge entire zone', purge_urls:'Purge URLs',
urls_ph:'One URL per line',
set_title:'Settings', skin:'Theme', panel_name:'Panel name', lang:'Language',
cur_pass:'Current password', new_pass:'New password', ch_pass:'Change password',
tok_now:'Current token', tok_new:'New token (blank = keep)', tok_clear:'Clear token',
workers:'Workers', empty:'Nothing here', err:'Error', saved:'Saved', copied:'Copied',
vpn:'VPN', vpn_sub:'Works without a Cloudflare API token. The tunnel runs on this Worker.',
vpn_new:'New config', vpn_name:'Config name', vpn_path:'WebSocket path',
vpn_help:'This free tunnel rides Cloudflare’s network. No API token required. If workers.dev is blocked, attach your own domain in the Worker Settings → Domains.',
vpn_how:'Install on phone and desktop',
vpn_h1:'Android: v2rayNG or Hiddify — + then import from clipboard.',
vpn_h2:'iPhone: Streisand or V2Box — import the link.',
vpn_h3:'Windows: v2rayN or Hiddify — import from clipboard.',
vpn_off:'Off', vpn_on:'On', share:'Share link',
sub:'Subscription', sub_help:'Bundle several configs into one URL and import it in Hiddify or v2rayNG as a subscription.',
sub_count:'Config count', sub_make:'Create subscription',
vpn_loc:'Location', vpn_uuid_ph:'blank = random', vpn_uuid_rand:'Random',
vpn_tpass:'Trojan password', vpn_tpass_ph:'blank = same as UUID',
vpn_proto:'Protocols', vpn_quota:'Quota GB (0 = unlimited)', vpn_days:'Days (0 = unlimited)',
vpn_maxip:'Max IP/devices (0 = free)', vpn_traffic:'Traffic', vpn_edge:'Cloudflare edge', vpn_proxy:'Proxy settings',
vpn_proto_hint:'Live tunnel on the Worker: VLESS.',
loc_random:'Random', logs_clear:'Clear logs',
set_sec:'Security and camouflage', set_panel_path:'Panel path', set_panel_path_h:'Hides the URL only — not a password. Default /dash',
set_camo:'Camouflage URL', set_camo_h:'Root redirects here. Obscurity is not auth; login is still required.',
set_kill:'Sign out all sessions', set_reset_tr:'Reset traffic on all configs',
ips:'Connect IPs', ips_h:'One IP per line. Tick in VPN/sub edit so that single config connects via the IP — not one config per IP.', ips_none:'Add IPs in Settings first.', ips_pick:'IPs', tg_bot:'The bot has a menu: create, get links, share. Save the token to set the webhook.',
ports:'Cloudflare ports', ports_h:'Defaults: 80, 8080, 443, 2052. Add others in Extra ports.',
port:'Port',
sub_brand:'Sub brand',
tg:'Telegram', tg_token:'Bot token', tg_chat:'Chat ID', tg_h:'Sends a message when quota or time runs out. The bot also creates configs with /vpn and /sub.', tg_test:'Send test',
backup:'JSON backup', backup_dl:'Download backup', backup_up:'Restore from file',
chart:'Daily traffic', sub_ports:'Ports — one config per port',
sub_help2:'Creating a subscription does not add items to the VPN menu. Each selected port and protocol becomes one link named like 443 Ham vless.',
vpn_one_port:'VPN configs allow a single port', vpn_one_proto:'VPN configs allow a single protocol',
edit:'Edit', update:'Update', edit_vpn:'Edit config', edit_sub:'Edit subscription',
edit_sub_h:'Change ports, quota and time. After save, clients get the new configs on the next subscription refresh.',


tok_guide:'VPN works without a token. A token is only needed to manage DNS and cache from this panel.',
tok_g1:'Click the profile icon at the top right in Cloudflare.',
tok_g2:'Open My Profile, then API Tokens.',
tok_g3:'Click Create Token.',
tok_g4:'Choose the Edit zone DNS template.',
tok_g5:'Also add Zone → Cache Purge, then Create Token.',
tok_g6:'The key is shown once. Paste it in the box above and save.',
mismatch:'Password and confirmation do not match.', wait_db:'Continue is blocked until Variable name is DB and the Worker is Deployed.',
done_t:'You are ready', done_s:'The button below creates the admin account and signs you in.',
done_user:'Admin username', done_cf:'Cloudflare token', done_cf_yes:'Provided', done_cf_no:'Skipped — add later in Settings',
speed:'Speed cap (Mbps, 0 = free)', extra_host:'Connect host', host_default:'Worker host (default)',
sub_pass:'Sub password (optional)', one_shot:'One-shot link', clone:'Clone', status_page:'Status page',
clash:'Clash', singbox:'sing-box', extra_hosts:'Extra domains (one per line)', extra_hosts_h:'Domains pointed at this Worker. Pick one when building configs.',
tg_2fa:'Telegram 2FA login', tg_2fa_h:'After password, a 6-digit code is sent to the bot.', otp:'Login code', otp_h:'8 English letters/digits from Telegram or email, or your recovery code.',
otp_ok:'Yes! You are signed in', otp_bad:'Wrong code — look again',
rec_code:'Recovery code', rec_warn:'Never forget this code. It is the backup if Telegram or email fail.',
rec_bad:'Recovery code must be exactly 8 English letters or digits',
rec_need:'Set a recovery code now and store it somewhere safe.',
email_need:'Enter an admin email so login codes can be sent there too.',
email_new:'New email', email_old_code:'Code from old email',
geo_wait:'country…',

proxy_ips:'Outbound proxy', proxy_ips_h:'These IPs are NOT put in the config link. After you connect, the Worker sends traffic via these proxies (helps with sites like ChatGPT that block direct Worker IPs). Empty = direct.',
backup_hosts:'Backup workers (one domain per line)', backup_hosts_h:'Shown after save for building configs. Visiting a backup domain never puts that host in links — the main panel host is always used.',
panel_host:'Main config domain', panel_host_h:'This hostname is written into VLESS links. Do not put a backup domain here.',
extra_ports:'Extra ports', extra_ports_h:'Ports besides the defaults. Configs on removed ports are disabled, not deleted.',
backup_none:'No backup domains saved yet.',
online:'Online', offline:'Offline', last_conn:'Last connect',

ips_best:'Tick 5 best',
vpn_ip_test:'Ping these IPs', vpn_ip_direct:'No proxy (direct Worker egress)',
remark:'Display name (optional)', remark_h:'Empty = country + random name, e.g. NL 7sb5v',
remember:'Remember me (7 days)',
qr:'QR',
vpn_ip_pick:'Outbound proxy for this config', vpn_ip_none:'No proxy: direct Worker egress. Add proxies in Settings.',
ips_find:'Find IPs', ips_found:'IPs found:',
ips_ping:'Ping test', ips_pick:'Enable for configs (tick)', ips_pick_empty:'After save or find, IPs appear here.',
ips_dead:'down', ips_wait:'Testing…',
wiz_tg_h:'Optional but recommended: bot token and your numeric Telegram chat id. Logins are sent to the bot.',
login_info:'Signed in from IP',

}
};
function t(k){ var p = T[S.lang] || T.fa; return p[k] != null ? p[k] : k; }
function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function h(){ return Array.prototype.slice.call(arguments).join(''); }
function applyDir(){
  document.documentElement.lang = S.lang;
  document.documentElement.dir = S.lang === 'fa' ? 'rtl' : 'ltr';
}
function applyTheme(name){
  name = name === 'dark' ? 'dark' : 'light';
  S.theme = name;
  document.documentElement.setAttribute('data-theme', name);
  try { localStorage.setItem('ham_theme', name); } catch (e) {}
}
function toast(msg, bad){
  var n = document.createElement('div');
  n.className = 'toast';
  if (bad) n.style.borderColor = '#5a2a32';
  n.textContent = msg;
  document.getElementById('toast').appendChild(n);
  setTimeout(function(){ n.remove(); }, 3200);
}
var BASE = location.pathname; while (BASE.length > 1 && BASE.charAt(BASE.length-1)==='/') BASE = BASE.slice(0,-1); if (!BASE) BASE = '/dash';
function api(path, method, body){
  var opt = { method: method || 'GET', credentials: 'same-origin', headers: {} };
  if (S.csrf) opt.headers['X-CSRF-Token'] = S.csrf;
  if (body !== undefined){ opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  return fetch(BASE + path, opt).then(function(res){
    return res.json().then(function(j){
      j._status = res.status;
      if (j && j.csrf) S.csrf = j.csrf;
      return j;
    }).catch(function(){ return { ok:false, error:'Bad response', _status: res.status }; });
  });
}
function route(){
  var hash = (location.hash || '#/').replace(/^#/, '');
  if (hash.charAt(0) !== '/') hash = '/' + hash;
  return hash.split('?')[0];
}
function go(p){ location.hash = '#' + p; }
function langBtn(){
  return h('<button class="btn ghost" data-act="lang" type="button">', S.lang === 'fa' ? 'EN' : 'فا', '</button>');
}
function brandName(){
  var p = S.status && S.status.panel;
  p = String(p || '').trim();
  return p || 'Ham';
}
function logo(){
  var ch = brandName().charAt(0) || 'H';
  return '<div class="logo">' + esc(ch.toUpperCase()) + '</div>';
}

function renderBoot(){
  document.getElementById('app').innerHTML = h('<div class="center"><div class="muted">', esc(t('boot')), '</div></div>');
}

var wiz = { step: 0, u:'admin', p:'', p2:'', e:'', rec:'', tok:'', err:'', tg_token:'', tg_chat:'' };

function validUser(u){ return /^[a-z0-9_]{3,32}$/.test(String(u || '').trim().toLowerCase()); }
function adminError(p, p2, rec){
  if (String(p || '').length < 8) return t('pass_short');
  if (p !== p2) return t('mismatch');
  rec = String(rec || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (rec.length !== 8) return t('rec_bad');
  return '';
}
function passLiveText(n){
  if (!n) return { c:'hint', m: t('pass_hint') };
  if (n < 8) return { c:'hint bad', m: t('pass_need') + String(8 - n) };
  return { c:'hint ok', m: t('pass_ok') };
}
function guideList(){
  var keys = ['db_1','db_2','db_3','db_4','db_5','db_6','db_7','db_8'];
  var out = '<ol class="guide">';
  var i;
  for (i = 0; i < keys.length; i++) out += h('<li><span class="n">', String(i + 1), '</span><span>', esc(t(keys[i])), '</span></li>');
  return out + '</ol>';
}

function renderSetup(){
  var db = S.status && S.status.db;
  if (!db) wiz.step = 0;
  var steps = ['s_db','s_admin','s_go'];
  var bars = '';
  var labs = '';
  var i;
  for (i=0;i<steps.length;i++){
    bars += h('<div class="step', i <= wiz.step ? ' on' : '', '"></div>');
    labs += h('<span class="', i === wiz.step ? 'on' : '', '">', esc(t(steps[i])), '</span>');
  }
  var inner = '';
  var live = passLiveText((wiz.p || '').length);
  if (wiz.step === 0){
    inner = h(
      db ? '<div class="okbox">' + esc(t('db_ok')) + '</div>' : '<div class="err">' + esc(t('db_fail')) + '</div>',
      '<p class="why"><b>', esc(t('db_why')), '</b> ', esc(t('db_why_t')), '</p>',
      '<div class="help"><b>', esc(t('db_help')), '</b>', guideList(),
      '<div class="mono" style="margin-top:8px">Variable name = <code>DB</code></div></div>',
      db ? '' : h('<p class="muted" style="margin-top:12px">', esc(t('wait_db')), '</p>'),
      '<div class="row" style="margin-top:16px;justify-content:space-between">',
      '<button class="btn" type="button" data-act="wiz-recheck">', esc(t('recheck')), '</button>',
      '<button class="btn primary" data-act="wiz-next" ', db ? '' : 'disabled', '>', esc(t('next')), '</button></div>'
    );
  } else if (wiz.step === 1){
    inner = h(
      '<p class="why">', esc(t('admin_help')), '</p>',
      wiz.err ? h('<div class="err">', esc(wiz.err), '</div>') : '',
      '<form data-form="wiz-admin">',
      '<div class="split">',
      '<div class="field"><label>', esc(t('pass')), '</label><input class="input" name="p" type="password" autocomplete="new-password" required minlength="8" value="', esc(wiz.p), '">',
      '<div id="pass-live" class="', live.c, '">', esc(live.m), '</div></div>',
      '<div class="field"><label>', esc(t('pass2')), '</label><input class="input" name="p2" type="password" autocomplete="new-password" required minlength="8" value="', esc(wiz.p2), '"></div>',
      '</div>',
      '<div class="field"><label>', esc(t('email')), '</label><input class="input" name="e" value="', esc(wiz.e), '" type="email" placeholder="admin@email.com"></div>',
      '<div class="field"><label>', esc(t('rec_code')), '</label><input class="input" name="rec" maxlength="8" dir="ltr" style="text-transform:uppercase;letter-spacing:4px" value="', esc(wiz.rec), '" required>',
      '<div class="rec-warn">', esc(t('rec_warn')), '</div></div>',
      '<div class="row" style="justify-content:space-between">',
      '<button class="btn" type="button" data-act="wiz-back">', esc(t('back')), '</button>',
      '<button class="btn primary" type="submit">', esc(t('next')), '</button></div></form>'
    );
  } else {
    inner = h(
      '<h2 style="margin-bottom:8px">', esc(t('done_t')), '</h2>',
      '<p class="muted" style="margin:0 0 14px">', esc(t('done_s')), '</p>',
      '<div class="okbox">', esc(t('vpn_help')), '</div>',
      '<p class="hint" style="margin-top:14px">', esc(t('wiz_tg_h')), '</p>',
      '<div class="field"><label>', esc(t('tg_token')), '</label><input class="input" id="wiz-tg-token" value="', esc(wiz.tg_token || ''), '" placeholder="123456:ABC..."></div>',
      '<div class="field"><label>', esc(t('tg_chat')), '</label><input class="input" id="wiz-tg-chat" value="', esc(wiz.tg_chat || ''), '" placeholder="123456789" inputmode="numeric"></div>',
      '<div class="row" style="margin-top:16px;justify-content:space-between">',
      '<button class="btn" type="button" data-act="wiz-back">', esc(t('back')), '</button>',
      '<button class="btn primary" data-act="wiz-finish">', esc(t('finish')), '</button></div>'
    );
  }
  document.getElementById('app').innerHTML = h(
    '<div class="center"><div class="card wiz-card">',
    '<div class="row" style="justify-content:space-between;margin-bottom:18px">',
    '<div class="brand">', logo(), '<div><h1 style="font-size:22px">', esc(t('brand')), '</h1><div class="muted" style="font-size:12px">', esc(t('tag')), '</div></div></div>',
    langBtn(), '</div>',
    '<h2 style="font-size:20px;margin-bottom:6px">', esc(t('w_title')), '</h2>',
    '<p class="muted" style="margin:0 0 16px;font-size:13px;line-height:1.7">', esc(t('w_sub')), '</p>',
    '<div class="steps">', bars, '</div>',
    '<div class="step-lbl">', labs, '</div>',
    inner,
    '<div class="muted" style="margin-top:18px;font-size:11px">', esc(brandName()), ' · ', esc(t('author')), '</div>',
    '</div></div>'
  );
}

function otpBoxesHtml(){
  var i, s = '<div class="otp-row" id="otp-row">';
  for (i = 0; i < 8; i++) s += '<input class="otp-cell" maxlength="1" inputmode="text" autocomplete="off" data-i="' + i + '">';
  return s + '</div><div id="otp-banner"></div>';
}
function bindOtp(onFull){
  var cells = document.querySelectorAll('.otp-cell');
  function val(){
    var s = '', i;
    for (i = 0; i < cells.length; i++) s += String(cells[i].value || '').toUpperCase().replace(/[^A-Z0-9]/g,'');
    return s.slice(0, 8);
  }
  function paint(ch, idx){
    ch = String(ch || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!ch) { cells[idx].value = ''; return; }
    cells[idx].value = ch.charAt(0);
    if (idx < 7) cells[idx + 1].focus();
    if (val().length === 8 && onFull) onFull(val());
  }
  Array.prototype.forEach.call(cells, function(el, idx){
    el.addEventListener('input', function(){ paint(el.value, idx); });
    el.addEventListener('keydown', function(ev){
      if (ev.key === 'Backspace' && !el.value && idx > 0) { cells[idx-1].focus(); cells[idx-1].value=''; }
    });
    el.addEventListener('paste', function(ev){
      ev.preventDefault();
      var p = normOtp((ev.clipboardData || window.clipboardData).getData('text'));
      var i;
      for (i = 0; i < 8; i++) cells[i].value = p.charAt(i) || '';
      if (p.length === 8 && onFull) onFull(p);
    });
  });
  if (cells[0]) cells[0].focus();
  return val;
}
function showOtpBanner(ok){
  var row = document.getElementById('otp-row');
  var ban = document.getElementById('otp-banner');
  if (row) row.className = 'otp-row ' + (ok ? 'ok' : 'bad');
  if (ban) ban.innerHTML = ok
    ? h('<div class="otp-banner ok"><span class="otp-emo">😄</span>', esc(t('otp_ok')), '</div>')
    : h('<div class="otp-banner bad"><span class="otp-emo">😢</span>', esc(t('otp_bad')), '</div>');
}
function renderLogin2fa(tmp, remember){
  document.getElementById('app').innerHTML = h(
    '<div class="center"><div class="card" style="width:min(460px,100%);padding:26px">',
    '<div class="brand" style="margin-bottom:18px">', logo(), '<div><h1 style="font-size:22px">', esc(t('otp')), '</h1><div class="muted" style="font-size:12px">', esc(t('otp_h')), '</div></div></div>',
    '<form data-form="login-2fa">',
    '<input type="hidden" name="tmp" value="', esc(tmp || ''), '">',
    otpBoxesHtml(),
    '</form></div></div>'
  );
  bindOtp(function(code){
    api('/api/login/2fa','POST',{ tmp: tmp, code: code, remember: !!remember }).then(function(r){
      showOtpBanner(!!r.ok);
      if (r.ok) setTimeout(function(){ boot(); }, 900);
    });
  });
}
function renderLogin(){
  document.getElementById('app').innerHTML = h(
    '<div class="center"><div class="card" style="width:min(420px,100%);padding:26px">',
    '<div class="row" style="justify-content:space-between;margin-bottom:18px">',
    '<div class="brand">', logo(), '<div><h1 style="font-size:22px">', esc(brandName()), '</h1><div class="muted" style="font-size:12px">', esc(t('login_sub')), '</div></div></div>',
    langBtn(), '</div>',
    '<form data-form="login">',
    '<div class="field"><label>', esc(t('pass')), '</label><input class="input" name="p" type="password" autocomplete="current-password" required></div>',
    '<label class="pill" style="margin-bottom:12px"><input type="checkbox" name="remember"> ', esc(t('remember')), '</label>',
    '<button class="btn primary" style="width:100%" type="submit">', esc(t('enter')), '</button>',
    '</form>',
    '<div class="muted" style="margin-top:18px;font-size:11px">', esc(brandName()), ' · ', esc(t('author')), '</div>',
    '</div></div>'
  );
}

function ico(name){
  var p = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';
  if (name==='dash') return '<svg '+p+'><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/></svg>';
  if (name==='vpn') return '<svg '+p+'><path d="M12 3l8 4v5c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V7l8-4z"/><path d="M9 12l2 2 4-4"/></svg>';
  if (name==='sub') return '<svg '+p+'><path d="M4 7h16M4 12h10M4 17h7"/><path d="M16 12l4 4-4 4"/></svg>';
  if (name==='users') return '<svg '+p+'><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="3"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>';
  if (name==='cf') return '<svg '+p+'><path d="M4 15h12a4 4 0 1 0-1-7.9A5.5 5.5 0 0 0 4.4 12"/><path d="M4 15h16a3 3 0 0 0 0-6"/></svg>';
  if (name==='dns') return '<svg '+p+'><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>';
  if (name==='cache') return '<svg '+p+'><path d="M13 2L4 14h7l-1 8 10-14h-7z"/></svg>';
  if (name==='logs') return '<svg '+p+'><path d="M8 6h13M8 12h13M8 18h13M4 6h.01M4 12h.01M4 18h.01"/></svg>';
  if (name==='settings') return '<svg '+p+'><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1"/></svg>';
  return '';
}
function navItem(href, key){
  var on = S.view === href || (href === '/' && (S.view === '/' || S.view === ''));
  return h('<a href="#', href, '" class="', on ? 'on' : '', '"><span class="ni">', ico(key), '</span><span>', esc(t(key)), '</span></a>');
}
function pingIpBrowser(ip){
  return new Promise(function(resolve){
    var t0 = performance.now();
    var done = false;
    function finish(ok){
      if (done) return;
      done = true;
      resolve({ ip: ip, ok: !!ok, ms: Math.round(performance.now() - t0) });
    }
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var tid = setTimeout(function(){ if (ctrl) try { ctrl.abort(); } catch (e) {} finish(false); }, 3500);
    var opt = { cache: 'no-store', mode: 'no-cors' };
    if (ctrl) opt.signal = ctrl.signal;
    fetch('https://' + ip + '/cdn-cgi/trace', opt).then(function(){
      clearTimeout(tid);
      finish(true);
    }).catch(function(){
      var img = new Image();
      img.onload = function(){ clearTimeout(tid); finish(true); };
      img.onerror = function(){ clearTimeout(tid); finish(false); };
      img.src = 'https://' + ip + '/favicon.ico?t=' + Date.now();
    });
  });
}
function taIps(){
  var ta = document.querySelector('[name=proxy_ips]');
  if (!ta) return [];
  var raw = String(ta.value || '').split(/[\s,]+/);
  var out = [], i, x;
  for (i = 0; i < raw.length; i++){
    x = raw[i].trim();
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(x)) continue;
    if (out.indexOf(x) === -1) out.push(x);
  }
  return out;
}
function syncIpPick(){
  var box = document.getElementById('ip-pick');
  if (!box) return;
  var ips = taIps();
  var on = {};
  var i, ip, ping;
  box.querySelectorAll('[name=proxy_ip_on]:checked').forEach(function(c){ on[c.value] = 1; });
  if (S.ipOn){
    for (i = 0; i < S.ipOn.length; i++) on[S.ipOn[i]] = 1;
  }
  if (!ips.length){
    box.innerHTML = '<div class="muted">' + esc(t('ips_pick_empty')) + '</div>';
    return;
  }
  var html = '<div class="chkgrid">';
  for (i = 0; i < ips.length; i++){
    ip = ips[i];
    ping = S.ipPing ? S.ipPing[ip] : null;
    var geo = (S.ipGeo && S.ipGeo[ip]) ? (S.ipGeo[ip].cc || S.ipGeo[ip].country) : '';
    html += '<label class="pill"><input type="checkbox" name="proxy_ip_on" value="' + esc(ip) + '"' + (on[ip] ? ' checked' : '') + '> ' + esc(ip);
    if (geo) html += ' · ' + esc(geo);
    if (ping === 'wait' || ping === '…') html += ' · …';
    else if (ping === -1) html += ' · N/A';
    else if (typeof ping === 'number' && ping >= 0) html += ' · ' + ping + 'ms';
    html += '</label>';
  }
  box.innerHTML = html + '</div>';
  requestIpGeo(ips);
}
function requestIpGeo(ips){
  S.ipGeo = S.ipGeo || {};
  var miss = [];
  var i;
  for (i = 0; i < ips.length; i++) if (!S.ipGeo[ips[i]]) miss.push(ips[i]);
  if (!miss.length) return;
  api('/api/ips/geo','POST',{ ips: miss.slice(0, 40) }).then(function(r){
    if (!r.ok || !r.geo) return;
    var k;
    for (k in r.geo) if (r.geo[k]) S.ipGeo[k] = r.geo[k];
    syncIpPick();
  });
}
function randName(){
  var c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  var s = '', i;
  for (i = 0; i < 5; i++) s += c.charAt(Math.floor(Math.random() * c.length));
  return s;
}
function copyText(s){
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(s).then(function(){ toast(t('copied')); }).catch(function(){ toast(s); });
  } else toast(s);
}
function fmtDashBytes(n){
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  if (n < 1024*1024*1024) return (n/(1024*1024)).toFixed(2) + ' MB';
  return (n/(1024*1024*1024)).toFixed(2) + ' GB';
}
function hostSelect(name, cur){
  var hosts = S.hosts || [];
  var o = h('<option value="">', esc(t('host_default')), '</option>');
  var i;
  for (i = 0; i < hosts.length; i++){
    o += h('<option value="', esc(hosts[i]), '"', (cur && cur === hosts[i]) ? ' selected' : '', '>', esc(hosts[i]), '</option>');
  }
  if (cur && hosts.indexOf(cur) === -1) o += h('<option value="', esc(cur), '" selected>', esc(cur), '</option>');
  return h('<select name="', name, '">', o, '</select>');
}
function locSelect(name){
  var locs = ['random','DE','NL','TR','US','GB','FR','FI','SE','AT','AE','SG','JP','IN','CA','AU','PL','IT','ES'];
  var o = '';
  var i;
  for (i = 0; i < locs.length; i++){
    o += h('<option value="', locs[i], '">', esc(locs[i] === 'random' ? t('loc_random') : locs[i]), '</option>');
  }
  return h('<select name="', name, '">', o, '</select>');
}
function portBoxes(name, multi, selected){
  var on = (S.meta && S.meta.ports && S.meta.ports.length) ? S.meta.ports : [80,8080,2052,443];
  selected = selected || [];
  var seln = [];
  var si;
  for (si = 0; si < selected.length; si++) seln.push(Number(selected[si]));
  var out = '<div class="chkgrid">';
  var i, p, typ, chk, has443;
  has443 = on.indexOf(443) !== -1 || on.indexOf('443') !== -1;
  for (i = 0; i < on.length; i++){
    p = Number(on[i]);
    typ = multi ? 'checkbox' : 'radio';
    if (seln.length) chk = seln.indexOf(p) !== -1 ? ' checked' : '';
    else chk = multi ? ' checked' : ((has443 ? p===443 : i===0) ? ' checked' : '');
    out += h('<label class="pill"><input type="', typ, '" name="', name, '" value="', String(p), '"', chk, '> ', String(p), '</label>');
  }
  return out + '</div>';
}
function pickedPorts(f, name){
  var els = f.querySelectorAll('[name="'+name+'"]');
  var out = [];
  var i;
  for (i=0;i<els.length;i++) if (els[i].checked) out.push(els[i].value);
  return out;
}
function shell(content){
  stopVpnAlivePoll();
  var u = S.status && S.status.user ? S.status.user.username : '';
  document.getElementById('app').innerHTML = h(
    '<div class="shell">',
    '<header class="topbar">',
    '<div class="brand">', logo(), '<div><b>', esc(brandName()), '</b></div></div>',
    '<nav class="nav">',
    navItem('/', 'dash'),
    navItem('/vpn', 'vpn'),
    navItem('/logs', 'logs'),
    navItem('/settings', 'settings'),
    '</nav>',
    '<div class="hbar">',
    '<span class="muted" style="font-size:12px">', esc(t('hello')), ' ', esc(u), '</span>',
    langBtn(),
    '<button class="btn ghost" data-act="theme-tog" title="theme">', S.theme === 'dark' ? '☀' : '☾', '</button>',
    '<button class="btn" data-act="logout">', esc(t('logout')), '</button>',
    '</div></header>',
    '<main>',
    content,
    '</main></div>'
  );
}

function renderApp(){
  S.view = route();
  if (S.view === '/vpn') return viewVpn();
  if (S.view === '/logs') return viewLogs();
  if (S.view === '/settings') return viewSettings();
  return viewDash();
}

function appBtns(url){
  var enc = encodeURIComponent(url);
  return h(
    '<div class="row">',
    '<a class="btn primary" href="hiddify://install-sub?url=', enc, '">Hiddify</a>',
    '<a class="btn" href="v2rayng://install-config?url=', enc, '">v2rayNG</a>',
    '<a class="btn" href="clash://install-config?url=', enc, '">Clash</a>',
    '<a class="btn" href="streisand://import/', enc, '">Streisand</a>',
    '<a class="btn" href="shadowrocket://add/', enc, '">Shadowrocket</a>',
    '</div>'
  );
}

function vpnModal(pr){
  var el = document.getElementById('modal');
  if (!el) return;
  pr = pr || null;
  var days = pr && pr.remain_days != null && pr.remain_days >= 0 ? String(pr.remain_days) : '0';
  var qgb = pr && pr.quota_gb != null ? String(pr.quota_gb) : '0';
  var proto = pr && String(pr.protocols||'vless').indexOf('trojan') !== -1 ? 'trojan' : 'vless';
  el.innerHTML = h(
    '<div class="modalbg"><div class="card modal"><h3 style="margin-bottom:12px">', esc(pr ? t('edit_vpn') : t('vpn_new')), '</h3>',
    '<form data-form="', pr ? 'vpn-edit' : 'vpn-add', '">',
    pr ? h('<input type="hidden" name="id" value="', esc(pr.id), '">') : '',
    '<div class="field"><label>', esc(t('vpn_name')), '</label><input class="input" name="name" value="', esc(pr ? pr.name : randName()), '" required></div>',
    '<div class="field"><label>', esc(t('remark')), '</label><input class="input" name="remark" value="', esc(pr ? (pr.remark||'') : ''), '" placeholder="', esc(t('remark_h')), '"></div>',
    '<div class="field"><label>UUID</label><div class="row"><input class="input grow" name="uuid" id="uuid-in" value="', esc(pr ? (pr.uuid||'') : ''), '" placeholder="', esc(t('vpn_uuid_ph')), '"><button class="btn" type="button" data-act="uuid-gen">', esc(t('vpn_uuid_rand')), '</button></div></div>',
    '<div class="field"><label>', esc(t('vpn_proto')), ' · ', esc(t('vpn_one_proto')), '</label><div class="chkgrid">',
    '<label class="pill"><input type="radio" name="proto" value="vless" checked> VLESS</label>',
    '</div><div class="hint">', esc(t('vpn_proto_hint')), '</div></div>',
    '<div class="field"><label>', esc(t('port')), ' · ', esc(t('vpn_one_port')), '</label>', portBoxes('port', false, pr ? [pr.port||443] : []), '</div>',
    '<div class="split"><div class="field"><label>', esc(t('vpn_quota')), '</label><input class="input" name="quota_gb" type="number" min="0" step="0.1" value="', esc(qgb), '"></div>',
    '<div class="field"><label>', esc(t('vpn_days')), '</label><input class="input" name="days" type="number" min="0" value="', esc(days), '"></div></div>',
    '<div class="field"><label>', esc(t('vpn_maxip')), '</label><input class="input" name="max_ip" type="number" min="0" value="', esc(pr ? String(pr.max_ip||0) : '0'), '"></div>',
    '<div class="field"><label>', esc(t('speed')), '</label><input class="input" name="speed_mbps" type="number" min="0" step="0.1" value="', esc(pr ? String(((Number(pr.speed_kbps)||0)/1024)) : '0'), '"></div>',
    (function(){
      var pool = (S.vpnIps || []).slice();
      if (pr && pr.ips){
        var extraIp = String(pr.ips).split(/[\s,]+/).filter(Boolean)[0];
        if (extraIp && pool.indexOf(extraIp) === -1) pool.unshift(extraIp);
      }
      if (!pool.length) return '<p class="hint">' + esc(t('vpn_ip_none')) + '</p>';
      var sel = String((pr && pr.ips) || '').split(/[\s,]+/).filter(Boolean)[0] || '';
      var html = '<div class="field"><label>' + esc(t('vpn_ip_pick')) + '</label>';
      html += '<div class="row" style="margin-bottom:8px"><button class="btn" type="button" data-act="cfg-ips-ping">' + esc(t('vpn_ip_test')) + '</button></div>';
      html += '<div class="chkgrid">';
      html += '<label class="pill"><input type="radio" name="cfg_ip" value=""' + (!sel?' checked':'') + '> ' + esc(t('vpn_ip_direct')) + '</label>';
      var i, ip, ping, extra;
      for (i = 0; i < pool.length; i++){
        ip = pool[i];
        ping = S.ipPing ? S.ipPing[ip] : null;
        extra = '';
        if (ping === -1) extra = ' · N/A';
        else if (typeof ping === 'number') extra = ' · ' + ping + 'ms';
        var g = (S.ipGeo && S.ipGeo[ip]) ? (S.ipGeo[ip].cc || S.ipGeo[ip].country) : '';
        html += '<label class="pill"><input type="radio" name="cfg_ip" value="' + esc(ip) + '"' + (sel===ip?' checked':'') + '> ' + esc(ip) + (g ? ' · ' + esc(g) : '') + '<span data-ip-ms="' + esc(ip) + '">' + extra + '</span></label>';
      }
      try { requestIpGeo(pool); } catch (eG2) {}
      return html + '</div></div>';
    })(),
    '<div class="row" style="justify-content:flex-end"><button class="btn" type="button" data-act="modal-close">', esc(t('cancel')), '</button>',
    '<button class="btn primary" type="submit">', esc(pr ? t('update') : t('create')), '</button></div></form></div></div>'
  );
  if (pr && pr.location){
    var sel = el.querySelector('[name=location]');
    if (sel) sel.value = pr.location;
  }
}

function subModal(s){
  var el = document.getElementById('modal');
  if (!el) return;
  s = s || null;
  var days = s && s.remain_days != null && s.remain_days >= 0 ? String(s.remain_days) : '30';
  var qgb = s && s.quota_gb != null ? String(s.quota_gb) : '0';
  var protos = String((s && s.protocols) || 'vless,trojan');
  var ports = s && s.ports ? String(s.ports).split(',') : [];
  el.innerHTML = h(
    '<div class="modalbg"><div class="card modal"><h3 style="margin-bottom:8px">', esc(s ? t('edit_sub') : t('sub_make')), '</h3>',
    '<p class="hint" style="margin-bottom:12px">', esc(t('edit_sub_h')), '</p>',
    '<form data-form="', s ? 'sub-edit' : 'sub-add', '">',
    s ? h('<input type="hidden" name="id" value="', esc(s.id), '">') : '',
    '<div class="field"><label>', esc(t('vpn_name')), '</label><input class="input" name="name" value="', esc(s ? s.name : randName()), '" required></div>',
    '<div class="split">',
    '<div class="field"><label>', esc(t('vpn_quota')), '</label><input class="input" name="quota_gb" type="number" min="0" step="0.1" value="', esc(qgb), '"></div>',
    '<div class="field"><label>', esc(t('vpn_days')), '</label><input class="input" name="days" type="number" min="0" value="', esc(days), '"></div>',
    '</div>',
    '<div class="split">',
    '<div class="field"><label>', esc(t('vpn_maxip')), '</label><input class="input" name="max_ip" type="number" min="0" value="', esc(s ? String(s.max_ip||0) : '0'), '"></div>',
    '</div>',
    '<div class="field"><label>', esc(t('vpn_proto')), '</label><div class="chkgrid">',
    '<label class="pill"><input type="checkbox" name="p_vless"', protos.indexOf('vless')!==-1?' checked':'', '> VLESS</label>',
    '<label class="pill"><input type="checkbox" name="p_trojan"', protos.indexOf('trojan')!==-1?' checked':'', '> Trojan</label>',
    '</div></div>',
    '<div class="field"><label>', esc(t('sub_ports')), '</label>', portBoxes('port', true, ports), '</div>',
    '<div class="split"><div class="field"><label>', esc(t('speed')), '</label><input class="input" name="speed_mbps" type="number" min="0" step="0.1" value="', esc(s ? String(((Number(s.speed_kbps)||0)/1024)) : '0'), '"></div>',
    '<div class="field"><label>', esc(t('extra_host')), '</label>', hostSelect('extra_host', s ? (s.extra_host||'') : ''), '</div></div>',
    '<div class="split"><div class="field"><label>', esc(t('sub_pass')), '</label><input class="input" name="sub_pass" value="', esc(s ? (s.sub_pass||'') : ''), '"></div>',
    '<div class="field"><label class="pill"><input type="checkbox" name="one_shot"', (s && Number(s.one_shot)) ? ' checked' : '', '> ', esc(t('one_shot')), '</label></div></div>',
    '<div class="row" style="justify-content:flex-end"><button class="btn" type="button" data-act="modal-close">', esc(t('cancel')), '</button>',
    '<button class="btn primary" type="submit">', esc(s ? t('update') : t('sub_make')), '</button></div></form></div></div>'
  );
  if (s && s.location){
    var sel = el.querySelector('[name=location]');
    if (sel) sel.value = s.location;
  }
}

function viewVpn(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/vpn').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    S.meta = { ports: d.ports || [] };
    S.hosts = d.hosts || [];
    S.vpnIps = d.ips || [];
    S.vpnList = d.peers || [];
    var cards = (d.peers || []).map(function(pr){
      var L = pr.links || {};
      var items = L.items || [];
      var first = (items[0] && items[0].link) || L.vless || L.trojan || '';
      var exp = pr.remain_days != null && pr.remain_days >= 0 ? (String(pr.remain_days) + 'd') : '∞';
      var vless = L.vless || first;
      return h(
        '<div class="card vpn-card">',
        '<div class="row" style="justify-content:space-between">',
        '<div><b>', esc(pr.name), '</b> ', pr.location ? h('<span class="pill">', esc(pr.location), '</span>') : '',
        ' <span class="pill">', esc(String(pr.port||443)), '</span>',
        '<span class="alive-wrap"><span class="alive-box ', pr.online ? 'on' : 'off', '" data-act="alive-tip" data-alive-id="', pr.id, '" data-last="', esc(pr.last_h || ''), '">', esc(pr.online ? t('online') : t('offline')), '</span><span class="alive-tip">', esc(t('last_conn')), ': ', esc(pr.last_h || '—'), '</span></span>',
        '<div class="muted" style="font-size:12px;margin-top:6px">', esc(pr.used_h), ' / ', esc(pr.quota_h), ' · ', esc(exp), '</div></div>',
        pr.alive ? '<span class="pill ok">' + esc(t('vpn_on')) + '</span>' : '<span class="pill bad">' + esc(t('vpn_off')) + '</span>',
        '</div>',
        vless ? h('<div class="row" style="align-items:flex-start;gap:10px;margin-top:10px"><div class="linkbox" style="flex:1">', esc(vless), '</div><img alt="QR" width="96" height="96" style="border-radius:8px;background:#fff;flex:none" src="https://api.qrserver.com/v1/create-qr-code/?size=96x96&ecc=M&margin=4&data=', encodeURIComponent(vless), '"></div>') : '',
        '<div class="row">',
        vless ? h('<button class="btn primary" data-act="vpn-copy" data-link="', esc(vless), '">', esc(t('share')), '</button>') : '',
        vless ? h('<button class="btn" data-act="vpn-copy" data-link="', esc(vless), '">VLESS</button>') : '',
        vless ? h('<button class="btn" data-act="vpn-qr" data-link="', esc(vless), '">', esc(t('qr')), '</button>') : '',
        '<button class="btn" data-act="vpn-edit" data-id="', pr.id, '">', esc(t('edit')), '</button>',
        '<button class="btn" data-act="vpn-tog" data-id="', pr.id, '" data-en="', pr.enabled ? 0 : 1, '">', esc(pr.enabled ? t('vpn_off') : t('vpn_on')), '</button>',
        '<button class="btn danger" data-act="vpn-del" data-id="', pr.id, '">', esc(t('del')), '</button>',
        '</div></div>'
      );
    }).join('');
    shell(h(
      '<div class="top"><div><div class="page-kicker">', esc(brandName()), '</div><h2>', esc(t('vpn')), '</h2></div>',
      '<button class="btn primary" data-act="vpn-add">', esc(t('vpn_new')), '</button></div>',
      '<div class="card" style="padding:16px;margin-bottom:14px">',
      '<div class="howto">',
      '<div><span class="pill">1</span><span>', esc(t('vpn_h1')), '</span></div>',
      '<div><span class="pill">2</span><span>', esc(t('vpn_h2')), '</span></div>',
      '<div><span class="pill">3</span><span>', esc(t('vpn_h3')), '</span></div></div>',
      '<div class="muted mono" style="margin-top:10px;font-size:11px">', esc((d.proxy && d.proxy.host) || ''), ' · ', esc((d.proxy && d.proxy.path) || ''), '</div></div>',
      (d.hosts && d.hosts.length ? h('<div class="host-chips" style="margin:0 0 12px">', d.hosts.map(function(hh){ return h('<span class="pill">', esc(hh), '</span>'); }).join(''), '</div>') : ''),
      '<div class="vpn-grid">', cards || h('<div class="card" style="padding:18px"><span class="muted">', esc(t('empty')), '</span></div>'), '</div>',
      '<div id="modal"></div>'
    ));
    startVpnAlivePoll();
  });
}

function stopVpnAlivePoll(){
  if (S.vpnAliveT) { clearInterval(S.vpnAliveT); S.vpnAliveT = 0; }
}
function paintAlive(p){
  var el = document.querySelector('[data-alive-id="' + p.id + '"]');
  if (!el) return;
  el.className = 'alive-box ' + (p.online ? 'on' : 'off');
  el.textContent = p.online ? t('online') : t('offline');
  el.setAttribute('data-last', p.last_h || '');
  var tip = el.parentNode && el.parentNode.querySelector('.alive-tip');
  if (tip) tip.textContent = t('last_conn') + ': ' + (p.last_h || '—');
}
function refreshVpnAlive(){
  if (S.view !== '/vpn') return;
  api('/api/vpn/alive').then(function(d){
    if (!d.ok || !d.peers) return;
    var i;
    for (i = 0; i < d.peers.length; i++) paintAlive(d.peers[i]);
  });
}
function startVpnAlivePoll(){
  stopVpnAlivePoll();
  S.vpnAliveT = setInterval(refreshVpnAlive, 60000);
}

function viewSub(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/sub').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    S.meta = { ports: d.ports || [] };
    S.hosts = d.hosts || [];
    S.subList = d.subs || [];
    var rows = (d.subs || []).map(function(s){
      var exp = s.remain_days != null && s.remain_days >= 0 ? (String(s.remain_days) + 'd') : '∞';
      return h(
        '<div class="card vpn-card">',
        '<div class="row" style="justify-content:space-between">',
        '<div class="row"><b>', esc(s.brand || s.name), '</b></div>',
        '<span class="pill">', esc(String(s.count)), '</span></div>',
        '<div class="muted" style="font-size:12px">', esc(s.protocols||''), ' · ', esc(s.ports||''), ' · ', esc(s.used_h||'0 B'), ' / ', esc(s.quota_h||'∞'), ' · ', esc(exp), '</div>',
        '<div class="linkbox">', esc(s.url), '</div>',
        '<div class="row">',
        '<button class="btn primary" data-act="vpn-copy" data-link="', esc(s.url), '">', esc(t('copied')==='Copied'?'Copy':'کپی ساب'), '</button>',
        '<button class="btn" data-act="vpn-copy" data-link="', esc(s.url + (s.url.indexOf('?')===-1?'?':'&') + 'format=clash'), '">', esc(t('clash')), '</button>',
        '<button class="btn" data-act="vpn-copy" data-link="', esc(s.url + (s.url.indexOf('?')===-1?'?':'&') + 'format=singbox'), '">', esc(t('singbox')), '</button>',
        s.status_url ? h('<button class="btn" data-act="vpn-copy" data-link="', esc(s.status_url), '">', esc(t('status_page')), '</button>') : '',
        '<button class="btn" data-act="sub-clone" data-id="', s.id, '">', esc(t('clone')), '</button>',
        '<button class="btn" data-act="sub-edit" data-id="', s.id, '">', esc(t('edit')), '</button>',
        '<button class="btn danger" data-act="sub-del" data-id="', s.id, '">', esc(t('del')), '</button>',
        '</div></div>'
      );
    }).join('');
    shell(h(
      '<div class="top"><div><div class="page-kicker">', esc(brandName()), '</div><h2>', esc(t('sub')), '</h2><p class="muted" style="margin:6px 0 0;font-size:13px">', esc(t('sub_help')), '</p></div>',
      '<button class="btn primary" data-act="sub-add">', esc(t('sub_make')), '</button></div>',
      '<p class="why">', esc(t('sub_help2')), '</p>',
      '<div class="vpn-grid">', rows || h('<div class="card" style="padding:18px"><span class="muted">', esc(t('empty')), '</span></div>'), '</div>',
      '<div id="modal"></div>'
    ));
  });
}

function viewDash(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/dashboard').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    var logs = (d.logs || []).map(function(x){
      return h('<tr><td class="mono">', esc(x.created_at || '').replace('T',' ').slice(0,19), '</td><td>', esc(x.action), '</td><td class="muted">', esc(x.detail || ''), '</td></tr>');
    }).join('');
    shell(h(
      '<div class="grid">',
      '<div class="card stat"><div class="muted">', esc(t('vpn')), '</div><b>', esc(d.peers_on || 0), '</b><div class="muted" style="font-size:11px">', esc(d.peers || 0), '</div></div>',
      '<div class="card stat"><div class="muted">', esc(t('vpn_traffic')), '</div><b>', esc(d.used_h || '0 B'), '</b></div>',
            '<div class="card stat"><div class="muted">', esc(t('vpn_loc')), '</div><b>', esc((d.loc && (d.loc.country || d.loc.colo)) || '—'), '</b><div class="muted" style="font-size:11px">', esc((d.loc && (d.loc.city || d.loc.colo)) || ''), '</div></div>',
      '<div class="card stat"><div class="muted">', esc(t('cf')), '</div>',
      (d.cf_money && d.cf_money.ok
        ? h('<b>', esc(t('cf_spend')), ' ', esc(d.cf_money.used_h), '</b><div class="muted" style="font-size:11px">', esc(t('cf_left')), ' ', esc(d.cf_money.left_h), '</div>')
        : h('<b style="font-size:13px">', esc(t('cf_no_tok')), '</b>')),
      '</div>',
      '</div>',
      '<div class="card" style="margin-top:14px;padding:16px">',
      '<span class="pill ok">', esc(t('vpn_edge')), '</span> <span class="muted">', esc((d.loc && d.loc.asOrg) || 'Cloudflare'), ' · ', esc((d.loc && d.loc.colo) || ''), '</span>',
      ' <a class="btn" href="', BASE, '/api/vpn.csv" style="margin-inline-start:8px">', esc(t('csv_export')), '</a>',
      '</div>',
      (d.health && d.health.length ? (function(){
        var hh = '<div class="card" style="margin-top:14px;padding:16px"><h3 style="margin-bottom:8px">' + esc(t('backup_health')) + '</h3>';
        var i, x;
        for (i = 0; i < d.health.length; i++){
          x = d.health[i];
          hh += '<div class="row" style="margin:6px 0"><span class="pill ' + (x.ok ? 'ok' : 'bad') + '">' + (x.ok ? 'OK' : 'DOWN') + '</span> <span class="mono">' + esc(x.host) + '</span> <span class="muted">' + esc(x.ms != null ? (x.ms + ' ms') : '') + '</span></div>';
        }
        return hh + '</div>';
      })() : ''),
      (function(){
        var cfgs = d.cfgs || [];
        if (!cfgs.length) return '';
        var html = '<div class="card" style="margin-top:14px;padding:16px"><h3 style="margin-bottom:10px">' + esc(t('vpn')) + '</h3>';
        var i, c, days;
        for (i = 0; i < cfgs.length; i++){
          c = cfgs[i];
          days = c.remain_days != null && c.remain_days >= 0 ? (c.remain_days + 'd') : '∞';
          html += '<div class="row" style="justify-content:space-between;align-items:flex-start;padding:10px 0;border-top:1px solid var(--line)">';
          html += '<div><b>' + esc(c.name) + '</b> ' + (c.location ? ('<span class="pill">' + esc(c.location) + '</span> ') : '');
          html += c.enabled ? '<span class="pill ok">' + esc(t('vpn_on')) + '</span>' : '<span class="pill bad">' + esc(t('vpn_off')) + '</span>';
          html += '<div class="muted" style="font-size:12px;margin-top:6px">' + esc(c.used_h) + ' / ' + esc(c.quota_h);
          html += ' · ' + esc(c.remain_h) + ' · ' + esc(days) + '</div></div></div>';
        }
        return html + '</div>';
      })(),
      '<div class="card" style="margin-top:14px;padding:16px">',
      '<h3 style="margin-bottom:8px">', esc(t('chart')), '</h3>',
      (function(){
        var daily = d.daily || [];
        if (!daily.length) return '<div class="muted">'+esc(t('empty'))+'</div>';
        var max = 1, i;
        for (i=0;i<daily.length;i++) if (Number(daily[i].bytes)>max) max=Number(daily[i].bytes);
        var html = '<div class="bars">';
        for (i=0;i<daily.length;i++){
          var ht = Math.max(6, Math.round(100 * Number(daily[i].bytes) / max));
          html += '<div class="barcol" title="'+esc(fmtDashBytes(daily[i].bytes))+'"><div class="bar" style="height:'+ht+'%"></div><div class="barlbl">'+esc(String(daily[i].day||'').slice(5))+'</div></div>';
        }
        return html + '</div>';
      })(),
      '</div>',
      '<div class="card" style="margin-top:14px;padding:16px;overflow:auto">',
      '<h3 style="margin-bottom:10px">', esc(t('recent')), '</h3>',
      '<table class="table"><thead><tr><th>time</th><th>action</th><th>detail</th></tr></thead><tbody>',
      logs || h('<tr><td colspan="3" class="muted">', esc(t('empty')), '</td></tr>'),
      '</tbody></table></div>'
    ));
  });
}

function roleLabel(r){ return r === 'admin' ? t('admin') : r === 'operator' ? t('operator') : t('viewer'); }

function viewUsers(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/users').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    var rows = (d.users || []).map(function(u){
      return h(
        '<tr>',
        '<td>', esc(u.username), '</td>',
        '<td><span class="pill">', esc(roleLabel(u.role)), '</span></td>',
        '<td>', esc(u.email || ''), '</td>',
        '<td>', u.active ? '<span class="pill ok">on</span>' : '<span class="pill bad">off</span>', '</td>',
        '<td class="muted mono">', esc((u.last_login || '').replace('T',' ').slice(0,16)), '</td>',
        '<td><div class="row">',
        '<button class="btn" data-act="u-edit" data-id="', u.id, '" data-username="', esc(u.username), '" data-role="', esc(u.role), '" data-email="', esc(u.email || ''), '" data-active="', u.active ? 1 : 0, '">', esc(t('edit')), '</button>',
        '<button class="btn danger" data-act="u-del" data-id="', u.id, '">', esc(t('del')), '</button>',
        '</div></td></tr>'
      );
    }).join('');
    shell(h(
      '<div class="top"><h2>', esc(t('users')), '</h2><button class="btn primary" data-act="u-add">', esc(t('add_user')), '</button></div>',
      '<div class="card" style="padding:8px 12px;overflow:auto"><table class="table"><thead><tr>',
      '<th>', esc(t('user')), '</th><th>', esc(t('role')), '</th><th>email</th><th>', esc(t('active')), '</th><th>login</th><th>', esc(t('actions')), '</th>',
      '</tr></thead><tbody>', rows || h('<tr><td colspan="6" class="muted">', esc(t('empty')), '</td></tr>'), '</tbody></table></div>',
      '<div id="modal"></div>'
    ));
  });
}

function userModal(mode, u){
  u = u || { id:'', username:'', role:'viewer', email:'', active:1 };
  var el = document.getElementById('modal');
  if (!el) return;
  el.innerHTML = h(
    '<div class="modalbg"><div class="card modal">',
    '<h3 style="margin-bottom:14px">', esc(mode === 'add' ? t('add_user') : t('edit')), '</h3>',
    '<form data-form="', mode === 'add' ? 'user-add' : 'user-edit', '">',
    '<input type="hidden" name="id" value="', esc(u.id), '">',
    '<div class="field"><label>', esc(t('user')), '</label><input class="input" name="username" value="', esc(u.username), '" ', mode==='edit'?'readonly':'', ' required></div>',
    '<div class="field"><label>', esc(t('pass')), '</label><input class="input" name="password" type="password" ', mode==='add'?'required':'', '></div>',
    '<div class="field"><label>', esc(t('role')), '</label><select name="role">',
    '<option value="admin"', u.role==='admin'?' selected':'', '>', esc(t('admin')), '</option>',
    '<option value="operator"', u.role==='operator'?' selected':'', '>', esc(t('operator')), '</option>',
    '<option value="viewer"', u.role==='viewer'?' selected':'', '>', esc(t('viewer')), '</option>',
    '</select></div>',
    '<div class="field"><label>email</label><input class="input" name="email" value="', esc(u.email), '"></div>',
    mode==='edit' ? h('<div class="field"><label>', esc(t('active')), '</label><select name="active"><option value="1"', u.active?' selected':'', '>on</option><option value="0"', !u.active?' selected':'', '>off</option></select></div>') : '',
    '<div class="row" style="justify-content:flex-end"><button class="btn" type="button" data-act="modal-close">', esc(t('cancel')), '</button>',
    '<button class="btn primary" type="submit">', esc(t('save')), '</button></div></form></div></div>'
  );
}

function viewCf(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  Promise.all([api('/api/cf/zones'), api('/api/cf/workers'), api('/api/cf/accounts')]).then(function(arr){
    var z = arr[0], w = arr[1], a = arr[2];
    var zrows = '';
    if (z.ok) (z.zones || []).forEach(function(x){
      zrows += h('<tr><td>', esc(x.name), '</td><td class="mono muted">', esc(x.id), '</td><td><span class="pill ', x.status==='active'?'ok':'warn', '">', esc(x.status), '</span></td><td>', esc(x.plan && x.plan.name || ''), '</td></tr>');
    });
    var wrows = '';
    if (w.ok) (w.scripts || []).forEach(function(s){
      wrows += h('<tr><td>', esc(s.id), '</td><td class="muted">', esc((s.modified_on || '').replace('T',' ').slice(0,19)), '</td></tr>');
    });
    shell(h(
      '<div class="top"><h2>', esc(t('zones_title')), '</h2><div class="row">',
      '<button class="btn" data-act="cf-verify">', esc(t('verify')), '</button>',
      '<button class="btn" data-act="reload">', esc(t('refresh')), '</button></div></div>',
      !z.ok ? h('<div class="err">', esc(z.error || t('err')), '</div>') : '',
      '<div class="card" style="padding:8px 12px;overflow:auto;margin-bottom:14px"><table class="table"><thead><tr><th>zone</th><th>id</th><th>status</th><th>plan</th></tr></thead><tbody>',
      zrows || h('<tr><td colspan="4" class="muted">', esc(t('empty')), '</td></tr>'), '</tbody></table></div>',
      '<h3 style="margin:0 0 10px">', esc(t('workers')), '</h3>',
      !w.ok ? h('<div class="err">', esc(w.error || t('err')), '</div>') : '',
      '<div class="card" style="padding:8px 12px;overflow:auto"><table class="table"><thead><tr><th>script</th><th>modified</th></tr></thead><tbody>',
      wrows || h('<tr><td colspan="2" class="muted">', esc(t('empty')), '</td></tr>'), '</tbody></table></div>'
    ));
  });
}

function zoneSelect(id, zones){
  var o = h('<option value="">', esc(t('pick_zone')), '</option>');
  (zones || []).forEach(function(z){ o += h('<option value="', esc(z.id), '"', z.id===id?' selected':'', '>', esc(z.name), '</option>'); });
  return h('<select id="zone" data-act="zone-change">', o, '</select>');
}

function viewDns(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/cf/zones').then(function(z){
    if (!z.ok){ shell(h('<div class="err">', esc(z.error || t('err')), '</div>')); return; }
    var zid = sessionStorage.getItem('ham_zone') || ((z.zones && z.zones[0] && z.zones[0].id) || '');
    function draw(records){
      var rows = (records || []).map(function(r){
        return h('<tr><td class="pill">', esc(r.type), '</td><td class="mono">', esc(r.name), '</td><td>', esc(r.content), '</td><td>', r.proxied ? '<span class="pill ok">proxied</span>' : '<span class="pill">dns</span>', '</td>',
          '<td><div class="row"><button class="btn danger" data-act="dns-del" data-zid="', esc(zid), '" data-id="', esc(r.id), '">', esc(t('del')), '</button></div></td></tr>');
      }).join('');
      shell(h(
        '<div class="top"><h2>', esc(t('dns_title')), '</h2><div class="row" style="min-width:280px">', zoneSelect(zid, z.zones),
        '<button class="btn primary" data-act="dns-add">', esc(t('add_rec')), '</button></div></div>',
        '<div class="card" style="padding:8px 12px;overflow:auto"><table class="table"><thead><tr><th>', esc(t('type')), '</th><th>', esc(t('name')), '</th><th>', esc(t('content')), '</th><th>', esc(t('proxied')), '</th><th></th></tr></thead><tbody>',
        rows || h('<tr><td colspan="5" class="muted">', esc(t('empty')), '</td></tr>'), '</tbody></table></div><div id="modal"></div>'
      ));
    }
    if (!zid){ draw([]); return; }
    sessionStorage.setItem('ham_zone', zid);
    api('/api/cf/zones/' + zid + '/dns').then(function(d){
      if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
      draw(d.records);
    });
  });
}

function dnsModal(){
  var zid = sessionStorage.getItem('ham_zone') || '';
  var el = document.getElementById('modal');
  if (!el) return;
  el.innerHTML = h(
    '<div class="modalbg"><div class="card modal"><h3 style="margin-bottom:14px">', esc(t('add_rec')), '</h3>',
    '<form data-form="dns-add"><input type="hidden" name="zid" value="', esc(zid), '">',
    '<div class="split"><div class="field"><label>', esc(t('type')), '</label><select name="type"><option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option><option>MX</option><option>NS</option></select></div>',
    '<div class="field"><label>', esc(t('ttl')), '</label><input class="input" name="ttl" value="1"></div></div>',
    '<div class="field"><label>', esc(t('name')), '</label><input class="input" name="name" required></div>',
    '<div class="field"><label>', esc(t('content')), '</label><input class="input" name="content" required></div>',
    '<div class="field"><label><input type="checkbox" name="proxied"> ', esc(t('proxied')), '</label></div>',
    '<div class="row" style="justify-content:flex-end"><button class="btn" type="button" data-act="modal-close">', esc(t('cancel')), '</button>',
    '<button class="btn primary" type="submit">', esc(t('create')), '</button></div></form></div></div>'
  );
}

function viewCache(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/cf/zones').then(function(z){
    if (!z.ok){ shell(h('<div class="err">', esc(z.error || t('err')), '</div>')); return; }
    var zid = sessionStorage.getItem('ham_zone') || ((z.zones && z.zones[0] && z.zones[0].id) || '');
    sessionStorage.setItem('ham_zone', zid);
    shell(h(
      '<div class="top"><h2>', esc(t('cache_title')), '</h2><div style="min-width:260px">', zoneSelect(zid, z.zones), '</div></div>',
      '<div class="card" style="padding:18px">',
      '<form data-form="purge">',
      '<div class="field"><label>', esc(t('urls_ph')), '</label><textarea name="urls" placeholder="https://example.com/path"></textarea></div>',
      '<div class="row"><button class="btn danger" name="all" value="1" type="submit">', esc(t('purge_all')), '</button>',
      '<button class="btn primary" type="submit">', esc(t('purge_urls')), '</button></div>',
      '</form></div>'
    ));
  });
}

function viewLogs(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/logs').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    var rows = (d.logs || []).map(function(x){
      return h('<tr><td class="mono muted">', esc((x.created_at||'').replace('T',' ').slice(0,19)), '</td><td>', esc(x.username||''), '</td><td>', esc(x.action), '</td><td class="muted">', esc(x.detail||''), '</td><td class="mono muted">', esc(x.ip||''), '</td></tr>');
    }).join('');
    shell(h('<div class="top"><h2>', esc(t('logs')), '</h2><button class="btn danger" data-act="logs-clear">', esc(t('logs_clear')), '</button></div><div class="card" style="padding:8px 12px;overflow:auto"><table class="table"><thead><tr><th>time</th><th>user</th><th>action</th><th>detail</th><th>ip</th></tr></thead><tbody>',
      rows || h('<tr><td colspan="5" class="muted">', esc(t('empty')), '</td></tr>'), '</tbody></table></div>'));
  });
}

function viewSettings(){
  shell(h('<p class="muted">', esc(t('boot')), '</p>'));
  api('/api/settings').then(function(d){
    if (!d.ok){ shell(h('<div class="err">', esc(d.error || t('err')), '</div>')); return; }
    var s = d.settings || {};
    shell(h(
      '<h2 style="margin-bottom:12px">', esc(t('set_title')), '</h2>',
      '<div class="split">',
      '<form class="card" style="padding:18px" data-form="settings">',
      '<h3 style="margin-bottom:12px">', esc(t('set_title')), '</h3>',
      '<div class="field"><label>', esc(t('panel_name')), '</label><input class="input" name="panel_name" value="', esc(s.panel_name || 'Ham'), '"></div>',
      '<div class="field"><label>', esc(t('lang')), '</label><select name="lang"><option value="fa"', s.lang==='fa'?' selected':'', '>فارسی</option><option value="en"', s.lang==='en'?' selected':'', '>English</option></select></div>',
      '<h3 style="margin:8px 0 12px">', esc(t('vpn_proxy')), '</h3>',
      '<div class="field"><label>', esc(t('vpn_path')), '</label><input class="input" name="vpn_path" value="', esc(s.vpn_path || '/vpnws'), '"></div>',
            '<h3 style="margin:8px 0 12px">', esc(t('set_sec')), '</h3>',
      '<div class="field"><label>', esc(t('set_panel_path')), '</label><input class="input" name="panel_path" value="', esc(s.panel_path || '/dash'), '"><div class="hint">', esc(t('set_panel_path_h')), '</div></div>',
      '<h3 style="margin:8px 0 12px">', esc(t('cf')), '</h3>',
      '<div class="field"><label>', esc(t('cf_tok')), '</label><input class="input" name="cf_token" placeholder="Bearer token" value="" autocomplete="off"><div class="hint">', esc(s.cf_token_set === '1' ? t('cf_tok_saved') : t('cf_hint')), '</div></div>',
      '<div class="field"><label>', esc(t('allow_ips')), '</label><textarea class="input" name="allow_ips" rows="3" placeholder="1.2.3.4\n5.6.7.0/24">', esc(s.allow_ips || ''), '</textarea><div class="hint">', esc(t('allow_ips_h')), '</div></div>',
      '<div class="field"><label>', esc(t('abuse_gb')), '</label><input class="input" name="abuse_gb" type="number" min="0" value="', esc(s.abuse_gb || '80'), '"><div class="hint">', esc(t('abuse_gb_h')), '</div></div>',
      '<label class="pill" style="margin-bottom:12px"><input type="checkbox" name="access_only"', s.access_only==='1'?' checked':'', '> ', esc(t('access_only')), '</label><div class="hint">', esc(t('access_only_h')), '</div>',
      '<h3 style="margin:8px 0 12px">', esc(t('tg')), '</h3>',
      '<p class="hint">', esc(t('tg_h')), '</p>',
      '<p class="hint">', esc(t('tg_bot')), '</p>',
      '<div class="field"><label>', esc(t('tg_token')), '</label><input class="input" name="tg_token" value="', esc(s.tg_token || ''), '"></div>',
      '<div class="field"><label>', esc(t('tg_chat')), '</label><input class="input" name="tg_chat" value="', esc(s.tg_chat || ''), '"></div>',
      '<div class="field"><label>', esc(t('email')), '</label><input class="input" name="admin_email" type="email" value="" placeholder="', esc(s.has_email || s.admin_email_set ? '••••' : ''), '"><div class="hint">', esc(t('email_need')), '</div></div>',
      '<div class="row" style="margin-bottom:12px"><button class="btn" type="button" data-act="email-chg">', esc(t('email')), '</button></div>',
      '<div class="row" style="margin-bottom:12px"><button class="btn" type="button" data-act="tg-test">', esc(t('tg_test')), '</button></div>',
      '<h3 style="margin:8px 0 12px">', esc(t('backup')), '</h3>',
      '<div class="row" style="margin-bottom:12px">',
      '<a class="btn" href="', esc(BASE + '/api/backup'), '">', esc(t('backup_dl')), '</a>',
      '<label class="btn" style="display:inline-flex;align-items:center;gap:6px">', esc(t('backup_up')), '<input type="file" accept="application/json" data-act="backup-file" style="display:none"></label>',
      '</div>',
      '<div class="row"><button class="btn primary" type="submit">', esc(t('save')), '</button>',
      '<button class="btn" type="button" data-act="sess-kill">', esc(t('set_kill')), '</button>',
      '<button class="btn danger" type="button" data-act="traffic-reset">', esc(t('set_reset_tr')), '</button></div>',
      '</form>',
      '<div style="display:flex;flex-direction:column;gap:14px;min-width:0">',
      '<form class="card" style="padding:18px" data-form="pass">',
      '<h3 style="margin-bottom:12px">', esc(t('ch_pass')), '</h3>',
      '<div class="field"><label>', esc(t('cur_pass')), '</label><input class="input" type="password" name="current" required></div>',
      '<div class="field"><label>', esc(t('new_pass')), '</label><input class="input" type="password" name="next" required></div>',
      '<button class="btn primary" type="submit">', esc(t('ch_pass')), '</button>',
      '</form>',
      '<form class="card" style="padding:18px;margin-top:14px" data-form="settings">',
      '<h3 style="margin:8px 0 12px">', esc(t('ports')), '</h3>',
      '<p class="hint">', esc(t('ports_h')), '</p>',
      (function(){
        var on = String(s.cf_ports || '').split(',').map(function(x){return x.trim();}).filter(Boolean);
        var all = [80,8080,2052,443];
        if (!on.length) on = all.map(String);
        var html = '<div class="chkgrid" style="margin-bottom:14px">';
        var i, p;
        for (i=0;i<all.length;i++){
          p = all[i];
          html += '<label class="pill"><input type="checkbox" name="cf_port" value="'+p+'"'+(on.indexOf(String(p))!==-1?' checked':'')+'> '+p+'</label>';
        }
        return html + '</div>';
      })(),
      '<div class="field"><label>', esc(t('extra_ports')), '</label><input class="input" name="extra_ports" placeholder="2083,2053" value="', esc(s.extra_ports || ''), '"><div class="hint">', esc(t('extra_ports_h')), '</div></div>',
      '<h3 style="margin:8px 0 12px">', esc(t('proxy_ips')), '</h3>',
      '<p class="hint">', esc(t('proxy_ips_h')), '</p>',
      '<div class="field"><textarea class="input" name="proxy_ips" rows="8" placeholder="104.16.1.1">', esc(s.proxy_ips || ''), '</textarea></div>',
      '<div class="row" style="margin-bottom:12px">',
      '<button class="btn" type="button" data-act="ips-find">', esc(t('ips_find')), '</button>',
      '<button class="btn" type="button" data-act="ips-ping">', esc(t('ips_ping')), '</button>',
      '<button class="btn" type="button" data-act="ips-best">', esc(t('ips_best')), '</button>',
      '</div>',
      '<div class="field"><label>', esc(t('panel_host')), '</label><input class="input" name="panel_host" placeholder="xxx.workers.dev" value="', esc(s.panel_host || ''), '"><div class="hint">', esc(t('panel_host_h')), '</div></div>',
      '<div class="field"><label>', esc(t('backup_hosts')), '</label><textarea class="input" name="backup_hosts" rows="3" placeholder="ham2.example.com">', esc(s.backup_hosts || ''), '</textarea><div class="hint">', esc(t('backup_hosts_h')), '</div><div id="backup-chips" class="host-chips"></div></div>',
      '<div class="hint">', esc(t('ips_pick')), '</div>',
      '<div id="ip-pick" style="margin:8px 0 14px"></div>',
      '<button class="btn primary" type="submit">', esc(t('save')), '</button>',
      '</form></div></div>'
    ));
    S.ipOn = String(s.proxy_ips_on || '').split(/[\s,]+/).filter(Boolean);
    S.ipPing = S.ipPing || {};
    syncIpPick();
    function paintBackupChips(){
      var box = document.getElementById('backup-chips');
      var ta = document.querySelector('[name=backup_hosts]');
      if (!box) return;
      var raw = ta ? ta.value : (s.backup_hosts || '');
      var arr = String(raw || '').split(/[\n,\s]+/).map(function(x){ return x.trim(); }).filter(Boolean);
      if (!arr.length) { box.innerHTML = h('<span class="muted">', esc(t('backup_none')), '</span>'); return; }
      box.innerHTML = arr.map(function(hh){ return h('<span class="pill">', esc(hh), '</span>'); }).join('');
    }
    paintBackupChips();
    var bta = document.querySelector('[name=backup_hosts]');
    if (bta) bta.addEventListener('input', paintBackupChips);
  });
}

function paint(){
  applyDir();
  try { document.title = brandName(); } catch (eT) {}
  applyTheme(S.theme || (typeof localStorage !== 'undefined' && localStorage.getItem('ham_theme')) || 'light');
  if (!S.status){ document.body.className=''; renderBoot(); return; }
  if (!S.status.db || !S.status.setup){ document.body.className='stage-wiz'; renderSetup(); return; }
  if (!S.status.authed){ document.body.className='stage-login'; renderLogin(); return; }
  if (S.status.need_recovery){ document.body.className='stage-login'; renderRecoveryGate(); return; }
  if (S.status.need_email){ document.body.className='stage-login'; renderEmailGate(); return; }
  document.body.className='stage-app';
  renderApp();
}
function renderRecoveryGate(){
  document.getElementById('app').innerHTML = h(
    '<div class="center"><div class="card" style="width:min(460px,100%);padding:26px">',
    '<h2>', esc(t('rec_code')), '</h2>',
    '<p class="rec-warn">', esc(t('rec_warn')), '</p>',
    '<p class="muted">', esc(t('rec_need')), '</p>',
    '<form data-form="set-recovery">',
    '<div class="field"><input class="input" name="rec" maxlength="8" dir="ltr" style="text-transform:uppercase;letter-spacing:4px" required></div>',
    '<button class="btn primary" type="submit" style="width:100%">', esc(t('save')), '</button>',
    '</form></div></div>'
  );
}
function renderEmailGate(){
  document.getElementById('app').innerHTML = h(
    '<div class="center"><div class="card" style="width:min(460px,100%);padding:26px">',
    '<h2>', esc(t('email')), '</h2>',
    '<p class="muted">', esc(t('email_need')), '</p>',
    '<form data-form="set-email">',
    '<div class="field"><input class="input" name="email" type="email" required></div>',
    '<button class="btn primary" type="submit" style="width:100%">', esc(t('next')), '</button>',
    '</form>',
    '<div id="email-otp"></div>',
    '</div></div>'
  );
}

async function boot(){
  applyDir();
  try { applyTheme(localStorage.getItem('ham_theme') || 'light'); } catch (e0) { applyTheme('light'); }
  renderBoot();
  try { S.status = await api('/api/status'); }
  catch(e){ S.status = { ok:false, db:false, setup:false, authed:false }; }
  if (S.status && S.status.csrf) S.csrf = S.status.csrf;
  paint();
}

document.getElementById('app').addEventListener('click', function(e){
  var b = e.target.closest('[data-act]');
  if (!b) return;
  var act = b.getAttribute('data-act');
  if (act === 'lang'){
    S.lang = S.lang === 'fa' ? 'en' : 'fa';
    localStorage.setItem('ham_lang', S.lang);
    paint();
    return;
  }
  if (act === 'wiz-next'){ if (S.status && S.status.db){ wiz.step = 1; renderSetup(); } else toast(t('wait_db'), true); return; }
  if (act === 'wiz-back'){ wiz.step = Math.max(0, wiz.step-1); renderSetup(); return; }
  if (act === 'wiz-skip'){ wiz.tok=''; wiz.step=3; renderSetup(); return; }
  if (act === 'wiz-recheck'){ boot(); return; }
  if (act === 'wiz-finish'){
    var fe = adminError(wiz.p, wiz.p2, wiz.rec);
    if (fe){ wiz.err = fe; wiz.step = 1; renderSetup(); toast(fe, true); return; }
    var tgTokEl = document.getElementById('wiz-tg-token');
    var tgChatEl = document.getElementById('wiz-tg-chat');
    wiz.tg_token = tgTokEl ? String(tgTokEl.value || '').trim() : '';
    wiz.tg_chat = tgChatEl ? String(tgChatEl.value || '').trim() : '';
    if (!wiz.tg_token || wiz.tg_token.indexOf(':') < 1){ toast(t('tg_token'), true); return; }
    if (!/^-?\d{5,18}$/.test(wiz.tg_chat)){ toast(t('tg_chat'), true); return; }
    api('/api/setup','POST',{ password:wiz.p, email:wiz.e, recovery:wiz.rec, lang:S.lang, tg_token:wiz.tg_token, tg_chat:wiz.tg_chat }).then(function(r){
      if (!r.ok){ toast(r.error || t('err'), true); return; }
      if (r.login_ip) toast(t('login_info') + ' ' + r.login_ip);
      boot();
    });
    return;
  }
  if (act === 'email-chg'){
    var em = (document.querySelector('[name=admin_email]') || {}).value || '';
    api('/api/email','POST',{ action:'start', email: em }).then(function(r){
      if (!r.ok){ toast(r.error||t('err'), true); return; }
      var code = prompt(t('otp'));
      if (!code) return;
      if (r.step === 'old') {
        var neu = prompt(t('email_new'));
        api('/api/email','POST',{ action:'verify_old', code: code, email: neu }).then(function(r2){
          if (!r2.ok){ toast(r2.error||t('err'), true); return; }
          var c2 = prompt(t('otp'));
          if (!c2) return;
          api('/api/email','POST',{ action:'verify_new', code: c2 }).then(function(r3){ toast(r3.ok?t('saved'):(r3.error||t('err')), !r3.ok); });
        });
      } else {
        api('/api/email','POST',{ action:'verify_new', code: code }).then(function(r3){ toast(r3.ok?t('saved'):(r3.error||t('err')), !r3.ok); });
      }
    });
    return;
  }
  if (act === 'logout'){ api('/api/logout','POST',{}).then(function(){ boot(); }); return; }
  if (act === 'reload'){ paint(); return; }
  if (act === 'modal-close'){ var m=document.getElementById('modal'); if(m) m.innerHTML=''; return; }
  if (act === 'u-add'){ userModal('add'); return; }
  if (act === 'u-edit'){
    userModal('edit', { id:b.getAttribute('data-id'), username:b.getAttribute('data-username'), role:b.getAttribute('data-role'), email:b.getAttribute('data-email'), active: b.getAttribute('data-active')==='1' });
    return;
  }
  if (act === 'u-del'){
    if (!confirm(t('del') + '?')) return;
    api('/api/users/' + b.getAttribute('data-id'), 'DELETE').then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewUsers(); } });
    return;
  }
  if (act === 'cf-verify'){
    api('/api/cf/verify','POST',{}).then(function(r){ toast(r.ok ? t('cf_on') : (r.error || t('err')), !r.ok); });
    return;
  }
  if (act === 'dns-add'){ dnsModal(); return; }
  if (act === 'dns-del'){
    if (!confirm(t('del') + '?')) return;
    api('/api/cf/zones/' + b.getAttribute('data-zid') + '/dns/' + b.getAttribute('data-id'), 'DELETE').then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else viewDns(); });
    return;
  }
  if (act === 'vpn-add'){ vpnModal(null); return; }
  if (act === 'sub-add'){ subModal(null); return; }
  if (act === 'vpn-edit'){
    var vid = Number(b.getAttribute('data-id'));
    var prs = (S.vpnList || []).filter(function(x){ return Number(x.id) === vid; })[0];
    if (prs) vpnModal(prs);
    return;
  }
  if (act === 'sub-edit'){
    var sid = Number(b.getAttribute('data-id'));
    var su = (S.subList || []).filter(function(x){ return Number(x.id) === sid; })[0];
    if (su) subModal(su);
    return;
  }
  if (act === 'sub-clone'){
    api('/api/sub/' + b.getAttribute('data-id') + '/clone', 'POST', {}).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(r.url || t('saved')); viewSub(); }
    });
    return;
  }
  if (act === 'uuid-gen'){
    var inp = document.getElementById('uuid-in');
    if (inp) inp.value = (crypto.randomUUID && crypto.randomUUID()) || '';
    return;
  }
  if (act === 'sub-del'){
    if (!confirm(t('del') + '?')) return;
    api('/api/sub/' + b.getAttribute('data-id'), 'DELETE').then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else viewSub(); });
    return;
  }
  if (act === 'logs-clear'){
    if (!confirm(t('logs_clear') + '?')) return;
    api('/api/logs','DELETE').then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewLogs(); } });
    return;
  }
  if (act === 'sess-kill'){
    api('/api/sessions/revoke','POST',{}).then(function(){ boot(); });
    return;
  }
  if (act === 'traffic-reset'){
    if (!confirm(t('set_reset_tr') + '?')) return;
    api('/api/vpn/reset-traffic','POST',{}).then(function(r){ toast(r.ok?t('saved'):(r.error||t('err')), !r.ok); });
    return;
  }
  if (act === 'tg-test'){
    api('/api/tg/test','POST',{}).then(function(r){ toast(r.ok?t('saved'):(r.error||t('err')), !r.ok); });
    return;
  }
  if (act === 'ips-find'){
    api('/api/ips/discover','POST',{}).then(function(r){
      if (!r.ok){ toast(r.error||t('err'), true); return; }
      var ta = document.querySelector('[name=proxy_ips]');
      var ips = r.ips || [];
      if (ta) ta.value = ips.join('\n');
      S.ipPing = {};
      syncIpPick();
      toast(t('ips_found') + ' ' + ips.length);
    });
    return;
  }
  if (act === 'cfg-ips-ping'){
    var poolP = S.vpnIps || [];
    if (!poolP.length){ toast(t('vpn_ip_none'), true); return; }
    toast(t('ips_wait'));
    S.ipPing = S.ipPing || {};
    var spans0 = document.querySelectorAll('[data-ip-ms]');
    var si;
    for (si = 0; si < spans0.length; si++) spans0[si].textContent = ' · …';
    function paintPing(){
      var spans = document.querySelectorAll('[data-ip-ms]');
      var pi, el, ipx, v;
      for (pi = 0; pi < spans.length; pi++){
        el = spans[pi];
        ipx = el.getAttribute('data-ip-ms');
        v = S.ipPing[ipx];
        if (v == null) el.textContent = ' · …';
        else if (typeof v === 'number' && v >= 0) el.textContent = ' · ' + v + 'ms';
        else el.textContent = ' · N/A';
      }
    }
    function pingChunk(i){
      if (i >= poolP.length){
        paintPing();
        toast(t('vpn_ip_test'));
        return;
      }
      var n = Math.min(4, poolP.length - i);
      var chunk = poolP.slice(i, i + n);
      api('/api/ips/ping','POST',{ ips: chunk }).then(function(r){
        var arr = (r && r.pings) || [];
        var j;
        for (j = 0; j < chunk.length; j++) S.ipPing[chunk[j]] = -1;
        for (j = 0; j < arr.length; j++) S.ipPing[arr[j].ip] = arr[j].ok ? arr[j].ms : -1;
        paintPing();
        pingChunk(i + n);
      }).catch(function(){
        var j;
        for (j = 0; j < chunk.length; j++) S.ipPing[chunk[j]] = -1;
        paintPing();
        pingChunk(i + n);
      });
    }
    pingChunk(0);
    return;
  }
  if (act === 'ips-best'){
    var best = taIps();
    var scored = [], bi, bp;
    for (bi = 0; bi < best.length; bi++){
      bp = S.ipPing ? S.ipPing[best[bi]] : null;
      if (typeof bp === 'number' && bp >= 0) scored.push({ ip: best[bi], ms: bp });
    }
    if (!scored.length){ toast(t('ips_ping'), true); return; }
    scored.sort(function(a,b){ return a.ms - b.ms; });
    document.querySelectorAll('[name=proxy_ip_on]').forEach(function(c){ c.checked = false; });
    S.ipOn = scored.slice(0, 5).map(function(x){ return x.ip; });
    syncIpPick();
    toast(t('ips_best') + ' · ' + S.ipOn.length);
    return;
  }
  if (act === 'ips-ping'){
    var ipsP = taIps();
    if (!ipsP.length){ toast(t('ips_pick_empty'), true); return; }
    toast(t('ips_wait'));
    S.ipPing = S.ipPing || {};
    var wi;
    for (wi = 0; wi < ipsP.length; wi++) S.ipPing[ipsP[wi]] = 'wait';
    syncIpPick();
    function pingChunk(i){
      if (i >= ipsP.length){
        syncIpPick();
        toast(t('ips_ping') + ' · ' + ipsP.length);
        return;
      }
      var n = Math.min(5, ipsP.length - i);
      var chunk = ipsP.slice(i, i + n);
      api('/api/ips/ping','POST',{ ips: chunk }).then(function(r){
        var arr = (r && r.pings) || [];
        var map = {}, j;
        for (j = 0; j < arr.length; j++) map[arr[j].ip] = arr[j];
        for (j = 0; j < chunk.length; j++){
          var row = map[chunk[j]];
          S.ipPing[chunk[j]] = (row && row.ok) ? row.ms : -1;
        }
        syncIpPick();
        pingChunk(i + n);
      }).catch(function(){
        var j;
        for (j = 0; j < chunk.length; j++) if (S.ipPing[chunk[j]] === 'wait') S.ipPing[chunk[j]] = -1;
        syncIpPick();
        pingChunk(i + n);
      });
    }
    pingChunk(0);
    return;
  }
  if (act === 'theme-tog'){
    var th = S.theme === 'dark' ? 'light' : 'dark';
    applyTheme(th);
    api('/api/settings','PUT',{ theme: th });
    return;
  }
  if (act === 'vpn-copy'){ copyText(b.getAttribute('data-link') || ''); return; }
  if (act === 'alive-tip'){
    var wrap = b.closest('.alive-wrap');
    if (wrap) wrap.classList.toggle('open');
    return;
  }
  if (act === 'vpn-qr'){
    var qlink = b.getAttribute('data-link') || '';
    var qel = document.getElementById('modal');
    if (!qel){ copyText(qlink); return; }
    qel.innerHTML = h(
      '<div class="modalbg" data-act="modal-close"><div class="card modal" style="text-align:center;max-width:320px">',
      '<h3 style="margin-bottom:10px">', esc(t('qr')), '</h3>',
      '<img class="qr" style="width:240px;height:240px;margin:8px auto;display:block" alt="QR" src="', esc('https://api.qrserver.com/v1/create-qr-code/?size=280x280&ecc=M&margin=8&data=' + encodeURIComponent(qlink)), '">',
      '<div class="row" style="margin-top:10px;justify-content:center">',
      '<button class="btn" type="button" data-act="modal-close">', esc(t('cancel')), '</button>',
      '</div></div></div>'
    );
    return;
  }
  if (act === 'vpn-tog'){
    api('/api/vpn/' + b.getAttribute('data-id'), 'PATCH', { enabled: Number(b.getAttribute('data-en')) }).then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else viewVpn(); });
    return;
  }
  if (act === 'vpn-del'){
    if (!confirm(t('del') + '?')) return;
    api('/api/vpn/' + b.getAttribute('data-id'), 'DELETE').then(function(r){ if(!r.ok) toast(r.error||t('err'), true); else viewVpn(); });
    return;
  }
  if (act === 'tok-clear'){
    api('/api/settings','PUT',{ cf_token:'-' }).then(function(r){ toast(r.ok?t('saved'):(r.error||t('err')), !r.ok); if(r.ok) viewSettings(); });
    return;
  }
});

document.getElementById('app').addEventListener('input', function(e){
  var f = e.target && e.target.closest && e.target.closest('[data-form="wiz-admin"]');
  if (!f) return;
  var p = f.querySelector('[name=p]');
  var hint = document.getElementById('pass-live');
  if (p && hint){
    var live = passLiveText(p.value.length);
    hint.className = live.c;
    hint.textContent = live.m;
  }
});
document.getElementById('app').addEventListener('change', function(e){
  if (e.target && e.target.id === 'zone'){
    sessionStorage.setItem('ham_zone', e.target.value);
    paint();
  }
  if (e.target && e.target.getAttribute && e.target.getAttribute('data-act') === 'backup-file'){
    var file = e.target.files && e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(){
      var data;
      try { data = JSON.parse(String(reader.result||'')); } catch (err) { toast(t('err'), true); return; }
      api('/api/backup','POST', data).then(function(r){
        toast(r.ok ? t('saved') : (r.error || t('err')), !r.ok);
        if (r.ok) boot();
      });
    };
    reader.readAsText(file);
  }
});

document.getElementById('app').addEventListener('submit', function(e){
  var f = e.target.closest('[data-form]');
  if (!f) return;
  e.preventDefault();
  var fd = new FormData(f);
  var form = f.getAttribute('data-form');
  if (form === 'wiz-admin'){
    wiz.u = 'admin';
    wiz.p = String(fd.get('p')||'');
    wiz.p2 = String(fd.get('p2')||'');
    wiz.e = String(fd.get('e')||'');
    wiz.rec = String(fd.get('rec')||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    wiz.err = adminError(wiz.p, wiz.p2, wiz.rec);
    if (wiz.err){ renderSetup(); toast(wiz.err, true); return; }
    wiz.step = 2; renderSetup(); return;
  }
  if (form === 'wiz-cf'){ wiz.step = 2; renderSetup(); return; }
  if (form === 'login'){
    api('/api/login','POST',{ password: fd.get('p'), remember: !!(f.querySelector('[name=remember]') && f.querySelector('[name=remember]').checked) }).then(function(r){
      if (!r.ok) toast(r.error || t('err'), true);
      else if (r.need_2fa) renderLogin2fa(r.tmp, r.remember);
      else boot();
    });
    return;
  }
  if (form === 'login-2fa'){
    return;
  }
  if (form === 'set-recovery'){
    var rc = String(fd.get('rec')||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    if (rc.length !== 8){ toast(t('rec_bad'), true); return; }
    api('/api/recovery','POST',{ code: rc }).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else boot();
    });
    return;
  }
  if (form === 'set-email'){
    api('/api/email','POST',{ action:'start', email: fd.get('email') }).then(function(r){
      if (!r.ok){ toast(r.error||t('err'), true); return; }
      var box = document.getElementById('email-otp');
      if (box){
        box.innerHTML = otpBoxesHtml();
        bindOtp(function(code){
          api('/api/email','POST',{ action:'verify_new', code: code }).then(function(r2){
            showOtpBanner(!!r2.ok);
            if (r2.ok) setTimeout(function(){ boot(); }, 800);
          });
        });
      }
    });
    return;
  }
  if (form === 'email-change'){
    var st = f.getAttribute('data-step') || 'start';
    if (st === 'start'){
      api('/api/email','POST',{ action:'start', email: fd.get('email') }).then(function(r){
        if (!r.ok){ toast(r.error||t('err'), true); return; }
        toast(t('otp'));
        f.setAttribute('data-step', r.step === 'old' ? 'old' : 'new');
      });
    } else if (st === 'old'){
      api('/api/email','POST',{ action:'verify_old', code: fd.get('code'), email: fd.get('email') }).then(function(r){
        if (!r.ok) toast(r.error||t('err'), true); else { toast(t('otp')); f.setAttribute('data-step','new'); }
      });
    } else {
      api('/api/email','POST',{ action:'verify_new', code: fd.get('code') }).then(function(r){
        if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); boot(); }
      });
    }
    return;
  }
  if (form === 'user-add'){
    api('/api/users','POST',{ username: fd.get('username'), password: fd.get('password'), role: fd.get('role'), email: fd.get('email') }).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewUsers(); }
    });
    return;
  }
  if (form === 'user-edit'){
    api('/api/users/' + fd.get('id'), 'PATCH', { role: fd.get('role'), email: fd.get('email'), active: Number(fd.get('active')), password: fd.get('password') || undefined }).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewUsers(); }
    });
    return;
  }
  if (form === 'dns-add'){
    var zid = fd.get('zid');
    api('/api/cf/zones/' + zid + '/dns', 'POST', { type: fd.get('type'), name: fd.get('name'), content: fd.get('content'), ttl: fd.get('ttl'), proxied: f.querySelector('[name=proxied]').checked }).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewDns(); }
    });
    return;
  }
  if (form === 'purge'){
    var z = sessionStorage.getItem('ham_zone') || '';
    if (!z){ toast(t('pick_zone'), true); return; }
    var urls = String(fd.get('urls')||'').split(/\n/).map(function(x){ return x.trim(); }).filter(Boolean);
    var submitter = e.submitter;
    var body = (submitter && submitter.name === 'all') ? {} : { files: urls };
    if (submitter && submitter.name !== 'all' && !urls.length){ toast(t('urls_ph'), true); return; }
    api('/api/cf/zones/' + z + '/purge', 'POST', body).then(function(r){
      toast(r.ok ? t('saved') : (r.error || t('err')), !r.ok);
    });
    return;
  }
  if (form === 'vpn-path'){
    api('/api/vpn/path','PUT',{ path: fd.get('path') }).then(function(r){
      toast(r.ok ? t('saved') : (r.error || t('err')), !r.ok);
      if (r.ok) viewVpn();
    });
    return;
  }
  if (form === 'vpn-add' || form === 'vpn-edit'){
    var protoEl = f.querySelector('[name=proto]:checked');
    var proto = protoEl ? protoEl.value : 'vless';
    var ports = pickedPorts(f, 'port');
    var vbody = {
      name: fd.get('name'), uuid: fd.get('uuid'), trojan_pass: fd.get('trojan_pass'),
      protocols: proto,
      port: ports[0] || '443',
      quota_gb: fd.get('quota_gb'), days: fd.get('days'), max_ip: fd.get('max_ip'), location: fd.get('location'),
      speed_mbps: fd.get('speed_mbps'), extra_host: fd.get('extra_host'),
      remark: fd.get('remark') || '',
      ips: (function(){ var r = f.querySelector('[name=cfg_ip]:checked'); return r ? r.value : ''; })()
    };
    var vreq = form === 'vpn-edit' ? api('/api/vpn/' + fd.get('id'), 'PUT', vbody) : api('/api/vpn','POST', vbody);
    vreq.then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); viewVpn(); }
    }).catch(function(){ toast(t('err'), true); });
    return;
  }
  if (form === 'sub-add' || form === 'sub-edit'){
    var sprotos = [];
    if (f.querySelector('[name=p_vless]') && f.querySelector('[name=p_vless]').checked) sprotos.push('vless');
    if (f.querySelector('[name=p_trojan]') && f.querySelector('[name=p_trojan]').checked) sprotos.push('trojan');
    var sbody = {
      name: fd.get('name'), brand: fd.get('name'),
      quota_gb: fd.get('quota_gb'), days: fd.get('days'), location: fd.get('location'),
      max_ip: fd.get('max_ip'),
      protocols: sprotos.join(',') || 'vless',
      ports: pickedPorts(f, 'port').join(',') || '443',
      speed_mbps: fd.get('speed_mbps'), extra_host: fd.get('extra_host'),
      sub_pass: fd.get('sub_pass') || '',
      one_shot: !!(f.querySelector('[name=one_shot]') && f.querySelector('[name=one_shot]').checked)
    };
    var sreq = form === 'sub-edit' ? api('/api/sub/' + fd.get('id'), 'PATCH', sbody) : api('/api/sub','POST', sbody);
    sreq.then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(r.url || t('saved')); viewSub(); }
    });
    return;
  }
  if (form === 'settings'){
    var payload = {};
    if (fd.get('panel_name') != null) payload.panel_name = fd.get('panel_name');
    if (fd.get('lang') != null) payload.lang = fd.get('lang');
    if (fd.get('vpn_path') != null) payload.vpn_path = fd.get('vpn_path');
    if (fd.get('panel_path') != null) payload.panel_path = fd.get('panel_path');
    if (fd.get('allow_ips') != null) payload.allow_ips = fd.get('allow_ips') || '';
    if (fd.get('abuse_gb') != null) payload.abuse_gb = fd.get('abuse_gb') || '0';
    if (f.querySelector('[name=access_only]')) payload.access_only = f.querySelector('[name=access_only]').checked ? '1' : '0';
    if (f.querySelector('[name=cf_port]')) payload.cf_ports = pickedPorts(f, 'cf_port').join(',');
    if (fd.get('tg_token') != null) payload.tg_token = fd.get('tg_token');
    if (fd.get('tg_chat') != null) payload.tg_chat = fd.get('tg_chat');
    if (fd.get('cf_token') != null && String(fd.get('cf_token') || '').trim()) payload.cf_token = fd.get('cf_token');
    if (fd.get('admin_email') != null && String(fd.get('admin_email') || '').trim()) payload.admin_email_new = fd.get('admin_email');
    if (f.querySelector('[name=tg_2fa]')) payload.tg_2fa = f.querySelector('[name=tg_2fa]').checked ? '1' : '0';
    if (f.querySelector('[name=proxy_ips]')) {
      payload.proxy_ips = fd.get('proxy_ips') || '';
      payload.proxy_ips_on = Array.prototype.map.call(document.querySelectorAll('[name=proxy_ip_on]:checked'), function(c){ return c.value; }).join('\n');
    }
    if (fd.get('backup_hosts') != null) payload.backup_hosts = fd.get('backup_hosts') || '';
    if (fd.get('extra_ports') != null) payload.extra_ports = fd.get('extra_ports') || '';
    if (fd.get('panel_host') != null) payload.panel_host = fd.get('panel_host') || '';
    api('/api/settings','PUT', payload).then(function(r){
      if (!r.ok) toast(r.error||t('err'), true); else { toast(t('saved')); boot(); }
    });
    return;
  }
  if (form === 'pass'){
    api('/api/me/password','POST',{ current: fd.get('current'), next: fd.get('next') }).then(function(r){
      toast(r.ok ? t('saved') : (r.error || t('err')), !r.ok);
    });
  }
});

S.aliveAt = Date.now();
setInterval(function(){
  if (!S.status || !S.status.authed) return;
  if (Date.now() - (S.aliveAt || 0) > 2 * 3600 * 1000){
    api('/api/logout','POST',{}).then(function(){ boot(); });
  }
}, 60000);
document.addEventListener('click', function(){ S.aliveAt = Date.now(); });
document.addEventListener('input', function(e){
  if (e.target && e.target.getAttribute('name') === 'proxy_ips'){
    S.ipOn = Array.prototype.map.call(document.querySelectorAll('[name=proxy_ip_on]:checked'), function(c){ return c.value; });
    syncIpPick();
  }
});
document.addEventListener('change', function(e){
  if (e.target && e.target.getAttribute('name') === 'proxy_ip_on'){
    var ta = document.querySelector('[name=proxy_ips]');
    var on = Array.prototype.map.call(document.querySelectorAll('[name=proxy_ip_on]:checked'), function(c){ return c.value; });
    S.ipOn = on;
    api('/api/settings','PUT',{ proxy_ips: ta ? ta.value : '', proxy_ips_on: on.join('\n') });
  }
});
window.addEventListener('hashchange', function(){ if (S.status && S.status.setup && S.status.authed) renderApp(); });
boot();
})();
</script>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    RUNTIME_ENV = env;
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      var msg = String((e && e.stack) || (e && e.message) || e);
      return new Response('Ham error\n' + msg, {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }
      });
    }
  },
  async scheduled(event, env, ctx) {
    try { ctx.waitUntil(handleCron(env, ctx)); } catch (eC) {}
  }
};
