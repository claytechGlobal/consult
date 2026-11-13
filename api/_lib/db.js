const crypto = require('crypto');

const DB_KEY = 'exact:db';
const ADMIN_EMAIL = 'staff@exactcc.com';
const ADMIN_PASSWORD = 'exact2026';

function blank() {
  return { users: [], sessions: {}, records: {} };
}

function redisEnv() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
  return url && token ? { url, token } : null;
}

async function redis(command) {
  const env = redisEnv();
  if (!env) return { missing: true };
  const res = await fetch(env.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(command)
  });
  if (!res.ok) throw new Error('store request failed');
  const data = await res.json();
  return { result: data.result };
}

function seedAdmin(db) {
  if (db.users.some(function (u) { return u.email === ADMIN_EMAIL; })) return db;
  const hashed = hashPassword(ADMIN_PASSWORD);
  db.users.push({
    email: ADMIN_EMAIL,
    name: 'Staff',
    phone: '',
    role: 'admin',
    salt: hashed.salt,
    passHash: hashed.hash
  });
  return db;
}

async function load() {
  const remote = await redis(['GET', DB_KEY]);
  if (!remote.missing) {
    let db = blank();
    if (remote.result) {
      try { db = JSON.parse(remote.result); } catch (e) { db = blank(); }
    }
    if (!db.users) db.users = [];
    if (!db.sessions) db.sessions = {};
    if (!db.records) db.records = {};
    const before = db.users.length;
    seedAdmin(db);
    if (db.users.length !== before) await save(db);
    return { db: db, persistent: true };
  }
  if (!global.__exactDb) {
    global.__exactDb = seedAdmin(blank());
  }
  return { db: global.__exactDb, persistent: false };
}

async function save(db) {
  const remote = await redis(['SET', DB_KEY, JSON.stringify(db)]);
  if (remote.missing) global.__exactDb = db;
}

function hashPassword(password, salt) {
  const useSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), useSalt, 32).toString('hex');
  return { salt: useSalt, hash: hash };
}

function verifyPassword(password, salt, hash) {
  const next = hashPassword(password, salt).hash;
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(next, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function publicUser(user) {
  return {
    email: user.email,
    name: user.name,
    phone: user.phone || '',
    role: user.role
  };
}

function readCookie(req) {
  const raw = req.headers.cookie || '';
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const bit = parts[i].trim();
    if (bit.indexOf('exact_session=') === 0) return decodeURIComponent(bit.slice('exact_session='.length));
  }
  return '';
}

function sessionUser(db, token) {
  if (!token || !db.sessions[token]) return null;
  const row = db.sessions[token];
  if (!row.exp || row.exp < Date.now()) {
    delete db.sessions[token];
    return null;
  }
  const user = db.users.find(function (u) { return u.email === row.email; });
  return user || null;
}

function cookieHeader(token, req) {
  const host = String(req.headers.host || '');
  const secure = host.indexOf('localhost') === -1 && host.indexOf('127.0.0.1') === -1;
  let value = 'exact_session=' + encodeURIComponent(token) + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=1209600';
  if (secure) value += '; Secure';
  return value;
}

function clearCookie(req) {
  const host = String(req.headers.host || '');
  const secure = host.indexOf('localhost') === -1 && host.indexOf('127.0.0.1') === -1;
  let value = 'exact_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0';
  if (secure) value += '; Secure';
  return value;
}

module.exports = {
  ADMIN_EMAIL: ADMIN_EMAIL,
  load: load,
  save: save,
  hashPassword: hashPassword,
  verifyPassword: verifyPassword,
  publicUser: publicUser,
  readCookie: readCookie,
  sessionUser: sessionUser,
  cookieHeader: cookieHeader,
  clearCookie: clearCookie
};
