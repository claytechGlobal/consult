const db = require('./_lib/db');

function send(res, code, body, extra) {
  if (extra) res.setHeader('Set-Cookie', extra);
  res.status(code).setHeader('Content-Type', 'application/json').send(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'Method not allowed' });
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body || '{}'); } catch (e) { body = {}; }
  }
  body = body || {};
  const action = body.action;
  const loaded = await db.load();
  const store = loaded.db;

  if (!loaded.persistent && action === 'ping') {
    return send(res, 200, { ok: true, persistent: false });
  }
  if (action === 'ping') return send(res, 200, { ok: true, persistent: true });

  if (!loaded.persistent) {
    return send(res, 200, { ok: false, persistent: false });
  }

  if (action === 'me') {
    const user = db.sessionUser(store, db.readCookie(req));
    await db.save(store);
    if (!user) return send(res, 200, { ok: true, user: null });
    return send(res, 200, { ok: true, user: db.publicUser(user) });
  }

  if (action === 'logout') {
    const token = db.readCookie(req);
    if (token) delete store.sessions[token];
    await db.save(store);
    return send(res, 200, { ok: true }, db.clearCookie(req));
  }

  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const role = body.role === 'admin' ? 'admin' : 'client';

  if (action === 'register') {
    if (role !== 'client') return send(res, 400, { ok: false, error: 'Staff accounts are created by the office.' });
    const name = String(body.name || '').trim();
    const phone = String(body.phone || '').trim();
    if (!name || !email || !password) return send(res, 400, { ok: false, error: 'Name, email, and password are required.' });
    if (password.length < 6) return send(res, 400, { ok: false, error: 'Use at least 6 characters for the password.' });
    if (store.users.some(function (u) { return u.email === email; })) {
      return send(res, 400, { ok: false, error: 'An account with that email already exists. Sign in instead.' });
    }
    const hashed = db.hashPassword(password);
    const user = {
      email: email, name: name, phone: phone, role: 'client',
      salt: hashed.salt, passHash: hashed.hash
    };
    store.users.push(user);
    store.records['clients:' + email] = {
      email: email, name: name, phone: phone, subscribed: false,
      joinedAt: new Date().toISOString(), budget: '', neighborhoods: '', beds: 0, pet: false
    };
    const token = require('crypto').randomBytes(24).toString('hex');
    store.sessions[token] = { email: email, exp: Date.now() + 14 * 24 * 60 * 60 * 1000 };
    await db.save(store);
    return send(res, 200, { ok: true, user: db.publicUser(user) }, db.cookieHeader(token, req));
  }

  if (action === 'login') {
    const user = store.users.find(function (u) { return u.email === email; });
    if (!user || user.role !== role || !db.verifyPassword(password, user.salt, user.passHash)) {
      return send(res, 401, { ok: false, error: 'Incorrect email or password.' });
    }
    const token = require('crypto').randomBytes(24).toString('hex');
    store.sessions[token] = { email: user.email, exp: Date.now() + 14 * 24 * 60 * 60 * 1000 };
    await db.save(store);
    return send(res, 200, { ok: true, user: db.publicUser(user) }, db.cookieHeader(token, req));
  }

  return send(res, 400, { ok: false, error: 'Unknown action' });
};
