const db = require('./_lib/db');

function send(res, code, body) {
  res.status(code).setHeader('Content-Type', 'application/json').send(JSON.stringify(body));
}

function allowed(user, op, key, value) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (op === 'list') {
    return key === 'listings:' || key === 'requests:' || key === 'clients:' || key === 'favorites:';
  }
  if (key.indexOf('listings:') === 0) return op === 'get' || op === 'list';
  if (key === 'clients:' + user.email) return op === 'get' || op === 'set';
  if (key === 'favorites:' + user.email) return op === 'get' || op === 'set';
  if (key.indexOf('requests:') === 0) {
    if (op === 'get') return true;
    if (op === 'set') return value && value.clientEmail === user.email;
  }
  return false;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'Method not allowed' });
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body || '{}'); } catch (e) { body = {}; }
  }
  body = body || {};
  const loaded = await db.load();
  if (!loaded.persistent) return send(res, 200, { ok: false, persistent: false });
  const store = loaded.db;
  const user = db.sessionUser(store, db.readCookie(req));
  const op = body.op;
  const key = String(body.key || '');

  if (op === 'list') {
    if (!allowed(user, 'list', key)) return send(res, 401, { ok: false, error: 'Sign in required' });
    let keys = Object.keys(store.records).filter(function (k) { return k.indexOf(key) === 0; });
    if (user.role === 'client' && key === 'requests:') {
      keys = keys.filter(function (k) {
        const row = store.records[k];
        return row && row.clientEmail === user.email;
      });
    }
    if (user.role === 'client' && key === 'clients:') keys = keys.filter(function (k) { return k === 'clients:' + user.email; });
    if (user.role === 'client' && key === 'favorites:') keys = keys.filter(function (k) { return k === 'favorites:' + user.email; });
    await db.save(store);
    return send(res, 200, { ok: true, keys: keys });
  }

  if (!allowed(user, op, key, body.value)) return send(res, 401, { ok: false, error: 'Sign in required' });

  if (op === 'get') {
    const value = Object.prototype.hasOwnProperty.call(store.records, key) ? store.records[key] : null;
    if (user.role === 'client' && key.indexOf('requests:') === 0 && value && value.clientEmail !== user.email) {
      return send(res, 401, { ok: false, error: 'Sign in required' });
    }
    await db.save(store);
    return send(res, 200, { ok: true, value: value });
  }

  if (op === 'set') {
    if (body.value === null || body.value === undefined) delete store.records[key];
    else store.records[key] = body.value;
    await db.save(store);
    return send(res, 200, { ok: true });
  }

  if (op === 'delete') {
    delete store.records[key];
    await db.save(store);
    return send(res, 200, { ok: true });
  }

  return send(res, 400, { ok: false, error: 'Unknown operation' });
};
