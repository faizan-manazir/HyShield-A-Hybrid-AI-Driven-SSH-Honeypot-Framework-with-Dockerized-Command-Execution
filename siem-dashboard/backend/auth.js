const crypto = require('node:crypto');

const TOKEN_TTL_SECONDS = 15 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 10;

function safeEqual(a, b) {
    const left = Buffer.from(String(a));
    const right = Buffer.from(String(b));
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, stored) {
    // SIEM_ADMIN_PASSWORD_HASH format: scrypt$<salt-hex>$<hash-hex>
    if (typeof password !== 'string' || !stored || typeof stored !== 'string') return false;
    const parts = stored.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt' || !/^[a-f0-9]{32,128}$/i.test(parts[1]) || !/^[a-f0-9]{64}$/i.test(parts[2])) return false;
    const expected = Buffer.from(parts[2], 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(parts[1], 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
}

function signToken(payload, secret) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const data = header + '.' + body;
    const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    return data + '.' + signature;
}

function verifyToken(token, secret) {
    if (typeof token !== 'string' || token.length > 4096) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const expected = crypto.createHmac('sha256', secret).update(data).digest();
    const supplied = Buffer.from(parts[2], 'base64url');
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
    try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;
        if (!Number.isInteger(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
        if (typeof payload.sub !== 'string' || !['admin', 'analyst'].includes(payload.role)) return null;
        return payload;
    } catch { return null; }
}

function createAuth({ username, passwordHash, secret }) {
    const configured = Boolean(username && passwordHash && secret && Buffer.byteLength(secret) >= 32);
    const loginFailures = new Map();

    function login(req, res) {
        if (!configured) return res.status(503).json({ error: 'Authentication is not configured' });
        const nowMs = Date.now();
        const clientKey = req.ip || req.socket.remoteAddress || 'unknown';
        const existing = loginFailures.get(clientKey);
        const attempts = existing && nowMs - existing.windowStart < LOGIN_WINDOW_MS
            ? existing
            : { count: 0, windowStart: nowMs };
        if (attempts.count >= LOGIN_MAX_FAILURES) {
            res.setHeader('Retry-After', String(Math.ceil((LOGIN_WINDOW_MS - (nowMs - attempts.windowStart)) / 1000)));
            return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
        }

        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const validUser = typeof body.username === 'string' && safeEqual(body.username, username);
        const validPassword = verifyPassword(body.password, passwordHash);
        if (!validUser || !validPassword) {
            attempts.count += 1;
            loginFailures.set(clientKey, attempts);
            console.warn('[SIEM auth] Login rejected for client', clientKey);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        loginFailures.delete(clientKey);
        console.info('[SIEM auth] Administrator login successful');
        const now = Math.floor(nowMs / 1000);
        const token = signToken({ sub: username, role: 'admin', iat: now, exp: now + TOKEN_TTL_SECONDS }, secret);
        return res.json({ access_token: token, token_type: 'Bearer', expires_in: TOKEN_TTL_SECONDS, user: { username, role: 'admin' } });
    }

    function verifyBearerToken(token) {
        if (!configured) return null;
        return verifyToken(token, secret);
    }

    function requireAuth(req, res, next) {
        if (req.path === '/health' || (req.path === '/auth/login' && req.method === 'POST')) return next();
        if (!configured) return res.status(503).json({ error: 'Authentication is not configured' });
        const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(req.get('authorization') || '');
        const payload = match ? verifyBearerToken(match[1]) : null;
        if (!payload) return res.status(401).json({ error: 'Authentication required' });
        req.auth = { username: payload.sub, role: payload.role };
        if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.auth.role !== 'admin') {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        return next();
    }

    return { login, requireAuth, verifyBearerToken, configured };
}

module.exports = { createAuth, verifyPassword, verifyToken, signToken, TOKEN_TTL_SECONDS };
