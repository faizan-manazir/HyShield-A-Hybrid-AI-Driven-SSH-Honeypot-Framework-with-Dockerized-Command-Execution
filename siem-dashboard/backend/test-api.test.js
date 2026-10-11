const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');

const salt = '00112233445566778899aabbccddeeff';
const hash = crypto.scryptSync('test-password-only', Buffer.from(salt, 'hex'), 32).toString('hex');
process.env.SIEM_ADMIN_USERNAME = 'test-admin';
process.env.SIEM_ADMIN_PASSWORD_HASH = 'scrypt$' + salt + '$' + hash;
process.env.SIEM_AUTH_SECRET = 'test-only-secret-that-is-at-least-32-bytes-long';

const { app } = require('./server');
const { migrate, closeDb } = require('./db/migrate');

test('SIEM API authentication and request hardening', async (t) => {
    await migrate();
    t.after(async () => { await closeDb(); });
    let token;
    await t.test('login issues a short-lived bearer token for valid credentials', async () => {
        const res = await request(app).post('/api/auth/login')
            .send({ username: 'test-admin', password: 'test-password-only' });
        assert.equal(res.status, 200);
        assert.equal(res.body.token_type, 'Bearer');
        assert.ok(res.body.access_token);
        assert.equal(res.body.user.role, 'admin');
        token = res.body.access_token;
    });

    await t.test('invalid credentials are rejected', async () => {
        const res = await request(app).post('/api/auth/login')
            .send({ username: 'test-admin', password: 'wrong-password' });
        assert.equal(res.status, 401);
        assert.deepEqual(res.body, { error: 'Invalid credentials' });
    });

    await t.test('protected API routes reject missing or invalid bearer tokens', async () => {
        let res = await request(app).get('/api/events');
        assert.equal(res.status, 401);
        res = await request(app).get('/api/events').set('Authorization', 'Bearer invalid.token.value');
        assert.equal(res.status, 401);
    });

    await t.test('valid bearer token can access protected read routes', async () => {
        const res = await request(app).get('/api/events').set('Authorization', 'Bearer ' + token);
        assert.equal(res.status, 200);
        assert.ok(Array.isArray(res.body));
    });

    await t.test('malformed JSON is rejected with 400', async () => {
        const res = await request(app).post('/api/auth/login')
            .set('Content-Type', 'application/json').send('{not-json');
        assert.equal(res.status, 400);
        assert.deepEqual(res.body, { error: 'Invalid JSON body' });
    });

    await t.test('oversized JSON is rejected with 413', async () => {
        const res = await request(app).post('/api/auth/login')
            .set('Content-Type', 'application/json')
            .send(JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 32) }));
        assert.equal(res.status, 413);
        assert.deepEqual(res.body, { error: 'Request body too large' });
    });

    await t.test('security headers and CORS allow-list are enforced', async () => {
        const allowed = await request(app).get('/api/health').set('Origin', 'http://localhost:3000');
        assert.equal(allowed.status, 200);
        assert.equal(allowed.headers['x-content-type-options'], 'nosniff');
        assert.equal(allowed.headers['x-frame-options'], 'DENY');
        assert.equal(allowed.headers['referrer-policy'], 'no-referrer');
        assert.equal(allowed.headers['cache-control'], 'no-store');
        assert.equal(allowed.headers['x-powered-by'], undefined);
        assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:3000');

        const blocked = await request(app).get('/api/health').set('Origin', 'https://untrusted.example');
        assert.equal(blocked.status, 403);
        assert.deepEqual(blocked.body, { error: 'Origin not allowed' });
    });
});
