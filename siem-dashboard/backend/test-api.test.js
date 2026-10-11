const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { WebSocket } = require('ws');

const testDbPath = path.join(os.tmpdir(), 'hyshield-auth-test-' + process.pid + '.db');
const testLogPath = path.join(os.tmpdir(), 'hyshield-auth-test-' + process.pid + '.json');
process.env.DB_PATH = testDbPath;
process.env.COWRIE_LOG_PATH = testLogPath;
process.env.CORS_ORIGINS = 'http://localhost:3000';

const salt = '00112233445566778899aabbccddeeff';
const hash = crypto.scryptSync('test-password-only', Buffer.from(salt, 'hex'), 32).toString('hex');
process.env.SIEM_ADMIN_USERNAME = 'test-admin';
process.env.SIEM_ADMIN_PASSWORD_HASH = 'scrypt$' + salt + '$' + hash;
process.env.SIEM_AUTH_SECRET = 'test-only-secret-that-is-at-least-32-bytes-long';

const { app, server } = require('./server');
const { migrate, closeDb, getDb } = require('./db/migrate');
const IngestionService = require('./services/ingestion');

let token;
function authedGet(pathname) {
    return request(app).get(pathname).set('Authorization', 'Bearer ' + token);
}
function listenServer() {
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.removeListener('error', reject);
            resolve(server.address().port);
        });
    });
}
function closeServer() {
    return new Promise((resolve, reject) => {
        if (!server.listening) return resolve();
        server.close((error) => error ? reject(error) : resolve());
    });
}

test('SIEM API regression, authentication and WebSocket security', async (t) => {
    let ingestor = null;
    await closeServer();
    for (const filePath of [testDbPath, testDbPath + '-shm', testDbPath + '-wal', testLogPath]) {
        try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
    }
    fs.writeFileSync(testLogPath, '');
    await migrate();

    t.after(async () => {
        if (ingestor) ingestor.closeFile();
        await closeServer();
        await closeDb();
        for (const filePath of [testDbPath, testDbPath + '-shm', testDbPath + '-wal', testLogPath]) {
            try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
        }
    });

    await t.test('valid credentials issue the access_token returned by the API', async () => {
        const res = await request(app).post('/api/auth/login')
            .send({ username: 'test-admin', password: 'test-password-only' });
        assert.equal(res.status, 200);
        assert.equal(res.body.token_type, 'Bearer');
        assert.equal(typeof res.body.access_token, 'string');
        assert.equal(res.body.expires_in, 900);
        assert.equal(res.body.user.role, 'admin');
        token = res.body.access_token;
    });

    await t.test('invalid credentials are rejected', async () => {
        const res = await request(app).post('/api/auth/login')
            .send({ username: 'test-admin', password: 'wrong-password' });
        assert.equal(res.status, 401);
        assert.deepEqual(res.body, { error: 'Invalid credentials' });
    });

    await t.test('protected endpoints reject missing or invalid bearer tokens', async () => {
        let res = await request(app).get('/api/events');
        assert.equal(res.status, 401);
        res = await request(app).get('/api/events').set('Authorization', 'Bearer invalid.token.value');
        assert.equal(res.status, 401);
    });

    await t.test('health endpoint remains available without authentication', async () => {
        const res = await request(app).get('/api/health');
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, { status: 'ok' });
    });

    await t.test('1. Empty database responses', async () => {
        let res = await authedGet('/api/events');
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, []);
        res = await authedGet('/api/alerts');
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, []);
        res = await authedGet('/api/actors');
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, []);
        res = await authedGet('/api/overview/metrics');
        assert.equal(res.status, 200);
        assert.equal(res.body.metrics.totalEvents, 0);
    });

    await t.test('2. Ingestion and session endpoint regression', async () => {
        ingestor = new IngestionService(testLogPath);
        await ingestor.init();
        fs.appendFileSync(testLogPath, JSON.stringify({
            eventid: 'cowrie.session.connect', session: 'sess-api-1',
            src_ip: '10.0.0.1', timestamp: new Date().toISOString()
        }) + '\n');
        fs.appendFileSync(testLogPath, JSON.stringify({
            eventid: 'cowrie.command.input', session: 'sess-api-1',
            src_ip: '10.0.0.1', timestamp: new Date().toISOString(), input: 'wget malware'
        }) + '\n');
        await new Promise(resolve => setTimeout(resolve, 500));

        let res = await authedGet('/api/events');
        assert.equal(res.status, 200);
        assert.equal(res.body.length, 2);
        res = await authedGet('/api/sessions');
        assert.equal(res.status, 200);
        assert.equal(res.body.length, 1);
        res = await authedGet('/api/sessions/sess-api-1');
        assert.equal(res.status, 200);
        assert.equal(res.body.id, 'sess-api-1');
        assert.equal(res.body.events.length, 2);

        const db = await getDb();
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['malformed-json-test', null, new Date().toISOString(), 'test.malformed', '{not-json']
        );
        res = await authedGet('/api/events');
        assert.equal(res.status, 200);
        assert.equal(res.body.length, 3);
        assert.ok(res.body.some(event => event.mitre_context === null));

        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['null-payload-test', null, new Date().toISOString(), 'cowrie.command.input', 'null']
        );
        res = await authedGet('/api/fim');
        assert.equal(res.status, 200);
    });

    await t.test('3. API errors do not expose database details', async () => {
        const res = await authedGet('/api/sessions/invalid-id');
        assert.equal(res.status, 404);
        assert.deepEqual(res.body, { error: 'Session not found' });
    });

    await t.test('4. Malformed and oversized JSON are rejected', async () => {
        let res = await request(app).post('/api/auth/login')
            .set('Content-Type', 'application/json').send('{not-json');
        assert.equal(res.status, 400);
        assert.deepEqual(res.body, { error: 'Invalid JSON body' });

        res = await request(app).post('/api/auth/login')
            .set('Content-Type', 'application/json')
            .send(JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 32) }));
        assert.equal(res.status, 413);
        assert.deepEqual(res.body, { error: 'Request body too large' });
    });

    await t.test('5. Security headers and CORS allow-list are enforced', async () => {
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

    await t.test('6. WebSocket rejects unauthenticated clients', async () => {
        const port = await listenServer();
        const ws = new WebSocket('ws://127.0.0.1:' + port);
        const result = await new Promise((resolve, reject) => {
            ws.once('error', reject);
            ws.once('close', (code, reason) => resolve({ code, reason: reason.toString() }));
        });
        assert.equal(result.code, 1008);
        assert.equal(result.reason, 'Authentication required');
        await closeServer();
    });

    await t.test('7. WebSocket accepts a valid bearer token in the first message', async () => {
        const port = await listenServer();
        const ws = new WebSocket('ws://127.0.0.1:' + port);
        const message = await new Promise((resolve, reject) => {
            ws.once('error', reject);
            ws.once('open', () => ws.send(JSON.stringify({ type: 'auth', token })));
            ws.once('message', raw => resolve(JSON.parse(raw.toString())));
        });
        assert.equal(message.type, 'connected');
        const closed = new Promise(resolve => ws.once('close', resolve));
        ws.close();
        await closed;
        await closeServer();
    });

    await t.test('8. Repeated failed logins are rate-limited', async () => {
        for (let i = 0; i < 9; i += 1) {
            const res = await request(app).post('/api/auth/login')
                .send({ username: 'test-admin', password: 'wrong-password' });
            assert.equal(res.status, 401);
        }
        const blocked = await request(app).post('/api/auth/login')
            .send({ username: 'test-admin', password: 'wrong-password' });
        assert.equal(blocked.status, 429);
        assert.ok(Number(blocked.headers['retry-after']) > 0);
    });
});
