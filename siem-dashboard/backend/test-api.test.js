const test = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const path = require('path');
const os = require('node:os');
const fs = require('fs');
const crypto = require('node:crypto');

// We need to set up the DB before mounting routes
const { migrate, closeDb, getDb } = require('./db/migrate');
const IngestionService = require('./services/ingestion');

// Use isolated temporary files; never delete or overwrite tracked Cowrie fixtures.
const testDbPath = path.join(os.tmpdir(), `hyshield-api-test-${process.pid}.db`);
process.env.DB_PATH = testDbPath;
const testLogPath = path.join(os.tmpdir(), `hyshield-api-test-${process.pid}.json`);

// Configure deterministic test-only credentials before loading the production app.
const testSalt = '00112233445566778899aabbccddeeff';
const testHash = crypto.scryptSync('test-password-only', Buffer.from(testSalt, 'hex'), 32).toString('hex');
process.env.SIEM_ADMIN_USERNAME = 'test-admin';
process.env.SIEM_ADMIN_PASSWORD_HASH = 'scrypt

test('API Regression Tests', async (t) => {
    const login = await request(app).post('/api/auth/login').send({ username: 'test-admin', password: 'test-password-only' });
    assert.strictEqual(login.status, 200);
    testToken = login.body.access_token;
    let ingestor = null;
    // Always close the watcher/database, even when setup or an assertion fails.
    t.after(async () => {
        if (ingestor) ingestor.closeFile();
        await closeDb();
        for (const filePath of [testDbPath, `${testDbPath}-shm`, `${testDbPath}-wal`, testLogPath]) {
            try {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            } catch (error) {
                console.warn(`Could not clean up temporary test file ${filePath}:`, error.message);
            }
        }
    });

    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(testLogPath)) fs.unlinkSync(testLogPath);
    fs.writeFileSync(testLogPath, '');

    await migrate();
    ingestor = new IngestionService(testLogPath);
    await ingestor.init();

    await t.test('1. Empty Database Responses', async () => {
        let res = await apiRequest().get('/api/health');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, { status: 'ok' });

        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/alerts');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/actors');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);
        
        res = await request(app).get('/api/overview/metrics');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.metrics.totalEvents, 0);
    });

    await t.test('2. Populating Database with Test Events', async () => {
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.session.connect', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString() }) + '\n');
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.command.input', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString(), input: 'wget malware' }) + '\n');
        
        // Wait for ingestion
        await new Promise(resolve => setTimeout(resolve, 500));
        
        let res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 2, 'Should return 2 events');

        res = await request(app).get('/api/sessions');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 1, 'Should return 1 session');
        
        res = await request(app).get('/api/sessions/sess-api-1');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.id, 'sess-api-1', 'Should fetch specific session');
        assert.strictEqual(res.body.events.length, 2, 'Session should have 2 raw events embedded');

        // Corrupt persisted JSON should not make the entire events endpoint fail.
        const db = await getDb();
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['malformed-json-test', null, new Date().toISOString(), 'test.malformed', '{not-json']
        );
        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 3, 'Malformed payload should not hide valid events');
        assert.ok(res.body.some(event => event.mitre_context === null), 'Malformed payload should use a safe fallback');

        // Valid JSON with an unexpected shape must not break FIM processing either.
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['null-payload-test', null, new Date().toISOString(), 'cowrie.command.input', 'null']
        );
        res = await request(app).get('/api/fim');
        assert.strictEqual(res.status, 200, 'Unexpected payload shapes should not break FIM responses');
    });

    await t.test('3. API Error Handling does not leak DB details', async () => {
        // We will simulate a SQL injection attempt or bad parameter if possible, 
        // or just ensure basic 404/500 works.
        const res = await request(app).get('/api/sessions/invalid-id');
        assert.strictEqual(res.status, 404);
        assert.deepStrictEqual(res.body, { error: 'Session not found' });
    });

    await t.test('4. Security middleware rejects malformed and oversized JSON', async () => {
        let res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send('{not-json');
        assert.strictEqual(res.status, 400);
        assert.deepStrictEqual(res.body, { error: 'Invalid JSON body' });

        res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send(JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 32) }));
        assert.strictEqual(res.status, 413);
        assert.deepStrictEqual(res.body, { error: 'Request body too large' });
    });

    await t.test('5. Security headers and CORS allow-list are enforced', async () => {
        const res = await request(app)
            .get('/api/health')
            .set('Origin', 'http://localhost:3000');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
        assert.strictEqual(res.headers['x-frame-options'], 'DENY');
        assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
        assert.strictEqual(res.headers['cache-control'], 'no-store');
        assert.strictEqual(res.headers['x-powered-by'], undefined);
        assert.strictEqual(res.headers['access-control-allow-origin'], 'http://localhost:3000');

        const blocked = await request(app)
            .get('/api/health')
            .set('Origin', 'https://untrusted.example');
        assert.strictEqual(blocked.status, 403);
        assert.deepStrictEqual(blocked.body, { error: 'Origin not allowed' });
    });

});
 + testSalt + '

test('API Regression Tests', async (t) => {
    let ingestor = null;
    // Always close the watcher/database, even when setup or an assertion fails.
    t.after(async () => {
        if (ingestor) ingestor.closeFile();
        await closeDb();
        for (const filePath of [testDbPath, `${testDbPath}-shm`, `${testDbPath}-wal`, testLogPath]) {
            try {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            } catch (error) {
                console.warn(`Could not clean up temporary test file ${filePath}:`, error.message);
            }
        }
    });

    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(testLogPath)) fs.unlinkSync(testLogPath);
    fs.writeFileSync(testLogPath, '');

    await migrate();
    ingestor = new IngestionService(testLogPath);
    await ingestor.init();

    await t.test('1. Empty Database Responses', async () => {
        let res = await request(app).get('/api/health');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, { status: 'ok' });

        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/alerts');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/actors');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);
        
        res = await request(app).get('/api/overview/metrics');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.metrics.totalEvents, 0);
    });

    await t.test('2. Populating Database with Test Events', async () => {
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.session.connect', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString() }) + '\n');
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.command.input', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString(), input: 'wget malware' }) + '\n');
        
        // Wait for ingestion
        await new Promise(resolve => setTimeout(resolve, 500));
        
        let res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 2, 'Should return 2 events');

        res = await request(app).get('/api/sessions');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 1, 'Should return 1 session');
        
        res = await request(app).get('/api/sessions/sess-api-1');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.id, 'sess-api-1', 'Should fetch specific session');
        assert.strictEqual(res.body.events.length, 2, 'Session should have 2 raw events embedded');

        // Corrupt persisted JSON should not make the entire events endpoint fail.
        const db = await getDb();
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['malformed-json-test', null, new Date().toISOString(), 'test.malformed', '{not-json']
        );
        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 3, 'Malformed payload should not hide valid events');
        assert.ok(res.body.some(event => event.mitre_context === null), 'Malformed payload should use a safe fallback');

        // Valid JSON with an unexpected shape must not break FIM processing either.
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['null-payload-test', null, new Date().toISOString(), 'cowrie.command.input', 'null']
        );
        res = await request(app).get('/api/fim');
        assert.strictEqual(res.status, 200, 'Unexpected payload shapes should not break FIM responses');
    });

    await t.test('3. API Error Handling does not leak DB details', async () => {
        // We will simulate a SQL injection attempt or bad parameter if possible, 
        // or just ensure basic 404/500 works.
        const res = await request(app).get('/api/sessions/invalid-id');
        assert.strictEqual(res.status, 404);
        assert.deepStrictEqual(res.body, { error: 'Session not found' });
    });

    await t.test('4. Security middleware rejects malformed and oversized JSON', async () => {
        let res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send('{not-json');
        assert.strictEqual(res.status, 400);
        assert.deepStrictEqual(res.body, { error: 'Invalid JSON body' });

        res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send(JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 32) }));
        assert.strictEqual(res.status, 413);
        assert.deepStrictEqual(res.body, { error: 'Request body too large' });
    });

    await t.test('5. Security headers and CORS allow-list are enforced', async () => {
        const res = await request(app)
            .get('/api/health')
            .set('Origin', 'http://localhost:3000');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
        assert.strictEqual(res.headers['x-frame-options'], 'DENY');
        assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
        assert.strictEqual(res.headers['cache-control'], 'no-store');
        assert.strictEqual(res.headers['x-powered-by'], undefined);
        assert.strictEqual(res.headers['access-control-allow-origin'], 'http://localhost:3000');

        const blocked = await request(app)
            .get('/api/health')
            .set('Origin', 'https://untrusted.example');
        assert.strictEqual(blocked.status, 403);
        assert.deepStrictEqual(blocked.body, { error: 'Origin not allowed' });
    });

});
 + testHash;
process.env.SIEM_AUTH_SECRET = 'test-only-secret-that-is-at-least-32-bytes-long';
const { app } = require('./server');

let testToken = '';
function apiRequest() { return request(app).set('Authorization', 'Bearer ' + testToken); }

test('API Regression Tests', async (t) => {
    let ingestor = null;
    // Always close the watcher/database, even when setup or an assertion fails.
    t.after(async () => {
        if (ingestor) ingestor.closeFile();
        await closeDb();
        for (const filePath of [testDbPath, `${testDbPath}-shm`, `${testDbPath}-wal`, testLogPath]) {
            try {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            } catch (error) {
                console.warn(`Could not clean up temporary test file ${filePath}:`, error.message);
            }
        }
    });

    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(testLogPath)) fs.unlinkSync(testLogPath);
    fs.writeFileSync(testLogPath, '');

    await migrate();
    ingestor = new IngestionService(testLogPath);
    await ingestor.init();

    await t.test('1. Empty Database Responses', async () => {
        let res = await request(app).get('/api/health');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, { status: 'ok' });

        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/alerts');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);

        res = await request(app).get('/api/actors');
        assert.strictEqual(res.status, 200);
        assert.deepStrictEqual(res.body, []);
        
        res = await request(app).get('/api/overview/metrics');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.metrics.totalEvents, 0);
    });

    await t.test('2. Populating Database with Test Events', async () => {
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.session.connect', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString() }) + '\n');
        fs.appendFileSync(testLogPath, JSON.stringify({ eventid: 'cowrie.command.input', session: 'sess-api-1', src_ip: '10.0.0.1', timestamp: new Date().toISOString(), input: 'wget malware' }) + '\n');
        
        // Wait for ingestion
        await new Promise(resolve => setTimeout(resolve, 500));
        
        let res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 2, 'Should return 2 events');

        res = await request(app).get('/api/sessions');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 1, 'Should return 1 session');
        
        res = await request(app).get('/api/sessions/sess-api-1');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.id, 'sess-api-1', 'Should fetch specific session');
        assert.strictEqual(res.body.events.length, 2, 'Session should have 2 raw events embedded');

        // Corrupt persisted JSON should not make the entire events endpoint fail.
        const db = await getDb();
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['malformed-json-test', null, new Date().toISOString(), 'test.malformed', '{not-json']
        );
        res = await request(app).get('/api/events');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.length, 3, 'Malformed payload should not hide valid events');
        assert.ok(res.body.some(event => event.mitre_context === null), 'Malformed payload should use a safe fallback');

        // Valid JSON with an unexpected shape must not break FIM processing either.
        await db.run(
            'INSERT INTO raw_events (id, session_id, timestamp, eventid, payload) VALUES (?, ?, ?, ?, ?)',
            ['null-payload-test', null, new Date().toISOString(), 'cowrie.command.input', 'null']
        );
        res = await request(app).get('/api/fim');
        assert.strictEqual(res.status, 200, 'Unexpected payload shapes should not break FIM responses');
    });

    await t.test('3. API Error Handling does not leak DB details', async () => {
        // We will simulate a SQL injection attempt or bad parameter if possible, 
        // or just ensure basic 404/500 works.
        const res = await request(app).get('/api/sessions/invalid-id');
        assert.strictEqual(res.status, 404);
        assert.deepStrictEqual(res.body, { error: 'Session not found' });
    });

    await t.test('4. Security middleware rejects malformed and oversized JSON', async () => {
        let res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send('{not-json');
        assert.strictEqual(res.status, 400);
        assert.deepStrictEqual(res.body, { error: 'Invalid JSON body' });

        res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send(JSON.stringify({ payload: 'x'.repeat(1024 * 1024 + 32) }));
        assert.strictEqual(res.status, 413);
        assert.deepStrictEqual(res.body, { error: 'Request body too large' });
    });

    await t.test('5. Security headers and CORS allow-list are enforced', async () => {
        const res = await request(app)
            .get('/api/health')
            .set('Origin', 'http://localhost:3000');
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
        assert.strictEqual(res.headers['x-frame-options'], 'DENY');
        assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
        assert.strictEqual(res.headers['cache-control'], 'no-store');
        assert.strictEqual(res.headers['x-powered-by'], undefined);
        assert.strictEqual(res.headers['access-control-allow-origin'], 'http://localhost:3000');

        const blocked = await request(app)
            .get('/api/health')
            .set('Origin', 'https://untrusted.example');
        assert.strictEqual(blocked.status, 403);
        assert.deepStrictEqual(blocked.body, { error: 'Origin not allowed' });
    });

});
