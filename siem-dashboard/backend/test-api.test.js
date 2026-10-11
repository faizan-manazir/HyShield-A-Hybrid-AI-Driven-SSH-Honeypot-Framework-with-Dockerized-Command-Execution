const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const request = require('supertest');
const path = require('path');
const os = require('node:os');
const fs = require('fs');

// We need to set up the DB before mounting routes
const { migrate, closeDb, getDb } = require('./db/migrate');
const IngestionService = require('./services/ingestion');
const apiRoutes = require('./routes/api');

// Use isolated temporary files; never delete or overwrite tracked Cowrie fixtures.
const testDbPath = path.join(os.tmpdir(), `hyshield-api-test-${process.pid}.db`);
process.env.DB_PATH = testDbPath;
const testLogPath = path.join(os.tmpdir(), `hyshield-api-test-${process.pid}.json`);

const app = express();
app.use(express.json());
app.use('/api', apiRoutes);

test('API Regression Tests', async (t) => {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(testLogPath)) fs.unlinkSync(testLogPath);
    fs.writeFileSync(testLogPath, '');

    await migrate();
    const ingestor = new IngestionService(testLogPath);
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

    ingestor.closeFile();
    await closeDb();
    for (const filePath of [testDbPath, `${testDbPath}-shm`, `${testDbPath}-wal`, testLogPath]) {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
});
