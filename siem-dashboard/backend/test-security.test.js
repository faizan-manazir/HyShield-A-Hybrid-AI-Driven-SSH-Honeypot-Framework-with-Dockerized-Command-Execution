const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

// Importing the app must not start the listener, database migration, or Cowrie watcher.
process.env.CORS_ORIGINS = 'http://localhost:3000';
const { app } = require('./server');

test('security middleware', async (t) => {
    await t.test('sets defensive response headers and does not disclose Express', async () => {
        const res = await request(app).get('/api/health');

        assert.equal(res.status, 200);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['x-frame-options'], 'DENY');
        assert.equal(res.headers['referrer-policy'], 'no-referrer');
        assert.equal(res.headers['cache-control'], 'no-store');
        assert.equal(res.headers['x-powered-by'], undefined);
    });

    await t.test('allows the configured browser origin', async () => {
        const res = await request(app)
            .get('/api/health')
            .set('Origin', 'http://localhost:3000');

        assert.equal(res.status, 200);
        assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:3000');
    });

    await t.test('rejects an unapproved browser origin', async () => {
        const res = await request(app)
            .get('/api/health')
            .set('Origin', 'https://untrusted.example');

        assert.equal(res.status, 403);
        assert.deepEqual(res.body, { error: 'Origin not allowed' });
    });

    await t.test('returns 400 for malformed JSON', async () => {
        const res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send('{"broken":');

        assert.equal(res.status, 400);
        assert.deepEqual(res.body, { error: 'Invalid JSON body' });
    });

    await t.test('returns 413 for JSON larger than 1 MB', async () => {
        const oversizedBody = JSON.stringify({ data: 'x'.repeat(1024 * 1024) });
        const res = await request(app)
            .post('/api/health')
            .set('Content-Type', 'application/json')
            .send(oversizedBody);

        assert.equal(res.status, 413);
        assert.deepEqual(res.body, { error: 'Request body too large' });
    });
});
