const fs = require('fs');
const readline = require('readline');
const engine = require('./services/correlation');

const store = {
    events: [],
    sessions: {},
    alerts: [],
    actors: new Set()
};

async function loadTestData() {
    const logFilePath = 'C:\\Users\\Faizan\\Desktop\\cowrie.json.2026-05-18';
    if (!fs.existsSync(logFilePath)) {
        console.warn(`[DataStore] Warning: Test file not found at ${logFilePath}`);
        return;
    }

    console.log(`[DataStore] Loading test data from ${logFilePath}...`);
    const rl = readline.createInterface({ input: fs.createReadStream(logFilePath) });
    
    for await (const line of rl) {
        if (!line.trim()) continue;
        try {
            const evt = JSON.parse(line);
            store.events.push(evt);
            
            if (evt.src_ip) store.actors.add(evt.src_ip);

            if (evt.session) {
                if (!store.sessions[evt.session]) {
                    store.sessions[evt.session] = { id: evt.session, src_ip: evt.src_ip, events: [], start_time: evt.timestamp };
                }
                store.sessions[evt.session].events.push(evt);
                store.sessions[evt.session].end_time = evt.timestamp; // update to last seen
            }
        } catch (e) {}
    }

    // Run correlation
    for (const [id, session] of Object.entries(store.sessions)) {
        const result = engine.evaluateSessionEvents(session.events);
        session.threatScore = result.threatScore;
        session.riskLevel = result.riskLevel;
        session.alerts = result.alerts;
        session.explanations = result.explanations;
        session.dimensions = result.dimensions;
        session.mitre = result.mitre;
        
        result.alerts.forEach(a => {
            store.alerts.push({ 
                ...a, 
                id: Math.random().toString(36).substring(7),
                session: id, 
                src_ip: session.src_ip, 
                timestamp: session.start_time,
                status: 'OPEN'
            });
        });
    }
    
    // Sort alerts newest first
    store.alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

const { generateRandomThreatEvents } = require('./services/eventGenerator');

    // Generate realistic global threat events including user's local IP (192.168.100.11)
    generateRandomThreatEvents(store);

    console.log(`[DataStore] Loaded ${store.events.length} total events, ${Object.keys(store.sessions).length} sessions, ${store.actors.size} actors, ${store.alerts.length} alerts.`);
}

module.exports = { store, loadTestData };
