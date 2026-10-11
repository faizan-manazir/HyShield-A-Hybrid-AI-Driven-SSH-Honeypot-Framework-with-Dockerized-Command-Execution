const express = require('express');
const router = express.Router();
const { getDb } = require('../db/migrate');
const { resolveGeo } = require('../services/geoService');

// Keep one malformed stored JSON payload from breaking an entire dashboard response.
function safeJsonParse(value, fallback = {}) {
    if (typeof value !== 'string') return fallback;
    try {
        const parsed = JSON.parse(value);
        // API consumers expect an object; reject null, arrays, and primitives too.
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return fallback;
        return parsed;
    } catch (error) {
        return fallback;
    }
}

router.get('/health', (req, res) => res.json({ status: 'ok' }));

router.get('/alerts', async (req, res) => {
    try {
        const db = await getDb();
        const alerts = await db.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 500');
        // frontend expects .session for session id
        res.json(alerts.map(a => ({...a, session: a.session_id})));
    } catch (e) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

router.patch('/alerts/:id/close', async (req, res) => {
    try {
        const db = await getDb();
        await db.run('UPDATE alerts SET status = "CLOSED" WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Dashboard Endpoints
router.get('/overview/metrics', async (req, res) => {
    try {
        const db = await getDb();
        
        const totalEventsRow = await db.get('SELECT COUNT(*) as count FROM raw_events');
        const totalEvents = totalEventsRow.count;
        
        const activeSessionsRow = await db.get('SELECT COUNT(*) as count FROM sessions WHERE is_closed = 0');
        const activeSessions = activeSessionsRow.count;
        
        const openAlertsRow = await db.get('SELECT COUNT(*) as count FROM alerts WHERE status = "OPEN"');
        const openAlerts = openAlertsRow.count;
        
        const uniqueActorsRow = await db.get('SELECT COUNT(DISTINCT src_ip) as count FROM sessions');
        const uniqueActors = uniqueActorsRow.count;
        
        // Timeline (last 20 mins)
        // SQLite doesn't easily format time, so we pull recent events and group in JS
        const recentEvents = await db.all('SELECT timestamp FROM raw_events ORDER BY timestamp DESC LIMIT 1000');
        const timelineMap = {};
        recentEvents.forEach(e => {
            const timeKey = new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            timelineMap[timeKey] = (timelineMap[timeKey] || 0) + 1;
        });
        const timeline = Object.entries(timelineMap).map(([time, events]) => ({ time, events })).slice(-20).reverse();
        
        const recentAlerts = await db.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 5');
        
        // Category distribution
        const catCounts = await db.all(`
            SELECT 
                SUM(CASE WHEN eventid LIKE '%login%' THEN 1 ELSE 0 END) as AUTH,
                SUM(CASE WHEN eventid LIKE '%command%' THEN 1 ELSE 0 END) as CMD,
                SUM(CASE WHEN eventid LIKE '%connect%' OR eventid LIKE '%closed%' THEN 1 ELSE 0 END) as SESS,
                SUM(CASE WHEN eventid NOT LIKE '%login%' AND eventid NOT LIKE '%command%' AND eventid NOT LIKE '%connect%' AND eventid NOT LIKE '%closed%' THEN 1 ELSE 0 END) as INFO
            FROM raw_events
        `);
        const cat = catCounts[0];
        const categoryData = [
            { name: 'AUTH', value: cat.AUTH || 0 },
            { name: 'CMD', value: cat.CMD || 0 },
            { name: 'SESS', value: cat.SESS || 0 },
            { name: 'INFO', value: cat.INFO || 0 }
        ];

        res.json({ metrics: { totalEvents, activeSessions, openAlerts, uniqueActors }, recentAlerts, timeline, categoryData });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Internal Server Error' }); }
});

router.get('/events', async (req, res) => {
    try {
        const db = await getDb();
        const events = await db.all(`
            SELECT r.*, s.summary as session_summary
            FROM raw_events r
            LEFT JOIN sessions s ON r.session_id = s.session_id
            ORDER BY r.timestamp DESC LIMIT 500
        `);
        
        const enrichedEvents = events.map(e => {
            const payload = safeJsonParse(e.payload);
            let mitre_context = null;
            if (e.session_summary) {
                try {
                    const parsed = safeJsonParse(e.session_summary);
                    if (parsed.mitre && Array.isArray(parsed.mitre)) {
                        mitre_context = parsed.mitre.map(m => `${m.id} ${m.name} ${m.tactic}`).join(' | ');
                    }
                } catch(err) {}
            }
            return {
                ...payload,
                id: e.id,
                session_id: e.session_id,
                timestamp: e.timestamp ?? payload.timestamp ?? null,
                eventid: e.eventid ?? payload.eventid ?? null,
                mitre_context
            };
        });
        res.json(enrichedEvents);
    } catch (e) { console.error(e); res.status(500).json({ error: 'Internal Server Error' }); }
});

router.get('/actors', async (req, res) => {
    try {
        const db = await getDb();
        const actorsQuery = await db.all(`
            SELECT src_ip as ip, 
                   MIN(start_time) as firstSeen, 
                   MAX(end_time) as lastSeen,
                   COUNT(session_id) as sessionCount,
                   MAX(risk_level) as maxRisk
            FROM sessions GROUP BY src_ip
        `);
        
        // Event count per actor requires a subquery or join
        const eventCounts = await db.all('SELECT src_ip, COUNT(*) as c FROM sessions JOIN raw_events ON sessions.session_id = raw_events.session_id GROUP BY src_ip');
        const countMap = {};
        eventCounts.forEach(r => countMap[r.src_ip] = r.c);

        const actors = actorsQuery.map(a => {
            let riskLevel = a.maxRisk;
            if (riskLevel === 'LOW' && a.sessionCount > 5) riskLevel = 'MEDIUM'; // fallback heuristic
            
            return {
                ip: a.ip,
                eventCount: countMap[a.ip] || 1,
                firstSeen: a.firstSeen,
                lastSeen: a.lastSeen,
                riskLevel: riskLevel,
                location: resolveGeo(a.ip, a.ip)
            };
        });
        
        res.json(actors.sort((a, b) => b.eventCount - a.eventCount));
    } catch (e) { console.error(e); res.status(500).json({ error: 'Internal Server Error' }); }
});

router.get('/sessions', async (req, res) => {
    try {
        const db = await getDb();
        const sessions = await db.all('SELECT * FROM sessions ORDER BY start_time DESC LIMIT 500');
        const list = sessions.map(s => {
            let summary = {};
            let mitre = [];
            if (s.summary) {
                const parsed = safeJsonParse(s.summary);
                summary = parsed.summary || {};
                mitre = parsed.mitre || [];
            }
            return {
                id: s.session_id,
                src_ip: s.src_ip,
                start_time: s.start_time,
                end_time: s.end_time,
                is_closed: s.is_closed,
                threatScore: s.threat_score,
                riskLevel: s.risk_level,
                summary,
                mitre,
                location: resolveGeo(s.src_ip, s.session_id)
            };
        });
        res.json(list);
    } catch (e) { console.error(e); res.status(500).json({ error: 'Internal Server Error' }); }
});

router.get('/sessions/:id', async (req, res) => {
    try {
        const db = await getDb();
        const s = await db.get('SELECT * FROM sessions WHERE session_id = ?', [req.params.id]);
        if (!s) return res.status(404).json({ error: 'Session not found' });
        
        // Fetch raw events
        const rows = await db.all('SELECT payload FROM raw_events WHERE session_id = ? ORDER BY timestamp ASC', [s.session_id]);
        const events = rows.map(r => safeJsonParse(r.payload));
        
        const parsed = safeJsonParse(s.summary || '{}');
        
        res.json({
            id: s.session_id,
            src_ip: s.src_ip,
            start_time: s.start_time,
            end_time: s.end_time,
            threatScore: s.threat_score,
            riskLevel: s.risk_level,
            summary: parsed.summary || {},
            dimensions: parsed.dimensions || {},
            explanations: parsed.explanations || [],
            mitre: parsed.mitre || [],
            events,
            location: resolveGeo(s.src_ip, s.session_id)
        });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Internal Server Error' }); }
});

const { generateRandomThreatEvents } = require('../services/eventGenerator');

router.post('/generate-events', (req, res) => {
    res.status(400).json({ error: 'Generation disabled in database mode. Please use Cowrie logs.' });
});

router.get('/geo', async (req, res) => {
    try {
        const honeypot = {
            name: 'HyShield Honeypot Sensor (192.168.100.11:22)',
            lat: 33.6844,
            lng: 73.0479,
            city: 'Local Sensor Node (192.168.100.11)',
            country: 'Local Network Target',
            flag: '🛡️'
        };

        const db = await getDb();
        const sessionList = await db.all('SELECT * FROM sessions');
        
        const countryMap = {};
        const attackNodes = [];
        const attackArcs = [];

        sessionList.forEach(session => {
            const geo = resolveGeo(session.src_ip, session.session_id);
            // We'll estimate eventCount per session using the summary JSON
            let eventCount = 1;
            if (session.summary) {
                const parsed = safeJsonParse(session.summary);
                if (parsed.summary && parsed.summary.commandCount) eventCount = parsed.summary.commandCount + 2; // +2 for auth
            }
            const risk = session.risk_level || 'LOW';

            if (!countryMap[geo.countryCode]) {
                countryMap[geo.countryCode] = {
                    code: geo.countryCode,
                    name: geo.countryName,
                    flag: geo.flag,
                    eventCount: 0,
                    sessionCount: 0,
                    criticalCount: 0,
                    highCount: 0,
                    mediumCount: 0,
                    lowCount: 0,
                    lat: geo.lat,
                    lng: geo.lng
                };
            }

            countryMap[geo.countryCode].eventCount += eventCount;
            countryMap[geo.countryCode].sessionCount += 1;
            if (risk === 'CRITICAL') countryMap[geo.countryCode].criticalCount += 1;
            else if (risk === 'HIGH') countryMap[geo.countryCode].highCount += 1;
            else if (risk === 'MEDIUM') countryMap[geo.countryCode].mediumCount += 1;
            else countryMap[geo.countryCode].lowCount += 1;

            attackNodes.push({
                id: session.session_id,
                ip: session.src_ip,
                sessionId: session.session_id,
                city: geo.city,
                countryName: geo.countryName,
                countryCode: geo.countryCode,
                flag: geo.flag,
                org: geo.org,
                lat: geo.lat,
                lng: geo.lng,
                eventCount,
                riskLevel: risk,
                startTime: session.start_time,
                isPrivate: geo.isPrivate
            });

            attackArcs.push({
                id: session.session_id,
                from: [geo.lng, geo.lat],
                to: [honeypot.lng, honeypot.lat],
                country: geo.countryName,
                city: geo.city,
                flag: geo.flag,
                ip: session.src_ip,
                riskLevel: risk
            });
        });

        const totalEvents = sessionList.reduce((acc, s) => {
            let c = 1;
            if (s.summary) {
                 const p = safeJsonParse(s.summary).summary;
                 if (p && p.commandCount) c = p.commandCount;
            }
            return acc + c;
        }, 0) || 1;
        
        const countries = Object.values(countryMap)
            .map(c => ({
                ...c,
                percentage: Math.round((c.eventCount / totalEvents) * 100)
            }))
            .sort((a, b) => b.eventCount - a.eventCount);

        res.json({
            honeypot,
            countries,
            attackNodes,
            attackArcs,
            stats: {
                totalCountries: countries.length,
                totalMappedNodes: attackNodes.length,
                totalAttacks: totalEvents,
                topCountry: countries[0] ? `${countries[0].flag} ${countries[0].name}` : 'N/A'
            }
        });
    } catch (e) { res.status(500).json({ error: e.message ? 'Internal Server Error' : 'Internal Server Error' }); }
});

router.get('/fim', async (req, res) => {
    try {
        const fimData = [];
        const db = await getDb();
        const events = await db.all("SELECT payload FROM raw_events WHERE eventid IN ('cowrie.session.file_download', 'cowrie.session.file_upload', 'cowrie.command.input') ORDER BY timestamp DESC LIMIT 1000");
        
        events.forEach(row => {
            const e = safeJsonParse(row.payload);
            if (e.eventid === 'cowrie.session.file_download' || e.eventid === 'cowrie.session.file_upload') {
                fimData.push({
                    id: Math.random().toString(),
                    path: e.outfile || e.filename || e.url || '/tmp/unknown',
                    action: 'added',
                    user: 'root',
                    time: new Date(e.timestamp).toLocaleString(),
                    size: e.size ? `${e.size} B` : 'Unknown',
                    hash: e.shasum ? e.shasum.substring(0, 10) + '...' : '-',
                    risk: 'CRITICAL'
                });
            } else if (e.eventid === 'cowrie.command.input') {
                // Persisted payloads may be malformed or lack the expected Cowrie fields.
                if (typeof e.input !== 'string') return;
                if (e.input.includes('rm ')) {
                    fimData.push({ id: Math.random().toString(), path: e.input.split('rm ')[1].split(' ')[0], action: 'deleted', user: 'root', time: new Date(e.timestamp).toLocaleString(), size: '0 B', hash: '-', risk: 'HIGH' });
                } else if (e.input.includes('nano ') || e.input.includes('vi ') || e.input.includes('echo ') || e.input.includes('touch ')) {
                    fimData.push({ id: Math.random().toString(), path: e.input.split(' ').pop(), action: 'modified', user: 'root', time: new Date(e.timestamp).toLocaleString(), size: 'Unknown', hash: '-', risk: 'MEDIUM' });
                }
            }
        });
        res.json(fimData.slice(0, 50));
    } catch (e) { res.status(500).json({ error: e.message ? 'Internal Server Error' : 'Internal Server Error' }); }
});

router.get('/mitre', async (req, res) => {
    try {
        const tactics = [
          { name: 'Initial Access', techniques: [{ name: 'Valid Accounts', count: 0, severity: 'HIGH' }] },
          { name: 'Execution', techniques: [{ name: 'Command and Scripting', count: 0, severity: 'HIGH' }, { name: 'User Execution', count: 0, severity: 'CRITICAL' }] },
          { name: 'Persistence', techniques: [{ name: 'Create Account', count: 0, severity: 'CRITICAL' }, { name: 'Scheduled Task', count: 0, severity: 'MEDIUM' }] },
          { name: 'Defense Evasion', techniques: [{ name: 'Indicator Removal', count: 0, severity: 'CRITICAL' }] },
          { name: 'Credential Access', techniques: [{ name: 'Brute Force', count: 0, severity: 'HIGH' }, { name: 'OS Credential Dumping', count: 0, severity: 'CRITICAL' }] },
          { name: 'Discovery', techniques: [{ name: 'System Information Discovery', count: 0, severity: 'MEDIUM' }, { name: 'System Network Connections', count: 0, severity: 'MEDIUM' }] },
          { name: 'Command and Control', techniques: [{ name: 'Ingress Tool Transfer', count: 0, severity: 'HIGH' }] },
          { name: 'Lateral Movement', techniques: [{ name: 'Remote Services', count: 0, severity: 'CRITICAL' }] },
          { name: 'Impact', techniques: [{ name: 'Resource Hijacking', count: 0, severity: 'HIGH' }] },
        ];

        const increment = (tacticName, techName) => {
            const tactic = tactics.find(t => t.name === tacticName);
            if (tactic) {
                const tech = tactic.techniques.find(t => t.name === techName);
                if (tech) tech.count++;
            }
        };

        const db = await getDb();
        const sessions = await db.all('SELECT summary FROM sessions');
        
        sessions.forEach(s => {
            if (s.summary) {
                const parsed = safeJsonParse(s.summary);
                if (parsed.mitre && Array.isArray(parsed.mitre)) {
                    parsed.mitre.forEach(m => {
                        increment(m.tactic, m.name);
                    });
                }
            }
        });

        res.json(tactics);
    } catch (e) { res.status(500).json({ error: e.message ? 'Internal Server Error' : 'Internal Server Error' }); }
});

let systemConfig = {
    alertLevel: 7, logRetention: 90, arEnabled: true, arCommand: 'firewall-drop', arTimeout: 600, vtEnabled: true, vtKey: '************************', otxEnabled: false
};
router.get('/settings', (req, res) => res.json(systemConfig));
router.post('/settings', (req, res) => {
    systemConfig = { ...systemConfig, ...req.body };
    res.json({ success: true, config: systemConfig });
});

router.get('/vulnerabilities', (req, res) => {
    res.json([
      { id: 'CVE-2024-3094', package: 'xz-utils', version: '5.6.0', severity: 'CRITICAL', cvss: 10.0, status: 'Vulnerable', published: '2024-03-29' },
      { id: 'CVE-2023-38408', package: 'openssh-server', version: '9.3p1', severity: 'HIGH', cvss: 8.1, status: 'Patched', published: '2023-07-19' },
      { id: 'CVE-2021-44228', package: 'log4j-core', version: '2.14.1', severity: 'CRITICAL', cvss: 10.0, status: 'Vulnerable', published: '2021-12-10' },
      { id: 'CVE-2022-0847', package: 'linux-kernel', version: '5.8', severity: 'HIGH', cvss: 7.8, status: 'Vulnerable', published: '2022-03-07' },
      { id: 'CVE-2023-23397', package: 'outlook', version: 'N/A', severity: 'MEDIUM', cvss: 6.5, status: 'Not Applicable', published: '2023-03-14' }
    ]);
});

module.exports = router;
