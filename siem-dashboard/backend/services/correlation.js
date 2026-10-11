/**
 * HyShield Correlation Engine v2 — Production-Grade Threat Scoring
 * 
 * Methodology:
 *   The score is a composite of four weighted dimensions, each scored 0–25,
 *   giving a final Threat Score of 0–100.
 * 
 *   ┌────────────────────────────────────────────────────────────┐
 *   │  Dimension              │ Max  │ What it measures          │
 *   ├─────────────────────────┼──────┼───────────────────────────┤
 *   │ 1. Access Severity      │  25  │ Auth attempts & outcomes  │
 *   │ 2. Post-Auth Activity   │  25  │ Recon, credential theft   │
 *   │ 3. Weaponization        │  25  │ Downloads, execution      │
 *   │ 4. Intent & Persistence │  25  │ Evasion, lateral movement │
 *   └────────────────────────────────────────────────────────────┘
 * 
 *   Risk Level Thresholds (aligned with Wazuh/OSSEC rule levels):
 *     0–19  → LOW       (Informational / opportunistic scan)
 *     20–49 → MEDIUM    (Credentialed reconnaissance)  
 *     50–74 → HIGH      (Active exploitation attempt)
 *     75–100→ CRITICAL  (Confirmed compromise / payload execution)
 * 
 *   Alert Severities follow NIST SP 800-61 (Incident Handling Guide):
 *     LOW      = Port scan / version probe
 *     MEDIUM   = Credential guessing / recon
 *     HIGH     = Successful unauthorized access  
 *     CRITICAL = Data exfiltration / malware execution
 */

class CorrelationEngine {
    constructor() {
        // ── Command Classification Dictionaries ──────────────────────
        this.reconCommands = [
            'whoami', 'id', 'uname', 'hostname', 'netstat', 'ps', 'df',
            'uptime', 'ifconfig', 'ip addr', 'ip route', 'route', 'w',
            'last', 'cat /etc/issue', 'cat /etc/os-release', 'lscpu',
            'cat /proc/cpuinfo', 'cat /proc/meminfo', 'lsof', 'ss',
            'arp', 'nmap', 'cat /etc/hostname'
        ];

        this.credentialFiles = [
            '/etc/shadow', '/etc/passwd', '/etc/sudoers',
            '.ssh/authorized_keys', '.ssh/id_rsa', '.bash_history',
            '/root/.ssh', '.pgpass', '.my.cnf', '/etc/krb5.conf'
        ];

        this.downloadTools = ['wget', 'curl', 'ftp', 'scp', 'tftp', 'git clone'];

        this.executionPatterns = [
            'chmod +x', 'chmod 777', 'chmod 755',
            './', 'sh ', 'bash ', 'python', 'perl', 'ruby',
            'nohup', '| bash', '| sh'
        ];

        this.evasionPatterns = [
            'history -c', 'unset HISTFILE', 'rm -rf /var/log',
            'rm -f /var/log', 'echo "" >', 'kill -9', 'pkill',
            'iptables -F', 'setenforce 0', 'systemctl stop'
        ];

        this.lateralPatterns = [
            'ssh ', 'sshpass', 'nc ', 'ncat', 'socat',
            'python3 -c', 'python -c', 'pty.spawn',
            'useradd', 'adduser', 'usermod', 'passwd',
            'crontab', 'at ', 'echo.*>>.*cron'
        ];

        this.cryptominerPatterns = [
            'xmrig', 'stratum+tcp', 'minerd', 'cpuminer',
            'ethminer', 'nbminer', 'pool.', 'minergate'
        ];

        // ── MITRE ATT&CK Tactic Mapping ──────────────────────────
        this.mitreTactics = {
            'T1078':  { name: 'Valid Accounts',                   tactic: 'Initial Access' },
            'T1110':  { name: 'Brute Force',                      tactic: 'Credential Access' },
            'T1059':  { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
            'T1082':  { name: 'System Information Discovery',     tactic: 'Discovery' },
            'T1049':  { name: 'System Network Connections',       tactic: 'Discovery' },
            'T1003':  { name: 'OS Credential Dumping',            tactic: 'Credential Access' },
            'T1105':  { name: 'Ingress Tool Transfer',            tactic: 'Command and Control' },
            'T1204':  { name: 'User Execution',                   tactic: 'Execution' },
            'T1070':  { name: 'Indicator Removal',                tactic: 'Defense Evasion' },
            'T1136':  { name: 'Create Account',                   tactic: 'Persistence' },
            'T1053':  { name: 'Scheduled Task/Job',               tactic: 'Persistence' },
            'T1021':  { name: 'Remote Services',                  tactic: 'Lateral Movement' },
            'T1496':  { name: 'Resource Hijacking',               tactic: 'Impact' }
        };
    }

    evaluateSessionEvents(events) {
        // ── Phase 1: Event Classification ────────────────────────
        let failedLogins = 0;
        let successfulLogin = false;
        let loginUsername = '';
        let loginPassword = '';
        let sshClient = '';
        let commandsExecuted = [];
        let reconHits = [];
        let credentialHits = [];
        let downloadHits = [];
        let executionHits = [];
        let evasionHits = [];
        let lateralHits = [];
        let cryptominerHits = [];
        let fileDownloads = [];
        let sessionDurationMs = 0;
        let mitreHits = [];

        if (events.length > 1) {
            const first = new Date(events[0].timestamp).getTime();
            const last = new Date(events[events.length - 1].timestamp).getTime();
            sessionDurationMs = last - first;
        }

        events.forEach(event => {
            const type = event.eventid;

            // SSH client fingerprint
            if (type === 'cowrie.client.version' && event.version) {
                sshClient = event.version;
            }

            // Authentication
            if (type === 'cowrie.login.failed') {
                failedLogins++;
            }
            if (type === 'cowrie.login.success') {
                successfulLogin = true;
                loginUsername = event.username || '';
                loginPassword = event.password || '';
            }

            // Commands
            if (type === 'cowrie.command.input' && event.input) {
                const cmd = event.input;
                commandsExecuted.push(cmd);
                
                const hasMatch = (arr, c) => arr.some(r => {
                    // Escape special regex chars if necessary, but most of our dict doesn't have them
                    // Using word boundary to prevent 'w' or 'id' matching inside 'shadow' or 'cd'
                    const escaped = r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    return new RegExp(`(^|\\b|\\s)${escaped}(\\b|\\s|$)`, 'i').test(c);
                });

                if (hasMatch(this.reconCommands, cmd)) {
                    reconHits.push(cmd);
                }
                if (hasMatch(this.credentialFiles, cmd)) {
                    credentialHits.push(cmd);
                }
                if (hasMatch(this.downloadTools, cmd)) {
                    downloadHits.push(cmd);
                }
                if (hasMatch(this.executionPatterns, cmd)) {
                    executionHits.push(cmd);
                }
                if (hasMatch(this.evasionPatterns, cmd)) {
                    evasionHits.push(cmd);
                }
                if (hasMatch(this.lateralPatterns, cmd)) {
                    lateralHits.push(cmd);
                }
                if (hasMatch(this.cryptominerPatterns, cmd)) {
                    cryptominerHits.push(cmd);
                }
            }

            // File downloads
            if (type === 'cowrie.session.file_download') {
                fileDownloads.push({
                    url: event.url || event.outfile || 'unknown',
                    sha: event.shasum || ''
                });
            }
        });

        // Deduplicate command hits to prevent repeated identical commands from inflating the score endlessly
        commandsExecuted = [...new Set(commandsExecuted)];
        reconHits = [...new Set(reconHits)];
        credentialHits = [...new Set(credentialHits)];
        downloadHits = [...new Set(downloadHits)];
        executionHits = [...new Set(executionHits)];
        evasionHits = [...new Set(evasionHits)];
        lateralHits = [...new Set(lateralHits)];
        cryptominerHits = [...new Set(cryptominerHits)];

        // ── Phase 2: Dimension Scoring ──────────────────────────
        let explanations = [];
        let alerts = [];

        // ─── Dimension 1: Access Severity (0–25) ────────────────
        let accessScore = 0;

        if (events.length === 0) {
            accessScore = 0; // Empty session is strictly zero
        } else if (failedLogins === 0 && !successfulLogin && events.some(e => e.eventid === 'cowrie.session.connect')) {
            // Port scan / version probe only
            accessScore = 2;
            explanations.push({ score: 2, reason: 'TCP connection established (port probe)', dimension: 'Access', mitre: null });
        }

        if (failedLogins > 0 && failedLogins <= 3 && !successfulLogin) {
            accessScore = 5;
            explanations.push({ score: 5, reason: `${failedLogins} failed login attempt(s) — opportunistic credential guess`, dimension: 'Access', mitre: 'T1110' });
            mitreHits.push('T1110');
        }

        if (failedLogins > 3 && !successfulLogin) {
            accessScore = 12;
            explanations.push({ score: 12, reason: `${failedLogins} failed logins — dictionary / brute-force attack`, dimension: 'Access', mitre: 'T1110' });
            alerts.push({ severity: 'HIGH', title: 'SSH Brute Force Detected', reason: `${failedLogins} sequential failed password attempts from single source`, mitre: 'T1110' });
            mitreHits.push('T1110');
        }

        if (successfulLogin && failedLogins === 0) {
            accessScore = 10;
            explanations.push({ score: 10, reason: `Successful authentication as '${loginUsername}' (first attempt — possible leaked credential)`, dimension: 'Access', mitre: 'T1078' });
            alerts.push({ severity: 'MEDIUM', title: 'Direct Credential Access', reason: `Immediate login success as '${loginUsername}' suggests pre-compromised or default credential`, mitre: 'T1078' });
            mitreHits.push('T1078');
        }

        if (successfulLogin && failedLogins > 0) {
            accessScore = 18;
            explanations.push({ score: 18, reason: `Successful login as '${loginUsername}' after ${failedLogins} failed attempts — credential compromised in honeypot`, dimension: 'Access', mitre: 'T1078' });
            alerts.push({ severity: 'CRITICAL', title: 'Honeypot Credential Compromise', reason: `Brute-force success: authenticated as '${loginUsername}' after ${failedLogins} failed guesses in honeypot environment`, mitre: 'T1078' });
            mitreHits.push('T1078');
        }

        if (loginUsername === 'root' && successfulLogin) {
            accessScore = Math.min(25, accessScore + 5);
            explanations.push({ score: 5, reason: 'Root-level access obtained (maximum privilege)', dimension: 'Access', mitre: 'T1078' });
        }

        // Suspicious SSH client fingerprint bonus
        const suspiciousClients = ['Mirai', 'Hydra', 'libssh', 'AsyncSSH', 'Go', 'paramiko'];
        if (suspiciousClients.some(c => sshClient.toLowerCase().includes(c.toLowerCase()))) {
            accessScore = Math.min(25, accessScore + 3);
            explanations.push({ score: 3, reason: `Suspicious SSH client: ${sshClient} (commonly used by automated attack tools)`, dimension: 'Access', mitre: null });
        }

        accessScore = Math.min(25, accessScore);

        // ─── Dimension 2: Post-Auth Activity (0–25) ─────────────
        let activityScore = 0;

        if (!successfulLogin) {
            activityScore = 0; // No post-auth activity possible
        } else {
            // Reconnaissance
            if (reconHits.length > 0 && reconHits.length <= 2) {
                activityScore += 5;
                explanations.push({ score: 5, reason: `System reconnaissance: ${reconHits.length} discovery command(s) [${reconHits[0]}]`, dimension: 'Activity', mitre: 'T1082' });
                mitreHits.push('T1082');
            }
            if (reconHits.length >= 3) {
                activityScore += 12;
                explanations.push({ score: 12, reason: `Extensive system enumeration: ${reconHits.length} discovery commands (host profiling)`, dimension: 'Activity', mitre: 'T1082' });
                alerts.push({ severity: 'MEDIUM', title: 'Host Enumeration Detected', reason: `${reconHits.length} system discovery commands executed in sequence`, mitre: 'T1082' });
                mitreHits.push('T1082');
            }

            // Credential theft
            if (credentialHits.length > 0) {
                const credScore = Math.min(15, credentialHits.length * 8);
                activityScore += credScore;
                explanations.push({ score: credScore, reason: `Credential file access: ${credentialHits.join(', ')}`, dimension: 'Activity', mitre: 'T1003' });
                alerts.push({ severity: 'HIGH', title: 'Credential Harvesting Attempt', reason: `Accessed ${credentialHits.length} sensitive credential file(s): ${credentialHits[0]}`, mitre: 'T1003' });
                mitreHits.push('T1003');
            }

            // Network discovery (netstat, ss, lsof)
          const netDiscovery = commandsExecuted.filter(c => {
              const normalized = c.toLowerCase();
              return normalized.includes('netstat') ||
                  normalized.includes('ss ') ||
                  normalized.includes('lsof') ||
                  normalized.includes('ip route') ||
                  normalized.includes('arp');
          });
            if (netDiscovery.length > 0) {
                activityScore += 3;
                explanations.push({ score: 3, reason: `Network topology discovery: ${netDiscovery[0]}`, dimension: 'Activity', mitre: 'T1049' });
                mitreHits.push('T1049');
            }
        }

        activityScore = Math.min(25, activityScore);

        // ─── Dimension 3: Weaponization (0–25) ──────────────────
        let weaponScore = 0;

        if (downloadHits.length > 0 || fileDownloads.length > 0) {
            const dlScore = Math.min(12, (downloadHits.length + fileDownloads.length) * 6);
            weaponScore += dlScore;
            const allDownloads = [...downloadHits, ...fileDownloads.map(f => f.url)];
            explanations.push({ score: dlScore, reason: `Remote payload download: ${allDownloads[0]}`, dimension: 'Weaponization', mitre: 'T1105' });
            alerts.push({ severity: 'HIGH', title: 'Ingress Tool Transfer', reason: `External file downloaded: ${allDownloads[0]}`, mitre: 'T1105' });
            mitreHits.push('T1105');
        }

        if (executionHits.length > 0) {
            const exeScore = Math.min(15, executionHits.length * 8);
            weaponScore += exeScore;
            explanations.push({ score: exeScore, reason: `Payload execution detected: ${executionHits[0]}`, dimension: 'Weaponization', mitre: 'T1204' });
            alerts.push({ severity: 'CRITICAL', title: 'Malicious Payload Execution', reason: `Binary or script executed: ${executionHits[0]}`, mitre: 'T1204' });
            mitreHits.push('T1204');
        }

        // Download-then-Execute chain: require the first download indicator to
        // appear before the first execution indicator in the observed command order.
        const firstDownloadIndex = commandsExecuted.findIndex(command =>
            downloadHits.includes(command)
        );
        const firstExecutionIndex = commandsExecuted.findIndex(command =>
            executionHits.includes(command)
        );
        const downloadThenExecute = firstDownloadIndex !== -1 &&
            firstExecutionIndex !== -1 &&
            firstDownloadIndex < firstExecutionIndex;

        if (downloadThenExecute) {
            weaponScore += 5;
            explanations.push({
                score: 5,
                reason: 'Attack chain detected: Download → Execute sequence (staged payload delivery)',
                dimension: 'Weaponization',
                mitre: 'T1105'
            });
            mitreHits.push('T1105');
        }

        // Cryptominer detection
        if (cryptominerHits.length > 0) {
            weaponScore += 8;
            explanations.push({ score: 8, reason: `Cryptominer deployment: ${cryptominerHits[0]}`, dimension: 'Weaponization', mitre: 'T1496' });
            alerts.push({ severity: 'CRITICAL', title: 'Cryptominer Deployment', reason: `Cryptocurrency mining software detected: ${cryptominerHits[0]}`, mitre: 'T1496' });
            mitreHits.push('T1496');
        }

        weaponScore = Math.min(25, weaponScore);

        // ─── Dimension 4: Intent & Persistence (0–25) ───────────
        let intentScore = 0;

        if (evasionHits.length > 0) {
            const evaScore = Math.min(12, evasionHits.length * 6);
            intentScore += evaScore;
            explanations.push({ score: evaScore, reason: `Anti-forensics / log evasion: ${evasionHits[0]}`, dimension: 'Intent', mitre: 'T1070' });
            alerts.push({ severity: 'HIGH', title: 'Evidence Destruction Attempt', reason: `Anti-forensic command: ${evasionHits[0]}`, mitre: 'T1070' });
            mitreHits.push('T1070');
        }

        if (lateralHits.length > 0) {
            const latScore = Math.min(15, lateralHits.length * 7);
            intentScore += latScore;

            // Distinguish account creation vs lateral movement
            const accountCreation = lateralHits.filter(c => {
                const normalized = c.toLowerCase();
                return normalized.includes('useradd') || normalized.includes('adduser') || normalized.includes('passwd');
            });
            const pivotAttempts = lateralHits.filter(c => {
                const normalized = c.toLowerCase();
                return normalized.includes('ssh ') || normalized.includes('pty.spawn') ||
                    normalized.includes('nc ') || normalized.includes('python');
            });
            const persistence = lateralHits.filter(c => {
                const normalized = c.toLowerCase();
                return normalized.includes('crontab') || normalized.includes('at ');
            });

            if (accountCreation.length > 0) {
                explanations.push({ score: 7, reason: `Backdoor account creation: ${accountCreation[0]}`, dimension: 'Intent', mitre: 'T1136' });
                alerts.push({ severity: 'CRITICAL', title: 'Backdoor Account Created', reason: `New user account created for persistence: ${accountCreation[0]}`, mitre: 'T1136' });
                mitreHits.push('T1136');
            }
            if (pivotAttempts.length > 0) {
                explanations.push({ score: 7, reason: `Lateral movement / pivot attempt: ${pivotAttempts[0]}`, dimension: 'Intent', mitre: 'T1021' });
                alerts.push({ severity: 'HIGH', title: 'Lateral Movement Detected', reason: `Pivot attempt to adjacent system: ${pivotAttempts[0]}`, mitre: 'T1021' });
                mitreHits.push('T1021');
            }
            if (persistence.length > 0) {
                explanations.push({ score: 5, reason: `Scheduled persistence mechanism: ${persistence[0]}`, dimension: 'Intent', mitre: 'T1053' });
                mitreHits.push('T1053');
            }
        }

        // Session velocity — very fast automated sessions suggest tooling
        const durationSec = sessionDurationMs / 1000;
        if (commandsExecuted.length > 4 && durationSec < 10) {
            intentScore += 5;
            explanations.push({ score: 5, reason: `High-velocity automated session: ${commandsExecuted.length} commands in ${durationSec.toFixed(1)}s (scripted attack)`, dimension: 'Intent', mitre: null });
        }

        // Long-duration persistent session (more than 5 minutes with many commands)
        if (durationSec > 300 && commandsExecuted.length > 8) {
            intentScore += 4;
            explanations.push({ score: 4, reason: `Extended interactive session: ${Math.floor(durationSec / 60)} minutes with ${commandsExecuted.length} commands (hands-on-keyboard adversary)`, dimension: 'Intent', mitre: null });
        }

        intentScore = Math.min(25, intentScore);

        // ── Phase 3: Composite Score ────────────────────────────
        const threatScore = Math.min(100, accessScore + activityScore + weaponScore + intentScore);

        // ── Phase 4: Risk Level Classification ──────────────────
        let riskLevel;
        if (threatScore < 20)      riskLevel = 'LOW';
        else if (threatScore < 50) riskLevel = 'MEDIUM';
        else if (threatScore < 75) riskLevel = 'HIGH';
        else                       riskLevel = 'CRITICAL';

        // ── Phase 5: Deduplicate MITRE hits ─────────────────────
        const uniqueMitre = [...new Set(mitreHits)].map(id => ({
            id,
            ...this.mitreTactics[id]
        }));

        return {
            threatScore,
            riskLevel,
            alerts,
            explanations,
            dimensions: {
                access: accessScore,
                activity: activityScore,
                weaponization: weaponScore,
                intent: intentScore
            },
            mitre: uniqueMitre,
            summary: {
                failedLogins,
                successfulLogin,
                loginUsername: loginUsername || null,
                sshClient: sshClient || null,
                commandCount: commandsExecuted.length,
                reconCount: reconHits.length,
                credentialAccessCount: credentialHits.length,
                downloadCount: downloadHits.length + fileDownloads.length,
                executionCount: executionHits.length,
                evasionCount: evasionHits.length,
                lateralCount: lateralHits.length,
                cryptominerCount: cryptominerHits.length,
                durationSeconds: Math.round(durationSec)
            }
        };
    }
}

module.exports = new CorrelationEngine();
