"""
Threat scoring engine (Python port of the original correlation.js).

Every session gets 4 scores, each 0-25, added up to a 0-100 Threat Score:

    Access        - login attempts and results
    Activity      - recon commands, reading password files
    Weaponization - downloads, running payloads, crypto miners
    Intent        - hiding tracks, creating accounts, moving sideways

Risk level:  0-19 LOW | 20-39 MEDIUM | 40-69 HIGH | 70-100 CRITICAL
"""
import re
from datetime import datetime, timezone

# ---- Word lists: what counts as "recon", "download", etc. ------------------
RECON = ["whoami", "id", "uname", "hostname", "netstat", "ps", "df", "uptime",
         "ifconfig", "ip addr", "ip route", "route", "w", "last",
         "cat /etc/issue", "cat /etc/os-release", "lscpu", "cat /proc/cpuinfo",
         "cat /proc/meminfo", "lsof", "ss", "arp", "nmap", "cat /etc/hostname"]
CREDENTIAL_FILES = ["/etc/shadow", "/etc/passwd", "/etc/sudoers",
                    ".ssh/authorized_keys", ".ssh/id_rsa", ".bash_history",
                    "/root/.ssh", ".pgpass", ".my.cnf", "/etc/krb5.conf"]
DOWNLOAD_TOOLS = ["wget", "curl", "ftp", "scp", "tftp", "git clone"]
EXECUTION = ["./", "sh ", "bash ", "python ", "python3 ", "perl ", "ruby ",
             "nohup ", "| bash", "| sh"]
EVASION = ["history -c", "unset HISTFILE", "rm -rf /var/log", "rm -f /var/log",
           'echo "" >', "kill -9", "pkill", "iptables -F", "setenforce 0",
           "systemctl stop"]
LATERAL = ["ssh ", "sshpass", "nc ", "ncat", "socat", "python3 -c", "python -c",
           "pty.spawn", "useradd", "adduser", "usermod", "crontab", "at "]
CRYPTOMINER = ["xmrig", "stratum+tcp", "minerd", "cpuminer", "ethminer",
               "nbminer", "pool.", "minergate"]
SUSPICIOUS_CLIENTS = ["mirai", "hydra", "libssh", "asyncssh", "paramiko", "ssh-2.0-go"]

# MITRE ATT&CK technique id -> (name, tactic)
MITRE = {
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1049": ("System Network Connections", "Discovery"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1204": ("User Execution", "Execution"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1136": ("Create Account", "Persistence"),
    "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1496": ("Resource Hijacking", "Impact"),
}


def _compile(words):
    # whole-word match, so "id" does not match inside "cd" and "w" not inside "shadow"
    return [re.compile(r"(^|\b|\s)" + re.escape(w) + r"(\b|\s|$)", re.I) for w in words]


_RECON = _compile(RECON)
_CRED = _compile(CREDENTIAL_FILES)
_DOWNLOAD = _compile(DOWNLOAD_TOOLS)
_EXEC = _compile(EXECUTION)
_EVASION = _compile(EVASION)
_LATERAL = _compile(LATERAL)
_MINER = _compile(CRYPTOMINER)
_CRON_ECHO = re.compile(r"echo.*>>.*cron", re.I)
# Creating/changing an account. Matches the COMMAND "passwd bob" but not the FILE in "cat /etc/passwd".
_ACCOUNT_CMD = re.compile(r"(^|[;&|]\s*)(sudo\s+)?(useradd|adduser|usermod|passwd)(\s|$)", re.I)


def _any(patterns, command):
    return any(p.search(command) for p in patterns)


def _unique(items):
    return list(dict.fromkeys(items))  # removes repeats, keeps order


def _parse_time(text):
    try:
        value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value
    except (ValueError, TypeError):
        return None


def risk_level(score):
    if score < 20:
        return "LOW"
    if score < 40:
        return "MEDIUM"
    if score < 70:
        return "HIGH"
    return "CRITICAL"


def evaluate_session(events):
    """Takes the list of Cowrie events of ONE session, returns the verdict."""
    # ---- Phase 1: read the events -------------------------------------
    failed_logins = 0
    logged_in = False
    username = ""
    ssh_client = ""
    commands = []
    recon, creds, downloads, execs, evasion, lateral, miners = [], [], [], [], [], [], []
    file_downloads = []

    duration = 0.0
    if len(events) > 1:
        first, last = _parse_time(events[0].get("timestamp")), _parse_time(events[-1].get("timestamp"))
        if first and last:
            duration = (last - first).total_seconds()

    for event in events:
        kind = event.get("eventid")
        if kind == "cowrie.client.version" and event.get("version"):
            ssh_client = event["version"]
        elif kind == "cowrie.login.failed":
            failed_logins += 1
        elif kind == "cowrie.login.success":
            logged_in = True
            username = event.get("username") or ""
        elif kind == "cowrie.command.input" and event.get("input"):
            cmd = str(event["input"])
            commands.append(cmd)
            if _any(_RECON, cmd):
                recon.append(cmd)
            if _any(_CRED, cmd):
                creds.append(cmd)
            if _any(_DOWNLOAD, cmd):
                downloads.append(cmd)
            if _any(_EXEC, cmd):
                execs.append(cmd)
            if _any(_EVASION, cmd):
                evasion.append(cmd)
            if _any(_LATERAL, cmd) or _CRON_ECHO.search(cmd) or _ACCOUNT_CMD.search(cmd):
                lateral.append(cmd)
            if _any(_MINER, cmd):
                miners.append(cmd)
        elif kind == "cowrie.session.file_download":
            file_downloads.append(event.get("url") or event.get("outfile") or "unknown")

    sequence = list(commands)          # keep order to spot "download then run"
    commands = _unique(commands)       # repeats must not inflate the score
    recon, creds, downloads = _unique(recon), _unique(creds), _unique(downloads)
    execs, evasion, lateral, miners = _unique(execs), _unique(evasion), _unique(lateral), _unique(miners)

    explanations, alerts, mitre_hits = [], [], []

    def explain(score, reason, dimension, mitre=None):
        explanations.append({"score": score, "reason": reason, "dimension": dimension, "mitre": mitre})
        if mitre:
            mitre_hits.append(mitre)

    def alert(severity, title, reason, mitre):
        alerts.append({"severity": severity, "title": title, "reason": reason, "mitre": mitre})

    # ---- Dimension 1: Access (0-25) ------------------------------------
    access = 0
    saw_connect = any(e.get("eventid") == "cowrie.session.connect" for e in events)
    if events and failed_logins == 0 and not logged_in and saw_connect:
        access = 2
        explain(2, "TCP connection established (port probe)", "Access")
    if 0 < failed_logins <= 3 and not logged_in:
        access = 5
        explain(5, f"{failed_logins} failed login attempt(s) - opportunistic credential guess", "Access", "T1110")
    if failed_logins > 3 and not logged_in:
        access = 12
        explain(12, f"{failed_logins} failed logins - dictionary / brute-force attack", "Access", "T1110")
        alert("HIGH", "SSH Brute Force Detected",
              f"{failed_logins} sequential failed password attempts from single source", "T1110")
    if logged_in and failed_logins == 0:
        access = 10
        explain(10, f"Successful authentication as '{username}' (first attempt - possible leaked credential)", "Access", "T1078")
        alert("MEDIUM", "Direct Credential Access",
              f"Immediate login success as '{username}' suggests pre-compromised or default credential", "T1078")
    if logged_in and failed_logins > 0:
        access = 18
        explain(18, f"Successful login as '{username}' after {failed_logins} failed attempts - credential compromised in honeypot", "Access", "T1078")
        alert("CRITICAL", "Honeypot Credential Compromise",
              f"Brute-force success: authenticated as '{username}' after {failed_logins} failed guesses in honeypot environment", "T1078")
    if username == "root" and logged_in:
        access = min(25, access + 5)
        explain(5, "Root-level access obtained (maximum privilege)", "Access", "T1078")
    if any(tool in ssh_client.lower() for tool in SUSPICIOUS_CLIENTS):
        access = min(25, access + 3)
        explain(3, f"Suspicious SSH client: {ssh_client} (commonly used by automated attack tools)", "Access")
    access = min(25, access)

    # ---- Dimension 2: Activity after login (0-25) ----------------------
    activity = 0
    if logged_in:
        if 0 < len(recon) <= 2:
            activity += 5
            explain(5, f"System reconnaissance: {len(recon)} discovery command(s) [{recon[0]}]", "Activity", "T1082")
        if len(recon) >= 3:
            activity += 12
            explain(12, f"Extensive system enumeration: {len(recon)} discovery commands (host profiling)", "Activity", "T1082")
            alert("MEDIUM", "Host Enumeration Detected",
                  f"{len(recon)} system discovery commands executed in sequence", "T1082")
        if creds:
            points = min(15, len(creds) * 8)
            activity += points
            explain(points, f"Credential file access: {', '.join(creds)}", "Activity", "T1003")
            alert("HIGH", "Credential Harvesting Attempt",
                  f"Accessed {len(creds)} sensitive credential file(s): {creds[0]}", "T1003")
        net = [c for c in commands if any(w in c.lower() for w in ("netstat", "ss ", "lsof", "ip route", "arp"))]
        if net:
            activity += 3
            explain(3, f"Network topology discovery: {net[0]}", "Activity", "T1049")
    activity = min(25, activity)

    # ---- Dimension 3: Weaponization (0-25) -----------------------------
    weapon = 0
    if downloads or file_downloads:
        points = min(12, (len(downloads) + len(file_downloads)) * 6)
        weapon += points
        first_download = (downloads + file_downloads)[0]
        explain(points, f"Remote payload download: {first_download}", "Weaponization", "T1105")
        alert("HIGH", "Ingress Tool Transfer", f"External file downloaded: {first_download}", "T1105")
    if execs:
        points = min(15, len(execs) * 8)
        weapon += points
        explain(points, f"Payload execution detected: {execs[0]}", "Weaponization", "T1204")
        alert("CRITICAL", "Malicious Payload Execution", f"Binary or script executed: {execs[0]}", "T1204")
    # a download command followed LATER by an execution command
    chain = any(cmd in downloads and any(later in execs for later in sequence[i + 1:])
                for i, cmd in enumerate(sequence))
    if chain:
        weapon += 5
        explain(5, "Attack chain detected: Download -> Execute sequence (staged payload delivery)", "Weaponization", "T1105")
    if miners:
        weapon += 8
        explain(8, f"Cryptominer deployment: {miners[0]}", "Weaponization", "T1496")
        alert("CRITICAL", "Cryptominer Deployment", f"Cryptocurrency mining software detected: {miners[0]}", "T1496")
    weapon = min(25, weapon)

    # ---- Dimension 4: Intent and persistence (0-25) --------------------
    intent = 0
    if evasion:
        points = min(12, len(evasion) * 6)
        intent += points
        explain(points, f"Anti-forensics / log evasion: {evasion[0]}", "Intent", "T1070")
        alert("HIGH", "Evidence Destruction Attempt", f"Anti-forensic command: {evasion[0]}", "T1070")
    if lateral:
        intent += min(15, len(lateral) * 7)
        low = [(c, c.lower()) for c in lateral]
        accounts = [c for c in lateral if _ACCOUNT_CMD.search(c)]
        pivots = [c for c, n in low if any(w in n for w in ("ssh ", "pty.spawn", "nc ", "python"))]
        persist = [c for c, n in low if "crontab" in n or re.search(r"\bat\s", n)]
        if accounts:
            explain(7, f"Backdoor account creation: {accounts[0]}", "Intent", "T1136")
            alert("CRITICAL", "Backdoor Account Created", f"New user account created for persistence: {accounts[0]}", "T1136")
        if pivots:
            explain(7, f"Lateral movement / pivot attempt: {pivots[0]}", "Intent", "T1021")
            alert("HIGH", "Lateral Movement Detected", f"Pivot attempt to adjacent system: {pivots[0]}", "T1021")
        if persist:
            explain(5, f"Scheduled persistence mechanism: {persist[0]}", "Intent", "T1053")
    if len(commands) > 4 and 0 <= duration < 10:
        intent += 5
        explain(5, f"High-velocity automated session: {len(commands)} commands in {duration:.1f}s (scripted attack)", "Intent")
    if duration > 300 and len(commands) > 8:
        intent += 4
        explain(4, f"Extended interactive session: {int(duration // 60)} minutes with {len(commands)} commands (hands-on-keyboard adversary)", "Intent")
    intent = min(25, intent)

    # ---- Final score ---------------------------------------------------
    score = min(100, access + activity + weapon + intent)
    # Critical aggregate risk requires corroborated high-impact behavior.
    # Event-level alert severity remains separate from the session-wide score.
    confirmed_chain = chain and logged_in
    confirmed_miner = bool(miners and logged_in)
    confirmed_persistence = bool(any(_ACCOUNT_CMD.search(c) for c in commands) and logged_in)
    if confirmed_chain or confirmed_miner or confirmed_persistence:
        score = max(score, 70)
    score = min(100, score)
    mitre = [{"id": t, "name": MITRE[t][0], "tactic": MITRE[t][1]} for t in _unique(mitre_hits)]
    return {
        "threatScore": score,
        "riskLevel": risk_level(score),
        "alerts": alerts,
        "explanations": explanations,
        "dimensions": {"access": access, "activity": activity,
                       "weaponization": weapon, "intent": intent},
        "mitre": mitre,
        "summary": {
            "failedLogins": failed_logins, "successfulLogin": logged_in,
            "loginUsername": username or None, "sshClient": ssh_client or None,
            "commandCount": len(commands), "reconCount": len(recon),
            "credentialAccessCount": len(creds),
            "downloadCount": len(downloads) + len(file_downloads),
            "executionCount": len(execs), "evasionCount": len(evasion),
            "lateralCount": len(lateral), "cryptominerCount": len(miners),
            "durationSeconds": round(duration),
        },
    }
