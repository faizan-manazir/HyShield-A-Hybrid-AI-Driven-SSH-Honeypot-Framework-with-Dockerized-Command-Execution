# HyShield — Complete Project Documentation

> End-to-end guide to the Cowrie-based SSH honeypot, Docker command-processing bridge, output sanitizer, optional AI refinement, and Python SIEM dashboard. This documents the checked-in implementation and calls out limitations that should be addressed before deployment.

## 1. Overview

HyShield is a research and educational SSH honeypot framework built around Cowrie. It combines:
1. SSH deception and session recording through Cowrie.
2. A modified Cowrie backend that forwards selected command input to a local TCP bridge.
3. Command execution inside a Docker container named `fake-ubuntu`.
4. Output sanitization to reduce obvious environment fingerprints.
5. Optional AI-assisted output refinement for selected commands using Groq.
6. Cowrie JSON-lines/text telemetry.
7. A Python SIEM that ingests logs, correlates sessions, scores behavior, raises alerts, maps selected behavior to MITRE ATT&CK, and provides analyst views.

**Important:** This is a honeypot/research prototype, not a production endpoint-detection agent. An alert means configured rules matched observed honeypot activity; it does not prove a separate production system was compromised.

## 2. Goals and limitations

### Goals
- Observe SSH authentication and interactive command activity.
- Keep command execution inside a container rather than directly on the host.
- Return plausible terminal output to sustain honeypot interaction.
- Record activity for later analysis.
- Provide a dashboard for alert triage, event search, actor review, session inspection, and approximate geographic visualization.
- Support local demonstrations with synthetic Cowrie-shaped events.

### Limitations
- IP geolocation does not establish an attacker's identity or precise physical location.
- Container isolation depends on runtime configuration and host security.
- Rule-based detections can produce false positives and false negatives.
- AI refinement is not a detection engine and must not be treated as evidence.
- The app should not be exposed directly to the public Internet without authentication, network restrictions, hardening, and a separate security review.

## 3. Architecture

```text
Remote SSH client
      |
      v
Cowrie SSH honeypot
      | authentication/session logging
      | modified command backend (llm.py)
      v
Local TCP bridge (bridge_server.py, 127.0.0.1:5050)
      |
      +--> DockerExecutor --> fake-ubuntu container
      +--> sanitize_output()
      +--> refine_output() for configured trigger commands
      |
      v
Terminal output returned through Cowrie

Cowrie JSON log (cowrie.json)
      |
      v
Python SIEM Ingestor
      |
      v
SQLite: raw events, sessions, alerts, checkpoints, cache
      |
      v
Correlation / scoring / MITRE mapping / query layer
      |
      v
FastAPI + Jinja pages + JSON API + SVG charts
      |
      v
Analyst browser
```

The command-response path and SIEM ingestion path are related but distinct. The bridge handles interactive responses; the SIEM reads Cowrie's JSON log for detection and investigation.

## 4. Repository layout

| Path | Role |
|---|---|
| `README.md` | Main project introduction, architecture, features, startup overview. |
| `requirements.txt` | Top-level Groq Python dependency. |
| `start.sh` | Lab startup script; contains machine-specific absolute paths and should be adapted. |
| `update_password.py` | Chooses a demonstration password and writes a Cowrie user database entry. |
| `bridge_server.py` | Local TCP listener coordinating executor, sanitizer, and optional AI refiner. |
| `docker_executor.py` | Runs commands in `fake-ubuntu`; tracks working directory/history. |
| `sanitizer.py` | Replaces selected environment strings and adjusts some command output. |
| `ai_refiner.py` | Calls the Groq API for configured trigger commands. |
| `state.py` | Shell-state helper for directory, history, and environment values. Verify its use in the current execution path. |
| `cowrie-modifications/cowrie.cfg` | Cowrie example configuration for SSH, backend, logging, and shell metadata. |
| `cowrie-modifications/src/cowrie/llm/llm.py` | Modified Cowrie command backend; inspect its current protocol/fallback behavior before changing the bridge. |
| `python-siem/` | Standalone Python SIEM, ingestion, correlation, database, dashboard, tools, and tests. |
| `python-siem/docs/PROJECT_DOCUMENTATION.md` | Detailed subsystem documentation for the Python SIEM. |

## 5. Honeypot components

### 5.1 Cowrie
Cowrie provides the SSH honeypot interface and records session events. The checked-in config sets SSH to port **2222**, uses the LLM backend, enables SFTP, and enables JSON and text logs; Telnet is disabled. Confirm the active configuration and firewall rules on the actual host.

### 5.2 Modified Cowrie backend
The modified `llm.py` is the integration point that forwards command input to the bridge. The precise message framing, timeout, and fallback behavior depend on the checked-in implementation. If changing the bridge protocol, update both sides and test multi-command sessions.

### 5.3 TCP bridge — `bridge_server.py`
The current bridge:
- Binds to `127.0.0.1:5050`.
- Starts a handler thread for each accepted TCP connection.
- Reads up to 4096 bytes and treats the decoded content as one command.
- Creates/reuses a `DockerExecutor` object in a session dictionary.
- Executes the command, sanitizes output, conditionally calls AI refinement, and sends the result.
- Uses a socket timeout and a background cleanup thread.

**Implementation caveats:** the session key is derived from `addr[0]` (peer IP), although a comment says it is keyed by port. Multiple connections from one peer IP can share state unexpectedly. The cleanup task clears the whole session dictionary when its size exceeds 100 rather than expiring individual inactive sessions.

### 5.4 Docker executor — `docker_executor.py`
The executor invokes Docker at `/usr/bin/docker` and targets `fake-ubuntu`. It tracks a current directory, history, and terminal width. Special handlers exist for `cd`, `history`, and `ls`; other commands are invoked through `docker exec` and a shell with a timeout. A list of command substrings is blocked.

**Security caveat:** a substring blocklist is not a complete sandbox. Shell syntax, quoting, chaining, and unexpected inputs can bypass naive filters. Container isolation, least privilege, resource limits, filesystem restrictions, network policy, and host hardening are the real safety boundaries. Do not mount sensitive host paths or the host Docker socket into the honeypot container.

### 5.5 Sanitizer — `sanitizer.py`
The sanitizer replaces selected container/terminal strings, substitutes a static process listing for some `ps`-like output, and compacts certain multiline output. It is a realism/presentation layer, not a forensic transformation. Preserve original Cowrie logs separately.

### 5.6 AI refiner — `ai_refiner.py` and Cowrie config
The Python refiner checks commands against a trigger list including system identity/version commands such as `uname`, `hostnamectl`, `neofetch`, `screenfetch`, and `/proc/version`. Matching commands send the command and sanitized output to a Groq-hosted model with instructions to return terminal output only. Non-trigger commands bypass this call.

The Cowrie config also has its own LLM configuration; confirm which component handles a request in your deployment rather than assuming the settings are interchangeable.

**Secrets:** never commit API keys. The checked-in Python refiner currently constructs a Groq client with an empty key, and the sample Cowrie config has an empty API key field. Configure credentials through environment variables or a secret manager, not committed source. Test API outage, rate-limit, and malformed-response behavior.

### 5.7 Password helper — `update_password.py`
The script selects from a hard-coded list of common passwords and writes a root user entry to a machine-specific Cowrie path. The current startup script also extracts and prints the active password. This is demonstration behavior, not secure password management. Never reuse these credentials outside an isolated honeypot or expose them in logs/shared terminals.

### 5.8 Startup script — `start.sh`
The script sets a fixed `PYTHONPATH`, calls scripts using absolute `/home/faizan/cowrie` paths, writes/prints the active password, activates a fixed virtual environment, and starts Cowrie, Docker, and the bridge.

**Operational caveat:** in the checked-in text, the foreground `twistd -n cowrie` command appears before `docker start fake-ubuntu` and `python3 bridge_server.py`. A foreground process may prevent later commands from running until Cowrie exits. Validate and correct process ordering for your host rather than assuming this script starts every component.

## 6. End-to-end event flows

### Interactive command
1. SSH client connects to Cowrie.
2. Cowrie records authentication and session behavior.
3. Modified backend forwards command input to the bridge.
4. Bridge obtains an executor for the connection.
5. Executor handles special commands or invokes the command in the container.
6. Output passes through sanitization.
7. Matching commands may be passed to the AI refiner if configured.
8. Bridge returns output through Cowrie.
9. Cowrie presents the response and records telemetry.

### SIEM event
1. Cowrie appends JSON records to `cowrie.json`.
2. SIEM ingestor polls the file and reads complete newline-terminated records.
3. A checkpoint records progress so ingestion can resume after restart.
4. Events are stored in SQLite and grouped into sessions.
5. Correlation evaluates behavior, calculates score/risk, and generates alerts.
6. Query functions aggregate metrics, alerts, events, actors, sessions, and geographic data.
7. FastAPI renders pages and JSON responses.
8. Analyst reviews an alert and inspects associated session evidence.

## SIEM accounts and roles

The Python SIEM requires a user account before protected routes are available. On a new database, create the initial Super Admin at `/setup`, then sign in at `/login`. The setup route is disabled once a user exists.

- **Super Admin:** full SIEM access, settings and account management, destructive actions, and audit logs.
- **Security Analyst:** read/investigate telemetry, close alerts, and use the test-event generator; no user management, settings, or purge.
- **Read-Only Auditor:** read-only dashboard and investigation access plus administrative audit-log viewing.

Passwords are stored as scrypt hashes. Signed HttpOnly session cookies expire after eight hours. Keep `python-siem/data/auth_secret` private and persistent, or configure `HYSHIELD_AUTH_SECRET`. Authorization is checked on the backend, not only by hiding navigation links. Audit/authentication events are stored in SQLite and available at `/audit-logs` to Super Admins and Auditors.

## 7. Python SIEM components

| Path | Responsibility |
|---|---|
| `python-siem/run.py` | Starts Uvicorn. |
| `python-siem/app/main.py` | App lifecycle, middleware, pages, API routes. |
| `python-siem/app/config.py` | Environment-based paths and settings. |
| `python-siem/app/db.py` | SQLite schema and helpers. |
| `python-siem/app/ingest.py` | Background JSON-lines ingestion and checkpoints. |
| `python-siem/app/correlation.py` | Rule-based session scoring and MITRE mapping. |
| `python-siem/app/queries.py` | Shared SQL queries. |
| `python-siem/app/geo.py` | IP classification, asynchronous geolocation, caching. |
| `python-siem/app/charts.py` | SVG charts and threat map. |
| `python-siem/app/settings.py` | Persistent settings and safe public settings view. |
| `python-siem/app/test_generator.py` | Synthetic Cowrie event generator. |
| `python-siem/app/templates/` | Jinja templates. |
| `python-siem/app/static/` | JavaScript, CSS, and map assets. |
| `python-siem/tools/` | CLI simulation utilities. |

See [Python SIEM detailed documentation](../python-siem/docs/PROJECT_DOCUMENTATION.md) for subsystem-level detail.

### Current SIEM behavior notes

- The refreshable dashboard pages poll every **5 seconds**; Event Explorer does so when Auto-refresh is enabled. This is browser polling, not a guarantee of end-to-end ingestion latency.
- Event Explorer applies its search and category filters in SQL before applying the result limit, avoiding missed older matches caused by filtering only a limited recent-event subset.
- Session timestamp upserts preserve an existing non-null start/end time when an incoming Cowrie record omits that timestamp.
- To validate the Python SIEM after changes, run `python -m pytest -q` from `python-siem/` and review the actual test output.

## 8. Dashboard routes

| Route | Purpose |
|---|---|
| `/` | Overview KPIs, Investigation Priorities, attack map, distribution, status, recent alerts, top actors. |
| `/live` | Recent Cowrie events. |
| `/geomap` | Interactive source map and location details. |
| `/mitre` | Observed MITRE ATT&CK summaries. |
| `/alerts` | Alert queue, severity filter, resolve/close actions. |
| `/explorer` | Search/filter telemetry. |
| `/actors` | Source IP summaries. |
| `/sessions` | Session list. |
| `/sessions/{id}` | Session evidence and score explanation. |
| `/settings` | Local settings. |
| `/generator` | Synthetic event generator. |
| `/docs` | FastAPI interactive API documentation. |

### Investigation Priorities vs Recent Alerts
- **Investigation Priorities** ranks open alerts CRITICAL → HIGH → MEDIUM → LOW, then newest timestamp within severity. It sorts before applying the five-alert limit.
- **Recent Alerts** remains chronological, emphasizing newest activity.
- Severity is a triage aid. Validate the detection against source events, commands, and session timeline.

## 9. Scoring and ATT&CK mapping

The SIEM correlation logic evaluates event types and command patterns including authentication attempts, reconnaissance, credential-file access, downloads, execution, evasion, lateral movement, and miner-related behavior. Selected behaviors map to technique IDs defined in the correlation code.

Current Python SIEM score thresholds:

| Score | Risk |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

These are heuristic rules and must be evaluated against representative telemetry. An ATT&CK mapping is a behavioral association, not attribution or proof of compromise.

## 10. Logs, database, and evidence

- **Cowrie JSON log:** configured in Cowrie; SIEM defaults to `python-siem/data/cowrie.json` unless `COWRIE_LOG_PATH` is set.
- **Cowrie text audit log:** configured in Cowrie config.
- **SQLite database:** stored in SIEM data directory unless overridden.
- **Settings and geolocation cache:** stored in SIEM data files/database.

For forensic use, preserve original logs read-only, record acquisition times and cryptographic hashes, restrict access, document transformations, and keep synthetic data separate. Sanitized output and normalized SIEM rows do not replace original evidence.

## 11. Installation and deployment

### Full honeypot prerequisites
Plan for an isolated Linux host/VM, compatible Cowrie installation, Docker Engine and the configured `fake-ubuntu` container, correct log output, lab firewall rules, and optional Groq credentials. The current repository startup script is host-specific and is not a portable installer.

### Verify Docker
Adapt these commands to the lab host:
```bash
docker ps -a
docker inspect fake-ubuntu
docker start fake-ubuntu
docker exec fake-ubuntu bash -lc 'pwd && id'
```
Review user, capabilities, mounts, network, resource limits, restart policy, and logs. Avoid privileged mode and host Docker socket mounts.

### Configure Cowrie
1. Install Cowrie using the official documentation for the chosen version.
2. Back up the original backend before applying the modified `llm.py`.
3. Review `cowrie-modifications/cowrie.cfg`; do not blindly overwrite a version-specific configuration.
4. Confirm listener port and bridge protocol.
5. Confirm JSON output path matches SIEM `COWRIE_LOG_PATH`.
6. Keep the bridge reachable only by the intended Cowrie process.
7. Test locally with harmless commands before external access.

### Start the bridge
From the project directory and intended Python environment:
```bash
python3 bridge_server.py
```
It binds to `127.0.0.1:5050`. Confirm the port is free and the console reports listening.

### Start Python SIEM
Linux/macOS:
```bash
cd python-siem
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```
Windows PowerShell:
```powershell
cd python-siem
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```
Default UI: `http://127.0.0.1:8000`; API explorer: `http://127.0.0.1:8000/docs`.

For a lab/Codespaces preview:
```bash
HOST=0.0.0.0 PORT=8000 DEMO_MODE=true python run.py
```
Binding to all interfaces can expose the service through the environment. Do so only when necessary and with appropriate access controls.

## 12. Configuration reference

### Honeypot and bridge

| Setting | Current value/meaning |
|---|---|
| Bridge host/port | `127.0.0.1:5050` in `bridge_server.py`. |
| Docker container | `fake-ubuntu`. |
| Docker CLI | `/usr/bin/docker`. |
| Cowrie SSH listener | `2222` in checked-in config. |
| Cowrie JSON/text logs | `cowrie.json` and `audit.log` under configured Cowrie log path. |
| Groq API | Used by `ai_refiner.py` for trigger commands; credentials must be configured securely. |
| Startup paths | `start.sh` and `update_password.py` use fixed `/home/faizan/cowrie` paths. |

### SIEM environment variables

| Variable | Default/meaning |
|---|---|
| `COWRIE_LOG_PATH` | JSON-lines input; defaults to `python-siem/data/cowrie.json`. |
| `HYSHIELD_DATA` | SIEM data directory. |
| `HYSHIELD_DB` | Optional explicit SQLite database path. |
| `HOST` | `127.0.0.1`. |
| `PORT` | `8000`. |
| `POLL_SECONDS` | `2` seconds between ingestion polls. |
| `DEMO_MODE` | Off by default; synthetic locations for private/loopback IPs in demo maps. |
| `HYSHIELD_GEO` | Enabled unless set to `off`; public lookups use ipwho.is over HTTPS. |
| `HONEYPOT_NAME` | Map sensor label. |
| `HONEYPOT_LAT`, `HONEYPOT_LNG` | Map sensor coordinates (default Islamabad coordinates). |
| `HONEYPOT_CITY`, `HONEYPOT_COUNTRY` | Map sensor labels (default Islamabad/Pakistan). |
| `ANALYST_LAN_IP` | Optional lab/analyst IP displayed specially on the map. |

## 13. Synthetic data and demo mode

The local event generator writes Cowrie-shaped JSON lines using documentation TEST-NET addresses; it does not send network traffic. Generated events pass through normal ingestion and correlation, changing metrics, sessions, alerts, and maps.

- Use a separate test log/database for demonstrations.
- Do not mix synthetic events with real investigation evidence.
- Private IP demo locations are synthetic and must not be presented as attribution.
- Clearly label synthetic screenshots and presentation data.

## 14. Security and privacy checklist

Before deployment beyond a local lab:
- [ ] Restrict SSH access to the intended lab network and monitor the host.
- [ ] Keep the bridge on loopback or a tightly controlled private network.
- [ ] Run Docker least-privileged; no privileged container or sensitive host mounts.
- [ ] Set CPU, memory, process, storage, and execution-time limits.
- [ ] Do not rely on the command blocklist as the primary security boundary.
- [ ] Keep API keys and active passwords out of source control, logs, and screenshots.
- [ ] Replace hard-coded host paths with configuration.
- [ ] Add authentication/authorization before remote SIEM access; the SIEM README notes that no login is currently provided.
- [ ] Use an authenticated VPN/reverse proxy for remote access.
- [ ] Restrict database/log permissions and define retention/backups.
- [ ] Disable external geolocation if data transfer is not approved.
- [ ] Preserve original logs and keep synthetic telemetry separate.
- [ ] Test Docker, malformed log, network, and AI API failure cases.
- [ ] Review dependencies and patch Cowrie, Docker, and the host OS.
- [ ] Complete a threat model and independent security review before public exposure.

## 15. Troubleshooting

**Bridge cannot bind to port 5050**
- Check whether the port is in use.
- Confirm bridge and modified Cowrie backend use the same address/protocol.
- Start the bridge before Cowrie needs it.

**Docker execution fails**
- Confirm `fake-ubuntu` exists and is running.
- Confirm `/usr/bin/docker` exists or update the configured path.
- Inspect Docker stderr and container logs.

**AI refinement fails**
- Configure Groq credentials securely.
- Check API availability, model name, rate limits, and network access.
- Verify non-trigger commands still work when AI is unavailable.
- Avoid sending sensitive data to external AI services.

**Cowrie events do not appear**
- Confirm JSON logging is enabled and find the actual resolved log path.
- Check file permissions and Cowrie logs.
- Set `COWRIE_LOG_PATH` to the exact JSON-lines file.

**SIEM shows no events**
- Confirm each line is valid JSON and newline-terminated.
- Check the ingestor logs and data-directory permissions.

**Map has no markers**
- Public lookup may be pending or unavailable.
- Private addresses have no real public geolocation.
- Demo locations are synthetic; set `HYSHIELD_GEO=off` to disable external lookups.

**Startup script starts only part of the system**
- Review fixed paths and foreground/background ordering.
- Start components individually while debugging and then use a corrected process supervisor.

**UI changes are not visible**
- Pull the intended branch.
- Restart the app for Python changes.
- Hard-refresh with Ctrl+Shift+R for static asset changes.

## 16. Testing and acceptance checklist

These are instructions, not a claim that tests have passed.

### Honeypot checks
- [ ] Container exists and harmless command execution succeeds.
- [ ] Bridge starts on the expected address/port.
- [ ] Test command returns a response.
- [ ] Sanitizer behavior is reviewed against representative outputs.
- [ ] AI triggers work with configured credentials and fail safely on API errors.
- [ ] Cowrie accepts a test SSH session and emits expected JSON events.

### SIEM checks
From `python-siem/`:
```bash
python -m pytest
```
Then verify:
- [ ] App starts and Overview renders.
- [ ] New records ingest once and restart/truncation behavior is tested.
- [ ] Session scores and alert reasons trace back to source evidence.
- [ ] Investigation Priorities sorts severity before recency.
- [ ] Recent Alerts stays chronological.
- [ ] Explorer, actor, session, MITRE, and map pages render.
- [ ] Synthetic data is kept separate from real evidence.
- [ ] Remote access is blocked or authenticated as intended.

## 17. Development workflow

For the current changes:
```bash
git switch fix/siem-audit-findings
git pull origin fix/siem-audit-findings
```

Recommended process:
1. Make focused changes.
2. Update tests and documentation.
3. Run automated tests and record actual results.
4. Manually verify affected pages and log ingestion.
5. Review diffs for secrets, absolute paths, and accidental files.
6. Commit to the feature branch and review the PR before merging.

## 18. Glossary

- **Cowrie:** SSH/Telnet honeypot that records session behavior.
- **Honeypot:** decoy service used to observe activity.
- **Bridge:** local TCP service connecting Cowrie to the command pipeline.
- **Docker executor:** component running commands inside the configured container.
- **Sanitizer:** output transformation layer for environment fingerprints.
- **AI refiner:** optional LLM call for selected output.
- **JSON Lines:** one JSON object per line.
- **SIEM:** system for collecting, correlating, searching, and presenting telemetry.
- **Correlation:** grouping/interpreting events to identify patterns.
- **Risk score:** heuristic estimate used for triage.
- **MITRE ATT&CK:** knowledge base of adversary tactics and techniques.
- **TEST-NET:** IP ranges reserved for documentation/examples.
- **Chain of custody:** documented evidence handling from collection through analysis.

## 19. References

- [Main README](../README.md)
- [Python SIEM README](../python-siem/README.md)
- [Python SIEM detailed documentation](../python-siem/docs/PROJECT_DOCUMENTATION.md)
- [Cowrie](https://github.com/cowrie/cowrie)
- [Docker documentation](https://docs.docker.com/)
- [FastAPI documentation](https://fastapi.tiangolo.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
