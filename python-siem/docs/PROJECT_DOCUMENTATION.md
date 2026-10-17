# HyShield Python SIEM — Project Documentation

This document covers the **Python SIEM in `python-siem/` only**. It describes the SIEM's architecture, installation, configuration, authentication, event ingestion, investigations, API, testing, and operational limitations. The parent HyShield SSH honeypot, Cowrie bridge, and Docker command-execution pipeline are separate components and are outside this document's scope.

> **Implementation is the source of truth.** Routes, schemas, settings, and behavior can change as the code evolves. Verify details against the current files and the running OpenAPI page at `/docs`.

## Contents

1. [Purpose and boundaries](#1-purpose-and-boundaries)
2. [Capabilities and limitations](#2-capabilities-and-limitations)
3. [Architecture and event flow](#3-architecture-and-event-flow)
4. [Project layout](#4-project-layout)
5. [Requirements](#5-requirements)
6. [Install and run](#6-install-and-run)
7. [Configuration reference](#7-configuration-reference)
8. [First-run setup and accounts](#8-first-run-setup-and-accounts)
9. [Roles and permissions](#9-roles-and-permissions)
10. [Dashboard and investigation workflow](#10-dashboard-and-investigation-workflow)
11. [Ingestion behavior](#11-ingestion-behavior)
12. [Database and evidence handling](#12-database-and-evidence-handling)
13. [Correlation, scoring, and ATT&CK](#13-correlation-scoring-and-attck)
14. [Geolocation and maps](#14-geolocation-and-maps)
15. [Settings and integrations](#15-settings-and-integrations)
16. [HTTP API](#16-http-api)
17. [Security and deployment](#17-security-and-deployment)
18. [Testing and validation](#18-testing-and-validation)
19. [Troubleshooting](#19-troubleshooting)
20. [Maintenance checklist](#20-maintenance-checklist)

## 1. Purpose and boundaries

The Python SIEM is HyShield's monitoring and investigation dashboard. It reads Cowrie JSON-lines telemetry, stores raw events and derived session/alert information in SQLite, calculates heuristic session risk, and serves an authenticated FastAPI web application.

It is intended for academic research, controlled honeypot monitoring, demonstrations, and defensive investigation. It is **not** a general-purpose endpoint detection agent. A score or alert describes activity observed by the honeypot and is not, by itself, proof that a separate production system was compromised.

## 2. Capabilities and limitations

### Main capabilities

- Incrementally read Cowrie JSON-lines logs.
- Persist raw events, sessions, alerts, ingestion checkpoints, audit logs, settings, and geolocation cache data.
- Correlate session activity into a heuristic score and risk band.
- Associate selected observed behaviors with MITRE ATT&CK technique identifiers.
- Provide overview metrics, alert triage, event search, actor summaries, session timelines, map visualizations, and settings.
- Export a standalone HTML snapshot of current findings.
- Expose JSON endpoints and FastAPI's OpenAPI interface.
- Run as a Python service with SQLite; no separate database server or JavaScript build step is required.

### Important limitations

- Risk scores are rule-based indicators, **not calibrated probabilities**.
- ATT&CK mappings describe behavior resemblance, not attribution.
- Public-IP geolocation is approximate and may indicate an ISP, VPN, proxy, cloud region, or intermediary rather than an operator's location.
- Malformed, incomplete, inaccessible, rotated, or incorrectly configured logs can affect ingestion. Test rotation behavior in the intended environment.
- A dashboard display is not a substitute for preserving and validating original log evidence.
- The presence of settings for an external integration does not prove that the integration is enabled, authorized, reachable, or functioning.
- Do not expose the dashboard directly to the public Internet without a separate deployment security review.

## 3. Architecture and event flow

```text
Cowrie JSON-lines log
        |
        v
app/ingest.py  -- poll, parse complete lines, checkpoint
        |
        v
app/db.py      -- SQLite events, sessions, alerts, checkpoints
        |
        v
app/correlation.py -- behavior rules, score, risk, ATT&CK mapping
        |
        v
app/queries.py -- aggregate data and investigation queries
        |
        +-------------------------+
        |                         |
        v                         v
app/main.py                 app/charts.py
FastAPI pages/API           SVG charts and map
        |                         |
        +------------+------------+
                     v
          Jinja templates + static JS/CSS
                     |
                     v
               Analyst browser
```

### Processing sequence

1. Cowrie appends JSON objects to its configured log file, one object per line.
2. The background ingestor polls the file and processes complete newline-terminated records.
3. Event records and ingestion progress are stored in SQLite. Session and alert data are derived from observed events.
4. The correlation logic evaluates configured indicators and produces a heuristic score, risk level, summary, and applicable alert/technique metadata.
5. Query functions provide data to dashboard pages and JSON endpoints.
6. FastAPI renders pages and API responses. Server-side code generates SVG visualizations; browser JavaScript handles interactions and periodic refreshes.
7. Analysts investigate alerts against the session timeline and original Cowrie records.

The SIEM reads telemetry; it is separate from the parent project's interactive SSH command-response bridge and Docker executor.

## 4. Project layout

Run commands from the `python-siem/` directory unless otherwise stated.

| Path | Responsibility |
|---|---|
| `run.py` | Starts Uvicorn using the configured host and port. |
| `app/main.py` | FastAPI lifecycle, middleware, authentication flow, page routes, JSON endpoints, and HTML report export. |
| `app/config.py` | Environment-based paths, bind settings, polling, and map/geolocation configuration. |
| `app/auth.py` | Account management, password verification, signed sessions, role checks, and audit logging. |
| `app/db.py` | SQLite connection helpers and database schema initialization. |
| `app/ingest.py` | Background JSON-lines ingestion and checkpoint handling. |
| `app/correlation.py` | Rule-based behavior scoring and selected ATT&CK mappings. |
| `app/queries.py` | Shared database queries and data aggregation. |
| `app/geo.py` | IP classification, geolocation lookups, and cache behavior. |
| `app/charts.py` | SVG charts and map rendering. |
| `app/settings.py` | Persistent settings, safe public settings projection, and raw configuration display. |
| `app/templates/` | Jinja HTML templates. |
| `app/static/app.js` | Browser interactions and background refresh behavior. |
| `app/static/style.css` | Dashboard styles and responsive layout. |
| `data/` | Default runtime location for the log, database, settings, and authentication secret; created as needed. |
| `tests/` | Automated tests. |
| `requirements.txt` | Runtime and test dependencies. |

## 5. Requirements

- Python 3.10 or newer (use a currently supported Python version compatible with the dependencies).
- Packages listed in `requirements.txt`.
- Read access to the Cowrie JSON-lines file.
- Write access to the configured SIEM data directory.
- A browser for the dashboard.
- Optional Internet access for public-IP geolocation or external integrations.

The SIEM uses SQLite from Python's standard library. It does not require Node.js/npm or a separate database service.

## 6. Install and run

### Linux or macOS

```bash
git clone https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution.git
cd HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/python-siem

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

### Windows PowerShell

```powershell
git clone https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution.git
Set-Location .\HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution\python-siem

py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

If PowerShell blocks virtual-environment activation, follow your organization's execution-policy guidance or invoke the environment's Python directly, for example `.\.venv\Scripts\python.exe run.py`.

### Open the application

The default bind address is localhost:

- Dashboard: `http://127.0.0.1:8000/`
- OpenAPI explorer: `http://127.0.0.1:8000/docs`
- OpenAPI schema: `http://127.0.0.1:8000/openapi.json`

On first run, the app initializes its SQLite schema and starts the background ingestor. The first browser visit should lead to the initial setup page if no account exists. Complete setup before using protected pages.

### Run in a development container or Codespaces

If a development environment requires port forwarding, start Uvicorn with an explicit bind address:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Binding to `0.0.0.0` makes the service listen on available network interfaces. Only do this in a controlled environment with appropriate network access restrictions; it is not a security control.

## 7. Configuration reference

Configuration is read in `app/config.py`. Environment variables must be set **before** starting the process.

| Variable | Default | Purpose |
|---|---|---|
| `COWRIE_LOG_PATH` | `python-siem/data/cowrie.json` | Cowrie JSON-lines input path. |
| `HYSHIELD_DATA` | `python-siem/data` | Runtime data directory. |
| `HYSHIELD_DB` | `<data directory>/hyshield.db` | Optional explicit SQLite database path. |
| `HOST` | `127.0.0.1` | Uvicorn bind address. |
| `PORT` | `8000` | Uvicorn port. |
| `POLL_SECONDS` | `2` | Ingestor polling interval in seconds. |
| `HYSHIELD_GEO` | `on` | Set to `off` to disable external geolocation lookups. |
| `HYSHIELD_COOKIE_SECURE` | `false` | Set to `true` when HTTPS terminates in front of the app so session cookies use the Secure attribute. |
| `HONEYPOT_NAME` | `HyShield Honeypot Sensor` | Sensor label shown on the map. |
| `HONEYPOT_LAT` | `33.6844` | Sensor latitude default. |
| `HONEYPOT_LNG` | `73.0479` | Sensor longitude default. |
| `HONEYPOT_CITY` | `Islamabad` | Sensor city label default. |
| `HONEYPOT_COUNTRY` | `Pakistan` | Sensor country label default. |
| `ANALYST_LAN_IP` | `192.168.100.11` | Optional lab IP treated specially in map logic. |

The active Cowrie path can also be configured in the Settings page. The application reads the saved path at startup and switches the ingestor when that setting is changed.

### Examples

Linux/macOS:

```bash
COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json python run.py
HYSHIELD_GEO=off python run.py
```

Windows PowerShell:

```powershell
$env:COWRIE_LOG_PATH = "C:\path\to\cowrie.json"
$env:HYSHIELD_GEO = "off"
python run.py
```

Do not set `HOST=0.0.0.0` or expose a forwarded port unless you understand who can reach the service and have implemented the required network and TLS controls.

## 8. First-run setup and accounts

1. Start the application.
2. Open `http://127.0.0.1:8000/`.
3. If no accounts exist, the app redirects to `/setup`.
4. Create the initial Super Admin account.
5. Sign in at `/login`; use the application's sign-out action when finished.

Once an account exists, the initial setup route redirects to login and cannot be used to create a second initial administrator. Additional accounts are managed by an authorized Super Admin.

Passwords are stored as salted scrypt hashes rather than plaintext. Session cookies are signed, HttpOnly, SameSite=Strict, and have an eight-hour maximum age. The signing secret is read from `HYSHIELD_AUTH_SECRET` or generated in the data directory as `auth_secret`. Protect this secret and keep it persistent across restarts; replacing it invalidates existing signed sessions. For multi-instance deployments, configure the same stable secret for each instance.

## 9. Roles and permissions

| Role | Intended permissions |
|---|---|
| `super_admin` | Full access, account management, supported settings changes, database purge, and administrative audit logs. |
| `analyst` | View investigation data and close alerts; no account management, settings changes, or purge. |
| `auditor` | Read-only investigation and audit-log access; cannot change alerts, settings, or accounts. |

Authorization is enforced by server-side middleware. Hiding a navigation item in the interface is not the security boundary. Authentication and administrative activity is recorded in the SQLite `audit_logs` table. Access to the audit-log view is restricted to authorized roles.

Failed sign-in attempts are throttled in the running application process. This in-process limit is not a substitute for shared rate limiting in a multi-worker or reverse-proxy deployment.

## 10. Dashboard and investigation workflow

Page routes and exact behavior are defined in `app/main.py` and the templates. Use the running application to confirm the available pages.

| Route | Purpose |
|---|---|
| `/` | Overview metrics, investigation priorities, recent alerts, activity summaries, and map/chart views. |
| `/login` | Sign-in page. |
| `/setup` | Initial administrator setup when no account exists. |
| `/live` | Live/recent event view, where enabled by the current build. |
| `/geomap` | Geographic visualization, where enabled by the current build. |
| `/mitre` | Summary of ATT&CK technique mappings. |
| `/alerts` | Alert queue and severity filtering. |
| `/explorer` | Event search and category filtering. |
| `/actors` | Source-IP activity summaries. |
| `/sessions` | Session list. |
| `/sessions/{session_id}` | Session detail and event evidence. |
| `/settings` | Supported settings and configuration display. |
| `/users` | User management for authorized administrators. |
| `/audit-logs` | Administrative/authentication audit history for authorized roles. |
| `/reports/export.html` | Download a standalone HTML report. |
| `/docs` | FastAPI OpenAPI explorer; protected by authentication. |

### Recommended analyst workflow

1. Start at Overview and inspect the highest-priority open alerts.
2. Open an alert and note its severity, timestamp, source, session, and reason.
3. Open the associated session and review the sequence of events and commands.
4. Search the relevant IP, session ID, or command in Event Explorer.
5. Use the ATT&CK view as a behavior reference, not as proof of attribution.
6. Treat map locations as approximate context only.
7. Preserve original Cowrie logs and document relevant timestamps before performing destructive actions.
8. Close an alert only according to the team's triage process and record the reason in the investigation notes.

### Investigation priorities versus recent alerts

Investigation Priorities and Recent Alerts serve different purposes. The priority queue ranks **open** alerts by severity (critical, high, medium, low), with newer session timestamps first within the same severity; the overview queue displays up to five items. Recent Alerts is intended to show recent activity chronologically. A high-severity alert should receive attention, but it remains a lead to investigate rather than a confirmed compromise verdict.

### Refresh and search

The refreshable dashboard pages poll at a five-second interval. Event Explorer uses that interval when Auto-refresh is enabled. This is browser polling, not a guarantee that each record will be visible within five seconds; ingestion, database writes, and rendering also affect latency.

Event Explorer applies category and text filters in the database query before limiting results. Results are still capped, so narrow the query when investigating large datasets.

## 11. Ingestion behavior

The ingestor in `app/ingest.py` runs in a background thread. It polls the configured JSON-lines file and stores progress in the SQLite checkpoint table.

Documented behavior includes:

- Reading newly appended bytes rather than re-reading the whole log on every poll.
- Waiting for a newline before processing a final partial record.
- Saving the file identity and byte offset as ingestion progress.
- Resetting the offset if the observed file becomes smaller than the saved offset.
- Coordinating polling with operations such as database purge.
- Logging ingestion errors so the polling thread can continue.

Log rotation and file replacement behavior must be tested against the actual Cowrie deployment. Do not assume a checkpoint alone guarantees lossless ingestion across every rotation strategy.

### Expected log format

Each non-empty line should contain a valid JSON object. Cowrie records commonly include fields such as `eventid`, `timestamp`, `session`, and source address information, with event-specific data depending on the event type.

To diagnose missing events:

1. Confirm the configured path points to the active Cowrie log.
2. Confirm the file exists and the SIEM process can read it.
3. Check that new records are valid JSON objects and end with a newline.
4. Inspect the application console for ingestion errors.
5. Verify that the file is receiving new events.

## 12. Database and evidence handling

SQLite is used through Python's built-in `sqlite3`. Schema initialization and database access are implemented in `app/db.py`.

| Data area | Purpose |
|---|---|
| Raw events | Stored event identifiers, session association, timestamps, event IDs, and original JSON payloads. |
| Sessions | Session metadata, time range, event count, score, risk level, and summary. |
| Alerts | Alert identifier, session association, severity, title/reason, status, and supporting metadata. |
| Checkpoints | Progress through the input log. |
| Audit logs | Selected authentication and administrative actions. |
| Geolocation cache | Cached lookup results for IP addresses. |
| Settings file | Persistent operational settings, including the configured Cowrie path and integration options. |

Exact columns, indexes, constraints, and migrations are defined by the current schema implementation. Do not use this summary as a database migration specification.

### Evidence-handling recommendations

- Preserve original Cowrie logs separately when they may be evidence.
- Record acquisition time and hash preserved copies when following a forensic workflow.
- Restrict access to log files, the SQLite database, settings, and authentication secret.
- Keep synthetic/demo telemetry separate from evidence-bearing logs and databases.
- Back up the database and settings before upgrades or destructive testing.
- Treat exported HTML reports as sensitive: they may contain IP addresses, commands, sessions, and alerts.
- Do not assume a dashboard view or normalized database row replaces the original event record.

## 13. Correlation, scoring, and ATT&CK

The rule-based correlation engine is implemented in `app/correlation.py`. Its score is heuristic and is derived from configured behavior indicators. The intended component categories are access, activity, weaponization, and intent; each contributes to an overall score from 0 to 100.

| Score | Risk band |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

The specific patterns and score contributions live in the source code and may change. Inspect `app/correlation.py` before relying on a particular command pattern or score contribution.

### Interpretation guidance

- A failed login is not the same as successful authentication.
- A suspicious-looking command can be benign when viewed without context.
- Activity observed in a honeypot session is not proof of access to another system.
- A high score means configured indicators matched; it is not a percentage probability of compromise.
- ATT&CK IDs and labels provide a shared behavior vocabulary, not actor attribution.

The MITRE page summarizes selected techniques mapped by the current rules. If a technique mapping is important to a report, compare the original event sequence with the official technique definition.

## 14. Geolocation and maps

The geolocation module classifies IP addresses and can query a public-IP geolocation provider over HTTPS. Results are cached in SQLite and lookup work is asynchronous.

- Private, loopback, and reserved IPs do not have ordinary public geolocation.
- Coordinates can describe a provider or network region rather than the person operating a system.
- VPNs, proxies, cloud hosts, NAT, and compromised intermediaries can make location misleading.
- External lookups disclose queried public IP addresses to the configured provider.
- Set `HYSHIELD_GEO=off` to disable external geolocation lookups.

Map locations are contextual hints only. Do not use them as standalone attribution or identity evidence.

## 15. Settings and integrations

Settings persistence and public settings projection are implemented in `app/settings.py`; environment and path configuration is in `app/config.py`. Supported settings include operational alert/retention values, active-response options, external threat-intelligence integration toggles/credentials, and the Cowrie log source.

The VirusTotal API key is intentionally not returned to the browser by the public settings projection; the interface receives only an indicator of whether a key is set. Do not include keys in logs, screenshots, issue reports, or source control.

Some settings describe or render integration configuration; they do not prove that another security product is installed or that a response action or external integration is operational. Verify external components independently before relying on them. Review any response-action configuration carefully before enabling it in a real environment.

The Settings page validates a selected Cowrie source path as an existing readable file that begins with a valid Cowrie event. Changing the source updates the ingestor path and records an administrative audit event.

## 16. HTTP API

The API is implemented in `app/main.py`. Use the running OpenAPI explorer at `/docs` to confirm current routes, methods, parameters, schemas, and authentication behavior.

Known route groups include:

| Route | Purpose |
|---|---|
| `GET /api/health` | Low-information liveness response; intentionally unauthenticated. |
| `GET /api/overview/metrics` | Overview metrics and time/category summaries. |
| `GET /api/overview/refresh` | Overview metrics and chart markup for refresh. |
| `GET /api/overview/charts` | Overview chart markup. |
| `GET /api/geo/visual` | Map markup and geolocation summary data. |
| `GET /api/alerts` | Alert data, optionally filtered by severity. |
| `GET /api/events` | Event search/category query with a bounded result limit. |
| `GET /api/actors` | Actor summaries. |
| `GET /api/sessions` | Session list. |
| `GET /api/sessions/{session_id}` | Session detail. |
| `GET /api/geo` | Geolocation overview data. |
| `GET /api/mitre` | ATT&CK technique summary. |
| `GET /api/settings` | Public settings representation. |
| `GET /api/users`, `POST /api/users` | Account listing/creation, subject to authorization. |
| `GET /api/audit-logs` | Audit-log data, subject to authorization. |

Protected API requests require a valid session and appropriate role. Unauthenticated API requests receive an authentication error; role violations receive a forbidden response. Use read-only endpoints first when exploring the API. Do not invoke purge, alert mutation, account management, or settings-write actions against evidence-bearing data unless the action is intended and authorized.

## 17. Security and deployment

The implementation includes controls such as:

- Server-side account authentication and role-based authorization.
- Salted scrypt password hashes and signed, HttpOnly, SameSite session cookies.
- A localhost-only default bind address.
- Jinja auto-escaping and escaping of log-derived values in generated SVG.
- Content Security Policy, `X-Content-Type-Options: nosniff`, and a restrictive referrer policy.
- Same-origin checks for state-changing requests where applicable.
- Hiding the saved VirusTotal key from the public settings response.
- Local data-directory permission restrictions where the platform supports POSIX permissions.

These controls do not make every deployment safe by default. Before remote or shared use:

1. Place the service behind a trusted HTTPS ingress and restrict network access.
2. Set `HYSHIELD_COOKIE_SECURE=true` when TLS terminates in front of the application.
3. Set a strong, persistent `HYSHIELD_AUTH_SECRET` and protect it.
4. Use least-privilege operating-system accounts and filesystem permissions.
5. Keep the database, logs, settings, and exported reports private.
6. Keep secrets out of source control and logs.
7. Review destructive operations and external response integrations.
8. Disable geolocation if sending public IPs to an external provider is not permitted.
9. Keep dependencies and the host patched; rerun tests and security checks after changes.
10. Do not expose the development server with `--reload` as a production deployment.

Cowrie telemetry may contain attacker-controlled strings, usernames, IP addresses, and commands. Treat it as potentially sensitive and untrusted input.

## 18. Testing and validation

Install the dependencies and run tests from the SIEM directory:

```bash
cd python-siem
python -m pytest -q
```

The repository's security workflow also runs dependency auditing with `pip-audit` and Bandit static analysis against the application code. Run the checks configured in the current workflow when making a change; use the workflow file as the authoritative list of CI commands.

A successful test command should be determined from its actual output and exit code. This document does not claim that a test suite has been run for a particular checkout.

### Manual acceptance checklist

- [ ] Application starts and redirects a first-time user to initial setup.
- [ ] Initial Super Admin can sign in and sign out.
- [ ] Protected pages and API routes enforce authentication and role permissions.
- [ ] Overview and investigation pages render.
- [ ] `/docs` lists the current API schema after sign-in.
- [ ] Configured Cowrie log path is correct and readable.
- [ ] A new valid JSON line is ingested.
- [ ] An incomplete final line is not treated as a complete record.
- [ ] Ingestion resumes after restart.
- [ ] Log truncation/rotation behavior is tested with the intended deployment.
- [ ] Session score and alert reason can be reviewed against source events.
- [ ] Event search, session detail, actor, ATT&CK, and map views work.
- [ ] Alert actions and settings changes respect roles and persist as expected.
- [ ] Attacker-controlled HTML-like values display as text rather than active markup.
- [ ] Geolocation can be disabled.
- [ ] Reports and evidence data are stored securely.

## 19. Troubleshooting

### No events appear

1. Check `COWRIE_LOG_PATH` and the saved path in Settings.
2. Confirm the file exists, is readable, and contains valid Cowrie JSON objects.
3. Confirm records are newline-terminated and new events are being appended.
4. Check the application console for ingestion errors.
5. Confirm the data directory and database are writable.

### Events appear late

The default poll interval is two seconds. Check `POLL_SECONDS`, log buffering, and whether a complete newline-terminated record has been written. Browser refresh is separate from ingestion polling.

### Missing or repeated events after rotation

Review how Cowrie rotates/replaces the log, the file identity and checkpoint state, and whether the file was truncated. Reproduce with a copy of the deployment's log before relying on the behavior for evidence.

### Cannot sign in

Confirm the username/password, verify that the account is active, and check the app console. Repeated failed attempts may trigger a temporary in-process rate limit. Do not delete or edit authentication data blindly; back up the data directory before recovery work.

### API returns 401 or 403

A 401 indicates that authentication is missing or invalid; a 403 indicates that the request is not permitted for the current role or was rejected by a request security check. Sign in, verify the role, inspect the request origin, and consult the app log.

### Map has no markers

Private/reserved IPs cannot be geolocated as ordinary public addresses. External lookup may be disabled, pending, unavailable, or blocked by network policy. Treat any returned location as approximate.

### Port 8000 is already in use

Stop the existing process or set a different `PORT` before starting the application.

### CSS or JavaScript changes are not visible

Hard-refresh the browser with Ctrl+Shift+R. Restart the Python process after server-side code or template changes.

### Settings or integration appears ineffective

Confirm the setting was saved, inspect the current configuration, and independently verify that the external service and credentials are available. A visible toggle is not an integration health check.

## 20. Maintenance checklist

- Monitor application logs and available disk space.
- Set a retention policy appropriate to the lab's privacy and evidence requirements.
- Back up the database, settings, and authentication secret before upgrades.
- Preserve original Cowrie logs before testing purge or other destructive actions.
- Keep Python dependencies and the host operating system updated.
- Re-run automated tests and the configured security checks after code changes.
- Re-test ingestion after Cowrie upgrades or log format changes.
- Verify log rotation behavior after changes to the deployment.
- Review access controls, network exposure, TLS, and secret handling before remote use.
- Document local configuration changes so another analyst can reproduce the setup.
