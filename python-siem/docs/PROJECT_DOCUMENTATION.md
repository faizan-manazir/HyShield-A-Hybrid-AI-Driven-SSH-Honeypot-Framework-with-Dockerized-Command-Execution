# HyShield Python SIEM — Complete A-to-Z Documentation

> This guide documents the Python SIEM subsystem under `python-siem/`: what it does, how data moves through it, its application modules, dashboard, API, storage, scoring, configuration, deployment, testing, troubleshooting, and operational limitations. It describes the SIEM only; the parent repository's Cowrie command bridge and Docker executor are documented separately in the root project documentation.

## 1. Purpose and scope

The Python SIEM is the monitoring and investigation component of HyShield. It reads Cowrie JSON-lines telemetry, persists events and derived session/alert data in SQLite, correlates activity into heuristic risk scores, and presents the results through a FastAPI web application.

It is designed for research, education, honeypot monitoring, and controlled lab demonstrations. It is not a production endpoint agent, and its alerts are not proof that a separate production system has been compromised. Analysts should validate findings against original Cowrie events and session evidence.

### Primary capabilities

- Incrementally ingest Cowrie JSON log records.
- Store raw events, sessions, alerts, ingestion checkpoints, settings, and geolocation cache data.
- Correlate session behavior into a score from 0 to 100 and a risk band.
- Raise rule-based alerts and attach selected MITRE ATT&CK technique mappings.
- Provide overview metrics, live event viewing, alert triage, event search, actor summaries, session evidence, map visualizations, settings, and downloadable standalone HTML security reports.
- Generate synthetic Cowrie-shaped events locally for testing and demos.
- Expose JSON endpoints and FastAPI's interactive API documentation.
- Use SQLite without requiring a separate database server or frontend build system.

### Out of scope / limitations

- The SIEM does not prove attacker identity or physical location.
- IP geolocation is approximate and can reflect VPNs, proxies, cloud egress, or ISP infrastructure.
- Rule-based scoring can produce false positives and false negatives.
- MITRE ATT&CK mappings are behavior labels, not attribution.
- Synthetic events are not real incidents and must not be mixed with evidence.
- The SIEM now has account authentication and role-based access control. Do not expose it directly to the Internet without a deployment security review, trusted HTTPS ingress, and network restrictions.

## 2. Architecture at a glance

```text
Cowrie JSON-lines log (cowrie.json)
             |
             v
      app/ingest.py
  poll -> parse complete lines -> checkpoint
             |
             v
        app/db.py
  SQLite raw events / sessions / alerts
  checkpoints / settings / geo cache
             |
             v
     app/correlation.py
  session features -> score / risk / alert
             |
             v
       app/queries.py
  KPIs, alert queues, event search, actors,
  sessions, charts and map data
             |
             +-----------------------+
             |                       |
             v                       v
      app/main.py              app/charts.py
  FastAPI routes/pages          SVG charts/map
             |                       |
             +-----------+-----------+
                         v
              Jinja templates + static
                 JavaScript / CSS
                         |
                         v
                 Analyst browser
```

### Core data flow

1. Cowrie appends one JSON object per line to its configured log.
2. The ingestor polls the file, reads new complete lines, parses events, and advances a checkpoint.
3. Events are stored in SQLite; session records and alert/correlation state are updated. Session start and end timestamps are merged without replacing an existing non-null timestamp with an incoming null value.
4. The correlation engine examines observed session events and commands, calculates component scores, a total score, risk band, summary, and applicable alert/technique metadata.
5. The query layer provides common database calculations to HTML pages and JSON APIs. Event Explorer search and category filtering are applied by the database query before its result limit, so matching older records are not discarded merely because they fall outside a pre-filtered recent-event window.
6. FastAPI serves Jinja templates and API responses. Python-generated SVG is used for charts/map visualizations; browser JavaScript powers interactions and periodic refreshes.
7. An analyst opens alerts or sessions and reviews the evidence behind the score.

The SIEM ingestion pipeline is distinct from the parent project's interactive SSH command-response bridge. It reads Cowrie's telemetry output rather than executing attacker commands itself.

## 3. Repository structure

| Path | Purpose |
|---|---|
| `run.py` | Starts the application through Uvicorn. |
| `app/main.py` | FastAPI app lifecycle, middleware, page routes, JSON endpoints, HTML report export, and request handling. |
| `app/config.py` | Environment variables, paths, server options, and geolocation/map settings. |
| `app/db.py` | SQLite connection helpers, schema creation, and JSON helpers. |
| `app/ingest.py` | Background JSON-lines reader, checkpointing, and log-change handling. |
| `app/correlation.py` | Rule-based session scoring and MITRE ATT&CK mapping. |
| `app/queries.py` | Shared SQL queries and data aggregation for pages/API. |
| `app/geo.py` | IP classification, asynchronous public-IP geolocation, and caching. |
| `app/charts.py` | Escaped SVG chart and threat-map generation. |
| `app/settings.py` | Persistent settings, public settings projection, and raw config rendering. |
| `app/test_generator.py` | Local synthetic Cowrie event generator. |
| `app/templates/` | Jinja templates for the pages. |
| `app/static/app.js` | Browser interactions, API requests, and quiet UI refreshes. |
| `app/static/style.css` | Layout, colors, responsive styles, risk indicators, and dashboard presentation. |
| `tools/simulate.py` | CLI utility for adding synthetic sessions/events. |
| `data/` | Default data directory for the log, SQLite database, and settings; created as needed. |
| `tests/` | Automated tests, run with pytest. |
| `requirements.txt` | FastAPI, Uvicorn, Jinja, multipart support, and test dependencies. |

Use the current files in the branch as the source of truth when code changes. This document explains responsibilities and known behavior; it is not a substitute for reading the implementation.

## Authentication and role-based access control

The SIEM provides an authenticated `/reports/export.html` endpoint that downloads a standalone HTML report with current metrics, recent alerts, source actors, sessions, and event records. The report is generated on demand, HTML-escapes log-derived content, and is sent as an attachment with caching disabled. Exported files may contain sensitive telemetry and should be stored securely.\n\nThe SIEM requires an account before protected pages and APIs can be used. On a fresh database, visit `/setup` to create the first Super Admin. Once at least one account exists, setup redirects to login and cannot create another initial administrator. Sign in at `/login`; use **Sign out** to clear the session cookie.

Passwords are stored as salted scrypt hashes, not plaintext. Session cookies are signed, HttpOnly, SameSite=Strict, and expire after eight hours. The signing secret is read from `HYSHIELD_AUTH_SECRET` or generated in `data/auth_secret`; protect this file and the data directory. The generated key must persist across restarts or users will be logged out. Set a stable secret through the environment when using multiple app instances.

### Roles

| Role | Permissions |
|---|---|
| `super_admin` | Full access, user creation/enable/disable, settings, purge, and administrative audit logs. |
| `analyst` | View dashboards and investigation data, close alerts, and use the synthetic event generator. No account management, settings changes, or purge. |
| `auditor` | Read-only dashboards, alerts, event/session investigation, and audit logs. Cannot mutate alerts, settings, accounts, or generator state. |

Authorization is enforced by server middleware on page and API requests; UI navigation hiding is not the security boundary. Administrative/authentication activity is recorded in the SQLite `audit_logs` table and shown at `/audit-logs` to Super Admins and Auditors. Use a trusted HTTPS ingress for remote access. This feature does not replace a full deployment security review.

## 4. Application startup and lifecycle

The application is created in `app/main.py`. Its lifespan initializes the SQLite schema and starts the background ingestor. The synthetic generator is available through its application interface. The server entry point in `run.py` imports configuration and runs Uvicorn using the configured host and port.

The app is designed to run as a single Python service. It does not require Node.js, npm, TypeScript compilation, or a separate frontend build.

### Startup sequence

1. Install the Python dependencies.
2. Set environment variables if the log/data paths or bind address differ from defaults.
3. Run `python run.py` from `python-siem/`.
4. Open the dashboard at `http://127.0.0.1:8000`.
5. Open `http://127.0.0.1:8000/docs` to inspect the generated API documentation.
6. Confirm the configured Cowrie log exists and the application process can read it.
7. Review application output if events are not appearing.

## 5. Dashboard pages and intended analyst workflow

The dashboard is organized around triage and investigation. Page availability and exact controls are defined in `app/main.py` and the templates.

| Route | Purpose | Typical analyst task |
|---|---|---|
| `/` | Security Overview with key metrics, Investigation Priorities, map, distributions, status indicators, recent alerts, top actors, and live activity. | Decide what requires attention first. |
| `/live` | Recent Cowrie events. | Review incoming telemetry and identify a sequence of events. |
| `/geomap` | Interactive map with source markers, risk filtering, and location details. | Explore approximate source geography and related sessions. |
| `/mitre` | Technique summaries for observed sessions. | Understand which behavior categories matched. |
| `/alerts` | Alert queue and severity filtering; alert resolution controls where enabled. | Triage, inspect, and close/resolve alerts. |
| `/explorer` | Event search and filters. | Search by fields such as IP, session, command, username, or technique text. |
| `/actors` | Source-IP summaries. | Compare activity and risk associated with sources. |
| `/sessions` | Session list. | Select a session for investigation. |
| `/sessions/{id}` | Session timeline/evidence and score explanation. | Review commands and context behind an alert. |
| `/settings` | Local settings and configuration display. | Adjust supported application settings. |
| `/generator` | Synthetic event generator. | Populate a test environment with harmless sample telemetry. |
| `/docs` | FastAPI OpenAPI explorer. | Inspect available JSON endpoints and schemas. |

### Suggested analyst workflow

1. Start on Overview and read Investigation Priorities.
2. Open a critical/high alert and check its source IP, timestamp, session, reason, and severity.
3. Open the linked session and examine the event sequence and commands.
4. Search the relevant session/IP in Event Explorer and Live Activity.
5. Use the MITRE page to understand the behavior label, not as proof of attribution.
6. Check actor history and map context, treating geolocation as approximate.
7. Resolve/close an alert only according to the team's workflow; preserve evidence first when needed.
8. Record conclusions separately from automated scores and include uncertainty.

## 6. Investigation Priorities versus Recent Alerts

These panels answer different questions and should not be conflated.

### Investigation Priorities
The Overview's priority panel uses open alerts and ranks them by severity:
1. CRITICAL
2. HIGH
3. MEDIUM
4. LOW

Within the same severity, newer session timestamps come first. The query sorts the candidate alerts before applying the five-item display limit, so a large number of newer low-severity alerts should not displace the highest-severity open alerts from this panel.

### Recent Alerts
The separate Recent Alerts panel is chronological and emphasizes the newest activity. It is useful for monitoring what has just happened, rather than choosing the most urgent investigation.

Severity is a triage aid, not a final verdict. A critical alert should be investigated promptly, but the analyst must review source events and session context before describing the event as a confirmed compromise.

## Dashboard refresh behavior

The refreshable dashboard pages use a **5-second** polling interval. Event Explorer uses the same interval when its Auto-refresh option is enabled. Browser refresh requests update page content in the background rather than forcing a full-page reload.

The JavaScript interval enforces a 5-second minimum. This controls browser polling only; it does not guarantee that every Cowrie record will appear within five seconds because file ingestion, database writes, and query/render time also contribute to end-to-end latency. The refresh setting is emitted by the page route in `app/main.py` and consumed by `app/static/app.js`.

## Event Explorer search and filtering

The query layer applies the selected category and search term in SQL before applying the requested result limit. This avoids the previous behavior in which the app could limit the newest events first and then filter that subset, hiding older records that matched the analyst's search. The result limit is clamped to the supported range, and unknown categories fall back to `ALL`.

Search results are still limited to the configured maximum, so use a narrower query or a different category when investigating a large event set. Search results should be corroborated with the underlying Cowrie log and session evidence.

## 7. Event ingestion

The ingestor in `app/ingest.py` runs as a background thread and polls the configured Cowrie JSON-lines file. It tracks file progress in the SQLite checkpoints table so that restarts do not require reprocessing the entire file.

### Important ingestion behavior
- It reads newly appended bytes from the file.
- It ignores a final partial record until a newline indicates that the line is complete.
- It records a checkpoint for the current file identity and offset.
- It handles file truncation by resetting the offset when the file size is smaller than the saved offset.
- It uses a lock to coordinate polling and operations such as purging.
- Errors are logged and counted so the thread can continue polling.

Log rotation behavior depends on the file identity/checkpoint logic and the behavior of the environment that rotates the log. Validate it against the actual Cowrie log rotation configuration before relying on it for evidentiary completeness.

### Expected input

The input is JSON Lines: each non-empty record should be a valid JSON object on its own line. The SIEM expects Cowrie-like fields such as event ID, timestamp, session ID, source IP, and event-specific data, where supplied by Cowrie.

If a log is malformed, incomplete, inaccessible, or not the file the app is configured to read, events may not appear as expected. Check the process logs and the active path before assuming the correlation engine is at fault.

## 8. Database and storage model

SQLite is used through Python's built-in `sqlite3`; a separate database server is not required. Schema definitions are in `app/db.py`.

The principal data areas include:

| Table/data area | Role |
|---|---|
| `raw_events` | Event identifier, session ID, timestamp, event ID, and original JSON payload. |
| `sessions` | Session identifier, source IP, start/end times, closed state, event count, score, risk level, and summary. |
| `alerts` | Alert identifier, session association, severity, title/reason, status, and supporting metadata. |
| `checkpoints` | Ingestion progress for log file identity and byte offset. |
| Geolocation cache | Previously resolved IP location/provider information. |
| Settings file | Persistent dashboard settings stored under the configured data directory. |

Indexes support common lookups such as raw events by session and timestamp. Exact columns and constraints are defined in the current schema source.

### Storage and evidence recommendations
- Restrict read/write permissions on the database, logs, and settings file.
- Back up the database according to the lab's retention needs.
- Preserve original Cowrie logs separately when they may be evidence.
- Hash acquired log copies and record acquisition time when following a forensic workflow.
- Keep demo/synthetic telemetry in a separate log and database.
- Do not treat normalized rows or UI labels as a replacement for the original event record.

## 9. Correlation, scoring, and alert generation

The rule-based correlation engine is implemented in `app/correlation.py`. The code describes four score components, each ranging from 0 to 25:

| Component | Intended behavior area |
|---|---|
| Access | Login attempts and results. |
| Activity | Reconnaissance commands and reading password/credential files. |
| Weaponization | Downloads, payload execution, and cryptocurrency-miner indicators. |
| Intent | Hiding tracks, creating accounts, and lateral/sideways movement indicators. |

The component scores are added to produce a total threat score from 0 to 100. The documented risk thresholds are:

| Total score | Risk level |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

The engine uses command/event pattern lists and rules. A command match may be ambiguous without context; the full session sequence should be reviewed. Alert titles and reasons are generated from detected patterns, and selected behaviors are mapped to MITRE ATT&CK technique identifiers in the correlation implementation.

### Interpretation guidance
- A failed login is not the same as successful authentication.
- A command containing a suspicious word is not necessarily malicious in isolation.
- A honeypot login success is evidence about the honeypot session, not proof of access to a separate production system.
- A high score means that more configured indicators matched; it is not a calibrated probability.
- ATT&CK technique labels provide a common vocabulary, not attribution to a specific actor or group.

Tune the rules against representative data and document any local changes to thresholds or pattern lists.

## 10. MITRE ATT&CK view

The MITRE page summarizes techniques associated with correlated behavior. Technique IDs and labels are derived from the mapping in the correlation code. Use the official ATT&CK knowledge base for definitions and context.

A technique mapping should be read as “the observed activity resembles this technique under the current rules,” not “this technique is conclusively proven.” If a technique label is central to a report, manually compare the original events and commands with the technique's definition.

## 11. Geolocation and threat map

The geolocation module classifies IP addresses and performs public-IP lookups through the configured HTTPS provider, caching results in SQLite. Lookup work is asynchronous so a page does not need to wait for a network response before rendering.

### Real-world limitations
- Private, loopback, and reserved IPs do not have normal public geolocation.
- In `DEMO_MODE`, private/loopback addresses may be assigned stable simulated locations so the map can be demonstrated.
- Simulated locations are not real source locations and must not be presented as attribution.
- Public-IP coordinates are approximate and may identify a provider/network region rather than the operator.
- VPNs, proxies, cloud servers, NAT, and compromised intermediaries can make location misleading.
- External lookups disclose queried public IP addresses to the geolocation provider.

Set `HYSHIELD_GEO=off` to disable external lookups when network policy or privacy requirements call for it. Document whether map data is real, unresolved, or simulated when exporting screenshots or reports.

## 12. Charts, map rendering, and browser UI

The `app/charts.py` module generates charts and map markup as SVG strings on the server. The code escapes text values before embedding them in SVG to reduce the risk that attacker-controlled log text becomes active markup.

The HTML templates are rendered with Jinja. The app's JavaScript handles client interactions and calls JSON endpoints; CSS defines the dashboard layout, severity colors, spacing, responsive behavior, and interaction states.

### Frontend troubleshooting
- If Python/template changes do not appear, restart the application.
- If CSS or JavaScript changes do not appear, hard-refresh the browser (Ctrl+Shift+R).
- Check browser developer tools for failed API requests or JavaScript errors.
- If a panel is empty, inspect the API response and the underlying query before changing the visual template.
- If a map marker has no location, check geolocation state and whether the IP is private/reserved.

## 13. API

The JSON API is implemented in `app/main.py`. FastAPI generates an OpenAPI schema and interactive documentation at `/docs` while the service is running. The exact list of paths and request/response schemas should be checked there because the API evolves with the code.

Use the API explorer to:
1. Find the route associated with the page or action.
2. Inspect required query/body parameters.
3. Execute safe read-only requests first.
4. Review status codes and returned JSON.
5. Avoid using purge, resolve, or settings-write endpoints against evidence-bearing data unless intended.

The overview uses a combined refresh endpoint to reduce duplicate browser requests. Alert actions and settings updates use API requests from the same application origin.

## 14. Application settings and secret handling

Settings defaults and persistence are managed in `app/settings.py`; configuration paths and environment variables are managed in `app/config.py`.

The public settings representation deliberately removes the stored VirusTotal API key and returns only whether a key is configured. This is intended to keep the secret write-only in the UI. Never log the actual key or include it in screenshots.

Settings may include the alert threshold, log retention, active-response options, VirusTotal integration toggle/key, and OTX toggle. A setting displayed in the UI does not prove that the external service is configured, authorized, or operational; test integrations separately.

## 15. Configuration reference

Configuration is read by `app/config.py`. Defaults below describe the current Python SIEM configuration; check the source before depending on them in another branch.

| Variable | Default / meaning |
|---|---|
| `COWRIE_LOG_PATH` | Input Cowrie JSON log; defaults to `data/cowrie.json` under the SIEM base directory. |
| `HYSHIELD_DATA` | Data directory; defaults to `python-siem/data/`. |
| `HYSHIELD_DB` | Optional SQLite path; otherwise the database is under the data directory. |
| `HOST` | `127.0.0.1`, localhost-only default bind. |
| `PORT` | `8000`. |
| `POLL_SECONDS` | `2` seconds between ingestion polls. |
| `DEMO_MODE` | Off by default; use `true` to give private/loopback IPs stable simulated map locations. |
| `HYSHIELD_GEO` | Geolocation enabled unless set to `off`. |
| `HONEYPOT_NAME` | Sensor label displayed by the map. |
| `HONEYPOT_LAT` / `HONEYPOT_LNG` | Sensor coordinates, defaulting to Islamabad coordinates. |
| `HONEYPOT_CITY` / `HONEYPOT_COUNTRY` | Sensor location labels, default Islamabad/Pakistan. |
| `ANALYST_LAN_IP` | Optional lab/analyst IP shown specially on the map. |

### Examples

Use a specific Cowrie log:

```bash
COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json python run.py
```

Disable geolocation:

```bash
HYSHIELD_GEO=off python run.py
```

Run a demo bound to all interfaces (only when the environment's access controls make this appropriate):

```bash
HOST=0.0.0.0 PORT=8000 DEMO_MODE=true python run.py
```

On Windows PowerShell, set variables before starting:

```powershell
$env:COWRIE_LOG_PATH = "C:\path\to\cowrie.json"
$env:HYSHIELD_GEO = "off"
python run.py
```

Binding to `0.0.0.0` can expose the service through available network interfaces. It does not add authentication or security controls.

## 16. Installation and local development

### Requirements
- Python 3.10 or newer, as stated in the project README.
- Dependencies listed in `requirements.txt`.
- A Cowrie JSON-lines log, or the sample/default data available in the checkout.
- Write permission for the data directory and read permission for the log.

### Linux/macOS

```bash
cd python-siem
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Windows PowerShell

```powershell
cd python-siem
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:8000`. The interactive API explorer is `http://127.0.0.1:8000/docs`.

### Development run in Codespaces

```bash
cd python-siem
DEMO_MODE=true uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Use the forwarded port only for the intended audience. Do not expose sensitive logs or an unauthenticated dashboard publicly.

## 17. Synthetic events and CLI simulation

The application includes a synthetic Cowrie event generator. It writes randomized Cowrie-shaped JSON lines using documentation-only TEST-NET IP ranges and does not send network traffic. Those records flow through the normal ingestion/correlation pipeline, so they affect metrics, sessions, risk scores, alerts, and demo maps.

The UI generator supports a bounded session count and normal/fast generation. A CLI simulator is also provided under `tools/simulate.py`.

Example documented workflow:

```bash
DEMO_MODE=true python run.py
# In another terminal, from python-siem/:
python tools/simulate.py --count 30
```

Use a separate test log/database whenever possible. If synthetic records are appended to the same log as real activity, they become part of the same ingested dataset and may be difficult to distinguish later. Mark demo data clearly and never report it as real attacker telemetry.

## 18. Security controls and deployment limitations

The current SIEM includes several useful controls described in its code/README:
- Jinja rendering auto-escapes values in templates.
- SVG chart/map text is escaped before insertion.
- Security headers include `X-Content-Type-Options: nosniff`, a same-origin-oriented Content Security Policy, and a restrictive referrer policy.
- Non-GET requests are checked for a cross-origin Origin where supplied.
- The VirusTotal key is not returned by the public settings representation.
- The default host is `127.0.0.1`.

These safeguards are not a complete deployment security review. Authentication and role-based access control are implemented, but that alone is not a complete deployment security review. Before remote or shared deployment:
- Put the dashboard behind an authenticated VPN or reverse proxy.
- Restrict network access and use TLS at the trusted ingress.
- Protect the database, log files, and settings file with filesystem permissions.
- Keep secrets out of source control and logs.
- Review destructive endpoints such as database purge and any response-action settings.
- Limit retention and back up data according to sensitivity.
- Disable external geolocation when policy requires it.
- Review dependency updates and run the application with least privilege.
- Test with attacker-controlled log strings to confirm escaping and filtering remain effective.

### Evidence and privacy
Cowrie logs can contain commands, usernames, source addresses, and attacker-supplied strings. Treat them as potentially sensitive. Keep evidence copies immutable where required, document handling, and avoid uploading logs to third-party services without authorization. Geolocation calls send public IP addresses to an external provider.

## 19. Testing and quality assurance

The project README identifies pytest as the test runner. Run tests from the SIEM directory:

```bash
cd python-siem
python -m pytest
```

A successful command should be judged by the actual test output and exit code; this document does not imply that tests have been run or passed.

### Recommended manual acceptance checklist
- [ ] The app starts and the Overview page renders.
- [ ] `/docs` opens and lists the current API routes.
- [ ] The configured log path is correct and readable.
- [ ] A new valid JSON line is ingested.
- [ ] An incomplete final line is not processed as a complete event.
- [ ] Ingestion resumes after app restart.
- [ ] Truncation and log rotation behavior are tested against the deployment.
- [ ] A session's score can be explained by its events/commands.
- [ ] Critical/high open alerts appear before medium/low alerts in Investigation Priorities.
- [ ] Recent Alerts remains chronological.
- [ ] Search, session detail, actor, MITRE, and map pages render.
- [ ] Alert actions and settings changes return expected status/results.
- [ ] Malicious-looking HTML in event fields is rendered as text, not active markup.
- [ ] Geolocation can be disabled.
- [ ] Synthetic events are isolated from evidence-bearing logs.
- [ ] The dashboard is not remotely reachable without intended access controls.

## 20. Troubleshooting

### No events appear
1. Confirm `COWRIE_LOG_PATH` points to the active Cowrie JSON log.
2. Check the file exists, is readable, and contains one JSON object per line.
3. Check app output for ingestion errors.
4. Confirm the data directory is writable.
5. Verify the log is receiving new events.

### Events arrive late
The default poll interval is two seconds. Check `POLL_SECONDS`, file buffering, and whether a complete newline-terminated record has been written.

### Duplicate or missing events after rotation
Check the log rotation mechanism, inode/file identity behavior, checkpoint state, and whether the file was replaced or truncated. Validate against a copy of the actual deployment log before relying on the pipeline for evidence.

### Overview alert ordering seems wrong
Confirm that the browser is using the updated branch and that the Overview uses the priority-alert data rather than the chronological recent-alert list. Restart the Python server after backend changes and hard-refresh the browser.

### Map shows no markers
Public lookups may be pending or unavailable. Private/reserved IPs have no public location. Demo-mode locations are synthetic. Try `HYSHIELD_GEO=off` if external requests are blocked.

### API returns errors
Open `/docs`, inspect the endpoint schema and status, then check the app console. Confirm the frontend request matches the current endpoint and required fields.

### Port 8000 is busy
Choose a different `PORT` or stop the existing process.

### Static changes do not appear
Hard-refresh with Ctrl+Shift+R. If server-side Python code changed, restart the application.

### Settings/integration does not work
Confirm the setting is persisted and that external credentials/service access are configured. A visible toggle alone does not verify integration health.

## 21. Operations and maintenance

- Monitor the app console and disk space.
- Set log/database retention according to the lab's evidence requirements.
- Back up the SQLite database and settings file before upgrades.
- Preserve a copy of raw Cowrie logs before testing destructive operations.
- Keep the application dependencies and host OS patched.
- Review risk rules when Cowrie event formats or command patterns change.
- Re-test the ingestion pipeline after Cowrie upgrades.
- Review API routes before exposing them through a reverse proxy.
- Document local configuration differences so another analyst can reproduce the deployment.
- Keep synthetic demo data clearly marked and separate.

## 22. Development workflow

Current feature branch for this work:

```bash
git switch fix/siem-audit-findings
git pull origin fix/siem-audit-findings
```

Recommended contribution process:
1. Make a focused code change.
2. Add/update tests for behavior changes.
3. Update this documentation if routes, schema, scoring, settings, or deployment change.
4. Run `python -m pytest` and record the actual result.
5. Manually verify the affected pages and ingestion flow.
6. Inspect the diff for secrets, real telemetry, generated databases, and machine-specific paths.
7. Commit to the feature branch and review the PR diff before merging.

Do not claim tests passed unless they were actually executed.

## 23. Glossary

- **Cowrie:** SSH/Telnet honeypot that records session behavior.
- **JSON Lines:** text format containing one JSON object per line.
- **Ingestor:** background worker that reads new log records.
- **Checkpoint:** saved file identity/offset used to resume ingestion.
- **SQLite:** embedded relational database used by the SIEM.
- **Session correlation:** grouping events and interpreting a sequence of activity.
- **Threat score:** heuristic score from configured detection rules.
- **Risk level:** LOW, MEDIUM, HIGH, or CRITICAL label derived from the score.
- **Alert:** record created by a detection rule/correlation result.
- **MITRE ATT&CK:** public knowledge base of adversary tactics and techniques.
- **Geolocation:** approximate network location associated with a public IP address.
- **TEST-NET:** documentation-reserved IP ranges used for examples and synthetic telemetry.
- **False positive:** an alert that does not represent the harmful behavior suggested by the rule.
- **False negative:** harmful behavior that the configured rules do not detect.
- **Chain of custody:** documented handling of evidence from acquisition through analysis.

## 24. References

- [Python SIEM README](../README.md)
- [Main HyShield README](../../README.md)
- [Cowrie project](https://github.com/cowrie/cowrie)
- [FastAPI documentation](https://fastapi.tiangolo.com/)
- [Uvicorn documentation](https://www.uvicorn.org/)
- [Jinja documentation](https://jinja.palletsprojects.com/)
- [SQLite documentation](https://www.sqlite.org/docs.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ipwho.is](https://ipwho.is/)


## Testing changes

From `python-siem/`, run `python -m pytest -q` to execute the automated suite. Record the actual command output and exit status when validating a change; historical test results do not verify later commits.
