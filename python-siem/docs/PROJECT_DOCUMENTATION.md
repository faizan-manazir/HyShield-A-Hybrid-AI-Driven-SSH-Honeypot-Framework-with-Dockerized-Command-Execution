# HyShield Python SIEM — Project Documentation

## 1. Purpose and scope

The Python SIEM is the web-based monitoring and investigation component of HyShield. It consumes Cowrie JSON-lines telemetry, stores normalized event/session/alert data in SQLite, evaluates observed session behavior, and presents the resulting evidence in an analyst dashboard.

This is a research, educational, and honeypot-monitoring project. It is not, by itself, a guarantee that a production host has been compromised or that an alert is a confirmed incident. Alerts are indicators generated from observed honeypot activity and should be validated against the session evidence.

## 2. Main capabilities

- Continuously ingest appended Cowrie JSON log lines.
- Persist raw events, sessions, alerts, and supporting state in SQLite.
- Correlate session activity into a 0–100 threat score and a risk band.
- Detect patterns such as failed/successful SSH authentication, reconnaissance, credential-file access, downloads, execution, evasion, lateral movement, and cryptocurrency-miner activity.
- Associate detected behavior with selected MITRE ATT&CK technique IDs.
- Present alert queues, event search, actor summaries, session timelines, risk explanations, telemetry charts, and a geographic view.
- Use a local synthetic-event generator to exercise dashboard behavior without sending attack traffic.
- Expose page routes and a JSON API; FastAPI's interactive API documentation is available at `/docs`.

## 3. Architecture and data flow

```text
Cowrie JSON log (JSON Lines)
        |
        v
Ingestor thread (polls appended lines)
        |
        +--> parse / validate event records
        +--> checkpoint file position; handle truncation/rotation
        |
        v
SQLite database
  raw events | sessions | alerts | checkpoints | geo cache
        |
        v
Correlation and query layer
  session features -> score/risk -> alerts and MITRE tags
        |
        +--> FastAPI page routes + Jinja templates
        +--> JSON API
        +--> charts and SVG threat map
        |
        v
Analyst browser
```

The ingestion interval defaults to two seconds. The app is designed to continue reading new log lines as they are appended. The dashboard's polling/refresh behavior is separate from ingestion.

### Main components

| Path | Responsibility |
|---|---|
| `run.py` | Starts the Uvicorn server using configured host and port. |
| `app/main.py` | FastAPI app lifecycle, security headers/middleware, HTML pages, JSON endpoints, and request handling. |
| `app/config.py` | Environment-based paths, host/port, polling, demo mode, geolocation, and map settings. |
| `app/ingest.py` | Background log reader, checkpointing, duplicate-safe ingestion, and handling of log truncation/rotation. |
| `app/db.py` | SQLite connection helpers, schema initialization, and JSON helpers. |
| `app/correlation.py` | Session behavior analysis, risk scoring, and MITRE ATT&CK mapping. |
| `app/queries.py` | Shared database queries for metrics, events, alerts, sessions, actors, and map data. |
| `app/geo.py` | IP classification, cached geolocation lookup, and location metadata. |
| `app/charts.py` | Server-generated SVG charts and world-map visualizations. |
| `app/settings.py` | Persistent dashboard settings and safe public configuration representation. |
| `app/test_generator.py` | Local synthetic Cowrie-shaped JSON event generator. |
| `app/templates/` | Jinja HTML templates for the dashboard pages. |
| `app/static/app.js` | Browser-side interactions and asynchronous UI actions. |
| `app/static/style.css` | Dashboard layout, colors, responsive styling, and risk presentation. |
| `tools/simulate.py` | CLI utility for adding synthetic sessions/events in demo mode. |
| `data/` | Default log/database/settings data directory (created as needed). |

## 4. Dashboard pages

| Route | Purpose |
|---|---|
| `/` | Security Overview: event/session/source/alert KPIs, Investigation Priorities, attack map, category distribution, system indicators, recent alerts, and top actors. |
| `/live` | Latest Cowrie events for near-real-time inspection. |
| `/geomap` | Interactive source map, risk filtering, IP details, and country/location summaries. Geolocation is approximate. |
| `/mitre` | MITRE ATT&CK techniques observed in correlated sessions. |
| `/alerts` | Alert queue with severity filtering and alert resolution controls. |
| `/explorer` | Search/filter event records, including IP, session, command, username, and MITRE-related text where available. |
| `/actors` | Source-IP summaries and actor risk. |
| `/sessions` | Session listing. |
| `/sessions/{id}` | Session evidence and attack-story details, including observed commands and scoring explanation. |
| `/settings` | Local application settings and configuration display. |
| `/generator` | Start/stop the local synthetic event generator. |

### Investigation Priorities ordering

The Overview's Investigation Priorities panel is intentionally different from the Recent Alerts panel:

1. Open alerts are ranked by severity: **CRITICAL, HIGH, MEDIUM, LOW**.
2. Within the same severity, newer session timestamps appear first.
3. The query sorts the open alert set before applying the five-item limit, so a flood of newer lower-severity alerts does not displace higher-severity alerts from this panel.
4. The separate Recent Alerts panel remains chronological.

Severity is a triage aid, not a substitute for examining the underlying session evidence.

## 5. API and web application

The application is built with FastAPI and serves Jinja-rendered HTML plus JSON endpoints. Open `/docs` while the app is running to inspect the API routes exposed by the current code.

Overview data is assembled by the query layer and rendered server-side. A combined overview refresh endpoint is used to reduce duplicate browser requests. Alert-resolution actions use same-origin requests and return a JSON result for the browser to display.

Security-related behavior currently visible in the app includes:
- Jinja template auto-escaping for rendered values.
- A Content Security Policy that limits scripts to the same origin.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- A same-origin check for non-GET requests when an Origin header is supplied.
- API keys are not returned in the public settings representation.

These controls are useful safeguards but do not replace a full security review before exposing the application beyond a trusted lab.

## 6. Storage model

SQLite is used; no separate database server is required. The schema is initialized by the application.

Core data areas include:
- **Raw events** — original Cowrie event payloads, identifiers, timestamps, and session references.
- **Sessions** — source IP, start/end times, open/closed state, event count, score, risk level, and correlated summary.
- **Alerts** — generated detections, severity, title/reason, session link, status, and MITRE metadata.
- **Checkpoints** — log-reader progress used to resume ingestion after restarts and handle file changes.
- **Geolocation cache** — previously resolved IP location metadata.

The exact schema is defined in `app/db.py`; query logic is centralized in `app/queries.py`.

## 7. Scoring and detection concepts

The correlation engine groups events by session and evaluates observed activity. Relevant indicators in the current code include:
- Failed and successful login events.
- SSH client/version information.
- Reconnaissance and system discovery commands.
- Access to credential-related files.
- Download tools and execution-related commands.
- Defense-evasion behavior.
- Lateral movement and remote-access tools.
- Cryptocurrency-miner indicators.

The engine returns a numeric score from 0 to 100 and maps it to risk levels using these thresholds:

| Score | Risk level |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

Selected technique IDs are mapped to MITRE ATT&CK names and tactics in the correlation code. These are rule-based indicators, not a machine-learning verdict. A matched command or event should be interpreted in context, and a honeypot alert should not automatically be described as a production compromise.

## 8. Installation and local run

### Requirements

- Python 3.10 or newer.
- Dependencies listed in `requirements.txt`.
- A Cowrie JSON-lines log, or the included sample/default data path for local demonstration.

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

By default, the server listens on `127.0.0.1:8000`. Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The API explorer is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

For a Codespaces session or a lab where the server must listen on all interfaces, configure the host explicitly, for example:

```bash
HOST=0.0.0.0 PORT=8000 DEMO_MODE=true python run.py
```

Only expose the port to trusted users. Binding to `0.0.0.0` makes the service reachable through available network interfaces and is not a security control.

## 9. Configuration

The current settings are read from environment variables by `app/config.py`.

| Variable | Default | Meaning |
|---|---|---|
| `COWRIE_LOG_PATH` | `python-siem/data/cowrie.json` | Cowrie JSON-lines log to ingest. |
| `HYSHIELD_DATA` | `python-siem/data/` | Directory for local application data. |
| `HYSHIELD_DB` | `HYSHIELD_DATA/hyshield.db` (otherwise default data DB) | SQLite database path. |
| `HOST` | `127.0.0.1` | Server bind address. |
| `PORT` | `8000` | Server port. |
| `POLL_SECONDS` | `2` | Interval between ingestion polls. |
| `DEMO_MODE` | disabled | Gives private/loopback sources stable simulated map locations for demos. |
| `HYSHIELD_GEO` | `on` | Set to `off` to disable external IP geolocation requests. |
| `HONEYPOT_NAME` | `HyShield Honeypot Sensor` | Map sensor label. |
| `HONEYPOT_LAT` / `HONEYPOT_LNG` | Islamabad coordinates | Sensor coordinates used by map arcs. |
| `HONEYPOT_CITY` / `HONEYPOT_COUNTRY` | `Islamabad` / `Pakistan` | Sensor location labels. |
| `ANALYST_LAN_IP` | `192.168.100.11` | Optional configured analyst/lab IP displayed specially on the map. |

Example using a real Cowrie log:

```bash
COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json python run.py
```

PowerShell example:

```powershell
$env:COWRIE_LOG_PATH = "C:\path\to\cowrie.json"
python run.py
```

### Geolocation and privacy

Public IP geolocation uses an external HTTPS provider and is performed asynchronously with caching; it does not block the page while waiting for a lookup. Geographic coordinates are estimates and must not be treated as precise physical attribution. Private addresses normally have no public geolocation. In demo mode, their displayed map locations are synthetic and must not be presented as real attacker locations.

Set `HYSHIELD_GEO=off` when external IP lookup is not desired. Review organizational privacy, data-transfer, and retention requirements before using real telemetry.

## 10. Synthetic/demo data

The Test Event Generator writes randomized Cowrie-shaped JSON events to the configured log. It uses documentation-only TEST-NET ranges and does not send network traffic. Generated records flow through the same ingestion and correlation pipeline as other log records, so they change counts, sessions, scores, alerts, and demo maps.

- Use synthetic data for interface checks and demonstrations.
- Prefer a separate test log/database when real evidence is present.
- Do not mix synthetic events with evidence intended for a formal investigation.
- The generator supports a bounded session count and normal/fast generation modes in the UI.

The CLI simulator can also be used as described in `python-siem/README.md`.

## 11. Testing and verification

The project README identifies `pytest` as the test runner. Install the dependencies, then run from the `python-siem` directory:

```bash
python -m pytest
```

For manual smoke testing:
1. Start the application.
2. Open the Overview and confirm it renders.
3. Open `/docs` and inspect the API routes.
4. Use the synthetic event generator with a test log.
5. Confirm new events appear, sessions and alerts are generated, and the Investigation Priorities panel places higher-severity open alerts first.
6. Open an alert/session to verify the supporting evidence.
7. Test with `HYSHIELD_GEO=off` to confirm the dashboard can run without external geolocation lookups.

No test result is implied by these instructions; run the checks in the target environment and record the actual result.

## 12. Operational and security considerations

- Treat the app as a lab/research tool unless it has undergone a separate deployment security review.
- Keep the server bound to localhost unless remote access is needed and protected.
- Do not commit API keys, secrets, production logs, or sensitive evidence to source control.
- Use a separate database/log for synthetic events and demonstrations.
- Preserve original log evidence and record hashes/chain-of-custody separately when used in a forensic workflow.
- Geolocation is approximate and does not prove the identity or physical location of an operator.
- Honeypot observations show activity against the honeypot; they do not establish compromise of a separate production system.
- Review the alert logic and tune thresholds for the environment before relying on it operationally.
- Configure backups and retention appropriate to the data sensitivity and investigation requirements.
- Do not assume that settings displayed by the dashboard imply that an external integration or automated response is deployed and functioning; verify integrations independently.

## 13. Troubleshooting

**The dashboard has no events**
- Confirm `COWRIE_LOG_PATH` points to the intended JSON-lines file.
- Confirm the file exists and contains one JSON event per line.
- Check the application console for ingestion errors.
- Check that the process has read permission for the log and write permission for the data directory.

**The map has no markers**
- Public-IP lookups may still be pending or may have failed.
- Private IPs do not have real public geolocation; use demo mode only for demonstrations.
- Disable external lookup with `HYSHIELD_GEO=off` if network policy prohibits it.

**Changes do not appear after updating the code**
- Pull the intended branch.
- Restart the app if server-side Python code changed.
- Hard-refresh the browser (Ctrl+Shift+R) if static assets were changed.

**Port 8000 is already in use**
- Stop the other process or configure a different `PORT`.

## 14. Repository and contribution workflow

The Python SIEM is located in `python-siem/` within the main HyShield repository. For the current audit/UI changes, use the feature branch `fix/siem-audit-findings`; do not push these changes directly to `main`.

```bash
git switch fix/siem-audit-findings
git pull origin fix/siem-audit-findings
```

Before submitting additional changes:
1. Keep changes scoped and explain behavior changes in the commit message.
2. Run the test suite and record any failures or environment limitations.
3. Manually verify affected routes and responsive layouts.
4. Do not claim tests passed unless they were actually run.
5. Update this document when routes, configuration, schema, detection rules, or deployment behavior changes.

## 15. Related documentation

- [Python SIEM README](../README.md) — quick-start and feature summary.
- [Main HyShield README](../../README.md) — parent honeypot framework, bridge, Docker command execution, sanitization, and AI-assisted response pipeline.
