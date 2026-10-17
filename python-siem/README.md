# HyShield SIEM Dashboard (Python version)

> **Full documentation:** [Project architecture, configuration, data flow, detection logic, routes, deployment, testing, and troubleshooting](docs/PROJECT_DOCUMENTATION.md).

The dashboard is implemented as a single Python application.
No Node, no npm, no TypeScript, and no frontend build step. A small amount of plain JavaScript powers chart interactions and quiet live updates.

It reads the Cowrie `cowrie.json` log, scores every attacker session (0-100), raises alerts, maps them to
MITRE ATT&CK and shows everything in a web dashboard.

## Authentication and roles

On the first run, open the dashboard URL and create the initial **Super Admin** account at `/setup`. This setup route is available only while no user accounts exist. After setup, sign in at `/login`. User accounts are stored in the SIEM SQLite database; passwords are stored as salted scrypt hashes, and sessions use a signed, HttpOnly cookie with an eight-hour expiry. The signing key is generated in `data/auth_secret` unless `HYSHIELD_AUTH_SECRET` is supplied through the environment. Keep the data directory private and back up the signing key securely; rotating it invalidates active sessions.

The Super Admin can create and disable accounts under **System → User Management**:
- **Super Admin:** system settings, account management, dashboard, investigations, and administrative actions.
- **Security Analyst:** dashboard, event/session investigation, and alert closure; no user management, settings changes, or database purge.
- **Read-Only Auditor:** read-only investigation views and audit log; cannot change alerts, settings, or accounts.

Backend route checks enforce these roles; hiding navigation links is only a usability aid. Use HTTPS when accessing through a trusted reverse proxy. Do not expose the app publicly without reviewing deployment controls. The initial setup must be completed before normal dashboard/API use.

## Run it

You need Python 3.10 or newer.

```bash
cd python-siem
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

For Windows PowerShell, use these commands instead of the activation line above:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open **http://127.0.0.1:8000**. Configure the SIEM to read your Cowrie JSON log before relying on dashboard results.

**Point it at your real honeypot log**

```bash
COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json python run.py
# Windows (PowerShell):
$env:COWRIE_LOG_PATH="C:\path\to\cowrie.json"; python run.py
```

New log lines are ingested by the background reader; dashboard page refresh is a separate mechanism.

**Dashboard auto-refresh**

- Auto-refreshable dashboard pages poll for updated content every **5 seconds**.
- The Event Explorer polls every 5 seconds when its Auto-refresh option is enabled.
- The browser uses background requests rather than a full-page reload.
- The JavaScript refresh interval has a **5-second minimum**. This is a UI polling interval, not a guarantee that every new log record will be visible within five seconds; ingestion and processing timing can also affect when data appears.
- To verify the setting, inspect the page's `data-refresh` attribute and the refresh logic in `app/static/app.js`.

## Pages

| Page | What it shows |
|---|---|
| `/` Security Overview | counters, events-per-minute chart, event types, newest alerts, top sources, and latest 20 Cowrie events (Live Activity) |
| `/geomap` Threat Map | pan/zoom SVG map, searchable and risk-filtered IP markers, click-to-inspect details, coordinates, source/ISP, threat score, related sessions, copy coordinates, external map link, and country table |
| `/mitre` MITRE ATT&CK | techniques your sessions matched |
| `/alerts` | alert list, filter by severity, close alerts |
| `/explorer` | search every event (IP, session, command, username, MITRE id) |
| `/actors` | one card per attacker IP |
| `/sessions`, `/sessions/<id>` | session list, and the full "attack story" + commands + score explanation |
| `/settings` | system settings |
| `/reports/export.html` | downloads a standalone HTML snapshot of metrics, alerts, actors, sessions, and recent events |

The JSON API is still there (`/api/...`), and FastAPI documents it at **/docs**.

## Export an HTML security report

From the Security Overview, select **Export HTML Report**. The authenticated `/reports/export.html` endpoint downloads a standalone HTML file containing current summary metrics, up to 100 alerts, 20 source actors, 50 sessions, and 100 recent events. The report is generated on demand, uses HTML escaping for logged values, and is marked as an attachment with caching disabled. Treat exported reports as sensitive because they may contain attacker IPs, usernames, and command telemetry.

## How the code is organised

```
run.py                 start the server
app/main.py            all web pages + API routes
app/queries.py         every database question (one place)
app/correlation.py     the threat-scoring engine
app/ingest.py          reads new log lines into SQLite
app/geo.py             HTTPS IP geolocation -> country/city/coordinates
app/charts.py          charts and world map drawn as SVG text by Python
app/templates/*.html   the pages (plain HTML + a little Jinja)
app/static/style.css   the look
tests/                 tests  ->  python -m pytest
```

## Run tests

From the `python-siem/` directory, install the requirements and run:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

The tests cover application routes and behaviors, but passing tests do not replace checking the dashboard against a real Cowrie log. Run the suite after code changes and review the actual test output.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `COWRIE_LOG_PATH` | `data/cowrie.json` | log file to read |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | where to listen |
| `HYSHIELD_GEO` | on | `off` = never call the HTTPS IP geolocation provider |
| `HONEYPOT_LAT`, `HONEYPOT_LNG`, `HONEYPOT_CITY`, `HONEYPOT_COUNTRY` | Islamabad | where map lines point |
| `ANALYST_LAN_IP` | `192.168.100.11` | private IP shown as your own lab machine |
| `HYSHIELD_DATA` | `data/` | folder for the database and settings |

## Implementation status

This repository's supported dashboard is the Python SIEM in this directory. The legacy Node.js/Next.js dashboard has been removed; do not follow old instructions to copy this directory over `siem-dashboard/` or install Node.js dependencies. Use the root [deployment walkthrough](../README.md) and this guide for the current layout and setup.

The Python dashboard includes session scoring, MITRE ATT&CK mapping, alert triage, event/session search, actor summaries, report export, role-based access, and a geospatial view. Scoring is rule-based and geolocation is approximate; validate the behavior against your own Cowrie telemetry before operational use.

## Security notes

- Listens on `127.0.0.1` by default and requires sign-in. Roles are Super Admin, Security Analyst, and Read-Only Auditor. For remote access, still use a VPN or trusted authenticating reverse proxy with HTTPS and review the deployment controls.
- Everything from the log is attacker-controlled text. Output is HTML-escaped, the map metadata is escaped before it enters SVG attributes, and the Content-Security-Policy permits only same-origin scripts. Tests cover output escaping.
- Forms reject requests that come from another website.
- Public IPs are looked up via `ipwho.is` over HTTPS in a background worker and cached in SQLite. Set `HYSHIELD_GEO=off` to disable lookups. IP geolocation coordinates are approximate network-region estimates, not GPS or street-level locations; this provider does not supply an accuracy radius in this integration.
- Active Response, VirusTotal and OTX are saved as settings only. As in the original, nothing is wired to them yet.

## Use it inside the HyShield repo

Replace the old `siem-dashboard/` folder with the contents of this folder, delete `node_modules`, `package*.json`,
`.next`, and commit. Keep `data/hyshield.db` and `data/settings.json` out of git (see `.gitignore`).

## UI visual refresh

The dashboard now uses a refined dark SOC-console theme with a clearer visual hierarchy, updated sidebar and navigation states, a compact context bar, more consistent cards/tables/forms, improved spacing and typography, visible keyboard focus states, reduced-motion support, and responsive layouts for smaller screens. This refresh is presentation-only: existing FastAPI routes, templates, data processing, and features are retained.

### Refresh and motion behavior

- Automatically refreshed pages poll every 10 seconds.
- Updates are fetched in the background and only the page content region is replaced; the browser does not perform a full-page reload or reset scroll position.
- Background refresh pauses while the tab is hidden, offline, or a form control is being edited.
- Motion is slower and more subtle, and respects the operating system's reduced-motion preference.



## Interactive Geo Threat Map

The map uses a self-contained SVG world outline (no third-party tile service required). Use the search field and risk filter to narrow sources, click a marker or table row to inspect its IP, estimated coordinates, score, events, sessions and network metadata, use the zoom/pan controls, copy coordinates, open the estimated point in OpenStreetMap, or follow a session link. The map refreshes from JSON in the background without reloading the page and preserves the current zoom and selection where possible.

Public IP coordinates are resolved over HTTPS through `ipwho.is` and cached locally. Private/reserved IPs cannot be geolocated on the public internet and are displayed as private-network sources. IP geolocation cannot reliably identify a person's precise physical location.

## Investigation prioritization

The Overview's **Investigation Priorities** panel sorts open alerts by severity (critical to low), then by newest timestamp within each severity. The separate **Recent Alerts** panel remains chronological.


## Security hardening and deployment

- The app binds to `127.0.0.1` by default. Expose it only behind a trusted TLS reverse proxy or VPN; configure trusted proxy headers and block direct unencrypted access to the ASGI port.
- If HTTPS terminates at a reverse proxy, set `HYSHIELD_COOKIE_SECURE=true` so the session cookie always has the `Secure` attribute. Do not trust arbitrary forwarded headers from the public internet.
- Runtime data is stored under `HYSHIELD_DATA` (default: `python-siem/data`). Keep that directory accessible only to the service account. On POSIX systems, the app attempts owner-only permissions for the directory, database, settings file, and signing secret; verify permissions on the actual deployment OS.
- Super Admins can change the Cowrie JSON log source from **Settings → Log Source**. The path must be an existing, readable file on the SIEM server; changes apply immediately without restarting the app. Ensure the service account can traverse the parent directories. The original log is not moved or modified.
- The `logRetention` setting now removes timestamped telemetry older than the configured number of days during periodic ingestion polling. Audit entries older than 365 days are pruned. Entries without parseable timestamps cannot be aged out by this policy; retain original Cowrie evidence separately according to your incident-response policy.
- Failed login attempts are limited to eight failures per client IP in a 15-minute window per application process. Multi-worker or multi-instance deployments must also configure a shared rate limit at the reverse proxy or shared store.
- Install dependencies from a reviewed lock/constraints file when deploying. The current requirements are range-based; CI audits the resolved dependencies but does not yet guarantee a reproducible pinned environment.
- Do not treat the dashboard as a substitute for preserving original Cowrie logs, access controls on backups, secure report handling, and a deployment-specific penetration test.
