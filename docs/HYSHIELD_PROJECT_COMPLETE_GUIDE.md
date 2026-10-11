# HyShield Project — Complete Technical Guide and Progress Record

**Document status:** 11 October 2026  
**Repository:** [HyShield on GitHub](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution)  
**Current working branch:** \`fix/siem-api-hardening\`  
**Target branch:** \`siem-integration\`  
**Pull request:** [PR #5 — Harden SIEM API defaults and malformed event handling](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5)  
**PR state:** Open, draft, not merged

---

## 1. Executive summary

HyShield is a research and educational SSH honeypot framework built around Cowrie. The core honeypot design routes commands entered through an SSH session into a controlled command-processing pipeline. That pipeline uses a bridge service, Docker-isolated execution, output sanitization, and optional AI-assisted response refinement to return plausible command output while recording attacker activity.

The project also contains a SIEM dashboard and backend intended to ingest Cowrie JSON-line logs, persist events, reconstruct sessions, calculate threat information, surface alerts, and present activity through a web interface.

The current stabilization effort concentrates on making the SIEM ingestion and API reliable, protecting test fixtures, improving frontend/backend integration, documenting security boundaries, and adding automated checks. Node.js/Express is the planned authoritative SIEM backend. The existing Python implementation is being retained until its unique functionality has been inventoried; it must not be removed just because the Node backend is being stabilized.

**Important distinction:** HyShield is a prototype/research project, not a production-ready security product. A passing test suite does not establish that the system is safe to expose to the public Internet. The current SIEM API has no application-level authentication or authorization.

## 2. Project goals

The project combines two related capabilities:

1. **SSH deception and command simulation**
   - Present an SSH honeypot through Cowrie.
   - Process commands in a controlled Docker environment rather than executing attacker commands directly on the host.
   - Sanitize and optionally refine command output before returning it through Cowrie.
   - Record interactions for analysis.

2. **Security monitoring and investigation**
   - Ingest Cowrie events from a JSON-lines log.
   - Persist raw events and session-related state in a database.
   - Detect suspicious activity and maintain alerts.
   - Provide event exploration, session views, actor summaries, geography, MITRE-related views, and file-integrity-related views.
   - Make malformed data and ingestion failures diagnosable rather than allowing one bad line to silently stop a batch.

The honeypot execution pipeline and the SIEM dashboard are related parts of the overall project, but they are not the same service. A working dashboard does not by itself prove that the complete Cowrie-to-Docker-to-response pipeline has been deployed and tested end to end.

## 3. Overall architecture

### 3.1 Honeypot and command-response path

The repository README describes this flow:

\`\`\`text
SSH client / attacker
        |
        v
Cowrie SSH honeypot
        |
        v
Modified Cowrie LLM backend (llm.py)
        |
        v
HyShield TCP bridge (bridge_server.py, port 5050)
        |
        +--------------------+
        |                    |
        v                    v
Docker command executor   Response sanitizer
        |                    |
        v                    |
Isolated fake-ubuntu        |
container                   |
        |                    |
        +---------+----------+
                  |
                  v
        Optional AI response refinement
                  |
                  v
        Bridge returns output to Cowrie
                  |
                  v
        SSH client receives simulated response

Cowrie activity logs
        |
        v
SIEM ingestion service
        |
        v
Database -> Express API -> Web dashboard
\`\`\`

The diagram describes the intended component flow from the project documentation. The complete deployed end-to-end path still needs to be revalidated on the target environment.

### 3.2 SIEM data path

The SIEM path currently under stabilization is:

1. Cowrie writes newline-delimited JSON records to a log file.
2. The Node.js ingestion service watches the configured path and reads new bytes.
3. The service parses records, records malformed lines for diagnostics, and persists events/checkpoints.
4. Database/session logic associates events with sessions and maintains threat and alert state.
5. Express exposes API endpoints for events, alerts, sessions, actors, metrics, geography, FIM-related views, MITRE data, settings, and vulnerabilities.
6. The Next.js frontend requests the API and renders the dashboard.
7. Automated backend tests and a frontend production build run in GitHub Actions.

## 4. Main components

### 4.1 Core honeypot components documented in the repository README

| Component | Responsibility |
|---|---|
| \`start.sh\` | Starts the HyShield workflow: prepares Python path/configuration, updates the honeypot password, activates Cowrie's environment, starts Docker/bridge services, and launches Cowrie. |
| \`update_password.py\` | Selects and updates the active honeypot password configuration. |
| \`bridge_server.py\` | Receives requests from modified Cowrie and coordinates the command-processing pipeline over TCP. The documented bridge port is 5050. |
| \`docker_executor.py\` | Executes commands in the configured isolated Docker environment. The README names the container \`fake-ubuntu\`. |
| \`sanitizer.py\` | Removes or reduces output details that could reveal the underlying execution environment. |
| \`ai_refiner.py\` | Provides optional AI-assisted command-response refinement. |
| \`state.py\` | Maintains execution/session state used by the command-processing path. |
| \`cowrie-modifications/cowrie.cfg\` | Contains configuration changes required for the HyShield integration. |
| \`cowrie-modifications/src/cowrie/llm/llm.py\` | Modified Cowrie integration that forwards commands into the HyShield bridge. |

Do not replace modified Cowrie integration files with default upstream files without first preserving and reapplying the HyShield changes.

### 4.2 SIEM backend

Key paths include:

- \`siem-dashboard/backend/server.js\` — creates the Express HTTP server, configures CORS and WebSocket origin checks, runs database migration, initializes ingestion, and binds the API.
- \`siem-dashboard/backend/routes/api.js\` — API routes and response shaping.
- \`siem-dashboard/backend/services/ingestion.js\` — watches/reads Cowrie logs, parses events, manages checkpoints and file lifecycle, and persists data.
- \`siem-dashboard/backend/db/migrate.js\` — database connection and migration utilities.
- \`siem-dashboard/backend/test-ingestion.test.js\` — ingestion, recovery, and lifecycle regression tests.
- \`siem-dashboard/backend/test-api.test.js\` — API regression tests.
- \`siem-dashboard/backend/package.json\` — backend scripts and dependencies.

The backend uses Node.js and Express. The package manifest includes SQLite-related packages, PostgreSQL support, WebSockets, CORS, dotenv, and GeoIP lookup functionality. The exact database selected at runtime depends on the project's database configuration; inspect the migration/database module and environment before assuming a deployment uses a particular database.

### 4.3 SIEM frontend

The frontend is a Next.js/React application. It includes pages for:

- Overview and metrics
- Live activity
- Event Explorer
- Actors
- Alerts
- Sessions and session detail
- Geography/map
- File-integrity-related events (FIM)
- MITRE-related views
- Settings
- Vulnerabilities

The shared API base URL lives in \`siem-dashboard/frontend/lib/api.ts\`. It uses \`NEXT_PUBLIC_API_BASE_URL\` when set and otherwise defaults to \`http://localhost:5000\`. Dashboard pages were updated to use the shared setting instead of independently hardcoding the API URL.

### 4.4 Python implementation

The repository contains a Python implementation in addition to the Node.js SIEM work. The agreed decision is to keep it intact until its unique functions, dependencies, and callers have been inventoried. Do not delete it or assume it is redundant before that assessment is complete.

## 5. How Cowrie ingestion works

### 5.1 Input format

The ingestion service expects one JSON record per line. Each line should represent an event object, typically containing fields such as:

- \`eventid\` — event type, for example a Cowrie session or command event.
- \`timestamp\` — event time.
- \`session\` — Cowrie session identifier when available.
- \`src_ip\` — source address when available.
- Event-specific fields such as command input, username, client version, or file details.

Records can be incomplete or malformed in real-world logs, so the ingestion process must treat input as untrusted.

### 5.2 Normal ingestion path

At a high level, the service reads newly appended bytes, separates complete lines, parses JSON, validates the parsed shape, computes a stable event identity from file/position context, and writes events and checkpoints. Session and alert logic uses the ingested event fields to update monitoring state.

Checkpoint and file-generation handling matter because the service must avoid losing unread data or incorrectly treating different records as duplicates when logs rotate, truncate, or are recreated.

### 5.3 Malformed and unexpected JSON

A valid JSON string is not necessarily a valid Cowrie event. For example, \`null\`, a number, a string, or an array can be valid JSON but not a valid event object.

The current ingestion hardening rejects non-object JSON shapes into the malformed-record diagnostic path. A malformed line is retained as an \`error.malformed\` event with its raw line recorded for later investigation. The processing loop then continues to subsequent lines rather than letting one bad record prevent later valid records from being ingested.

The API also uses safe parsing so malformed persisted payloads do not make an entire dashboard response fail.

### 5.4 File lifecycle cases covered by regression work

The ingestion tests exercise cases including:

- Initial event import and session reconstruction.
- Restart/idempotency behavior.
- Malformed JSON followed by a valid event.
- Valid JSON primitives such as \`null\` followed by a valid event.
- A Cowrie log that appears after the service starts.
- In-place truncation.
- Rotation while the old file has unread records.
- Recovery from checkpoints and rotated files.
- Overlapping ingestion triggers.
- Alert lifecycle preservation.
- Preservation of identical legitimate events that occur at distinct file offsets.
- Cleanup of file watchers, timers, database handles, and temporary test files.

Passing these tests provides evidence for the covered cases only. More realistic end-to-end tests under the intended deployment environment are still required.

## 6. API behavior and hardening

### 6.1 Main route groups

The current Express API includes route groups for:

- \`/api/health\`
- \`/api/alerts\` and alert closure
- \`/api/overview/metrics\`
- \`/api/events\`
- \`/api/actors\`
- \`/api/sessions\` and individual session detail
- \`/api/geo\`
- \`/api/fim\`
- \`/api/mitre\`
- \`/api/settings\`
- \`/api/vulnerabilities\`

Refer to \`siem-dashboard/backend/routes/api.js\` for the authoritative implementation and current response fields.

### 6.2 Safe parsing

A shared safe JSON parser returns a fallback when the stored value is not a string, cannot be parsed, or parses into a non-object shape such as \`null\`, an array, or a primitive. This prevents malformed stored JSON from breaking routes that aggregate data from multiple events or sessions.

FIM processing also checks that command input is a string before applying string operations.

### 6.3 Event metadata preservation — latest commit

Commit \`5036088aa14ea5cffce707343f99108fd3b444bf\` updated the \`/events\` response mapping in \`siem-dashboard/backend/routes/api.js\`. Each returned event now includes database metadata in addition to the parsed payload and MITRE context:

- \`id\`
- \`session_id\`
- \`timestamp\`
- \`eventid\`
- \`mitre_context\`

For timestamp and event ID, the database columns are preferred, with payload values used as fallbacks. This is particularly important for diagnostic records such as \`error.malformed\`, where the original payload may contain only the raw input line and therefore lack the database event classification.

This change was verified to be present on the GitHub branch. A fresh standard CI result for this exact commit still needs to be confirmed.

### 6.4 Network defaults and CORS

The Express service defaults to binding to \`127.0.0.1\`. Setting \`HOST=0.0.0.0\` is an explicit choice for container or remote deployment. Browser origins are checked against the comma-separated \`CORS_ORIGINS\` allowlist, defaulting to \`http://localhost:3000\`. WebSocket origin checks use the same configured allowlist.

**CORS is not authentication.** Requests without an Origin header may be accepted by the origin check, and non-browser clients can send requests directly. The current API does not provide application-level authentication, authorization, or role-based access control.

Do not expose the API to untrusted networks. For remote access, place it behind an authenticated reverse proxy or VPN until native authentication and authorization are designed, implemented, and tested.

## 7. Detection and alerting work already recorded

The earlier detection-engineering phase included case-insensitive matching for relevant reconnaissance, download, network discovery, SSH client, account-creation, pivot, and persistence command cases.

Download-to-execution correlation preserves command order and requires a download to occur before the associated execution. Alert lifecycle tests check that a previously closed alert remains closed when a later event updates the same session.

These are implemented project behaviors recorded in the stabilization history; the exact detection rules and their limitations should be reviewed in the detection-engineering code before relying on them as a complete threat-detection system.

## 8. Frontend integration and robustness

The shared \`API_BASE_URL\` helper centralizes the API address and allows the deployment to set \`NEXT_PUBLIC_API_BASE_URL\`. Relevant dashboard pages were migrated to it.

The Live Activity and Event Explorer event-category helper functions were made null-safe. They accept \`string | null | undefined\`, normalize valid strings to lowercase, and fall back to an informational category for missing or unexpected values instead of throwing when calling string methods.

TypeScript issues in geography style typing and MITRE technique/tactic data types were also corrected after a production build exposed them.

The dashboard is a monitoring and investigation interface; it is not itself proof that all detection rules are accurate or that the underlying honeypot is isolated correctly.

## 9. Test strategy and verified results

### 9.1 Backend regression tests

The backend uses Node's built-in test runner through \`npm test\`. The regression suite includes API behavior and ingestion lifecycle tests. Test setup uses temporary directories/files and cleanup hooks so tests do not deliberately overwrite or delete tracked Cowrie fixtures. Ingestion service instances are tracked and closed during cleanup.

### 9.2 Frontend production build

The frontend uses \`npm run build\`. The reported successful local build completed TypeScript validation and generated static pages without errors.

### 9.3 Results to date

**User-reported local validation in the extracted ZIP test copy:**

- Backend tests: **48 passed, 0 failed**.
- Frontend production build: **passed**.
- The local backend and dashboard were run at \`localhost:5000\` and \`localhost:3000\`.
- A malformed JSON line was retained as an \`error.malformed\` record, and a valid record after it was also ingested.
- The dashboard Event Explorer showed the malformed event after the local API response mapping was adjusted.

The test copy was extracted from a ZIP and has no \`.git\` metadata. Therefore, those test results refer to that local copy and should not be described as a fresh CI result for the current GitHub branch.

**Latest CI results documented before the latest API metadata commit:**

- Workflow run [38141399574](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38141399574): backend **48/48 passed**, frontend production build passed, audit-report jobs completed.
- Earlier Node 24 run [38134939532](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38134939532): backend **44/44 passed**, frontend production build passed.
- The newer local suite includes additional test coverage beyond the earlier 44-test CI run.

A completed audit-report job means the report ran; it does not mean all dependency advisories were fixed.

**Still required:** inspect/run the standard CI checks on the latest branch head, currently \`c5b1cabf8da86192100ce86af1a26aba853ffd81\` after this guide is committed, and record the actual results. Do not infer a pass from older runs.

## 10. Dependency and runtime status

The CI runtime was changed to Node 24 to match the declared engine requirement of \`geoip-lite@2.0.3\`. A previous successful run reported that the \`EBADENGINE\` warning was no longer present.

A dependency remediation preview updated backend and frontend manifests/lockfiles:

- The backend audit was reduced to **zero reported vulnerabilities** in the preview.
- The frontend Next.js and \`eslint-config-next\` versions were updated together to \`16.4.0\`; the preview frontend build passed.
- Five high-severity frontend tooling-chain advisories remained documented in the audit results. The suggested major downgrade of \`eslint-config-next\` to a Next 14 line was deliberately not applied because it does not match the project's Next 16 line.
- The upstream \`braces\` advisory was reported without a patched version in the audit snapshot.

The standard CI run for the bot-created dependency commit previously reported \`action_required\`. A fresh standard CI run against the current head is required to validate the current manifests and lockfiles. Re-run audits after validation because advisories and available fixes can change.

Do not use \`npm audit fix --force\` or apply a major downgrade blindly. Review dependency paths, apply compatible fixes, inspect lockfile changes, and rerun tests/builds.

## 11. Security posture and limitations

### Controls already implemented/documented

- Docker-isolated command execution is part of the documented honeypot design.
- Express binds to loopback by default.
- Browser CORS and WebSocket origins use an allowlist.
- Malformed and unexpected event payloads are handled more defensively.
- Test fixtures are isolated from normal ingestion regression runs.
- Recovery failures are logged more visibly in relevant paths.
- A pending retry timer can be cancelled when an ingestion service shuts down.
- The API response preserves database metadata for malformed event records.

### Risks and gaps still open

- No native application authentication or authorization/RBAC in the SIEM API.
- CORS does not prevent direct calls by arbitrary clients.
- The complete isolation properties of Docker execution need deployment-level validation; do not assume containerization alone guarantees safety.
- Five high-severity frontend tooling dependency findings were still unresolved in the recorded audit.
- Full dependency advisory review and repeat audit remain necessary.
- Ingestion rotation/restart/concurrency behavior needs continued testing beyond the currently covered regression cases.
- The entire SSH-to-Cowrie-to-bridge-to-Docker-to-response-to-SIEM path needs a repeatable end-to-end test on the intended host.
- Secrets, AI API keys, credentials, and live honeypot data must not be committed to the repository. Use environment configuration and protect real logs as sensitive security telemetry.

## 12. Work completed so far — consolidated timeline

1. **Core HyShield prototype documented:** Cowrie integration, TCP bridge, Docker executor, sanitizer, optional AI response refiner, state management, password update flow, and Cowrie logging.
2. **Detection engineering:** case-insensitive detection matching and ordered download-to-execution correlation.
3. **SIEM API hardening:** safe parsing for malformed persisted JSON and unexpected JSON shapes; FIM guards against non-string command input.
4. **Safer server defaults:** loopback bind by default and configurable CORS/WebSocket origin allowlist.
5. **Frontend API centralization:** shared API URL configuration and updates to dashboard pages.
6. **Build/type fixes:** corrected geography and MITRE TypeScript types uncovered by production build.
7. **Test isolation:** temporary test database/logs, cleanup hooks, and tracking/closing ingestion instances.
8. **Ingestion lifecycle fixes:** service recreation after log replacement in tests, retry timer cancellation on shutdown, recovery descriptor cleanup, more visible recovery errors, and processing of a populated log that appears after startup.
9. **Malformed record resilience:** JSON primitives such as \`null\` are quarantined as diagnostic records while later valid records continue processing.
10. **Dependency/runtime work:** Node 24 alignment and a dependency remediation preview; some frontend tooling advisories remain open.
11. **Local end-to-end testing:** 48 backend tests passed and frontend production build passed in the extracted local test copy, according to the user.
12. **Latest API response fix:** commit \`5036088aa14ea5cffce707343f99108fd3b444bf\` preserves database event metadata in the \`/events\` response.
13. **Project documentation:** the stabilization work log records detailed investigation history and current risks; this guide consolidates the project purpose, architecture, components, validation, and remaining work.

## 13. Remaining work — prioritized roadmap

### Priority 1 — Validate the current branch head

- Open [PR #5](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5) and inspect the checks for the latest commit.
- Run/confirm backend tests, frontend production build, and dependency-audit jobs against the exact latest commit.
- Record the run URL, commit SHA, runtime version, test count, and any failures.
- If a job is skipped or requires approval, document that state rather than treating it as a pass.

### Priority 2 — Validate ingestion end to end

- Test normal append and multiple rapid appends.
- Test malformed JSON and JSON primitives followed by valid records.
- Test identical legitimate events at different offsets.
- Test in-place truncation and rename/create rotation with unread bytes.
- Test process restart while a rotated file has unprocessed records.
- Test a log that is missing at startup and later appears populated.
- Test concurrent ingestion triggers and shutdown while retry/watcher activity is pending.
- Confirm checkpoint advancement, duplicate behavior, and database state after each case.
- Verify that diagnostic records retain useful identifiers and timestamps through the API and UI.

### Priority 3 — Close dependency security work

- Re-run \`npm audit\` for backend and frontend.
- Inspect each remaining advisory and the dependency path.
- Resolve the five recorded frontend tooling findings where compatible patched releases exist.
- Avoid forced upgrades and incompatible major downgrades.
- Re-run backend tests and frontend production build after each dependency change.

### Priority 4 — Design authentication and authorization

- Define who can view events, close alerts, change settings, and access session details.
- Add authentication and authorization/RBAC appropriate to the deployment.
- Protect sensitive settings and ensure secrets are not exposed to the frontend or logs.
- Add tests for unauthorized and insufficiently privileged requests.
- Until this is complete, keep the API on loopback or behind a trusted authenticated reverse proxy/VPN.

### Priority 5 — Deploy and validate the full honeypot safely

- Document supported OS/runtime versions and environment variables.
- Confirm Docker isolation, resource limits, filesystem permissions, network restrictions, and container privileges.
- Validate the modified Cowrie integration against the exact Cowrie version in use.
- Verify bridge request/response behavior, timeout handling, sanitizer behavior, and AI-refiner failure fallback.
- Run controlled authorized SSH test sessions and confirm that commands are not executed directly on the host.
- Verify Cowrie logs reach the SIEM and the dashboard reflects those events.
- Do not expose the honeypot to public networks until its isolation and operational monitoring are reviewed.

### Priority 6 — Assess the Python implementation

- Inventory Python modules, routes, scheduled jobs, database usage, and features not available in Node.
- Identify callers and deployment dependencies.
- Compare feature parity and tests.
- Decide deliberately whether to keep both implementations, migrate specific features, or deprecate anything. No removal should occur before this review.

### Priority 7 — Operational readiness and documentation

- Add environment-variable examples without real secrets.
- Document startup, shutdown, backup/restore, log rotation, database migration, troubleshooting, and safe update procedures.
- Define log retention, data privacy, and handling of attacker telemetry.
- Add monitoring for ingestion lag, parse errors, watcher state, checkpoint progress, and API health.
- Create a repeatable end-to-end test procedure and evidence checklist.
- Review licensing and third-party component notices before distribution.

## 14. Definition of done for the current stabilization phase

The SIEM stabilization phase should not be called complete until all of the following are true:

- [ ] The current PR head has a successful standard CI run for backend tests and frontend build.
- [ ] Dependency audit results are reviewed and unresolved findings are documented with a justified risk decision.
- [ ] Malformed records do not block subsequent valid records.
- [ ] Append, truncation, rotation, restart, late-created file, and concurrent-trigger behavior have repeatable tests.
- [ ] Test cleanup does not delete or overwrite tracked sample data.
- [ ] The API response exposes consistent event identifiers, timestamps, and event types, including diagnostic records.
- [ ] Deployment documentation accurately states that the API has no native authentication until that feature is implemented.
- [ ] The full honeypot-to-SIEM flow is validated in an authorized isolated environment.
- [ ] Python functionality has been inventoried before any consolidation decision.
- [ ] The user has reviewed and tested the work before PR #5 is merged.

## 15. Important repository and local-work safeguards

The current GitHub work is on \`fix/siem-api-hardening\` and is associated with PR #5 targeting \`siem-integration\`. The PR is intentionally still draft/open/unmerged.

The user's extracted ZIP test copy is not a Git repository; it is suitable for testing but cannot be used to commit changes directly. Do not initialize a new Git repository inside that extracted copy as a shortcut, and do not copy the whole extracted tree over the original working tree.

Previously reported local work that must be preserved includes modified Cowrie test fixtures, untracked root-level \`backend/\` and \`frontend/\` directories in the original workspace, and an existing stash. Do not reset, clean, overwrite, or discard those files. Only transfer specific reviewed changes through a safe, deliberate process.

---

## 16. Reference links

- [Repository](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution)
- [PR #5 — SIEM API hardening](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5)
- [SIEM stabilization work log](SIEM_STABILIZATION_WORKLOG.md)
- [SIEM security notes](../siem-dashboard/SECURITY.md)
- [GitHub Actions run 38141399574 — earlier 48-test/backend and frontend-build pass](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38141399574)

**Last verified branch context:** Before adding this guide, the branch head was \`c5b1cabf8da86192100ce86af1a26aba853ffd81\`, which documented the local API metadata fix and local test results. This guide's commit will advance the branch head. The status of CI on the new head must be checked separately.
