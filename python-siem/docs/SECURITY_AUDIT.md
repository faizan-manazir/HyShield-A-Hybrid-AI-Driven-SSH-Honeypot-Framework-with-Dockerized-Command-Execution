# HyShield Python SIEM — Security Audit

**Review date:** 2026-10-17  
**Scope:** `python-siem/` on branch `audit/fix-data-integrity-search-refresh`, including FastAPI routes/middleware, role checks, authentication/session handling, SQLite access, Cowrie ingestion, geolocation, report export, templates, configuration, tests, and CI configuration.  
**Method:** Static code review of repository files. No production system was contacted, no penetration test was run, and the current full test suite was not executed as part of this review. Findings below are code-review findings or risks to verify, not proof of exploitability in every deployment.

## Executive summary

The app has useful baseline controls: password hashing with scrypt, signed expiring sessions that are revalidated against active database users, backend role checks, parameterized SQL in the reviewed query paths, Jinja autoescaping, escaping for SVG metadata, a restrictive Content Security Policy, and a loopback bind by default.

**The app should not yet be considered production-hardened for network exposure.** Priorities are brute-force protection, deployment-safe cookie handling, CSRF defense-in-depth, protection of local secrets/data, ingestion/resource limits, and CI coverage for the Python SIEM itself.

## Findings and priorities

### HSA-01 — No login throttling or lockout policy
**Severity: High (exposure-dependent)**  
**Evidence:** `app/main.py` `/login` calls `auth.authenticate()` on each POST; `app/auth.py` has no attempt throttling, delay, or temporary lockout. Failed attempts also create audit records.

**Impact:** An attacker who can reach the login endpoint can make unlimited password guesses. Repeated attempts can also grow the audit table and increase scrypt CPU usage.

**Recommendation:** Add rate limiting for both source address and normalized username, use a bounded rolling window with progressive delay, and cap/rotate authentication audit records. For multi-worker or multi-instance deployments, use a shared store or enforce rate limits at a reverse proxy. Avoid permanent account lockouts that enable easy denial of service.

### HSA-02 — Secure-cookie behavior depends on the app's perceived URL scheme
**Severity: High (when TLS terminates upstream)**  
**Evidence:** `app/main.py` sets `secure=request.url.scheme == "https"` at login and initial setup.

**Impact:** If TLS terminates at a reverse proxy but the ASGI app sees an HTTP request, the session cookie may be issued without the `Secure` flag. A cookie could then be sent over an unencrypted connection if HTTP remains reachable.

**Recommendation:** Use an explicit deployment setting such as `HYSHIELD_COOKIE_SECURE=true` for HTTPS deployments, defaulting safely for production. Configure trusted proxy headers correctly and do not trust arbitrary forwarded headers from untrusted clients. Test the actual `Set-Cookie` header through the deployed proxy.

### HSA-03 — CSRF protection relies on Origin being present and SameSite behavior
**Severity: Medium**  
**Evidence:** The middleware rejects state-changing requests only when an `Origin` header exists and its network location differs from `Host`. There is no per-session CSRF token.

**Impact:** SameSite=Strict and Origin checking are useful defenses, but a missing Origin header bypasses the explicit check. Same-site sibling origins and unusual clients/proxy arrangements deserve particular scrutiny for privileged form actions.

**Recommendation:** Add CSRF tokens to authenticated state-changing forms and validate them server-side. Keep Origin/Referer validation as defense-in-depth, reject unexpected/malformed origins for browser form requests, and test login/setup/logout, user management, settings, purge, and alert closure.

### HSA-04 — Sensitive settings and database permissions are not explicitly restricted
**Severity: Medium (local multi-user/shared-host exposure)**  
**Evidence:** `app/settings.py` writes `data/settings.json` with `Path.write_text()`; `app/db.py` creates SQLite files using default OS permissions. The settings file can contain a VirusTotal API key in plaintext. The authentication secret is created with mode 0600 on platforms that honor POSIX modes, but the containing data directory is not explicitly secured.

**Impact:** On shared hosts or permissive deployments, local users or backup processes may be able to read API keys, password hashes, session-signing material, or honeypot telemetry.

**Recommendation:** Ensure the data directory is private to the service account (typically 0700 on POSIX), create settings/database files with restrictive permissions (typically 0600), apply permissions to existing files where supported, and document platform-specific handling. Prefer environment/secret-manager injection for production API keys. Treat the SQLite database, Cowrie log, exported reports, and backups as sensitive.

### HSA-05 — Ingestion has no explicit line-size or per-session processing bounds
**Severity: Medium (availability/integrity risk)**  
**Evidence:** `app/ingest.py` reads the available appended log chunk into memory, parses each full JSON line, stores the full payload, and re-evaluates every event for each touched session. There is no explicit maximum event size, per-poll byte budget, or session event cap.

**Impact:** A malformed, unexpectedly large, or attacker-influenced log entry can consume substantial memory/CPU/storage. Long-lived sessions can repeatedly trigger expensive full-session scoring as new lines arrive.

**Recommendation:** Process bounded chunks; reject or quarantine oversized lines with a capped diagnostic; cap payload sizes and field lengths; batch/limit scoring work; and add tests for huge lines, malformed JSON, repeated sessions, truncation, and rotation. Ensure file rotation and checkpoint behavior remains correct under chunking.

### HSA-06 — Test event generator can write to the configured telemetry log
**Severity: Medium (operational misuse / data integrity)**  
**Evidence:** `app/test_generator.py` appends synthetic events to the same `COWRIE_LOG_PATH` consumed by the ingestor. The API caps each run at 100 sessions but has no cooldown or aggregate quota.

**Impact:** Repeated authorised use can pollute production telemetry, grow the log/database, and reduce the evidentiary quality of incident data. A compromised analyst account could abuse the feature.

**Recommendation:** Disable the generator by default outside development, require an explicit enablement setting, and use a separate synthetic log/database in production-like deployments. If retained, add rate/aggregate limits and make the active log target and synthetic data status unmistakable.

### HSA-07 — Retention configuration does not currently enforce deletion
**Severity: Medium (data lifecycle / privacy)**  
**Evidence:** Settings expose `logRetention`, but the reviewed ingestion/database paths do not apply a retention cleanup policy. Audit logs are also kept without a retention cap.

**Impact:** Telemetry, usernames, commands, source IPs, and authentication audit entries may accumulate indefinitely, increasing storage pressure and the amount of data exposed by a local compromise.

**Recommendation:** Implement documented, scheduled retention for raw events, sessions, alerts, and audit logs with safe referential cleanup and a dry-run/test path. If deletion is intentionally not implemented, rename the setting so it cannot imply that data is actually deleted. Define backup retention separately.

### HSA-08 — Python SIEM is not covered by the existing CI workflow
**Severity: High (assurance gap; not an app exploit by itself)**  
**Evidence:** `.github/workflows/siem-backend-tests.yml` targets the older `siem-dashboard/backend` and `siem-dashboard/frontend` paths, and its push branches do not include the current Python SIEM audit branch. Its dependency audit runs npm audit for the older Node projects, not the Python requirements.

**Impact:** Changes to `python-siem/` can avoid automated test, dependency, and security checks. The current branch status was observed as pending with no statuses during this review; this is not a passing test result.

**Recommendation:** Add a Python workflow triggered on pull requests and pushes affecting `python-siem/**`. Install the requirements, run `python -m pytest -q`, and add Python dependency auditing (for example, `pip-audit`) plus static analysis (for example, Bandit). Make the checks required before merge where repository settings permit.

### HSA-09 — Dependencies are not locked to tested versions
**Severity: Medium (supply-chain/reproducibility)**  
**Evidence:** `python-siem/requirements.txt` uses lower bounds (for example, `fastapi>=0.110`, `uvicorn>=0.29`, `jinja2>=3.1`) rather than a lock or constraints file.

**Impact:** Fresh installs can resolve to different versions over time, including versions with new regressions or vulnerabilities, and a successful install is not necessarily reproducible.

**Recommendation:** Use a tested constraints/lock file, run automated vulnerability audits, and update dependencies deliberately with tests. Keep the lock process compatible with the supported Python versions.

### HSA-10 — Health endpoint exposes internal ingestion counters without authentication
**Severity: Low**  
**Evidence:** `/api/health` is exempt from authentication and returns `{"status":"ok","ingested": app.state.ingestor.stats}`.

**Impact:** The endpoint reveals whether the service is active and basic event/error counters. This is limited information, but may be unnecessary if the service is exposed beyond localhost.

**Recommendation:** Return only a minimal liveness status publicly, or restrict detailed readiness/ingestion counters to authenticated administrators or an internal monitoring network.

### HSA-11 — Reports contain sensitive telemetry and are downloadable by every authenticated role
**Severity: Low to Medium (policy-dependent)**  
**Evidence:** `/reports/export.html` exports IPs, usernames, commands/messages, sessions, and alert reasons. The endpoint is a GET and therefore available to analyst and auditor roles under the current role policy.

**Impact:** Exported reports are portable copies of sensitive incident telemetry. Users may retain or forward them beyond the app's access controls.

**Recommendation:** Confirm that all roles should be allowed to export. If not, restrict export to Super Admin/Analyst or add a separate permission. Keep `Cache-Control: no-store`, HTML escaping, attachment disposition, and the sensitivity notice; document secure storage and sharing.

## Positive controls observed

- Passwords use salted `scrypt` hashes and constant-time digest comparison.
- Session tokens are signed, expire after eight hours, and are revalidated against active user records and current roles in the database.
- Initial Super Admin creation is guarded by a database transaction that checks for existing users.
- Backend middleware checks route access; navigation hiding is not the only authorization layer.
- Reviewed SQL query values use parameter binding, and sort values are allowlisted.
- Jinja templates autoescape logged values by default; reviewed SVG metadata uses HTML escaping with quote escaping.
- A Content Security Policy, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer` are set on responses that pass through the main middleware.
- The run configuration defaults to `127.0.0.1`, reducing accidental network exposure for local development.
- The HTML export uses attachment disposition and disables caching.

## Verification plan before production

1. Add regression tests for each role against every HTML and JSON route, including direct requests that bypass hidden navigation.
2. Test cookie flags behind the actual HTTPS reverse proxy and verify HTTP is redirected or blocked.
3. Test CSRF against all state-changing routes, including requests with missing, malformed, same-site, and cross-site Origin headers.
4. Add automated login-throttling tests and verify audit storage remains bounded.
5. Add ingestion stress tests for oversized/malformed records, huge sessions, log rotation, and concurrent purge/poll.
6. Test filesystem permissions on supported deployment platforms and ensure runtime secrets/database/logs are not committed.
7. Add Python CI tests, dependency auditing, and static analysis; confirm the latest workflow run succeeds.
8. Perform a deployment review: VPN/reverse proxy, TLS, trusted proxy configuration, host firewall, service account privileges, backup protection, and no public exposure of debug/docs endpoints unless intended.

## Audit limitations

This is a static repository review, not a formal penetration test or a guarantee of security. No production deployment, external attack surface, proxy configuration, filesystem permissions, secret history, or live dependency advisory database was inspected. Runtime testing and a deployment-specific review remain necessary.
