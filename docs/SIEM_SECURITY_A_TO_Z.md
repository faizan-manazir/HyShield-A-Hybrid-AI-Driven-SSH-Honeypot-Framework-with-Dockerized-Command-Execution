# HyShield SIEM Integration and Security — A–Z Documentation

**Documentation snapshot:** 11 October 2026  
**Repository:** [HyShield](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution)  
**Scope:** SIEM integration, API hardening, authentication and authorization, dashboard session handling, WebSocket authentication, CI/test status, operational safety, known limitations, and next steps.

> **Important:** This document records the implementation and CI state known at the snapshot date. Passing CI is not equivalent to browser end-to-end validation or a production security review. Do not expose the service publicly based on CI results alone.

## 1. Executive summary

HyShield is a hybrid AI-driven SSH honeypot framework. The SIEM work connects honeypot/telemetry functionality to a dashboard and adds security controls around the SIEM API.

Recorded work includes:
- SIEM integration and dashboard/API changes.
- Request parsing and API security hardening.
- Application authentication using scrypt password verification and signed short-lived bearer tokens.
- Backend authorization for protected routes and admin-only mutation requests.
- Login throttling and defensive HTTP headers.
- Frontend login/session handling and authenticated WebSocket connection setup.
- Regression tests and GitHub Actions CI checks.

The authentication foundation is merged into `main`. Manual browser testing, security documentation cleanup, and deployment review remain necessary.

## 2. Repository map

Relevant files:
- `siem-dashboard/backend/auth.js` — password verification, token creation/verification, and auth middleware.
- `siem-dashboard/backend/server.js` — Express API, route protection, request hardening, and WebSocket authentication.
- `siem-dashboard/backend/test-api.test.js` — API/authentication regression coverage.
- `siem-dashboard/backend/test-security.test.js` — request/security behavior tests.
- `siem-dashboard/frontend/components/AuthShell.tsx` — session checks, API fetch wrapper, expiry/401 handling.
- `siem-dashboard/frontend/app/login/page.tsx` — login UI and token storage.
- `siem-dashboard/frontend/components/Sidebar.tsx` — logout UI.
- `siem-dashboard/frontend/app/live/page.tsx` — authenticated WebSocket connection setup.
- `siem-dashboard/frontend/app/page.tsx` — dashboard metrics/error handling.
- `siem-dashboard/SECURITY.md` — security guidance (updated in this documentation PR).

## 3. Local-work preservation rules

The original local working copy previously had valuable uncommitted changes:

```text
## siem-integration...origin/siem-integration
 M test_data/api_test_cowrie.json
 M test_data/test_cowrie.json
 M test_data/test_cowrie.json.1
?? ../../backend/
?? ../../frontend/
```

A `stash@{0}` was also present. Preserve these changes and the stash.

- Do not run `git reset --hard`, `git clean -fd`, or other broad destructive cleanup commands on the original working copy.
- Do not overwrite or delete the original working copy.
- The separate ZIP test copy at `C:\Users\Faizan\Downloads\HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution-fix-siem-api-hardening` has no `.git` directory. It is a test copy; do not initialize it as a Git repository.
- Do not touch `C:\Users\Faizan\hyshield-siem`, which was identified as unnecessary.
- Check `git status` before and after local Git operations.

## 4. Phases and scope

### Phase 1 — API request hardening
Recorded controls include strict JSON parsing, a 1 MB JSON body limit, controlled malformed/oversized request errors, CORS allowlisting, defensive headers, disabled Express `X-Powered-By`, and API error handling.

### Phase 2 — Authentication foundation
Recorded controls include scrypt password verification, signed short-lived bearer tokens, a public login endpoint, protected API routes, administrator-only mutation requests, analyst read-only access, in-memory login throttling, frontend token/session handling, and WebSocket authentication.

### Phase 3 — Detection engineering (recorded project context)
Previously recorded work/focus includes authentication and reconnaissance detections, suspicious command detection, correlation, MITRE ATT&CK mappings, ingestion checkpoint/log-rotation recovery, and alert quality. Notes describe a four-dimension correlation score with each dimension scored 0–25 and a composite score of 0–100. Categories mentioned include brute force, reconnaissance, credential theft, downloads, execution, evasion, persistence, and cryptomining.

These Phase 3 notes are project-history context, not a guarantee that every detector is present and validated on the current `main` branch. Verify the branch and source files before making that claim.

## 5. Pull request and CI record

| PR | Purpose | Recorded status |
|---|---|---|
| [#5](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5) | SIEM API hardening | Merged into `siem-integration`; squash commit `d0f447b6ad771c8ab0a24e2616fbb87ae04f47c2`; CI run [38153868094](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38153868094) passed four jobs |
| [#6](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/6) | SIEM integration | Merged into `main`; recorded backend tests, frontend build, and both dependency audit jobs passed in run `38154749090` |
| [#7](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/7) | Phase 1 API hardening | Closed without merge on 11 October 2026 because the relevant changes were included through PR #8 |
| [#8](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/8) | Phase 2 authentication foundation | Merged into `main`; squash commit `d5f6ead2f933182b7187d0745a173fbf484082e8`; recorded merge time 11 October 2026, 17:37:11 UTC |

The latest recorded PR #8 CI run was [38160318013](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38160318013), checking head commit `dc2aa62563f31f5273afe8c3946929d2ecc26fe9`. All four jobs passed: backend tests, frontend production build, backend dependency audit, and frontend dependency audit.

CI passing confirms those workflow jobs passed for the checked commit. It does not prove browser workflows, deployment configuration, or detection quality are fully validated.

## 6. Authentication configuration

The backend reads these environment variables:

| Variable | Purpose |
|---|---|
| `SIEM_ADMIN_USERNAME` | Configured administrator username |
| `SIEM_ADMIN_PASSWORD_HASH` | scrypt hash formatted as `scrypt$<salt-hex>$<hash-hex>` |
| `SIEM_AUTH_SECRET` | HMAC signing secret, validated to be at least 32 bytes |

Never commit a plaintext password, password hash, token, or signing secret. A password hash is still sensitive authentication material.

Generate a fresh random secret with Node.js:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Store it in a protected environment configuration or secret manager. Do not reuse the same secret across environments.

If the backend reports **“Authentication is not configured”**, confirm all three variables are set in the environment of the backend process itself. Setting a variable in a different PowerShell window does not update an already-running process. Restart the backend after configuration changes; do not hardcode credentials to bypass the error.

A previously discussed local test password, `FYP_login`, is weak and must remain local-only. Use a unique, strong password before any remote access.

## 7. Token and route behavior

- `POST /api/auth/login` is the public login endpoint.
- The health endpoint remains public for health checking.
- Other `/api` routes require authentication.
- Tokens are signed using HMAC-SHA256 and have a 15-minute lifetime.
- Mutating HTTP methods require the administrator role; analyst access is read-only.
- The initial configuration is a single-admin bootstrap, not a complete multi-user identity lifecycle.
- Server-side token revocation was not implemented in the recorded version; a token may remain valid until expiry unless another check rejects it.

## 8. Login throttling

The recorded implementation:
- limits failed login attempts to 10 per client in a 15-minute window;
- returns HTTP 429 with a `Retry-After` header when throttled;
- caps the in-memory client map at 10,000 entries and prunes/evicts entries;
- logs success/failure without logging credentials.

This throttle resets when the process restarts and is not a substitute for gateway/reverse-proxy rate limiting. Client identity and trusted-proxy configuration must be reviewed before deployment behind a proxy.

## 9. Request hardening and browser headers

Recorded API hardening:
- strict JSON parsing;
- request body limit of 1 MB;
- controlled HTTP 400 errors for malformed JSON and HTTP 413 for oversized bodies;
- CORS allowlist, with rejected origins returning HTTP 403;
- Express `X-Powered-By` disabled;
- defensive response headers including `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and `Permissions-Policy`.

These are useful controls, not a complete security boundary. A full Content Security Policy (CSP) review was not recorded as complete. CORS is a browser policy and does not authenticate non-browser clients.

## 10. WebSocket authentication

The client must send an authentication message as its first WebSocket message within five seconds. It must contain a valid bearer token. Clients that fail authentication are closed with code `1008`.

The frontend message has this shape:

```json
{
  "type": "auth",
  "token": "<access-token>"
}
```

The server acknowledges an authenticated connection. That acknowledgement does not prove that live event broadcasting is complete; event subscription and delivery need separate verification. Reverse-proxy WebSocket behavior and origin configuration also need review before remote deployment.

## 11. Frontend session behavior

`AuthShell.tsx` checks token and expiry, manages login redirects, and installs a stable `window.fetch` wrapper. It attaches the bearer token only to the configured API origin and `/api/` paths, skips the login endpoint, and clears the session/redirects on HTTP 401 or expiry.

The login page stores the returned token and expiry in `sessionStorage`. The sidebar exposes logout. The live page reads the token and sends it as the first WebSocket message.

A transient **“Authentication required”** message after sign-in was reported. A route-transition/fetch-wrapper fix was pushed in commit `dc2aa62563f31f5273afe8c3946929d2ecc26fe9`. CI passed for that commit, but the user’s browser flow still needs manual verification.

**Session-storage risk:** `sessionStorage` is accessible to JavaScript running on the same origin. An XSS vulnerability could expose the token. Treat this as a known limitation.

## 12. Dashboard data resilience

The dashboard page was adjusted to validate metrics/actors payloads and show API/authentication errors rather than crashing when expected fields are missing (for example, when `data.metrics` is undefined).

Verify normal responses, empty/incomplete payloads, unauthorized responses, and backend/network failures in the browser Network panel and console.

## 13. Automated test coverage recorded

Files:
- `siem-dashboard/backend/test-api.test.js`
- `siem-dashboard/backend/test-security.test.js`

Recorded coverage includes authentication, valid/invalid credentials, protected endpoints, public health, events/alerts/actors/metrics, ingestion/session paths, malformed persisted payloads, FIM, API errors, malformed/oversized JSON, headers, CORS, WebSocket authentication, login throttling, expired tokens, and analyst read-only permissions.

Automated tests do not prove every browser route works, that production proxy settings are correct, that secrets are strong, that live event broadcasting is complete, or that detection rules perform well on real telemetry.

## 14. Manual end-to-end checklist

### Login/session
- [ ] Logged-out user sees the login page.
- [ ] Incorrect credentials produce a safe error.
- [ ] Valid credentials open the dashboard without a manual reload.
- [ ] Refresh and route navigation work without a transient authentication error.
- [ ] Expired token redirects to login.
- [ ] Logout clears the session and protected requests are rejected.
- [ ] No credentials or bearer tokens appear in logs.

### API authorization
- [ ] Missing/invalid token is rejected on a protected endpoint.
- [ ] Authenticated request succeeds.
- [ ] Health endpoint works without a token.
- [ ] Analyst cannot perform mutations.
- [ ] Malformed JSON is rejected with a controlled error.
- [ ] Oversized JSON is rejected.
- [ ] Disallowed CORS origin is rejected.

### WebSocket/dashboard
- [ ] Unauthenticated WebSocket is closed.
- [ ] Invalid token is rejected.
- [ ] Valid token sent as the first message within five seconds is acknowledged.
- [ ] Live event delivery is tested separately from connection authentication.
- [ ] Missing/incomplete metrics do not crash the dashboard.
- [ ] A 401 clears session and redirects.

For failures, record commit SHA, date, browser, reproduction steps, console output, and relevant Network/WebSocket frames. Redact tokens and credentials.

## 15. Local testing workflow

Confirm the current README and package scripts before choosing exact commands. A safe general process:

1. Use the separate ZIP test copy for isolated tests.
2. Inspect the README and package scripts before installing or running services.
3. Set authentication variables in the same environment that starts the backend.
4. Start backend and frontend using the documented project commands.
5. Keep the backend on `127.0.0.1` for local testing.
6. Test login, protected routes, logout, expiry, and WebSocket authentication.
7. Run the documented automated test suite and frontend production build.
8. Check logs and ensure credentials/tokens are not logged.
9. Check `git status` in the original working copy before/after operations.

Keep local environment files out of source control and verify this with `git status` before committing.

## 16. Network and deployment boundary

The backend defaults to `127.0.0.1`. **No public deployment or public exposure was approved or performed in the recorded work.**

Do not bind to `0.0.0.0` or open a firewall port as a shortcut. Before remote access, review:
- private VPN/network or strict source allowlisting;
- TLS termination and a maintained reverse proxy/gateway;
- edge rate limiting and request limits;
- CORS origins and trusted proxy settings;
- WebSocket proxy and origin behavior;
- protected secret storage and rotation;
- monitoring, durable audit retention, recovery, and incident procedures;
- a production security review and explicit deployment approval.

Prefer VPN/private network access. Keep the API on loopback or a private container network behind the reviewed proxy.

## 17. Known limitations and residual risks

1. `sessionStorage` token is JavaScript-accessible and can be exposed by XSS.
2. Server-side token revocation was not implemented in the recorded version.
3. Login throttling is in-memory and resets on restart.
4. Authentication is a single-admin bootstrap, not a full user-management system.
5. Durable/tamper-resistant audit-log retention was not established.
6. A complete CSP review was not recorded.
7. Browser-level end-to-end validation is outstanding.
8. Live WebSocket event broadcasting was not confirmed.
9. Production proxy/TLS/network configuration has not been validated.
10. Detection quality requires empirical false-positive/false-negative testing.
11. Phase 3 notes require branch/file verification before claiming all items are in `main`.
12. The original local working copy contains valuable uncommitted changes that must be preserved.

## 18. Detection engineering validation

Recorded Phase 3 focus includes authentication, reconnaissance, suspicious command detection, event correlation, MITRE ATT&CK mapping, ingestion checkpoint/log-rotation recovery, and alert quality.

Build a reproducible test corpus containing benign activity, individual suspicious events, multi-event sequences, delayed/reordered/duplicate events, log rotation, and malformed input. Record expected alerts and correlation scores. Measure false positives, false negatives, event-to-alert latency, recovery after rotation, and repeatability. A rule existing or a unit test passing is not by itself proof of operational effectiveness.

## 19. Troubleshooting

### “Authentication is not configured”
- Verify all three environment variables.
- Confirm they are available to the backend process, not only another terminal.
- Check the hash format: `scrypt$<salt-hex>$<hash-hex>`.
- Restart the backend after changes.
- Do not hardcode credentials.

### “Authentication required” after login
- Confirm the browser uses the latest frontend build.
- Inspect the login response and first protected request in Network tools.
- Check token storage/expiry and API base URL.
- Verify the bearer header is attached to protected API calls but not login.
- Test navigation and refresh without using manual reload as a workaround.
- Fix commit: `dc2aa62563f31f5273afe8c3946929d2ecc26fe9`; browser verification remains necessary.

### `data.metrics` is undefined
- Inspect the actual response in the Network panel.
- Check backend version and logs.
- Confirm incomplete/empty responses are handled.

### WebSocket closes immediately
- Send the auth JSON as the first message, within five seconds.
- Confirm the token is valid and not expired.
- Inspect server logs and WebSocket frames.
- Test event delivery separately.

### CI passes but dashboard fails
- Confirm browser commit matches the tested commit.
- Check frontend console and Network panel.
- Verify API base URL, CORS, and backend environment.
- Capture exact reproduction steps.

## 20. Git collaboration and change safety

- Use a dedicated feature/documentation branch and a focused PR.
- Inspect the diff before merging.
- Never commit credentials, tokens, generated secrets, or sensitive logs.
- Check `git status` before and after local changes.
- Do not run destructive cleanup commands on the original working copy.
- Do not initialize the ZIP test copy as a Git repository.
- Re-check CI and merge history before claiming a change is complete.

## 21. Recommended next steps

1. Merge this documentation PR after review and CI checks.
2. Complete the manual browser E2E checklist.
3. Use a strong unique password and a fresh random signing secret before remote access.
4. Verify the current branch/files for all Phase 3 detection items.
5. Measure detection false positives/negatives with a reproducible dataset.
6. Review and test any deployment architecture before enabling remote access.
7. Re-run CI and inspect the final diff for every code/documentation PR.

## 22. Remote deployment readiness checklist

- [ ] Strong unique administrator password configured.
- [ ] Fresh random `SIEM_AUTH_SECRET` of at least 32 random bytes.
- [ ] Secrets stored outside source control.
- [ ] Backend process loads required environment variables.
- [ ] Reviewed frontend/backend commit versions match.
- [ ] Login, expiry, logout, and 401 behavior tested manually.
- [ ] Admin/analyst permissions tested.
- [ ] WebSocket auth and live event delivery tested separately.
- [ ] TLS/reverse proxy reviewed.
- [ ] Network access restricted to approved sources/private access.
- [ ] Edge rate limiting enabled.
- [ ] CORS allowlist reviewed.
- [ ] CSP and security headers reviewed.
- [ ] Logs contain no credentials/tokens.
- [ ] CI and dependency audits passed.
- [ ] Recovery, rotation, and incident procedures documented.
- [ ] Deployment explicitly approved.

## 23. References

- [Repository](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution)
- [PR #5](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5)
- [PR #6](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/6)
- [PR #7](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/7)
- [PR #8](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/8)
- [Latest recorded PR #8 CI run](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38160318013)

## Appendix — glossary

- **API:** Application Programming Interface.
- **Bearer token:** Token sent by a client to prove it authenticated.
- **CORS:** Browser policy governing cross-origin requests.
- **CI:** Continuous Integration.
- **FIM:** File Integrity Monitoring.
- **HMAC:** Message authentication code built from a hash and secret key.
- **scrypt:** Password-based key derivation function used for password verification.
- **SIEM:** Security Information and Event Management.
- **WebSocket:** Persistent bidirectional client/server connection.
- **XSS:** Cross-site scripting; attacker-controlled JavaScript executing in a trusted origin.
