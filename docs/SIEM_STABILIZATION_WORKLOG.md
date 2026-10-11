# SIEM Stabilization Work Log

**Status date:** 2026-10-11  
**Working PR:** [#5 — Harden SIEM API defaults and malformed event handling](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5)  
**Working branch:** `fix/siem-api-hardening`  
**Target branch:** `siem-integration`  
**Status:** Draft / open / not merged

## 1. Purpose and working rules

This document records the SIEM integration and hardening work completed so far, the checks performed, failures discovered, and the next work planned. It is intended to be the handoff record for continuing remotely while local-machine testing is unavailable.

The working approach is to keep changes on the PR branch for review and later testing. Do not merge this PR until the user has reviewed and tested it. Do not claim tests passed unless the relevant run confirms it. Avoid destructive changes to user data and tracked Cowrie fixtures.

## 2. Architecture decision

The agreed architecture is:

- **Node.js/Express is the authoritative SIEM backend.**
- **Retain the Python implementation** until its unique functionality has been inventoried and assessed.
- Do not remove, replace, or silently deprecate Python/FastAPI functionality during this hardening work.
- Keep the SIEM dashboard and API work on the integration/PR branch pending validation.

## 3. Earlier integration and detection work

The following earlier work is part of the current baseline:

- Phase 3 detection-engineering PR #3 was merged into `siem-integration` at commit `7ee47c63a146764cc744bdf8e60d5350102c82a7`.
- Detection matching was made case-insensitive, including relevant reconnaissance, download, network discovery, SSH client, account-creation, pivot and persistence command cases.
- Download-to-execution correlation preserves command order and requires the download to precede execution.
- A prior local backend run reported **44 tests passing**. This is historical evidence for that earlier code state, not proof that the current PR passes.
- Commit references recorded from the earlier work include `10809c9` for case-insensitive detection and `b726d76` for ignoring `node_modules`.

## 4. PR #5 changes currently on the branch

### 4.1 Express API parsing and malformed input

In `siem-dashboard/backend/routes/api.js`:

- Added a safe JSON parsing helper with a fallback for non-string and malformed values.
- Ensured persisted values that parse to `null`, primitives, or arrays are not treated as event objects.
- Applied safe parsing across event, session, geography, FIM, and MITRE-related API paths.
- Guarded FIM command-input processing so an unexpected non-string `input` value does not cause processing to fail.

Regression coverage in `siem-dashboard/backend/test-api.test.js`:

- Inserts malformed JSON into the raw event store and checks that `/api/events` remains HTTP 200 and provides null MITRE context for that malformed record.
- Inserts a valid JSON `null` payload for a Cowrie command-input event and checks that `/api/fim` remains HTTP 200.
- Uses unique temporary database/log paths and cleanup hooks so API tests do not overwrite or delete tracked fixture data.

### 4.2 API network defaults and browser-origin controls

In `siem-dashboard/backend/server.js`:

- Defaults the API bind host to `127.0.0.1`.
- Requires an explicit `HOST=0.0.0.0` setting for intentional container/remote binding.
- Reads a comma-separated `CORS_ORIGINS` allowlist, defaulting to `http://localhost:3000`.
- Applies the configured origin allowlist to browser CORS and WebSocket origin checks.
- Requests without an Origin header are not rejected by the origin check; this is not authentication and must not be treated as such.

Security boundary documented in `siem-dashboard/SECURITY.md`:

- The API does **not** currently provide application-level authentication or authorization.
- CORS is not authentication.
- Do not expose the API to untrusted networks. Use an authenticated reverse proxy or VPN before remote access until native authentication/authorization and RBAC are implemented.

### 4.3 Frontend API URL configuration

Added `siem-dashboard/frontend/lib/api.ts` with `API_BASE_URL`, using `NEXT_PUBLIC_API_BASE_URL` when configured and defaulting to `http://localhost:5000`.

Updated dashboard pages to use this shared base URL rather than hardcoding the API host:

- `app/actors/page.tsx`
- `app/alerts/page.tsx`
- `app/explorer/page.tsx`
- `app/fim/page.tsx`
- `app/geomap/page.tsx`
- `app/live/page.tsx`
- `app/mitre/page.tsx`
- `app/page.tsx`
- `app/sessions/[id]/page.tsx`
- `app/sessions/page.tsx`
- `app/settings/page.tsx`
- `app/vulnerabilities/page.tsx`

The geography style typing and MITRE technique/tactic data typing were also corrected after the production build exposed TypeScript errors.

### 4.4 Continuous integration

Added `.github/workflows/siem-backend-tests.yml`, which runs for relevant pull-request changes and pushes to `siem-integration` and `fix/siem-api-hardening`.

Jobs:

- **backend-tests:** Node.js 22, `npm ci`, then `timeout 120s npm test`; job timeout is five minutes.
- **frontend-build:** Node.js 22, `npm ci`, then `npm run build`.

The workflow uses `actions/checkout@v4` and `actions/setup-node@v4`.

The test timeout was added to prevent a hung Node test process from consuming an unbounded CI job. A timeout is not a substitute for fixing failing tests or leaked handles.

### 4.5 Ingestion test isolation and cleanup

In `siem-dashboard/backend/test-ingestion.test.js`:

- Added an OS temporary directory for the ingestion test database and Cowrie log.
- Redirected secondary log files used by the suite into that temporary directory.
- Added tracking of created ingestion service instances.
- Added an after-test cleanup hook that closes tracked services, closes the DB, and removes only the test's temporary directory.

This was necessary because the earlier tests manipulated a tracked fixture under `test_data/`; test failures could also skip normal cleanup and leave file watchers alive. The current isolation change avoids deliberately writing to tracked Cowrie fixtures.

## 5. CI validation results

Latest confirmed run for commit `0a98e255241d10d1ee157efe150110e35ceb6b33`:

[GitHub Actions run 38134477968](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38134477968)

| Check | Result | Notes |
|---|---|---|
| Frontend build | **Passed** | Production build completed successfully after TypeScript fixes. |
| Backend tests | **Failed** | Four ingestion subtests failed; the test command then timed out with exit code 124. |

Failing ingestion tests:

1. **Test 12 — Alert retained when criteria are no longer met:** expected one alert, found zero at the initial alert-generation assertion.
2. **Test 13 — Serialize overlapping ingestion triggers:** expected two events, found zero.
3. **Test 14 — In-place truncation while running:** expected one event after truncation, found zero.
4. **Test 15 — Restart-safe rotation recovery:** expected two events, found one.

The logs also showed a subsequent `SQLITE_MISUSE: Database is closed` message during teardown after failures, indicating lifecycle/cleanup behavior still needs review. The after-test cleanup reduced the risk of leaked watchers, but the latest run still ended in failure.

## 6. Current investigation findings and hypotheses

These are findings/hypotheses, not yet verified fixes:

- Test 11 deletes and recreates the log path. The existing ingestion instance may still be attached to the old file descriptor/watcher, while later tests continue using the same instance. This is a strong candidate for the missing events in tests 12–14.
- Test 14 truncates the file in place. The ingestion service must detect the size decrease even if the inode is unchanged, reset its offset, advance the generation safely, and process the new record.
- Test 15 simulates a restart after renaming a log with unread content. The recovery path must consume unread bytes from the rotated inode and checkpoint them before processing the new file. The observed single event means this recovery expectation is not currently met.
- Test 12's failure happens before it reaches the historical-alert-retention assertion: its first assertion cannot find the alert. Therefore, do not interpret it as evidence that alert retention itself is broken; first ensure the event is ingested and alert evaluation runs.
- Do not solve these failures by weakening assertions, adding arbitrary sleeps, or increasing timeouts alone. Fix service lifecycle/ingestion semantics and retain meaningful regression tests.

## 7. Dependency/runtime warnings to investigate separately

The previous CI log included an `EBADENGINE` warning: `geoip-lite@2.0.3` declares Node.js `>=24`, while the workflow uses Node.js 22. This mismatch should be resolved deliberately by checking package compatibility and project runtime requirements.

Dependency audit summaries previously reported vulnerabilities in backend and frontend dependency trees. The exact advisory paths and fix availability have not yet been fully reviewed. Do not run `npm audit fix --force` or make broad dependency upgrades without examining the advisory details and their breaking-change risk.

## 8. User-local work protection

The user has said their PC is unavailable and they want changes made remotely on the PR branch. Previously reported local files/changes to preserve include:

- Modified `siem-dashboard/backend/test_data/api_test_cowrie.json`
- Modified `siem-dashboard/backend/test_data/test_cowrie.json`
- Modified `siem-dashboard/backend/test_data/test_cowrie.json.1`
- Untracked root-level `backend/` and `frontend/` directories in the local `hyshield-siem` workspace
- Existing stash `stash@{0}` labelled `temporary test fixture changes`

Do not reset, clean, overwrite, or discard any of those local changes. The current remote test isolation is intended to protect tracked repository fixtures as well.

## 9. Next work plan

Work in this order, keeping all fixes on `fix/siem-api-hardening` and PR #5 open/draft:

1. **Fix ingestion test lifecycle first.** Review test 11's unlink/recreate scenario and ensure the test either uses a fresh ingestion service after inode replacement or explicitly exercises the production watcher/re-watch behavior. Register every created service with the cleanup tracker.
2. **Fix and verify in-place truncation.** Check the production `processNewData` path for file-size/inode checks, offset resets, generation increments, and checkpoint writes. Preserve protection against duplicate event IDs across generations.
3. **Fix rotated-file recovery.** Verify recovery of unread bytes from the old inode, checkpoint completion, and subsequent processing of the newly created active log. Avoid swallowing recovery errors without useful diagnostics.
4. Run the backend test suite and frontend build through CI. Record each run's commit SHA and results here. Do not call the backend green until all tests pass and the command exits normally without timeout.
5. Investigate the Node engine mismatch and review audit advisories; make only justified, tested dependency changes.
6. Continue the wider SIEM review after these regressions are green: API authentication/authorization, frontend API error handling, deployment configuration, and a feature-by-feature assessment of the retained Python implementation.

## 10. Completion criteria for this phase

This phase is ready for review only when:

- Frontend production build passes.
- Backend tests pass without assertion failures, timeout, or open-handle hang.
- Test fixtures are isolated and no test deletes tracked sample data.
- Ingestion behavior is validated for normal append, overlapping triggers, in-place truncation, rotation with unread data, and restart recovery.
- Security limitations are documented accurately and the API is not represented as authenticated.
- PR #5 remains unmerged until the user reviews and later tests it.


## 11. Follow-up after documenting the work

After adding this work log, commit `d47878b650fe41f0a8a7e4f59522d5e2a3474cce` updated the ingestion test lifecycle to recreate the ingestion service after the test deletes and recreates the log path, and ensured newly created services are tracked for cleanup.

The resulting CI run, [38134810579](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38134810579), completed with:

- **Backend tests: passed** — 44 passed, 0 failed; command exited successfully.
- **Frontend production build: passed.**

This confirms the four previously failing ingestion subtests passed on that commit. It does not by itself prove every production rotation scenario is correct; retain the tests and review the ingestion lifecycle before considering the SIEM fully stabilized.

The run also confirmed the dependency engine warning: `geoip-lite@2.0.3` declares Node.js `>=24.0.0`, while CI had been using Node 22. The workflow has now been updated to Node 24 in both backend and frontend jobs (commit `d4f622e96d9762fbcdc7ab91b1277b6e71d8dc56`). **Validation under Node 24 is pending** and must be checked before marking the workflow fully green on the new runtime.

Immediate next steps:
1. Confirm both CI jobs pass using Node 24 and verify the `EBADENGINE` warning is gone.
2. Review the full dependency audit reports and prioritize direct/transitive advisories without using forced upgrades.
3. Review ingestion shutdown/recovery lifecycle and error reporting, including the currently swallowed errors in rotated-file recovery, without weakening the regression tests.
4. Continue the API authorization and deployment review. The API remains unauthenticated; keep the documented network exposure restriction in place.
5. Inventory Python/FastAPI functionality before any consolidation/removal; Node.js/Express remains the agreed authoritative backend.


## 12. Node 24 validation and further test hardening

The workflow was switched to Node 24 because `geoip-lite@2.0.3` declares Node `>=24`. CI runs on the Node 24 commit confirmed the frontend build passed and the backend tests exposed one additional fixture issue in test 18: the operating system reused an inode number from a temporary file that an earlier test had deleted. The synthetic recovery checkpoint then collided with the stale checkpoint row (SQLite unique constraint), rather than failing because of the production recovery behavior itself.

Commit `178599dbbfe9e4db01f858d885b1b4ffc2df8c20` updates test 18 to remove only a stale checkpoint row for the reused inode before assigning that inode to the synthetic recovery checkpoint. The same branch also now logs candidate-file inspection and rotated-file stat errors instead of silently swallowing them (`fd574e2e5f9c8174d8bfc6d0b98da86687e2d9b1`).

Validation completed successfully in workflow run [38134939532](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38134939532): **backend tests passed (44 passed, 0 failed) and the frontend production build passed under Node 24**. The backend install logs no longer show the previous `EBADENGINE` warning.

Latest work sequence:
- `037f144`: added this stabilization work log.
- `d47878b`: recreated ingestion service after test log replacement and tracked all service instances for cleanup; CI run 38134810579 passed all 44 tests and the frontend build on Node 22.
- `d4f622e`: switched CI jobs to Node 24 to match the dependency engine requirement.
- `dba885e`: documented the earlier pass and the runtime follow-up.
- `fd574e2`: made rotated-file recovery inspection/stat failures visible in logs.
- `178599d`: made test 18 resilient to OS inode reuse; workflow run 38134939532 passed both backend tests and frontend build under Node 24.

The PR remains draft and unmerged. Local user changes remain out of scope and must be preserved.


## 13. Latest verified state

As of workflow run [38134939532](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38134939532) for code commit `178599dbbfe9e4db01f858d885b1b4ffc2df8c20`:

- Backend: **passed, 44 passed / 0 failed**.
- Frontend: **production build passed**.
- Node runtime: **Node 24**, matching the `geoip-lite` engine declaration; no `EBADENGINE` warning was found in the backend install/test log.
- Ingestion recovery error reporting: candidate-file inspection and stat failures are now logged rather than silently discarded.
- Documentation: this work log records the validation and remaining risks.

The latest documentation-only commit is `8400d9374f73976ca66885c30f87506f67a6232d`. The PR is still draft and unmerged. Remaining work is dependency advisory review, broader ingestion lifecycle review, and API authentication/authorization design; none of these should be described as complete.


## 14. Dependency audit results

The new CI dependency-audit matrix ran successfully for both projects in workflow [38135066228](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38135066228). These are audit findings, not test failures.

### Backend

The audit reports **2 vulnerabilities: 1 critical and 1 moderate**, both transitive and both marked as having a fix available:

- `proxy-addr` — critical; advisory [GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h), IPv4-mapped IPv6 trust-subnet/IP spoofing issue; affected range reported as `1.1.0 - 2.0.7`, fixed version is at least `2.0.8`.
- `qs` — moderate; advisories [GHSA-x5fp-wj9c-mxmx](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx) and [GHSA-4mjr-xmp4-gh2g](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g); the audit says a fix is available.

### Frontend

The audit reports **10 vulnerabilities: 9 high and 1 critical**. The most urgent direct dependency finding is:

- `next` — critical, currently locked at `16.3.2`; audit says affected versions include `16.0.0 - 16.3.7` and a non-major fix is available in `16.4.0`. The reported advisories include multiple issues affecting image optimization, `next/og`, cache handling, self-hosted SSG/ISR, development-server information disclosure, and SSRF. Review [GHSA-vcvr-r3jv-pc5j](https://github.com/advisories/GHSA-vcvr-r3jv-pc5j), [GHSA-3w37-wq28-93x7](https://github.com/advisories/GHSA-3w37-wq28-93x7), and [GHSA-cjq9-62q9-8jv4](https://github.com/advisories/GHSA-cjq9-62q9-8jv4) among the advisories surfaced by the audit.
- `eslint-config-next` and transitive linting dependencies `@next/eslint-plugin-next`, `fast-glob`, `braces`, and `micromatch` are also reported. The audit suggests a major downgrade path for `eslint-config-next`; do **not** apply that downgrade blindly because the project is on Next 16.
- Other fixable transitive findings include `js-yaml`, `source-map-js`, and `sharp`.

### Safe remediation plan

Do not run `npm audit fix --force` or accept an automatic major downgrade. Next actions:

1. Update Next.js and its matching `eslint-config-next` together to a compatible patched release (audit indicates Next `16.4.0` or later) and regenerate the lockfile with npm.
2. Apply non-breaking `npm audit fix` updates in each project, inspect the resulting package/lockfile diff, and rerun the complete backend suite and frontend production build.
3. Verify the audit again after updates and document any remaining advisory with a reasoned risk decision.
4. Remediate backend `proxy-addr` and `qs` through compatible transitive updates; inspect the dependency path before changing direct package versions.

The audit workflow currently reports findings without failing the build, so the main backend/frontend checks can still pass while advisories remain. **Dependency remediation is not yet complete.**


## 15. Watcher shutdown fix and regression coverage

Further review found that `watchFile()` scheduled a bare five-second retry with `setTimeout` when the Cowrie log did not exist. That timer was not stored, so `closeFile()` could not cancel it; a stopped ingestion instance could keep a timer alive and later call `watchFile()` again.

Commit `f04d4988363e5f2ea52c815972f6b3fc05aafafb` stores this as `watchRetryTimer`, avoids multiple pending retry timers, clears it once the file appears, and cancels it on shutdown. Commit `0f519b376cc8d5940b0cc1bd4046e32916be73b1` adds a regression test that verifies a missing-file retry is scheduled and that closing the service clears the timer and prevents restart.

CI run [38135066228](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38135066228) passed the backend suite and frontend build for the commit before this timer fix; the timer fix and new test require the next CI run to validate.

## 16. Audit CI status

The dependency-audit job has been added to the workflow and reports findings without masking the backend/frontend test results. On the audit run:

- Backend: 2 advisories (1 critical `proxy-addr`, 1 moderate `qs`), both marked fixable.
- Frontend: 10 advisories (9 high, 1 critical), including critical `next` advisories for the locked `16.3.2` version. The audit indicates Next `16.4.0` is a non-major fix for the current Next line; the current `eslint-config-next` fix suggestion is a major downgrade and must not be applied blindly.
- Audit results are detailed in Section 14. Package upgrades and regenerated lockfiles have **not** yet been committed. Resolve the advisories with compatible updates and validate the resulting lockfiles, tests, and production build before calling dependency security complete.
