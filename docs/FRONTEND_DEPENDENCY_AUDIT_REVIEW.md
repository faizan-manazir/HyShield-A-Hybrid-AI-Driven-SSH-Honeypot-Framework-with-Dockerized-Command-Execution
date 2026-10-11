# Frontend Dependency Audit Review

**Date:** 11 October 2026  
**Branch:** `fix/siem-api-hardening`  
**PR:** [#5 — Harden SIEM API defaults and malformed event handling](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/pull/5)

## Latest CI evidence

GitHub Actions run [38150282876](https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/38150282876) completed successfully for the PR merge commit containing head commit `5d19353ee0e25085fa01464a6b2e192f755b726e`.

- Backend tests: passed.
- Frontend production build: passed.
- Backend dependency audit: **0 vulnerabilities**.
- Frontend dependency audit report: **5 high-severity entries**.

The audit workflow's successful status means the report was generated; it does not mean all reported findings were fixed.

## Findings

The five frontend entries form one transitive development/lint-tooling chain:

1. `braces` — high; [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), affected versions through 3.0.3.
2. `micromatch` — via `braces`.
3. `fast-glob` — via `micromatch`.
4. `@next/eslint-plugin-next` — via `fast-glob`.
5. `eslint-config-next` — direct development dependency, via `@next/eslint-plugin-next`.

The audit output says no patched `braces` release is available. npm suggests `eslint-config-next@14.2.35` as a fix, which is a semver-major downgrade and is incompatible with the project's `next@16.4.0` version line.

## Decision

**Do not run `npm audit fix --force` and do not downgrade `eslint-config-next` to 14.x.** That is not a compatible, verified remediation and could break lint configuration. No dependency versions were changed during this investigation.

The available evidence does not establish a safe compatible package-only fix yet. Keep the advisory visible and monitor for an upstream patch or a compatible dependency-tree change. Do not suppress the audit or describe the risk as fixed.

If a temporary exception is later proposed, it should be explicitly approved, narrowly scoped to this advisory, time-limited, and contingent on verifying whether `braces` is absent from the production runtime dependency tree. A development-only dependency is not automatically harmless, but the risk differs from a package shipped and used by the production server.

## Status

- Backend audit: clean in the checked run.
- Frontend: build and CI pass, but the transitive development-tooling advisory remains unresolved.
- PR #5: remains open, draft, and unmerged.
- Next action: revisit the advisory when an upstream fix or compatible dependency update is available, then rerun the audit, frontend build, and backend tests.
