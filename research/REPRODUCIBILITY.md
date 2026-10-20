# Reproducibility and evidence ledger

## Manuscript
- Draft: research/paper.md
- References: included at the end of the manuscript; publisher records verified for the cited recent research.
- Status: completed evidence-grounded manuscript draft; author metadata and target-venue formatting still require author confirmation.

## Repository under test
- Repository: faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution
- Branch: audit/forensic-ingestion-tests
- Corrected fixture commit: b0e32d3b7e2a0d2ba23ff6bac08f05ee51ab0bdf
- CI run covering the source-to-SQLite reconciliation tests: https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/39483080807
- CI outcome for that test commit: test suite, dependency audit, and static security scan all completed successfully. Subsequent manuscript and ledger changes are documentation-only.

## Reproducible audit utility
- Script: `python-siem/scripts/forensic_audit.py`
- Tests: `python-siem/tests/test_forensic_audit.py`
- The script is read-only and reports counts, session summaries, timestamp decreases in file order, malformed/missing fields, SHA-256, and optional baseline comparison. It deliberately excludes raw command contents, credentials, and IP addresses from its output.
- Usage from `python-siem/`: `python scripts/forensic_audit.py /path/to/cowrie.json --baseline-sha256 <trusted-64-hex-digest> --output audit-report.json`
- The baseline must be stored independently and protected; a baseline generated from a possibly altered file does not establish authenticity.
- The utility was run against the preserved mounted copy on 21 October 2026 with the recorded SHA-256 supplied as baseline. It reported `baseline_match=true`, 55 JSON object records, 0 malformed/non-object lines, 0 missing event IDs, 0 missing timestamps, 0 invalid timestamps, 0 timestamp decreases, 6 sessions, and 11 command-input events.
- Publication-oriented, redacted profile summary: `research/results/cowrie_trace_audit_summary_redacted.json`. It excludes actual session IDs, source IPs, credentials, and command strings.

## Examined trace
- File: cowrie.json (local user-provided trace; not included in repository)
- Records: 55 parseable JSON lines
- Sessions: 6
- Command-input events: 11
- Time range: 2026-05-18 21:58:44.672 UTC to 22:13:26.631 UTC
- Source addresses: all observed values are 127.0.0.1; do not characterize this as an external-attack dataset.
- SHA-256 as recorded during offline analysis: 43F659EB94216AC20BFB8A17EB7043341295AC8ADD435DCDB25E1C8A4DF13DA4
- Sensitive values: submitted credentials exist in the raw source; do not publish the raw file without redaction and review.

## Repository audit utility run on preserved trace (21 October 2026)
- Input file: `/mnt/data/cowrie(1).json`, read-only profile; file size 29,336 bytes.
- SHA-256 recomputed: `43F659EB94216AC20BFB8A17EB7043341295AC8ADD435DCDB25E1C8A4DF13DA4` (matches the previously recorded fingerprint).
- 55 JSON object records; 0 malformed/non-object lines; 0 missing event IDs; 0 missing timestamps; 0 invalid timestamps; 0 backward timestamp steps in file order.
- 6 sessions; 11 `cowrie.command.input` events. Observed source IP values are exclusively `127.0.0.1`; this trace is a local/test trace, not evidence of external attacks.
- First/last valid timestamps in file order: `2026-05-18T21:58:44.672161Z` and `2026-05-18T22:13:26.630935Z`.
- The repository audit utility was run against the preserved copy using the recorded SHA-256 as the comparison baseline. `baseline_match` was `true`. The complete local report is `hyshield_actual_cowrie_audit_report.json`; a redacted publication-oriented summary is committed at `research/results/cowrie_trace_audit_summary_redacted.json`. The raw trace is not committed because it contains credentials.

## Source-to-database reconciliation tests added
- `python-siem/tests/test_forensic_pipeline_reconciliation.py` covers source-row to SQLite-row count/payload agreement for a synthetic session, retention of missing/invalid timestamp values, repeated identical JSON content at distinct offsets, and the limitation that pre-ingestion omission cannot be inferred without an independent manifest.
- These are automated tests of the actual `Ingestor` and isolated SQLite database, but use synthetic records; they are not an end-to-end test against a running Docker honeypot or the real user's trace.

## Reported offline controlled simulations
These outcomes were recorded from the user's offline console output; they were not automatically rerun by the GitHub workflow:
- Preserved source and unmodified working copy hashes matched.
- Append marker: hash changed from 43F659...4DF13DA4 to BFFDF7EE0654C994E2022DB3FE9D46A1CEDBD2241182D505A5EDA95226411352.
- Delete one command-input event (anonymized Session E): record count 55 to 54; command-input count 11 to 10; altered-copy hash 09E13730D0320483905446133D7A96324CF95AF69C44FA9D2961F3C752EDB3AE.
- Change timestamp of one command-input event to 2026-05-18T22:00:00.000000Z: observed timestamp decreases 0 to 1 in modified copy.
- Original file remained unchanged in the reported tests.

## Scope and non-claims
- CI tests exercise the SIEM ingestion component with synthetic events; they do not validate the entire deployed honeypot, Docker, and SIEM stack.
- Offline simulations are copy-level tests, not an end-to-end SIEM fault-injection benchmark.
- SHA-256 compares bytes against a trusted baseline; it does not prove source truth, completeness, origin, chain of custody, or admissibility.
- No performance metrics, generalized detection rate, false-positive rate, or statistical-significance claims are reported.
- Legal section is high-level orientation, not legal advice; jurisdiction-specific claims need specialist review.
