# Reproducibility and evidence ledger

## Manuscript
- Draft: research/paper.md
- References: included at the end of the manuscript; publisher records verified for the cited recent research.
- Status: evidence-grounded draft; authors and target-venue formatting require review.

## Repository under test
- Repository: faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution
- Branch: audit/forensic-ingestion-tests
- Corrected fixture commit: b0e32d3b7e2a0d2ba23ff6bac08f05ee51ab0bdf
- CI run: https://github.com/faizan-manazir/HyShield-A-Hybrid-AI-Driven-SSH-Honeypot-Framework-with-Dockerized-Command-Execution/actions/runs/39479778416
- CI outcome: test suite, dependency audit, and static security scan all completed successfully.

## Reproducible audit utility
- Script: `python-siem/scripts/forensic_audit.py`
- Tests: `python-siem/tests/test_forensic_audit.py`
- The script is read-only and reports counts, session summaries, timestamp decreases in file order, malformed/missing fields, SHA-256, and optional baseline comparison. It deliberately excludes raw command contents, credentials, and IP addresses from its output.
- Usage from `python-siem/`: `python scripts/forensic_audit.py /path/to/cowrie.json --baseline-sha256 <trusted-64-hex-digest> --output audit-report.json`
- The baseline must be stored independently and protected; a baseline generated from a possibly altered file does not establish authenticity.

## Examined trace
- File: cowrie.json (local user-provided trace; not included in repository)
- Records: 55 parseable JSON lines
- Sessions: 6
- Command-input events: 11
- Time range: 2026-05-18 21:58:44.672 UTC to 22:13:26.631 UTC
- Source addresses: all observed values are 127.0.0.1; do not characterize this as an external-attack dataset.
- SHA-256 as recorded during offline analysis: 43F659EB94216AC20BFB8A17EB7043341295AC8ADD435DCDB25E1C8A4DF13DA4
- Sensitive values: submitted credentials exist in the raw source; do not publish the raw file without redaction and review.

## Reported offline controlled simulations
These outcomes were recorded from the user's offline console output; they were not automatically rerun by the GitHub workflow:
- Preserved source and unmodified working copy hashes matched.
- Append marker: hash changed from 43F659...4DF13DA4 to BFFDF7EE0654C994E2022DB3FE9D46A1CEDBD2241182D505A5EDA95226411352.
- Delete one command-input event (session 30d26570617d, original line 38): record count 55 to 54; command-input count 11 to 10; altered-copy hash 09E13730D0320483905446133D7A96324CF95AF69C44FA9D2961F3C752EDB3AE.
- Change timestamp of cd /bin event to 2026-05-18T22:00:00.000000Z: observed timestamp decreases 0 to 1 in modified copy.
- Original file remained unchanged in the reported tests.

## Scope and non-claims
- CI tests exercise the SIEM ingestion component with synthetic events; they do not validate the entire deployed honeypot, Docker, and SIEM stack.
- Offline simulations are copy-level tests, not an end-to-end SIEM fault-injection benchmark.
- SHA-256 compares bytes against a trusted baseline; it does not prove source truth, completeness, origin, chain of custody, or admissibility.
- No performance metrics, generalized detection rate, false-positive rate, or statistical-significance claims are reported.
- Legal section is high-level orientation, not legal advice; jurisdiction-specific claims need specialist review.
