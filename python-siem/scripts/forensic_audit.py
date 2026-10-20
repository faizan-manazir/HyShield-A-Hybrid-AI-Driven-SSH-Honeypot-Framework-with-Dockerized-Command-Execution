#!/usr/bin/env python3
"""Privacy-conscious, read-only audit of a Cowrie JSON-lines file.

Reports structural/timeline indicators and SHA-256. It never prints event payloads,
usernames, passwords, command text, or source IPs. A baseline hash must be obtained
and stored independently to provide meaningful comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed


def audit_file(path: Path, baseline_sha256: str | None = None) -> dict[str, Any]:
    digest = hashlib.sha256()
    counts: Counter[str] = Counter()
    sessions: dict[str, dict[str, Any]] = {}
    records = malformed = missing_eventid = missing_timestamp = invalid_timestamp = 0
    timestamp_decreases = 0
    previous_time: datetime | None = None
    first_timestamp: str | None = None
    last_timestamp: str | None = None

    with path.open("rb") as handle:
        for raw in handle:
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
                if not isinstance(event, dict):
                    raise ValueError("JSON value is not an object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                malformed += 1
                continue

            records += 1
            eventid = event.get("eventid")
            if not isinstance(eventid, str) or not eventid:
                missing_eventid += 1
            else:
                counts[eventid] += 1

            raw_timestamp = event.get("timestamp")
            parsed_time = parse_timestamp(raw_timestamp)
            if not raw_timestamp:
                missing_timestamp += 1
            elif parsed_time is None:
                invalid_timestamp += 1
            else:
                if previous_time is not None:
                    # Compare only when both adjacent valid timestamps are timezone-compatible.
                    try:
                        if parsed_time < previous_time:
                            timestamp_decreases += 1
                    except TypeError:
                        pass
                previous_time = parsed_time
                if first_timestamp is None:
                    first_timestamp = str(raw_timestamp)
                last_timestamp = str(raw_timestamp)

            session_id = event.get("session")
            if isinstance(session_id, str) and session_id:
                entry = sessions.setdefault(session_id, {"records": 0, "command_events": 0})
                entry["records"] += 1
                if eventid == "cowrie.command.input":
                    entry["command_events"] += 1

    actual_hash = digest.hexdigest().upper()
    baseline = baseline_sha256.strip().upper() if baseline_sha256 else None
    if baseline and (len(baseline) != 64 or any(c not in "0123456789ABCDEF" for c in baseline)):
        raise ValueError("baseline_sha256 must be exactly 64 hexadecimal characters")

    return {
        "file_name": path.name,
        "file_size_bytes": path.stat().st_size,
        "sha256": actual_hash,
        "baseline_sha256": baseline,
        "baseline_match": (actual_hash == baseline) if baseline else None,
        "json_records": records,
        "malformed_or_non_object_lines": malformed,
        "missing_eventid": missing_eventid,
        "missing_timestamp": missing_timestamp,
        "invalid_timestamp": invalid_timestamp,
        "timestamp_decreases_in_file_order": timestamp_decreases,
        "first_valid_timestamp_in_file_order": first_timestamp,
        "last_valid_timestamp_in_file_order": last_timestamp,
        "event_counts": dict(sorted(counts.items())),
        "session_count": len(sessions),
        "sessions": dict(sorted(sessions.items())),
        "interpretation_warning": (
            "Hash comparison is meaningful only against a trusted, independently protected baseline. "
            "This report cannot establish event truth, completeness, origin, custody, or admissibility."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_file", type=Path, help="Cowrie JSON-lines file (read only)")
    parser.add_argument("--baseline-sha256", help="trusted baseline SHA-256 hex digest")
    parser.add_argument("--output", type=Path, help="write JSON report to this path; stdout otherwise")
    args = parser.parse_args()
    report = audit_file(args.log_file, args.baseline_sha256)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
