import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from forensic_audit import audit_file


def test_audit_reports_counts_timeline_and_matching_baseline(tmp_path):
    path = tmp_path / "cowrie.json"
    events = [
        {"eventid": "cowrie.session.connect", "session": "s1", "timestamp": "2026-10-20T10:00:00Z"},
        {"eventid": "cowrie.command.input", "session": "s1", "timestamp": "2026-10-20T10:00:02Z", "input": "id"},
        {"eventid": "cowrie.command.input", "session": "s1", "timestamp": "2026-10-20T09:59:00Z", "input": "whoami"},
    ]
    raw = "".join(json.dumps(event) + "\n" for event in events).encode()
    path.write_bytes(raw)
    baseline = hashlib.sha256(raw).hexdigest()

    report = audit_file(path, baseline)

    assert report["json_records"] == 3
    assert report["session_count"] == 1
    assert report["event_counts"]["cowrie.command.input"] == 2
    assert report["sessions"]["s1"]["command_events"] == 2
    assert report["timestamp_decreases_in_file_order"] == 1
    assert report["baseline_match"] is True
    assert '"id"' not in json.dumps(report)
    assert "whoami" not in json.dumps(report)


def test_audit_reports_malformed_and_missing_fields_without_payload(tmp_path):
    path = tmp_path / "cowrie.json"
    path.write_text(
        '{"eventid":"cowrie.session.connect","session":"s2","timestamp":"bad"}\n'
        '{"eventid":"cowrie.command.input","session":"s2","timestamp":"2026-10-20T10:00:00","input":"private"}\n'
        '{"password":"do-not-print"}\n'
        'not-json\n',
        encoding="utf-8",
    )

    report = audit_file(path)

    assert report["json_records"] == 3
    assert report["malformed_or_non_object_lines"] == 1
    # Invalid syntax and a timestamp without an explicit timezone are both invalid.
    assert report["invalid_timestamp"] == 2
    assert report["missing_eventid"] == 1
    assert report["missing_timestamp"] == 1
    assert "do-not-print" not in json.dumps(report)
    assert "password" not in json.dumps(report)
    assert "private" not in json.dumps(report)


def test_changed_file_does_not_match_trusted_baseline(tmp_path):
    path = tmp_path / "cowrie.json"
    path.write_text('{"eventid":"a","timestamp":"2026-10-20T10:00:00Z"}\n', encoding="utf-8")
    baseline = hashlib.sha256(path.read_bytes()).hexdigest().upper()
    path.write_text(path.read_text(encoding="utf-8") + '{"eventid":"b","timestamp":"2026-10-20T10:01:00Z"}\n', encoding="utf-8")

    report = audit_file(path, baseline)

    assert report["baseline_match"] is False
