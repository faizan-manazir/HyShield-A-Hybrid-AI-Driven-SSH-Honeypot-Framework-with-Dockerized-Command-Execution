"""Forensic-oriented regression tests for Cowrie JSONL ingestion.

These tests isolate the ingestion component with a temporary SQLite database and
synthetic records. They do not claim to validate the full deployed SIEM pipeline.
"""
import json
import time

import pytest

from app import config, db
from app.ingest import Ingestor


@pytest.fixture
def isolated_ingestor(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    log_path = tmp_path / "cowrie.json"
    monkeypatch.setattr(config, "DATA", data_dir)
    monkeypatch.setattr(config, "DB_PATH", data_dir / "test.db")
    monkeypatch.setattr(config, "SETTINGS_PATH", data_dir / "settings.json")
    db.init()

    ingestor = Ingestor(log_path, interval=0.01)
    # Avoid invoking periodic retention cleanup in these ingestion-specific tests.
    ingestor._last_retention_cleanup = time.monotonic()
    return ingestor, log_path


def _event(eventid, session, timestamp, **extra):
    return {
        "eventid": eventid,
        "session": session,
        "timestamp": timestamp,
        "src_ip": "192.0.2.10",
        **extra,
    }


def _raw_event_count():
    with db.connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]


def _checkpoint_offset(ingestor):
    with db.connect() as conn:
        row = conn.execute(
            "SELECT last_offset FROM checkpoints WHERE file_path=?",
            (ingestor.log_path,),
        ).fetchone()
        return None if row is None else row["last_offset"]


def test_repeated_poll_does_not_duplicate_stored_events(isolated_ingestor):
    ingestor, path = isolated_ingestor
    events = [
        _event("cowrie.session.connect", "session-a", "2026-10-20T10:00:00Z"),
        _event("cowrie.login.success", "session-a", "2026-10-20T10:00:01Z", username="test"),
    ]
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

    assert ingestor.poll() == 2
    assert _raw_event_count() == 2
    assert ingestor.poll() == 0
    assert _raw_event_count() == 2


def test_incomplete_final_line_is_not_checkpointed_until_completed(isolated_ingestor):
    ingestor, path = isolated_ingestor
    first = _event("cowrie.session.connect", "session-b", "2026-10-20T10:01:00Z")
    second = _event("cowrie.command.input", "session-b", "2026-10-20T10:01:01Z", input="id")
    first_line = json.dumps(first) + "\n"
    partial_line = json.dumps(second)[:-1]

    path.write_text(first_line + partial_line, encoding="utf-8")
    assert ingestor.poll() == 1
    assert _raw_event_count() == 1
    assert _checkpoint_offset(ingestor) == len(first_line.encode("utf-8"))

    with path.open("a", encoding="utf-8") as handle:
        handle.write("}\n")
    assert ingestor.poll() == 1
    assert _raw_event_count() == 2
    assert ingestor.poll() == 0


def test_malformed_line_is_recorded_and_following_valid_line_is_ingested(isolated_ingestor):
    ingestor, path = isolated_ingestor
    valid = _event("cowrie.session.connect", "session-c", "2026-10-20T10:02:00Z")
    path.write_text('{"eventid":\n' + json.dumps(valid) + "\n", encoding="utf-8")

    # The return count represents successfully parsed source events, not malformed rows.
    assert ingestor.poll() == 1
    assert _raw_event_count() == 2
    assert ingestor.stats["errors"] == 1
    with db.connect() as conn:
        malformed = conn.execute(
            "SELECT eventid, payload FROM raw_events WHERE eventid='error.malformed'"
        ).fetchone()
        assert malformed is not None
        assert json.loads(malformed["payload"])["raw_line"] == '{"eventid":'


def test_truncated_file_is_re_read_from_offset_zero(isolated_ingestor):
    ingestor, path = isolated_ingestor
    original = _event(
        "cowrie.session.connect",
        "session-original",
        "2026-10-20T10:03:00Z",
        extra_description="a deliberately long marker to make the initial file larger",
    )
    path.write_text(json.dumps(original) + "\n", encoding="utf-8")
    assert ingestor.poll() == 1
    original_offset = _checkpoint_offset(ingestor)
    assert original_offset == path.stat().st_size

    replacement = _event("cowrie.session.connect", "session-new", "2026-10-20T10:04:00Z")
    replacement_text = json.dumps(replacement) + "\n"
    assert len(replacement_text.encode("utf-8")) < original_offset
    path.write_text(replacement_text, encoding="utf-8")

    assert ingestor.poll() == 1
    assert _checkpoint_offset(ingestor) == path.stat().st_size
    with db.connect() as conn:
        sessions = {
            row["session_id"]
            for row in conn.execute("SELECT session_id FROM sessions").fetchall()
        }
    # Truncation causes re-reading; it does not automatically erase prior stored evidence.
    assert sessions == {"session-original", "session-new"}
