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



def test_oversized_line_is_flagged_and_next_valid_event_is_ingested(isolated_ingestor):
    from app.ingest import MAX_LINE_BYTES

    ingestor, path = isolated_ingestor
    oversized_line = b"x" * (MAX_LINE_BYTES + 1)
    valid = _event("cowrie.session.connect", "session-after-oversized", "2026-10-20T10:05:00Z")
    path.write_bytes(oversized_line + b"\n" + (json.dumps(valid) + "\n").encode("utf-8"))

    # The oversized row is not treated as a source event; it is recorded as an ingest error.
    assert ingestor.poll() == 1
    assert _raw_event_count() == 2
    assert ingestor.stats["errors"] == 1
    with db.connect() as conn:
        oversized = conn.execute(
            "SELECT eventid, payload FROM raw_events WHERE eventid='error.oversized'"
        ).fetchone()
        valid_row = conn.execute(
            "SELECT eventid FROM raw_events WHERE eventid='cowrie.session.connect'"
        ).fetchone()
    assert oversized is not None
    assert json.loads(oversized["payload"])["error"] == "Oversized log line discarded"
    assert valid_row is not None


def test_valid_json_non_object_is_recorded_as_malformed(isolated_ingestor):
    ingestor, path = isolated_ingestor
    valid = _event("cowrie.session.connect", "session-after-array", "2026-10-20T10:06:00Z")
    path.write_text("[]\n" + json.dumps(valid) + "\n", encoding="utf-8")

    assert ingestor.poll() == 1
    assert _raw_event_count() == 2
    assert ingestor.stats["errors"] == 1
    with db.connect() as conn:
        malformed = conn.execute(
            "SELECT eventid, payload FROM raw_events WHERE eventid='error.malformed'"
        ).fetchone()
    assert malformed is not None
    assert json.loads(malformed["payload"])["raw_line"] == "[]"



def test_appended_cowrie_event_is_ingested_on_next_poll(isolated_ingestor):
    ingestor, path = isolated_ingestor
    first = _event("cowrie.session.connect", "session-live", "2026-10-20T10:07:00Z")
    second = _event("cowrie.command.input", "session-live", "2026-10-20T10:07:05Z", input="id")
    path.write_text(json.dumps(first) + "\n", encoding="utf-8")

    assert ingestor.poll() == 1
    assert _raw_event_count() == 1

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")

    # A later poll ingests only the appended record, not the whole file again.
    assert ingestor.poll() == 1
    assert _raw_event_count() == 2
    assert ingestor.poll() == 0
    assert _raw_event_count() == 2


def test_changing_log_path_tails_new_file_without_reusing_old_offset(isolated_ingestor, tmp_path):
    ingestor, first_path = isolated_ingestor
    first = _event("cowrie.session.connect", "session-from-first-file", "2026-10-20T10:08:00Z")
    first_path.write_text(json.dumps(first) + "\n", encoding="utf-8")
    assert ingestor.poll() == 1
    first_offset = _checkpoint_offset(ingestor)
    assert first_offset == first_path.stat().st_size

    second_path = tmp_path / "selected-cowrie.json"
    second = _event("cowrie.session.connect", "session-from-selected-file", "2026-10-20T10:09:00Z")
    second_path.write_text(json.dumps(second) + "\n", encoding="utf-8")
    assert second_path.stat().st_size <= first_offset

    # Mirrors the dashboard's saved path change, then the background poll.
    ingestor.set_log_path(second_path)
    assert ingestor.poll() == 1
    assert ingestor.log_path == str(second_path)
    assert _raw_event_count() == 2
    assert _checkpoint_offset(ingestor) == second_path.stat().st_size

    with db.connect() as conn:
        sessions = {
            row["session_id"]
            for row in conn.execute("SELECT session_id FROM sessions").fetchall()
        }
    assert sessions == {"session-from-first-file", "session-from-selected-file"}
