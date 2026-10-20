"""Source-to-database reconciliation and fault-injection tests.

These tests use a temporary SQLite database and synthetic Cowrie JSONL input.
They validate the actual Ingestor -> SQLite path, not the full deployed Docker
honeypot or dashboard. They intentionally document that an event omitted before
ingestion cannot be detected without an independent expected-source baseline.
"""
import json
import time

import pytest

from app import config, db
from app.ingest import Ingestor


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    source = tmp_path / "cowrie.json"
    monkeypatch.setattr(config, "DATA", data_dir)
    monkeypatch.setattr(config, "DB_PATH", data_dir / "test.db")
    monkeypatch.setattr(config, "SETTINGS_PATH", data_dir / "settings.json")
    db.init()
    ingestor = Ingestor(source, interval=0.01)
    ingestor._last_retention_cleanup = time.monotonic()
    return ingestor, source


def event(eventid, timestamp="2026-10-20T10:00:00Z", session="session-x", **extra):
    return {"eventid": eventid, "timestamp": timestamp, "session": session,
            "src_ip": "192.0.2.10", **extra}


def source_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def stored_rows():
    with db.connect() as conn:
        return conn.execute(
            "SELECT id, session_id, timestamp, eventid, payload FROM raw_events ORDER BY rowid"
        ).fetchall()


def test_source_to_database_event_count_and_payload_reconciliation(pipeline):
    ingestor, source = pipeline
    source_rows = [
        event("cowrie.session.connect"),
        event("cowrie.login.success", "2026-10-20T10:00:01Z", username="lab-user"),
        event("cowrie.command.input", "2026-10-20T10:00:02Z", input="id"),
        event("cowrie.session.closed", "2026-10-20T10:00:03Z"),
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in source_rows), encoding="utf-8")

    ingestor.poll()
    stored = stored_rows()

    assert len(source_events(source)) == 4
    assert len(stored) == 4
    assert [row["eventid"] for row in stored] == [row["eventid"] for row in source_rows]
    assert [json.loads(row["payload"]) for row in stored] == source_rows
    with db.connect() as conn:
        session = conn.execute("SELECT event_count, is_closed FROM sessions WHERE session_id='session-x'").fetchone()
    assert session["event_count"] == 4
    assert session["is_closed"] == 1


def test_missing_and_invalid_timestamps_are_retained_but_not_validated(pipeline):
    ingestor, source = pipeline
    rows = [
        event("cowrie.session.connect"),
        {"eventid": "cowrie.command.input", "session": "session-x", "src_ip": "192.0.2.10", "input": "whoami"},
        event("cowrie.command.input", "not-a-timestamp", input="uname"),
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    ingestor.poll()
    stored = stored_rows()

    assert len(stored) == 3
    assert [row["timestamp"] for row in stored] == [
        "2026-10-20T10:00:00Z", None, "not-a-timestamp"
    ]
    # This is an observed limitation: ingestion stores these timestamp values
    # without rejecting or annotating their invalidity.
    assert all(row["eventid"] != "error.malformed" for row in stored)


def test_duplicate_event_content_at_different_offsets_is_stored_twice(pipeline):
    ingestor, source = pipeline
    repeated = event("cowrie.command.input", input="id")
    source.write_text(json.dumps(repeated) + "\n" + json.dumps(repeated) + "\n", encoding="utf-8")

    ingestor.poll()
    stored = stored_rows()

    # Current event IDs include the byte offset, so identical JSON lines are
    # separate rows. This is not semantic duplicate detection.
    assert len(stored) == 2
    assert stored[0]["payload"] == stored[1]["payload"]
    assert stored[0]["id"] != stored[1]["id"]


def test_source_omission_is_not_detectable_from_ingested_rows_alone(pipeline):
    ingestor, source = pipeline
    observed = [
        event("cowrie.session.connect"),
        # A command event that might have existed upstream is intentionally absent.
        event("cowrie.session.closed", "2026-10-20T10:00:03Z"),
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in observed), encoding="utf-8")

    ingestor.poll()
    stored = stored_rows()

    assert len(source_events(source)) == 2
    assert len(stored) == 2
    # No source-side signed count/manifest exists here; the pipeline cannot infer
    # that a third event was omitted before the source file was presented.
