"""Source-to-SQLite reconciliation tests using synthetic Cowrie records.

These tests exercise the real Ingestor against an isolated SQLite database.
They do not represent an end-to-end test of the running Docker/Cowrie deployment.
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


def _rows():
    with db.connect() as conn:
        return conn.execute(
            "SELECT session_id, timestamp, eventid, payload FROM raw_events "
            "WHERE eventid NOT LIKE 'error.%' ORDER BY rowid"
        ).fetchall()


def test_source_records_reconcile_to_stored_payloads(isolated_ingestor):
    ingestor, path = isolated_ingestor
    source = [
        _event("cowrie.session.connect", "synthetic-a", "2026-10-20T10:00:00Z", src_port=40001),
        _event("cowrie.command.input", "synthetic-a", "2026-10-20T10:00:01Z", input="id"),
        _event("cowrie.session.closed", "synthetic-a", "2026-10-20T10:00:02Z"),
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in source), encoding="utf-8")

    assert ingestor.poll() == len(source)
    rows = _rows()
    assert len(rows) == len(source)
    stored_payloads = [json.loads(row["payload"]) for row in rows]
    assert stored_payloads == source
    assert [row["eventid"] for row in rows] == [e["eventid"] for e in source]


def test_missing_and_invalid_timestamps_are_retained_as_source_values(isolated_ingestor):
    ingestor, path = isolated_ingestor
    source = [
        _event("cowrie.session.connect", "synthetic-b", "2026-10-20T10:00:00Z"),
        {"eventid": "cowrie.command.input", "session": "synthetic-b", "input": "whoami"},
        _event("cowrie.command.input", "synthetic-b", "not-a-timestamp", input="pwd"),
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in source), encoding="utf-8")

    assert ingestor.poll() == 3
    rows = _rows()
    assert len(rows) == 3
    assert rows[1]["timestamp"] is None
    assert rows[2]["timestamp"] == "not-a-timestamp"
    assert json.loads(rows[1]["payload"]) == source[1]
    assert json.loads(rows[2]["payload"]) == source[2]


def test_identical_json_content_at_distinct_offsets_is_stored_twice(isolated_ingestor):
    ingestor, path = isolated_ingestor
    event = _event("cowrie.command.input", "synthetic-c", "2026-10-20T10:00:00Z", input="id")
    line = json.dumps(event) + "\n"
    path.write_text(line + line, encoding="utf-8")

    assert ingestor.poll() == 2
    rows = _rows()
    assert len(rows) == 2
    assert [json.loads(row["payload"]) for row in rows] == [event, event]
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0] == 2


def test_pre_ingestion_omission_cannot_be_inferred_without_manifest(isolated_ingestor):
    ingestor, path = isolated_ingestor
    # The third event is deliberately absent from the source file presented to the ingestor.
    available_source = [
        _event("cowrie.session.connect", "synthetic-d", "2026-10-20T10:00:00Z"),
        _event("cowrie.session.closed", "synthetic-d", "2026-10-20T10:00:02Z"),
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in available_source), encoding="utf-8")

    assert ingestor.poll() == 2
    rows = _rows()
    assert len(rows) == 2
    assert [row["eventid"] for row in rows] == [
        "cowrie.session.connect",
        "cowrie.session.closed",
    ]
    # Without a trusted count/hash/manifest from before the omission, the ingestor has no
    # information that an additional event ever existed.
