"""SQLite helpers. Python's built-in sqlite3 is all we need."""
import sqlite3
import json
import os

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    timestamp   TEXT,
    eventid     TEXT,
    payload     TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_session ON raw_events(session_id);
CREATE INDEX IF NOT EXISTS idx_raw_time    ON raw_events(timestamp);

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    src_ip       TEXT,
    start_time   TEXT,
    end_time     TEXT,
    is_closed    INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    risk_level   TEXT DEFAULT 'LOW',
    event_count  INTEGER DEFAULT 0,
    summary      TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id         TEXT PRIMARY KEY,
    session_id TEXT,
    severity   TEXT,
    title      TEXT,
    reason     TEXT,
    mitre      TEXT,
    status     TEXT DEFAULT 'OPEN',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);

CREATE TABLE IF NOT EXISTS checkpoints (
    inode       TEXT PRIMARY KEY,
    file_path   TEXT,
    last_offset INTEGER
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id   INTEGER,
    actor_name TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('super_admin', 'analyst', 'auditor')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip   TEXT PRIMARY KEY,
    data TEXT
);
"""


def _restrict_file(path):
    """Best-effort owner-only permissions on POSIX; no-op where unsupported."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def connect() -> sqlite3.Connection:
    config.DATA.mkdir(parents=True, exist_ok=True)
    existed = config.DB_PATH.exists()
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    if not existed:
        _restrict_file(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def jload(text, default=None):
    """json.loads that never raises (one bad row must not break a whole page)."""
    if default is None:
        default = {}
    if not isinstance(text, str):
        return default
    try:
        value = json.loads(text)
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default
