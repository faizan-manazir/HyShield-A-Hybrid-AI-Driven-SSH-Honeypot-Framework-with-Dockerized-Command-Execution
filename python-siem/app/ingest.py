"""
Reads new lines from the Cowrie JSON log and stores them in SQLite.

It remembers how far it has read (a "checkpoint"), so restarting the app never
re-reads old lines, and it notices when the log file is rotated or emptied.
"""
import hashlib
import json
import logging
import os
import threading
import time

from . import correlation, db

log = logging.getLogger("hyshield.ingest")

MAX_BATCH_BYTES = 1024 * 1024
MAX_LINE_BYTES = 256 * 1024


class Ingestor(threading.Thread):
    def __init__(self, log_path, interval=2.0):
        super().__init__(daemon=True, name="ingestor")
        self.log_path = str(log_path)
        self.interval = interval
        self.lock = threading.Lock()      # so "purge" and "read" never run together
        self.stop_flag = threading.Event()
        self.stats = {"events": 0, "errors": 0}
        self._last_retention_cleanup = 0.0

    # ---- thread loop ----------------------------------------------------
    def run(self):
        while not self.stop_flag.is_set():
            try:
                self.poll()
            except Exception:                      # keep the thread alive no matter what
                log.exception("ingest poll failed")
                self.stats["errors"] += 1
            self.stop_flag.wait(self.interval)

    def stop(self):
        self.stop_flag.set()

    def set_log_path(self, log_path):
        """Switch the tailed source atomically with respect to poll/purge."""
        with self.lock:
            self.log_path = str(log_path)

    # ---- one pass -------------------------------------------------------
    def poll(self):
        """Read new log lines and periodically enforce configured telemetry retention."""
        with self.lock:
            now = time.monotonic()
            if now - self._last_retention_cleanup >= 3600:
                try:
                    from . import settings
                    db.cleanup_retention(settings.load().get("logRetention", 90))
                    self._last_retention_cleanup = now
                except Exception:
                    log.exception("retention cleanup failed")
            if not os.path.exists(self.log_path):
                return 0
            st = os.stat(self.log_path)
            inode = str(st.st_ino)
            conn = db.connect()
            try:
                row = conn.execute("SELECT last_offset, file_path FROM checkpoints WHERE inode=?", (inode,)).fetchone()
                # Inodes can be reused and can collide across different filesystems.
                # Never carry an offset from a different configured path.
                offset = row["last_offset"] if row and row["file_path"] == self.log_path else 0
                if st.st_size < offset:            # file was emptied/truncated -> start over
                    offset = 0
                if st.st_size == offset:
                    return 0
                with open(self.log_path, "rb") as f:
                    f.seek(offset)
                    data = f.read(min(st.st_size - offset, MAX_BATCH_BYTES))
                    end = data.rfind(b"\n")  # ignore a half-written last line
                    if end == -1:
                        # Keep ordinary partial writes, but stream-skip a pathological
                        # line rather than buffering it without limit forever.
                        if st.st_size - offset <= MAX_LINE_BYTES:
                            return 0
                        f.seek(offset)
                        skipped = 0
                        while True:
                            block = f.read(64 * 1024)
                            if not block:
                                return 0
                            newline = block.find(b"\n")
                            if newline >= 0:
                                skipped += newline + 1
                                break
                            skipped += len(block)
                        event_id = hashlib.sha256(f"{self.log_path}|{inode}|{offset}|oversized".encode()).hexdigest()
                        conn.execute("INSERT OR IGNORE INTO raw_events VALUES (?,?,?,?,?)",
                                     (event_id, None, None, "error.oversized", json.dumps({"error": "Oversized log line discarded"})))
                        conn.execute(
                            "INSERT INTO checkpoints (inode, file_path, last_offset) VALUES (?,?,?) "
                            "ON CONFLICT(inode) DO UPDATE SET last_offset=excluded.last_offset, file_path=excluded.file_path",
                            (inode, self.log_path, offset + skipped))
                        conn.commit()
                        self.stats["errors"] += 1
                        return 0
                    chunk = data[:end + 1]
                return self._store(conn, chunk, inode, offset)
            finally:
                conn.close()

    def _store(self, conn, chunk, inode, start_offset):
        touched, stored, position = set(), 0, start_offset
        try:
            for raw in chunk.split(b"\n")[:-1]:
                line_offset = position
                position += len(raw) + 1
                if len(raw) > MAX_LINE_BYTES:
                    event_id = hashlib.sha256(f"{self.log_path}|{inode}|{line_offset}|oversized".encode()).hexdigest()
                    conn.execute("INSERT OR IGNORE INTO raw_events VALUES (?,?,?,?,?)",
                                 (event_id, None, None, "error.oversized", json.dumps({"error": "Oversized log line discarded"})))
                    self.stats["errors"] += 1
                    continue
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                event_id = hashlib.md5(f"{self.log_path}|{inode}|{line_offset}|{line}".encode()).hexdigest()
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("not an object")
                except ValueError:
                    self.stats["errors"] += 1
                    conn.execute(
                        "INSERT OR IGNORE INTO raw_events VALUES (?,?,?,?,?)",
                        (event_id, "malformed", None, "error.malformed", json.dumps({"raw_line": line[:2000]})))
                    continue

                session = event.get("session")
                conn.execute(
                    "INSERT OR IGNORE INTO raw_events VALUES (?,?,?,?,?)",
                    (event_id, session, event.get("timestamp"), event.get("eventid"), json.dumps(event)))
                if session:
                    ts = event.get("timestamp")
                    closed = 1 if event.get("eventid") == "cowrie.session.closed" else 0
                    conn.execute(
                        """INSERT INTO sessions (session_id, src_ip, start_time, end_time, is_closed)
                           VALUES (?,?,?,?,?)
                           ON CONFLICT(session_id) DO UPDATE SET
                             src_ip     = COALESCE(sessions.src_ip, excluded.src_ip),
                             start_time = CASE
                                 WHEN sessions.start_time IS NULL THEN excluded.start_time
                                 WHEN excluded.start_time IS NULL THEN sessions.start_time
                                 ELSE MIN(sessions.start_time, excluded.start_time)
                             END,
                             end_time = CASE
                                 WHEN sessions.end_time IS NULL THEN excluded.end_time
                                 WHEN excluded.end_time IS NULL THEN sessions.end_time
                                 ELSE MAX(sessions.end_time, excluded.end_time)
                             END,
                             is_closed  = MAX(sessions.is_closed, excluded.is_closed)""",
                        (session, event.get("src_ip"), ts, ts, closed))
                    touched.add(session)
                stored += 1

            for session in touched:                 # score each touched session once per batch
                self.evaluate_session(conn, session)

            conn.execute(
                """INSERT INTO checkpoints (inode, file_path, last_offset) VALUES (?,?,?)
                   ON CONFLICT(inode) DO UPDATE SET last_offset=excluded.last_offset, file_path=excluded.file_path""",
                (inode, self.log_path, start_offset + len(chunk)))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        self.stats["events"] += stored
        return stored

    @staticmethod
    def evaluate_session(conn, session_id):
        rows = conn.execute("SELECT payload FROM raw_events WHERE session_id=? ORDER BY timestamp ASC",
                            (session_id,)).fetchall()
        events = [db.jload(r["payload"]) for r in rows]
        result = correlation.evaluate_session(events)
        summary = {k: result[k] for k in ("summary", "dimensions", "mitre", "explanations")}
        conn.execute(
            "UPDATE sessions SET threat_score=?, risk_level=?, event_count=?, summary=? WHERE session_id=?",
            (result["threatScore"], result["riskLevel"], len(events), json.dumps(summary), session_id))
        for a in result["alerts"]:
            alert_id = hashlib.md5(f"{session_id}|{a['title']}".encode()).hexdigest()
            # status is NOT updated on conflict, so an analyst's "closed" stays closed
            conn.execute(
                """INSERT INTO alerts (id, session_id, severity, title, reason, mitre)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,
                        reason=excluded.reason, mitre=excluded.mitre""",
                (alert_id, session_id, a["severity"], a["title"], a["reason"], a["mitre"]))

    # ---- admin ----------------------------------------------------------
    def purge(self):
        """Delete everything stored, and skip whatever is already in the log file."""
        with self.lock:
            conn = db.connect()
            try:
                for statement in (
                    "DELETE FROM raw_events",
                    "DELETE FROM sessions",
                    "DELETE FROM alerts",
                    "DELETE FROM checkpoints",
                ):
                    conn.execute(statement)
                if os.path.exists(self.log_path):
                    st = os.stat(self.log_path)
                    conn.execute("INSERT INTO checkpoints VALUES (?,?,?)",
                                 (str(st.st_ino), self.log_path, st.st_size))
                conn.commit()
            finally:
                conn.close()
