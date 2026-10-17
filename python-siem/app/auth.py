"""Small, database-backed authentication helpers for the HyShield SIEM."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from . import config, db

ROLES = ("super_admin", "analyst", "auditor")
ROLE_LABELS = {
    "super_admin": "Super Admin",
    "analyst": "Security Analyst",
    "auditor": "Read-Only Auditor",
}
COOKIE_NAME = "hyshield_session"
SESSION_SECONDS = 8 * 60 * 60


def _secret():
    configured = os.environ.get("HYSHIELD_AUTH_SECRET")
    if configured:
        return configured.encode()
    path = config.DATA / "auth_secret"
    try:
        secret = path.read_bytes()
    except FileNotFoundError:
        secret = secrets.token_bytes(48)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(secret)
        except FileExistsError:
            secret = path.read_bytes()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


def hash_password(password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if len(password) > 1024:
        raise ValueError("Password must not exceed 1024 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password, stored):
    try:
        algorithm, salt_text, digest_text = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def record_audit(actor, action, target=""):
    conn = db.connect()
    try:
        actor_id = actor.get("id") if actor else None
        actor_name = actor.get("username") if actor else "system"
        conn.execute("INSERT INTO audit_logs (actor_id, actor_name, action, target) VALUES (?, ?, ?, ?)",
                     (actor_id, actor_name, action[:100], str(target or "")[:200]))
        conn.commit()
    finally:
        conn.close()


def list_audit_logs(limit=200):
    conn = db.connect()
    try:
        return [dict(row) for row in conn.execute(
            "SELECT id, actor_name, action, target, created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 1000)),)
        ).fetchall()]
    finally:
        conn.close()


def create_user(username, password, role, actor=None):
    username = str(username or "").strip()
    if not 3 <= len(username) <= 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in username):
        raise ValueError("Username must be 3–64 characters and use only letters, numbers, dot, underscore, or hyphen.")
    if role not in ROLES:
        raise ValueError("Choose a valid role.")
    password_hash = hash_password(password)
    conn = db.connect()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)",
                     (username, password_hash, role))
        conn.commit()
        row = conn.execute("SELECT id, username, role, active, created_at FROM users WHERE username = ?", (username,)).fetchone()
        conn.commit()
        created = dict(row)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    record_audit(actor, "user_created", f"{created['username']} ({created['role']})")
    return created


def create_initial_admin(username, password):
    """Atomically create the one-time bootstrap account."""
    username = str(username or "").strip()
    if not 3 <= len(username) <= 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in username):
        raise ValueError("Username must be 3–64 characters and use only letters, numbers, dot, underscore, or hyphen.")
    password_hash = hash_password(password)
    conn = db.connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] != 0:
            conn.rollback()
            raise ValueError("Initial setup has already been completed. Sign in instead.")
        conn.execute("INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, 'super_admin', 1, CURRENT_TIMESTAMP)",
                     (username, password_hash))
        row = conn.execute("SELECT id, username, role, active, created_at FROM users WHERE username = ?", (username,)).fetchone()
        conn.commit()
        created = dict(row)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    record_audit(None, "initial_super_admin_created", created["username"])
    return created


def user_count():
    conn = db.connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    finally:
        conn.close()


def authenticate(username, password):
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ? AND active = 1", (str(username or "").strip(),)).fetchone()
    finally:
        conn.close()
    if not row or not verify_password(password or "", row["password_hash"]):
        record_audit(None, "login_failed", str(username or "")[:64])
        return None
    user = {"id": row["id"], "username": row["username"], "role": row["role"]}
    record_audit(user, "login_success", "")
    return user


def list_users():
    conn = db.connect()
    try:
        return [dict(row) for row in conn.execute(
            "SELECT id, username, role, active, created_at FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()]
    finally:
        conn.close()


def set_user_active(user_id, active, acting_user):
    conn = db.connect()
    try:
        row = conn.execute("SELECT id, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return False
        if int(user_id) == int(acting_user["id"]) and not active:
            raise ValueError("You cannot disable your own account.")
        if row["role"] == "super_admin" and not active:
            raise ValueError("Super Admin accounts cannot be disabled here. Update the account details or create another administrator instead.")
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
        conn.commit()
        changed_user = conn.execute("SELECT username, active FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    if changed_user:
        record_audit(acting_user, "user_enabled" if active else "user_disabled", changed_user["username"])
    return True



def update_user(user_id, username, role, new_password, acting_user):
    username = str(username or "").strip()
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not 3 <= len(username) <= 64 or any(ch not in allowed for ch in username):
        raise ValueError("Username must be 3–64 characters and use only letters, numbers, dot, underscore, or hyphen.")
    if role not in ROLES:
        raise ValueError("Choose a valid role.")
    new_password = str(new_password or "")
    if new_password and len(new_password) < 12:
        raise ValueError("New password must be at least 12 characters.")
    if len(new_password) > 1024:
        raise ValueError("New password must not exceed 1024 characters.")
    conn = db.connect()
    try:
        row = conn.execute("SELECT id, username, role, active FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return False
        if row["active"] and row["role"] == "super_admin" and role != "super_admin":
            count = conn.execute("SELECT COUNT(*) FROM users WHERE role='super_admin' AND active=1").fetchone()[0]
            if count <= 1:
                raise ValueError("At least one active Super Admin must remain.")
        if new_password:
            conn.execute("UPDATE users SET username=?, role=?, password_hash=? WHERE id=?",
                         (username, role, hash_password(new_password), user_id))
        else:
            conn.execute("UPDATE users SET username=?, role=? WHERE id=?", (username, role, user_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    record_audit(acting_user, "user_updated",
                 f"{row['username']} -> {username} ({role}); password_changed={'yes' if new_password else 'no'}")
    return True


def make_session(user):
    payload = {"uid": user["id"], "username": user["username"], "role": user["role"], "exp": int(time.time()) + SESSION_SECONDS}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(_secret(), encoded.encode(), hashlib.sha256).hexdigest()
    return encoded + "." + signature


def read_session(token):
    try:
        encoded, signature = token.rsplit(".", 1)
        expected = hmac.new(_secret(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        conn = db.connect()
        try:
            row = conn.execute("SELECT id, username, role FROM users WHERE id=? AND username=? AND role=? AND active=1",
                               (payload["uid"], payload["username"], payload["role"])).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def can_access(role, method, path):
    if path.startswith("/static/") or path in ("/login", "/setup", "/logout", "/api/health"):
        return True
    if role == "super_admin":
        return True
    if path.startswith("/audit-logs") or path.startswith("/api/audit-logs"):
        return role == "auditor"
    if path.startswith("/users") or path.startswith("/api/users"):
        return False
    if path.startswith("/settings") or path.startswith("/api/settings"):
        return False
    if path == "/settings/purge":
        return False
    if path.startswith("/api/test-generator") or path == "/generator":
        return role == "analyst"
    if method not in ("GET", "HEAD", "OPTIONS"):
        return role == "analyst" and path.startswith("/alerts/") and path.endswith("/close")
    return role in ("analyst", "auditor")
