"""Single-password login for the web GUI.

The password comes from WEBGUI_PASSWORD. It's held only as an scrypt hash,
and login attempts are checked with scrypt too. A successful login sets a
signed, HttpOnly, SameSite=Strict session cookie. The signing key is random,
kept in DATA_DIR/.session-key, and combined with the password hash, so
changing the password signs everyone out. Repeated failures from one client
are throttled.
"""

import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path

COOKIE = "pdb_session"
FAILURE_WINDOW = 600  # seconds
FAILURE_LIMIT = 10  # failures per client per window before refusing
SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}  # ~16 MiB, tens of ms per check


def load_key(path: Path) -> bytes:
    try:
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


class Auth:
    def __init__(self, enabled: bool, password: str, key_path: Path, session_hours: int, cookie_secure: str):
        self.enabled = enabled
        self.max_age = session_hours * 3600
        self.cookie_secure = cookie_secure
        file_key = load_key(key_path) if enabled else secrets.token_bytes(32)
        # A salt that's stable across restarts (so sessions survive them) but
        # unique to this install.
        self._salt = hmac.new(file_key, b"password-salt", hashlib.sha256).digest()
        self._password_hash = self._scrypt(password)
        self._key = hmac.new(file_key, self._password_hash, hashlib.sha256).digest()
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def issue(self) -> str:
        payload = f"{int(time.time()) + self.max_age}.{secrets.token_hex(8)}"
        return f"{payload}.{self._sign(payload)}"

    def valid(self, token: str | None) -> bool:
        if not self.enabled:
            return True
        if not token:
            return False
        payload, _, signature = token.rpartition(".")
        if not payload or not hmac.compare_digest(signature, self._sign(payload)):
            return False
        try:
            return int(payload.split(".", 1)[0]) > time.time()
        except ValueError:
            return False

    def _scrypt(self, password: str) -> bytes:
        return hashlib.scrypt(password.encode(), salt=self._salt, **SCRYPT)

    def check_password(self, attempt: str) -> bool:
        return hmac.compare_digest(self._scrypt(attempt), self._password_hash)

    def locked_out(self, client: str) -> bool:
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if t > time.time() - FAILURE_WINDOW]
            self._failures[client] = recent
            return len(recent) >= FAILURE_LIMIT

    def record_failure(self, client: str) -> None:
        with self._lock:
            self._failures.setdefault(client, []).append(time.time())

    def clear_failures(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)

    def secure_cookie(self, scheme: str) -> bool:
        if self.cookie_secure == "auto":
            return scheme == "https"
        return self.cookie_secure == "true"
