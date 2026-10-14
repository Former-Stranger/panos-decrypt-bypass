"""Tests for the web GUI login."""

import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scm_decrypt_bypass.web import auth as auth_module
from scm_decrypt_bypass.web.auth import Auth

PASSWORD = "correct-horse-battery"


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.key = self.dir / ".session-key"

    def tearDown(self):
        shutil.rmtree(self.dir)

    def make(self, password=PASSWORD, enabled=True, hours=12, secure="auto"):
        return Auth(enabled, password, self.key, hours, secure)

    def test_password_check(self):
        a = self.make()
        self.assertTrue(a.check_password(PASSWORD))
        self.assertFalse(a.check_password("wrong"))
        self.assertFalse(a.check_password(PASSWORD + " "))

    def test_session_tokens(self):
        a = self.make()
        token = a.issue()
        self.assertTrue(a.valid(token))
        self.assertFalse(a.valid(None))
        self.assertFalse(a.valid(""))
        self.assertFalse(a.valid(token[:-1] + ("0" if token[-1] != "0" else "1")))
        self.assertFalse(a.valid("garbage"))
        expires, rest = token.split(".", 1)
        self.assertFalse(a.valid(f"{int(expires) + 1}.{rest}"))  # tampered expiry

    def test_sessions_survive_restart_but_not_password_change(self):
        token = self.make().issue()
        self.assertTrue(self.make().valid(token))
        self.assertFalse(self.make(password="a-different-password").valid(token))

    def test_key_file_is_private(self):
        self.make()
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(len(self.key.read_bytes()), 32)

    def test_expiry(self):
        a = self.make(hours=1)
        token = a.issue()
        with mock.patch.object(auth_module.time, "time", return_value=time.time() + 3601):
            self.assertFalse(a.valid(token))

    def test_disabled_allows_everything(self):
        a = self.make(enabled=False)
        self.assertTrue(a.valid(None))
        self.assertFalse(self.key.exists())

    def test_throttling(self):
        a = self.make()
        for _ in range(auth_module.FAILURE_LIMIT - 1):
            a.record_failure("192.0.2.1")
        self.assertFalse(a.locked_out("192.0.2.1"))
        a.record_failure("192.0.2.1")
        self.assertTrue(a.locked_out("192.0.2.1"))
        self.assertFalse(a.locked_out("192.0.2.2"))
        a.clear_failures("192.0.2.1")
        self.assertFalse(a.locked_out("192.0.2.1"))

    def test_secure_cookie(self):
        self.assertTrue(self.make().secure_cookie("https"))
        self.assertFalse(self.make().secure_cookie("http"))
        self.assertTrue(self.make(secure="true").secure_cookie("http"))
        self.assertFalse(self.make(secure="false").secure_cookie("https"))


if __name__ == "__main__":
    unittest.main()
