"""Tests for the decrypt log viewer: `uv run python -m unittest discover tests`."""

import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo

from scm_decrypt_bypass.web.advice import bypass_status, explain
from scm_decrypt_bypass.web.panos import Firewall, PanosError, parse_entries
from scm_decrypt_bypass.web.poller import DEMO_FIXTURE as FIXTURE
from scm_decrypt_bypass.web.store import Store

TZ = ZoneInfo("Europe/Berlin")


class ParseTest(unittest.TestCase):
    def test_fixture(self):
        entries = parse_entries(FIXTURE.read_text())
        self.assertEqual(len(entries), 10)
        first = entries[0]
        self.assertEqual(first.uid, "013201000000:7000")
        self.assertEqual(first.fields["sni"], "api.pinnedapp.example")
        self.assertEqual(first.fields["from_zone"], "trust")
        self.assertEqual(first.fields["srcuser"], "example\\jdoe")

    def test_truncated_sni(self):
        def entry(sni, sni_len, cn):
            return f"<response status='success'><result><log><logs><entry><sni>{sni}</sni><sni_len>{sni_len}</sni_len><cn>{cn}</cn></entry></logs></log></result></response>"

        # CN is the full 37-character name: use it.
        full = parse_entries(entry("beacons.digital.disneyadvertisi", 37, "beacons.digital.disneyadvertising.com"))[0]
        self.assertEqual((full.fields["sni"], full.fields["sni_truncated"]), ("beacons.digital.disneyadvertising.com", ""))
        # Real case from the firewall: CN is a different (39-char) name, so keep the prefix and flag it.
        other = parse_entries(entry("beacons.digital.disneyadvertisi", 37, "beacons.digital.disneyadvertisingqa.com"))[0]
        self.assertEqual((other.fields["sni"], other.fields["sni_truncated"]), ("beacons.digital.disneyadvertisi", "37"))
        wild = parse_entries(entry("beacons.digital.disneyadvertisi", 37, "*.disneyadvertising.com"))[0]
        self.assertEqual(wild.fields["sni_truncated"], "37")
        short = parse_entries(entry("github.com", 10, "github.com"))[0]
        self.assertEqual(short.fields["sni_truncated"], "")

    def test_alternate_tag_names(self):
        xml = "<response status='success'><result><log><logs><entry><error_index>Cipher</error_index><src_user>bob</src_user></entry></logs></log></result></response>"
        e = parse_entries(xml)[0]
        self.assertEqual((e.fields["err_index"], e.fields["srcuser"]), ("Cipher", "bob"))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.store = Store(self.dir / "t.db", TZ)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_migration_repairs_truncated_sni_in_old_database(self):
        import sqlite3

        path = self.dir / "old.db"
        old_cols = [c for c in __import__("scm_decrypt_bypass.web.store", fromlist=["COLUMNS"]).COLUMNS if c != "sni_truncated"]
        db = sqlite3.connect(path)
        db.execute(
            f"CREATE TABLE events (uid TEXT PRIMARY KEY, ts REAL, target TEXT, failed INTEGER, {', '.join(c + ' TEXT' for c in old_cols)}, raw TEXT)"
        )
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        raw = {"sni": "beacons.digital.disneyadvertisi", "sni_len": "37", "cn": "beacons.digital.disneyadvertising.com"}
        db.execute(
            "INSERT INTO events (uid, ts, target, failed, sni, cn, raw) VALUES ('a', 1, ?, 1, ?, ?, ?)",
            (raw["sni"], raw["sni"], raw["cn"], __import__("json").dumps(raw)),
        )
        db.commit()
        db.close()
        store = Store(path, TZ)
        self.assertEqual(store.db.execute("SELECT target, sni FROM events").fetchone()[:], ("beacons.digital.disneyadvertising.com",) * 2)
        store.add(parse_entries(FIXTURE.read_text()))  # new rows still insert after ALTER TABLE
        self.assertEqual(store.count(), 11)

    def test_migration_fixes_rows_stored_as_failed(self):
        self.store.add(parse_entries(FIXTURE.read_text()))
        with self.store.db:
            self.store.db.execute("UPDATE events SET failed = 1")
            self.store.db.execute("DELETE FROM meta")
        reopened = Store(self.dir / "t.db", TZ)
        self.assertEqual(reopened.db.execute("SELECT SUM(failed) FROM events").fetchone()[0], 8)

    def test_dedup_and_grouping(self):
        entries = parse_entries(FIXTURE.read_text())
        self.assertEqual(self.store.add(entries), 10)
        self.assertEqual(self.store.add(entries), 0)
        self.assertEqual(self.store.latest_receive_time(), "2026/09/29 10:09:00")

        issues = {i["target"]: i for i in self.store.issues(0, failures_only=True)}
        self.assertNotIn("github.com", issues)
        pinned = issues["api.pinnedapp.example"]
        self.assertEqual((pinned["hits"], pinned["clients"]), (3, 2))
        self.assertEqual(pinned["client_ips"], ["192.168.1.42", "192.168.1.175"])  # numeric order
        self.assertIn("203.0.113.50", issues)  # no SNI or CN: grouped by destination IP
        self.assertEqual(pinned["dst_ips"], ["104.18.10.20"])
        self.assertEqual([i["target"] for i in self.store.issues(0, True, "104.154.89")], ["expired.badssl.com"])

        self.assertEqual(sum(i["hits"] for i in issues.values()), 8)  # err_index "None" rows aren't failures
        everything = {i["target"] for i in self.store.issues(0, failures_only=False)}
        self.assertIn("github.com", everything)
        self.assertEqual(len(self.store.events("api.pinnedapp.example", 0)), 3)


class AdviceTest(unittest.TestCase):
    def test_explain(self):
        self.assertEqual(explain("Received fatal alert CertificateUnknown from client", "Protocol")["kind"], "exclusion")
        self.assertEqual(explain("Certificate expired", "Certificate", "Untrusted")["kind"], "url")
        self.assertEqual(explain("Unsupported cipher", "Cipher")["kind"], "exclusion")
        self.assertIsNone(explain("Out of firewall resources: memory", "Resource")["kind"])
        self.assertEqual(explain("", "")["summary"], "No error")
        self.assertEqual(explain("", "None")["summary"], "No error")
        untrusted_chain = explain(
            "Received fatal alert UnknownCA from client. CA Issuer URL: http://i.pki.goog/wr3.crt", "Certificate", "Untrusted", "untrusted"
        )
        self.assertEqual((untrusted_chain["summary"], untrusted_chain["kind"]), ("Firewall doesn't trust the server's certificate chain", "url"))
        pinned = explain("Received fatal alert UnknownCA from client", "Protocol", "Trusted", "trusted")
        self.assertEqual((pinned["summary"], pinned["kind"]), ("Client rejected the firewall's certificate", "exclusion"))

    def test_bypass_status_matches_like_the_firewall(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "no-decrypt-urls.txt").write_text("*.signal.org\nexact.example.com\n")
            (d / "exclusion-hostnames.txt").write_text("*.pinned.example\n")
            (d / "no-decrypt-destinations.txt").write_text("203.0.113.0/24\n198.51.100.10-198.51.100.20\n")
            hit = lambda host, dst="": [h["entry"] for h in bypass_status(d, host, "", dst)]
            self.assertEqual(hit("sfu.voip.signal.org"), ["*.signal.org"])  # URL list: any depth
            self.assertEqual(hit("signal.org"), [])  # wildcard needs a subdomain
            self.assertEqual(hit("a.pinned.example"), ["*.pinned.example"])
            self.assertEqual(hit("a.b.pinned.example"), [])  # exclusions: one label
            self.assertEqual(hit("x.exact.example.com"), [])
            self.assertEqual(hit("", "203.0.113.50"), ["203.0.113.0/24"])
            self.assertEqual(hit("", "198.51.100.15"), ["198.51.100.10-198.51.100.20"])
        finally:
            shutil.rmtree(d)


class FakeFirewall(BaseHTTPRequestHandler):
    """Just enough of the PAN-OS log API: enqueue a job, report ACT once, then FIN."""

    requests: list[dict] = []
    polls = 0

    def do_GET(self):
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        FakeFirewall.requests.append(params | {"key": self.headers.get("X-PAN-KEY")})
        if self.headers.get("X-PAN-KEY") != "test-key":
            body = "<response status='error' code='403'><result><msg>Invalid Credential</msg></result></response>"
        elif params.get("action") == "get":
            FakeFirewall.polls += 1
            body = (
                FIXTURE.read_text()
                if FakeFirewall.polls > 1
                else "<response status='success'><result><job><status>ACT</status></job></result></response>"
            )
        else:
            body = "<response status='success'><result><msg><line>query job enqueued with jobid 42</line></msg><job>42</job></result></response>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a test certificate")
class FirewallClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cert, key = cls.dir / "cert.pem", cls.dir / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
        cls.cert = cert
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeFirewall)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.host = f"127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.dir)

    def setUp(self):
        FakeFirewall.requests, FakeFirewall.polls = [], 0

    def test_job_flow_with_private_ca(self):
        fw = Firewall(self.host, "test-key", ca_file=str(self.cert))
        start = time.monotonic()
        entries = fw.query_decryption_logs("(receive_time geq '2026/09/29 00:00:00')", nlogs=50)
        self.assertEqual(len(entries), 10)
        self.assertLess(time.monotonic() - start, 5)
        create, *polls = FakeFirewall.requests
        self.assertEqual((create["type"], create["log-type"], create["nlogs"], create["dir"]), ("log", "decryption", "50", "forward"))
        self.assertEqual(create["query"], "(receive_time geq '2026/09/29 00:00:00')")
        self.assertEqual([p["job-id"] for p in polls], ["42", "42"])
        self.assertTrue(all(r["key"] == "test-key" for r in FakeFirewall.requests))

    def test_untrusted_cert_is_rejected(self):
        with self.assertRaisesRegex(PanosError, "CERTIFICATE_VERIFY_FAILED"):
            Firewall(self.host, "test-key").query_decryption_logs("")

    def test_bad_key_reports_api_error(self):
        with self.assertRaisesRegex(PanosError, "Invalid Credential"):
            Firewall(self.host, "wrong", verify_tls=False).query_decryption_logs("")


if __name__ == "__main__":
    unittest.main()
