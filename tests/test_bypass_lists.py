"""Tests for bypass_lists: `uv run python -m unittest discover tests`."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from panos_decrypt_bypass import bypass_lists as bl
from panos_decrypt_bypass.workspace import Workspace


class CleanTest(unittest.TestCase):
    def test_hostnames_are_tidied(self):
        self.assertEqual(bl.clean("url", "https://MyBank.com/login?x=1")[0], "mybank.com")
        self.assertEqual(bl.clean("url", "Example.com:443")[0], "example.com")
        self.assertEqual(bl.clean("exclusion", "*.mtls.example.com")[0], "*.mtls.example.com")
        entry, notes = bl.clean("url", "example.com/path")
        self.assertEqual(entry, "example.com")
        self.assertTrue(notes)

    def test_bad_hostnames_rejected(self):
        for raw in ("8.8.8.8", "bad_host!", "example*.com", "a b", "x#y"):
            with self.assertRaises(ValueError, msg=raw):
                bl.clean("url", raw)

    def test_addresses(self):
        for ok in ("203.0.113.0/24", "10.1.1.1", "203.0.113.10-203.0.113.20", "2001:db8::/32", "cafe.be", "API.example.com"):
            bl.clean("destination", ok)
        for bad in ("10.0.0.0/255.0.0.0", "203.0.113.30-203.0.113.1", "1.2.3.4-2001:db8::1", "999.1.1.1", "nodots"):
            with self.assertRaises(ValueError, msg=bad):
                bl.clean("source", bad)

    def test_categories(self):
        self.assertEqual(bl.clean("category", "Financial Services")[0], "financial-services")
        with self.assertRaises(ValueError):
            bl.clean("category", "financial/services")

    def test_users_keep_case(self):
        self.assertEqual(bl.clean("user", r" EXAMPLE\CEO ")[0], r"EXAMPLE\CEO")


class SubdomainTest(unittest.TestCase):
    def test_with_subdomains(self):
        self.assertEqual(
            bl.with_subdomains(["www.chase.com", "fidelity.com", "*.x.com", "chase.com"]),
            ["chase.com", "*.chase.com", "fidelity.com", "*.fidelity.com", "*.x.com"],
        )


class EditTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "no-decrypt-urls.txt").write_text("# header\n# example.com\nKeep.com   # keep me")  # no trailing newline

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_add_appends_and_dedupes(self):
        self.assertTrue(bl.add(self.dir, "url", "new.com", "why"))
        self.assertFalse(bl.add(self.dir, "url", "HTTPS://keep.com/"))
        text = (self.dir / "no-decrypt-urls.txt").read_text()
        self.assertTrue(text.startswith("# header\n# example.com\nKeep.com   # keep me\n"))
        self.assertIn("new.com                       # why\n", text)
        self.assertEqual([e.value for e in bl.read(self.dir, "url")], ["keep.com", "new.com"])

    def test_remove_leaves_comments(self):
        bl.add(self.dir, "url", "keep.com")  # duplicate line (already there), no-op
        self.assertEqual(bl.remove(self.dir, "url", "keep.com"), 1)
        self.assertEqual(bl.remove(self.dir, "url", "example.com"), 0)  # only in a comment
        self.assertEqual((self.dir / "no-decrypt-urls.txt").read_text(), "# header\n# example.com\n")

    def test_add_creates_missing_file(self):
        self.assertTrue(bl.add(self.dir, "user", r"example\ceo"))
        self.assertEqual(bl.read(self.dir, "user"), [bl.Entry(r"example\ceo", None)])


@unittest.skipUnless(shutil.which("terraform"), "needs terraform")
class TerraformParityTest(unittest.TestCase):
    """Python and Terraform must agree on what the files contain."""

    def test_same_entries_as_terraform(self):
        fixtures = Path(__file__).resolve().parent / "fixtures" / "bypass"
        data = Path(tempfile.mkdtemp())
        try:
            tf_dir = Workspace(data).prepare_terraform()
            subprocess.run(["terraform", "init", "-backend=false", "-input=false"], cwd=tf_dir, check=True, capture_output=True)
            result = subprocess.run(
                ["terraform", "console", f"-var=bypass_dir={fixtures}", "-var=folder=ngfw-shared"],
                input="jsonencode(local.bypass)",
                cwd=tf_dir,
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            shutil.rmtree(data)
        tf = json.loads(json.loads(result.stdout))
        tf_kind = {
            "exclusion": "exclusions",
            "url": "urls",
            "category": "categories",
            "destination": "destinations",
            "source": "sources",
            "user": "users",
        }
        for kind, key in tf_kind.items():
            py = {e.value: e.description for e in bl.read(fixtures, kind)}
            self.assertEqual(py, tf[key], kind)


if __name__ == "__main__":
    unittest.main()
