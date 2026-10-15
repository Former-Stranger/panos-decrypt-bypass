"""Tests for the data directory and the bundled Terraform modules."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from panos_decrypt_bypass.workspace import CA_BUNDLE, MANIFEST, PATHS_FILE, TERRAFORM_DIR, Workspace, WorkspaceError

STATE = {
    "version": 4,
    "resources": [{"mode": "managed", "type": "x", "name": "y", "provider": 'provider["registry.terraform.io/paloaltonetworks/{}"]'}],
}


class ModulesTest(unittest.TestCase):
    def test_list_parsing_is_shared(self):
        # Both modules parse the bypass lists the same way.
        self.assertEqual((TERRAFORM_DIR / "scm" / "lists.tf").read_text(), (TERRAFORM_DIR / "local" / "lists.tf").read_text())

    def test_each_module_pins_its_provider(self):
        self.assertIn("PaloAltoNetworks/scm", (TERRAFORM_DIR / "scm" / "versions.tf").read_text())
        self.assertIn("PaloAltoNetworks/panos", (TERRAFORM_DIR / "local" / "versions.tf").read_text())
        for mode in ("scm", "local"):
            self.assertTrue((TERRAFORM_DIR / mode / ".terraform.lock.hcl").exists())


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_template_follows_mode(self):
        Workspace(self.dir / "scm", "scm").ensure()
        Workspace(self.dir / "local", "local").ensure()
        self.assertIn("folder", (self.dir / "scm" / "terraform.tfvars").read_text())
        self.assertIn("vsys", (self.dir / "local" / "terraform.tfvars").read_text())

    def test_local_needs_no_location(self):
        self.assertFalse(Workspace(self.dir, "scm").configured())
        self.assertTrue(Workspace(self.dir, "local").configured())

    def test_bad_mode(self):
        with self.assertRaisesRegex(WorkspaceError, "MANAGEMENT must be"):
            Workspace(self.dir, "panorama").mode  # noqa: B018

    def test_switching_modes_removes_the_other_modules_files(self):
        tf = Workspace(self.dir, "scm").prepare_terraform()
        self.assertTrue((tf / "modules" / "no-decrypt-rule" / "main.tf").exists())
        (tf / "backend.tf").write_text("# mine\n")
        Workspace(self.dir, "local").prepare_terraform()
        self.assertFalse((tf / "modules" / "no-decrypt-rule" / "main.tf").exists())
        self.assertIn("panos", (tf / "versions.tf").read_text())
        self.assertTrue((tf / "backend.tf").exists(), "files the user added are kept")
        self.assertNotIn("tests/plan.tftest.hcl", json.loads((tf / MANIFEST).read_text()))

    def test_upgrade_from_0_1_0_cleans_old_files(self):
        tf = self.dir / "terraform"
        tf.mkdir(parents=True)
        (tf / "zz-scm-decrypt-bypass.auto.tfvars.json").write_text("{}")
        (tf / "terraform.tfstate").write_text(json.dumps(STATE).replace("{}", "scm"))
        Workspace(self.dir, "scm").prepare_terraform()
        self.assertFalse((tf / "zz-scm-decrypt-bypass.auto.tfvars.json").exists())
        self.assertEqual(json.loads((tf / PATHS_FILE).read_text()), {"bypass_dir": str(self.dir / "bypass")})
        self.assertTrue((tf / "terraform.tfstate").exists())

    def test_refuses_state_from_the_other_mode(self):
        tf = self.dir / "terraform"
        tf.mkdir(parents=True)
        (tf / "terraform.tfstate").write_text(json.dumps(STATE).replace("{}", "scm"))
        with self.assertRaisesRegex(WorkspaceError, "MANAGEMENT=scm"):
            Workspace(self.dir, "local").prepare_terraform()
        (tf / "terraform.tfstate").write_text(json.dumps(STATE).replace("{}", "panos"))
        with self.assertRaisesRegex(WorkspaceError, "MANAGEMENT=local"):
            Workspace(self.dir, "scm").prepare_terraform()
        Workspace(self.dir, "local").prepare_terraform()

    def test_panos_provider_env(self):
        env = {"FIREWALL_HOST": "fw.example.com:4443", "FIREWALL_API_KEY": "k"}
        with mock.patch.dict(os.environ, env):
            tf_env = Workspace(self.dir, "local").terraform_env()
            self.assertNotIn("PANOS_HOSTNAME", Workspace(self.dir, "scm").terraform_env())
        self.assertEqual((tf_env["PANOS_HOSTNAME"], tf_env["PANOS_PORT"], tf_env["PANOS_API_KEY"]), ("fw.example.com", "4443", "k"))
        self.assertNotIn("PANOS_SKIP_VERIFY_CERTIFICATE", tf_env)

        with mock.patch.dict(os.environ, env | {"FIREWALL_VERIFY_TLS": "false"}):
            self.assertEqual(Workspace(self.dir, "local").terraform_env()["PANOS_SKIP_VERIFY_CERTIFICATE"], "true")

    def test_private_ca_goes_into_a_bundle_for_terraform(self):
        ca = self.dir / "home-ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nHOMECA\n-----END CERTIFICATE-----\n")
        with mock.patch.dict(os.environ, {"FIREWALL_HOST": "fw", "FIREWALL_CA_FILE": str(ca)}):
            tf_env = Workspace(self.dir, "local").terraform_env()
        bundle = Path(tf_env["SSL_CERT_FILE"])
        self.assertEqual(bundle, self.dir / "terraform" / CA_BUNDLE)
        self.assertTrue(bundle.read_text().rstrip().endswith("HOMECA\n-----END CERTIFICATE-----"))


if __name__ == "__main__":
    unittest.main()
