"""Tests for one-click deploys: `uv run --extra web python -m unittest discover tests`.

A fake `terraform` on PATH stands in for the real one, and the SCM push and
firewall commit are patched out, so nothing here talks to SCM or a firewall.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from panos_decrypt_bypass import bypass_lists, panos_commit, scm_api
from panos_decrypt_bypass.web.deployer import Busy, DemoDeployer, Deployer, summarize_plan
from panos_decrypt_bypass.workspace import PATHS_FILE, Workspace

FAKE_TERRAFORM = r"""#!/usr/bin/env python3
import json, os, sys
args = [a for a in sys.argv[1:] if a != "-no-color"]
cmd = args[0]
with open(os.environ["FAKE_TF_CALLS"], "a") as f:
    f.write(" ".join(args) + "\n")
if cmd == "init":
    print("Terraform has been successfully initialized!")
elif cmd == "plan":
    if os.environ.get("FAKE_TF_PLAN_FAIL"):
        print("Error: provider auth failed"); sys.exit(1)
    plan = os.environ.get("FAKE_TF_PLAN", "")
    if not plan:
        print("No changes."); sys.exit(0)
    out = next(a[5:] for a in args if a.startswith("-out="))
    open(out, "w").write(open(plan).read())
    print("Plan: 0 to add, 1 to change, 0 to destroy."); sys.exit(2)
elif cmd == "show":
    print(open(args[-1]).read())
elif cmd == "apply":
    print("Apply complete!")
elif cmd == "output":
    print('["ngfw-shared"]')
"""

URL_UPDATE = {
    "address": "scm_url_category.no_decrypt[0]",
    "change": {
        "actions": ["update"],
        "before": {"name": "tf-ssl-bypass-urls", "list": ["a.com"], "id": "1"},
        "after": {"name": "tf-ssl-bypass-urls", "list": ["a.com", "new.example"], "id": "1"},
        "after_unknown": {},
    },
}
PROFILE_UPDATE = {
    "address": "module.rule_urls[0].scm_decryption_rule.this",
    "change": {
        "actions": ["update"],
        "before": {"name": "tf-ssl-bypass-urls", "profile": None},
        "after": {"name": "tf-ssl-bypass-urls", "profile": "Corp-Decrypt-Profile"},
        "after_unknown": {},
    },
}
EXCLUSION_DELETE = {
    "address": 'scm_decryption_exclusion.this["pypi.org"]',
    "change": {"actions": ["delete"], "before": {"name": "pypi.org"}, "after": None},
}
UNCHANGED = {"address": "scm_tag.bypass", "change": {"actions": ["no-op"], "before": {}, "after": {}}}


def panos_rule(name, **kw):
    return {"name": name, "action": "no-decrypt", "category": ["any"], "profile": None, "uuid": f"uuid-{name}"} | kw


def panos_rules(actions, before, after):
    position = {"where": "first", "pivot": None, "directly": None}
    return {
        "address": "panos_decryption_policy_rules.no_decrypt[0]",
        "change": {
            "actions": actions,
            "before": {"position": position, "rules": before} if before is not None else None,
            "after": {"position": position, "rules": [{k: v for k, v in r.items() if k != "uuid"} for r in after]},
            "after_unknown": {},
        },
    }


PANOS_URL_UPDATE = {
    "address": "panos_custom_url_category.no_decrypt[0]",
    "change": {
        "actions": ["update"],
        "before": {"name": "tf-ssl-bypass-urls", "list": ["a.com"]},
        "after": {"name": "tf-ssl-bypass-urls", "list": ["a.com", "new.example"]},
        "after_unknown": {},
    },
}
DST, URLS = panos_rule("tf-ssl-bypass-destinations"), panos_rule("tf-ssl-bypass-urls", category=["tf-ssl-bypass-urls"])


class DescriptionTest(unittest.TestCase):
    def test_clean_description(self):
        # The exact description SCM rejected, from a real push.
        self.assertEqual(scm_api.clean_description("Decrypt viewer: bypass apple.com, *.apple.com"), "Decrypt viewer: bypass apple.com .apple.com")
        self.assertEqual(scm_api.clean_description("SSL decryption bypass update (Terraform)"), "SSL decryption bypass update Terraform")
        self.assertEqual(scm_api.clean_description("***"), "Terraform update")
        self.assertEqual(len(scm_api.clean_description("a" * 400)), 255)


class SummarizePlanTest(unittest.TestCase):
    def test_url_list_update_is_auto(self):
        changes, auto = summarize_plan({"resource_changes": [URL_UPDATE, UNCHANGED]})
        self.assertTrue(auto)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["label"], "No-decrypt URL list (tf-ssl-bypass-urls)")
        self.assertEqual(changes[0]["detail"], ["list: +new.example"])

    def test_anything_else_needs_review(self):
        changes, auto = summarize_plan({"resource_changes": [URL_UPDATE, PROFILE_UPDATE]})
        self.assertFalse(auto)
        self.assertEqual(changes[1]["detail"], ["profile: (none) → Corp-Decrypt-Profile"])
        changes, auto = summarize_plan({"resource_changes": [EXCLUSION_DELETE]})
        self.assertFalse(auto)
        self.assertEqual((changes[0]["label"], changes[0]["detail"]), ("Decryption exclusion pypi.org", ["remove"]))

    def test_no_changes_is_not_auto(self):
        self.assertEqual(summarize_plan({"resource_changes": [UNCHANGED]}), ([], False))


class SummarizePanosPlanTest(unittest.TestCase):
    def test_url_list_update_is_auto(self):
        changes, auto = summarize_plan({"resource_changes": [PANOS_URL_UPDATE]})
        self.assertTrue(auto)
        self.assertEqual(changes[0]["detail"], ["list: +new.example"])

    def test_first_url_rule_is_auto(self):
        self.assertTrue(summarize_plan({"resource_changes": [PANOS_URL_UPDATE, panos_rules(["create"], None, [URLS])]})[1])
        changes, auto = summarize_plan({"resource_changes": [panos_rules(["update"], [DST], [DST, URLS])]})
        self.assertTrue(auto)
        self.assertEqual(changes[0]["detail"], ["+ rule tf-ssl-bypass-urls"])

    def test_other_rule_changes_need_review(self):
        changed_dst = panos_rule("tf-ssl-bypass-destinations", profile="Corp")
        changes, auto = summarize_plan({"resource_changes": [panos_rules(["update"], [DST], [changed_dst, URLS])]})
        self.assertFalse(auto)
        self.assertEqual(changes[0]["detail"], ["+ rule tf-ssl-bypass-urls", "rule tf-ssl-bypass-destinations: profile: (none) → Corp"])
        self.assertFalse(summarize_plan({"resource_changes": [panos_rules(["update"], [DST, URLS], [DST])]})[1])
        self.assertFalse(summarize_plan({"resource_changes": [panos_rules(["create"], None, [DST, URLS])]})[1])
        moved = panos_rules(["update"], [DST], [DST, URLS])
        moved["change"]["after"]["position"] = {"where": "last", "pivot": None, "directly": None}
        self.assertFalse(summarize_plan({"resource_changes": [moved]})[1])


class DeployerTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.work = self.dir / "work"
        (self.work / "bypass").mkdir(parents=True)
        (self.work / "bypass" / "no-decrypt-urls.txt").write_text("# header\na.com\n")
        (self.work / "terraform.tfvars").write_text('folder = "ngfw-shared"\n')
        bindir = self.dir / "bin"
        bindir.mkdir()
        tf = bindir / "terraform"
        tf.write_text(FAKE_TERRAFORM)
        tf.chmod(0o755)
        self.calls = self.dir / "calls.log"
        self.env = mock.patch.dict(os.environ, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "FAKE_TF_CALLS": str(self.calls)})
        self.env.start()
        self.pushes = []
        self.push = mock.patch.object(scm_api, "push_and_wait", side_effect=lambda folders, desc, **kw: self.pushes.append((folders, desc)))
        self.push.start()
        self.deployer = Deployer(Workspace(self.work))

    def tearDown(self):
        self.push.stop()
        self.env.stop()
        shutil.rmtree(self.dir)

    def plan(self, *changes):
        path = self.dir / "plan.json"
        path.write_text(json.dumps({"resource_changes": list(changes)}))
        os.environ["FAKE_TF_PLAN"] = str(path)

    def add(self, entry):
        bypass_lists.add(self.work / "bypass", "url", entry)
        return [entry]

    def wait(self, *states):
        deadline = time.monotonic() + 10
        while self.deployer.job.state not in states:
            self.assertLess(time.monotonic(), deadline, f"stuck in {self.deployer.job.state}: {self.deployer.job.log}")
            time.sleep(0.05)
        return self.deployer.job

    def urls(self):
        return [e.value for e in bypass_lists.read(self.work / "bypass", "url")]

    def test_bypass_applies_and_pushes_without_review(self):
        self.plan(URL_UPDATE)
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("done", "failed", "review")
        self.assertEqual(job.state, "done", job.log)
        self.assertIn("apply -input=false tfplan.web", self.calls.read_text())
        self.assertEqual(self.pushes, [(["ngfw-shared"], "panos-decrypt-bypass: bypass new.example")])

    def test_push_description_names_domains_once(self):
        self.plan(URL_UPDATE)
        self.deployer.start("bypass", self.add("apple.com") + self.add("*.apple.com"))
        self.assertEqual(self.wait("done", "failed").state, "done")
        self.assertEqual(self.pushes[0][1], "panos-decrypt-bypass: bypass apple.com")

    def test_nothing_to_apply_can_still_push(self):
        os.environ["FAKE_TF_PLAN"] = ""
        job = self.deployer.start("manual")
        self.assertEqual(self.wait("nochange", "failed").state, "nochange")
        self.deployer.retry_push(job.id)
        self.assertEqual(self.wait("done", "failed").state, "done")
        self.assertEqual(self.pushes, [(["ngfw-shared"], "panos-decrypt-bypass: deploy")])
        self.assertFalse((self.work / "tfplan.web").exists())

    def test_unexpected_changes_wait_for_review_then_confirm(self):
        self.plan(URL_UPDATE, PROFILE_UPDATE)
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("review", "done", "failed")
        self.assertEqual(job.state, "review")
        self.assertNotIn("apply", self.calls.read_text())
        with self.assertRaises(Busy):
            self.deployer.start("manual")
        self.deployer.confirm(job.id)
        self.assertEqual(self.wait("done", "failed").state, "done")
        self.assertEqual(len(self.pushes), 1)

    def test_cancel_takes_new_entries_back_out(self):
        self.plan(URL_UPDATE, PROFILE_UPDATE)
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("review")
        self.assertIn("new.example", self.urls())
        self.deployer.cancel(job.id)
        self.assertEqual(job.state, "cancelled")
        self.assertEqual(self.urls(), ["a.com"])
        self.assertEqual(self.pushes, [])

    def test_manual_deploy_always_reviews(self):
        self.plan(URL_UPDATE)
        self.deployer.start("manual")
        self.assertEqual(self.wait("review", "done").state, "review")

    def test_no_changes(self):
        os.environ["FAKE_TF_PLAN"] = ""
        self.deployer.start("manual")
        self.assertEqual(self.wait("nochange", "failed").state, "nochange")
        self.assertEqual(self.pushes, [])

    def test_plan_failure_reverts_entries(self):
        os.environ["FAKE_TF_PLAN_FAIL"] = "1"
        try:
            self.deployer.start("bypass", self.add("new.example"))
            job = self.wait("failed", "done")
        finally:
            del os.environ["FAKE_TF_PLAN_FAIL"]
        self.assertEqual((job.state, job.failed_stage), ("failed", "plan"))
        self.assertIn("provider auth failed", "\n".join(job.log))
        self.assertEqual(self.urls(), ["a.com"])

    def test_failed_push_can_be_retried(self):
        self.plan(URL_UPDATE)
        self.push.stop()
        attempts = []

        def flaky(folders, desc, **kw):
            attempts.append(desc)
            if len(attempts) == 1:
                raise scm_api.ScmError("Can't reach api.sase.paloaltonetworks.com")

        with mock.patch.object(scm_api, "push_and_wait", side_effect=flaky):
            self.deployer.start("bypass", self.add("new.example"))
            job = self.wait("failed", "done")
            self.assertEqual((job.state, job.failed_stage), ("failed", "push"))
            self.assertIn("new.example", self.urls())  # applied to SCM, so it stays
            self.deployer.retry_push(job.id)
            self.assertEqual(self.wait("done", "failed").state, "done")
        self.push.start()
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.calls.read_text().count("apply"), 1)

    def test_prepares_working_directory_and_inits_first(self):
        os.environ["FAKE_TF_PLAN"] = ""
        self.deployer.start("manual")
        self.wait("nochange", "failed")
        self.assertTrue(self.calls.read_text().startswith("init -input=false"))
        tf = self.work / "terraform"
        self.assertTrue((tf / "main.tf").exists() and (tf / "modules" / "no-decrypt-rule" / "main.tf").exists())
        self.assertTrue((tf / ".terraform.lock.hcl").exists())
        self.assertEqual((tf / "terraform.tfvars").read_text(), 'folder = "ngfw-shared"\n')
        self.assertEqual(json.loads((tf / PATHS_FILE).read_text()), {"bypass_dir": str(self.work / "bypass")})

    def test_unconfigured_install_fails_before_terraform(self):
        (self.work / "terraform.tfvars").write_text('# folder = "ngfw-shared"\n')
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("failed", "done")
        self.assertIn("Set folder (or snippet)", job.error)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.urls(), ["a.com"])


class LocalDeployerTest(DeployerTest):
    """The same deploy flow against a locally managed firewall: commit, not push."""

    def setUp(self):
        super().setUp()
        (self.work / "terraform.tfvars").write_text('vsys = "vsys1"\n')
        self.commits = []
        self.commit = mock.patch.object(
            panos_commit, "commit_and_wait", side_effect=lambda desc, **kw: self.commits.append((desc, kw["expect_changes"]))
        )
        self.commit.start()
        self.deployer = Deployer(Workspace(self.work, "local"))

    def tearDown(self):
        self.commit.stop()
        super().tearDown()

    def test_bypass_applies_and_commits_without_review(self):
        self.plan(PANOS_URL_UPDATE)
        self.deployer.start("bypass", self.add("new.example"))
        self.assertEqual(self.wait("done", "failed", "review").state, "done")
        self.assertEqual(self.commits, [("panos-decrypt-bypass: bypass new.example", True)])
        self.assertEqual(self.pushes, [])
        self.assertNotIn("output", self.calls.read_text())

    def test_nothing_to_apply_can_still_commit(self):
        os.environ["FAKE_TF_PLAN"] = ""
        job = self.deployer.start("manual")
        self.assertEqual(self.wait("nochange", "failed").state, "nochange")
        self.deployer.retry_push(job.id)
        self.assertEqual(self.wait("done", "failed").state, "done")
        self.assertEqual(self.commits, [("panos-decrypt-bypass: deploy", False)])

    def test_prepares_working_directory_and_inits_first(self):
        os.environ["FAKE_TF_PLAN"] = ""
        self.deployer.start("manual")
        self.wait("nochange", "failed")
        tf = self.work / "terraform"
        self.assertIn("PaloAltoNetworks/panos", (tf / "versions.tf").read_text())
        self.assertFalse((tf / "modules").exists())

    # Covered by the SCM-specific versions above.
    test_bypass_applies_and_pushes_without_review = None
    test_push_description_names_domains_once = None
    test_nothing_to_apply_can_still_push = None
    test_failed_push_can_be_retried = None
    test_unconfigured_install_fails_before_terraform = None

    def test_unexpected_changes_wait_for_review_then_confirm(self):
        self.plan(PANOS_URL_UPDATE, panos_rules(["update"], [DST], [panos_rule("tf-ssl-bypass-destinations", profile="X")]))
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("review", "done", "failed")
        self.assertEqual(job.state, "review")
        self.deployer.confirm(job.id)
        self.assertEqual(self.wait("done", "failed").state, "done")
        self.assertEqual(len(self.commits), 1)

    def test_cancel_takes_new_entries_back_out(self):
        self.plan(PANOS_URL_UPDATE, panos_rules(["update"], [DST], [panos_rule("tf-ssl-bypass-destinations", profile="X")]))
        self.deployer.start("bypass", self.add("new.example"))
        job = self.wait("review")
        self.deployer.cancel(job.id)
        self.assertEqual(self.urls(), ["a.com"])
        self.assertEqual(self.commits, [])

    def test_manual_deploy_always_reviews(self):
        self.plan(PANOS_URL_UPDATE)
        self.deployer.start("manual")
        self.assertEqual(self.wait("review", "done").state, "review")


class DemoDeployerTest(unittest.TestCase):
    def test_simulates_without_terraform(self):
        work = Path(tempfile.mkdtemp())
        try:
            DemoDeployer.STEP = 0.01
            deployer = DemoDeployer(Workspace(work))
            with mock.patch.object(scm_api, "push_and_wait") as push, mock.patch("subprocess.Popen") as popen:
                deployer.start("bypass", ["example.org"])
                deadline = time.monotonic() + 5
                while deployer.job.state not in ("done", "failed") and time.monotonic() < deadline:
                    time.sleep(0.02)
            self.assertEqual(deployer.job.state, "done")
            self.assertEqual(deployer.job.changes[0]["detail"], ["list: +example.org"])
            push.assert_not_called()
            popen.assert_not_called()
        finally:
            shutil.rmtree(work)


if __name__ == "__main__":
    unittest.main()
