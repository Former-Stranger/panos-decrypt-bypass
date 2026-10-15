"""One deploy at a time from the web GUI: terraform plan → (review) → apply → SCM push.

A bypass deploy applies without asking only when the plan touches nothing but
the no-decrypt URL list (and, the first time, the rule that uses it). Anything
else (other rules, profile changes, deletions, drift) stops for review.
"""

import json
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field

from panos_decrypt_bypass import bypass_lists, scm_api
from panos_decrypt_bypass.workspace import Workspace, terraform_env

PLAN_FILE = "tfplan.web"
MAX_LOG_LINES = 3000

# (address, actions) a one-click bypass may apply without review.
AUTO_APPROVE = {
    ("scm_url_category.no_decrypt[0]", ("update",)),
    ("scm_url_category.no_decrypt[0]", ("create",)),
    ("module.rule_urls[0].scm_decryption_rule.this", ("create",)),
}
IGNORED_ATTRS = {"id", "tfid"}


class Busy(Exception):
    pass


@dataclass
class Job:
    id: int
    kind: str  # "bypass" (one click) or "manual" (review first)
    state: str = "planning"  # planning, review, applying, pushing, done, nochange, failed, cancelled
    added: list[str] = field(default_factory=list)
    description: str = ""
    changes: list[dict] = field(default_factory=list)
    review_reason: str = ""
    failed_stage: str = ""
    error: str = ""
    log: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    finished: float | None = None

    @property
    def active(self) -> bool:
        return self.state in ("planning", "applying", "pushing")

    def public(self) -> dict:
        d = asdict(self)
        d["log"] = self.log[-400:]
        return d


def _fmt(value) -> str:
    if value is None or value == "" or value == []:
        return "(none)"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _diff(before: dict, after: dict, unknown: dict) -> list[str]:
    parts = []
    for key in sorted(set(before) | set(after)):
        if key in IGNORED_ATTRS:
            continue
        b, a = before.get(key), after.get(key)
        if unknown.get(key) is True:
            parts.append(f"{key}: known after apply")
        elif b == a:
            continue
        elif isinstance(b, list) or isinstance(a, list):
            b, a = b or [], a or []
            delta = [f"+{x}" for x in a if x not in b] + [f"-{x}" for x in b if x not in a]
            parts.append(f"{key}: {', '.join(map(str, delta)) or 'reordered'}")
        else:
            parts.append(f"{key}: {_fmt(b)} → {_fmt(a)}")
    return parts


def _label(address: str, after: dict | None, before: dict | None) -> str:
    name = (after or before or {}).get("name", "")
    if address.startswith("scm_url_category.no_decrypt"):
        return f"No-decrypt URL list ({name})"
    if ".scm_decryption_rule." in address:
        return f"Decryption rule {name}"
    if address.startswith("scm_decryption_exclusion"):
        return f"Decryption exclusion {name}"
    if address.startswith("scm_address"):
        return f"Address object {name}"
    return f"{address}"


def summarize_plan(plan: dict) -> tuple[list[dict], bool]:
    """Human-readable changes from `terraform show -json`, and whether they may auto-apply."""
    changes = []
    for rc in plan.get("resource_changes", []):
        ch = rc.get("change", {})
        actions = tuple(ch.get("actions", []))
        if actions in (("no-op",), ("read",)):
            continue
        before, after = ch.get("before") or {}, ch.get("after") or {}
        if actions == ("update",):
            detail = _diff(before, after, ch.get("after_unknown") or {})
        elif "delete" in actions and "create" in actions:
            detail = ["replace"]
        else:
            detail = [{"create": "new", "delete": "remove"}.get(actions[0], "/".join(actions))]
        changes.append(
            {
                "address": rc["address"],
                "actions": list(actions),
                "label": _label(rc["address"], ch.get("after"), ch.get("before")),
                "detail": detail,
            }
        )
    auto = bool(changes) and all((c["address"], tuple(c["actions"])) in AUTO_APPROVE for c in changes)
    return changes, auto


class Deployer:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.workdir = workspace.tf_dir
        self.bypass_dir = workspace.bypass_dir
        self.lock = threading.Lock()
        self.job: Job | None = None
        self._next_id = 1
        # A plan left over from before a restart has no job to review it.
        (self.workdir / PLAN_FILE).unlink(missing_ok=True)

    # --- public API (called from request handlers) ---------------------------

    def current(self) -> dict | None:
        return self.job.public() if self.job else None

    def start(self, kind: str, added: list[str] | None = None, description: str = "") -> Job:
        with self.lock:
            if self.job and (self.job.active or self.job.state == "review"):
                raise Busy(f"Deploy #{self.job.id} is {self.job.state}. Finish or cancel it first.")
            self.job = Job(self._next_id, kind, added=added or [], description=description)
            self._next_id += 1
            job = self.job
        threading.Thread(target=self._plan, args=(job,), daemon=True).start()
        return job

    def confirm(self, job_id: int) -> Job:
        with self.lock:
            job = self._get(job_id, "review")
            job.state = "applying"
        threading.Thread(target=self._apply_and_push, args=(job,), daemon=True).start()
        return job

    def cancel(self, job_id: int) -> Job:
        with self.lock:
            job = self._get(job_id, "review")
            self._revert(job)
            (self.workdir / PLAN_FILE).unlink(missing_ok=True)
            self._finish(job, "cancelled")
        return job

    def retry_push(self, job_id: int) -> Job:
        """Push again after a failed push, or push a deploy that found nothing to
        apply (e.g. changes applied earlier whose push never happened)."""
        with self.lock:
            job = self.job
            if not job or job.id != job_id:
                raise Busy(f"Deploy #{job_id} is not the current deploy.")
            if not (job.state == "nochange" or (job.state == "failed" and job.failed_stage == "push")):
                raise Busy("Only a failed push, or a deploy with nothing to apply, can be pushed; start a new deploy instead.")
            job.state, job.error, job.failed_stage, job.finished = "pushing", "", "", None
        threading.Thread(target=self._push, args=(job,), daemon=True).start()
        return job

    # --- steps ----------------------------------------------------------------

    def _plan(self, job: Job) -> None:
        try:
            if not self.workspace.has_location():
                raise RuntimeError(f"Set folder (or snippet) in {self.workspace.tfvars} first.")
            self.workspace.prepare_terraform()
            self._tf_output(job, "init", "-input=false")
            job.log.append("terraform init: ok")
            rc = self._tf(job, "plan", "-input=false", "-detailed-exitcode", f"-out={PLAN_FILE}", ok=(0, 2))
            if rc == 0:
                (self.workdir / PLAN_FILE).unlink(missing_ok=True)
                job.log.append("No changes: SCM already matches the bypass lists.")
                self._finish(job, "nochange")
                return
            plan = json.loads(self._tf_output(job, "show", "-json", PLAN_FILE))
            job.changes, auto = summarize_plan(plan)
            if job.kind == "bypass" and auto:
                job.state = "applying"
                self._apply_and_push(job)
            else:
                job.review_reason = (
                    "This deploy changes more than the no-decrypt URL list." if job.kind == "bypass" else "Review the changes, then apply and push."
                )
                job.state = "review"
        except Exception as e:
            self._revert(job)
            self._fail(job, "plan", e)

    def _apply_and_push(self, job: Job) -> None:
        try:
            self._tf(job, "apply", "-input=false", PLAN_FILE)
        except Exception as e:
            self._fail(job, "apply", e)
            return
        finally:
            (self.workdir / PLAN_FILE).unlink(missing_ok=True)
        self._push(job)

    def _push(self, job: Job) -> None:
        job.state = "pushing"
        try:
            folders = json.loads(self._tf_output(job, "output", "-json", "push_folders"))
            hosts = list(dict.fromkeys(e.removeprefix("*.") for e in job.added))
            what = f"bypass {' '.join(hosts)}" if hosts else "deploy"
            scm_api.push_and_wait(folders, f"panos-decrypt-bypass: {what}", log=job.log.append)
            self._finish(job, "done")
        except Exception as e:
            self._fail(job, "push", e)

    # --- helpers --------------------------------------------------------------

    def _get(self, job_id: int, state: str) -> Job:
        job = self.job
        if not job or job.id != job_id:
            raise Busy(f"Deploy #{job_id} is not the current deploy.")
        if job.state != state:
            raise Busy(f"Deploy #{job_id} is {job.state}, not {state}.")
        return job

    def _revert(self, job: Job) -> None:
        """Take this job's new entries back out of the list: they never reached SCM."""
        for entry in job.added:
            bypass_lists.remove(self.bypass_dir, "url", entry)
        if job.added:
            job.log.append(f"Removed {', '.join(job.added)} from the list again (not deployed).")

    def _finish(self, job: Job, state: str) -> None:
        job.state, job.finished = state, time.time()

    def _fail(self, job: Job, stage: str, error: Exception) -> None:
        job.failed_stage, job.error = stage, str(error)
        job.log.append(f"ERROR ({stage}): {error}")
        self._finish(job, "failed")

    def _tf(self, job: Job, *args: str, ok: tuple[int, ...] = (0,)) -> int:
        """Run terraform, streaming output into the job log."""
        job.log.append(f"$ terraform {' '.join(args)}")
        proc = subprocess.Popen(
            ["terraform", args[0], "-no-color", *args[1:]],
            cwd=self.workdir,
            env=terraform_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            job.log.append(line.rstrip())
            del job.log[:-MAX_LOG_LINES]
        rc = proc.wait()
        if rc not in ok:
            raise RuntimeError(f"terraform {args[0]} failed (exit {rc}); see the log.")
        return rc

    def _tf_output(self, job: Job, *args: str) -> str:
        result = subprocess.run(
            ["terraform", args[0], "-no-color", *args[1:]],
            cwd=self.workdir,
            env=terraform_env(),
            capture_output=True,
            text=True,
        )
        if result.returncode:
            job.log.append(result.stderr.strip())
            raise RuntimeError(f"terraform {args[0]} failed (exit {result.returncode}).")
        return result.stdout


class DemoDeployer(Deployer):
    """For WEBGUI_DEMO: walks through the same states with made-up output and
    never runs Terraform or contacts SCM."""

    STEP = 1.2

    def _plan(self, job: Job) -> None:
        job.log.append("$ terraform plan (demo: nothing is sent anywhere)")
        time.sleep(self.STEP)
        if not job.added:
            job.log.append("No changes: SCM already matches the bypass lists.")
            self._finish(job, "nochange")
            return
        job.changes = [
            {
                "address": "scm_url_category.no_decrypt[0]",
                "actions": ["update"],
                "label": "No-decrypt URL list (tf-ssl-bypass-urls)",
                "detail": [f"list: {', '.join('+' + e for e in job.added)}"],
            }
        ]
        job.log.append("Plan: 0 to add, 1 to change, 0 to destroy.")
        job.state = "applying"
        self._apply_and_push(job)

    def _apply_and_push(self, job: Job) -> None:
        job.log.append("$ terraform apply (demo)")
        time.sleep(self.STEP)
        job.log.append("Apply complete! Resources: 0 added, 1 changed, 0 destroyed.")
        self._push(job)

    def _push(self, job: Job) -> None:
        job.state = "pushing"
        job.log.append("Pushing ngfw-shared (demo)")
        time.sleep(self.STEP * 2)
        job.log.append("  fw-demo: OK")
        job.log.append("Push complete.")
        self._finish(job, "done")
