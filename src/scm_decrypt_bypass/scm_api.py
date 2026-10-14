"""Strata Cloud Manager config push, shared by main.py and the web GUI.

The SCM Terraform provider (1.0.x stable) can create config but cannot push
it, so pushes go through the config operations API directly.
"""

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

DEFAULT_HOST = "api.sase.paloaltonetworks.com"
DEFAULT_AUTH_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
REQUIRED_ENV = ("SCM_CLIENT_ID", "SCM_CLIENT_SECRET", "SCM_SCOPE")


class ScmError(Exception):
    pass


def clean_description(text: str) -> str:
    """SCM rejects push descriptions with some punctuation (e.g. "*" and ","),
    so keep letters, digits, spaces and . _ : - only."""
    text = re.sub(r"[^A-Za-z0-9 ._:-]+", " ", text)
    return " ".join(text.split())[:255] or "Terraform update"


class SCM:
    def __init__(self) -> None:
        missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
        if missing:
            raise ScmError(f"Missing {', '.join(missing)} in the environment / .env.")
        self.client_id = os.environ["SCM_CLIENT_ID"]
        self.base = f"https://{os.environ.get('SCM_HOST', DEFAULT_HOST)}/config/operations/v1"
        self.token = self._get_token()

    def _get_token(self) -> str:
        auth_url = os.environ.get("SCM_AUTH_URL", DEFAULT_AUTH_URL)
        creds = base64.b64encode(f"{self.client_id}:{os.environ['SCM_CLIENT_SECRET']}".encode()).decode()
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": os.environ["SCM_SCOPE"]}).encode()
        req = urllib.request.Request(
            auth_url,
            data=body,
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"},
        )
        return self._send(req)["access_token"]

    def _send(self, req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            raise ScmError(f"{req.get_method()} {req.full_url} failed: HTTP {e.code}\n{e.read().decode(errors='replace')}") from e
        except urllib.error.URLError as e:
            host = urllib.parse.urlsplit(req.full_url).hostname
            raise ScmError(f"Can't reach {host}: {e.reason}") from e

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.base}{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        return self._send(req)

    def push(self, folders: list[str], description: str, admins: list[str] | None) -> tuple[str, str]:
        """Start a push. Returns (job_id, message)."""
        body = {"folders": folders, "description": clean_description(description)}
        if admins:
            body["admin"] = admins
        resp = self.request("POST", "/config-versions/candidate:push", body)
        if not resp.get("success"):
            raise ScmError(f"Push was not accepted: {resp}")
        return str(resp["job_id"]), resp.get("message", "")

    def job(self, job_id: str) -> dict:
        return self.request("GET", f"/jobs/{job_id}")["data"][0]

    def child_jobs(self, parent_id: str) -> list[dict]:
        jobs = self.request("GET", "/jobs?limit=200")["data"]
        return [j for j in jobs if str(j.get("parent_id")) == parent_id]


def push_and_wait(
    folders: list[str],
    description: str,
    all_admins: bool = False,
    timeout: int = 1800,
    interval: int = 10,
    log: Callable[[str], None] = print,
) -> None:
    """Push the candidate config and wait for every device. Raises ScmError on failure."""
    scm = SCM()
    # Scope the push to this service account's changes so we never push
    # another admin's half-finished edits along with the bypass list.
    admins = None if all_admins else [scm.client_id]
    log(f"Pushing {', '.join(folders)}{'' if all_admins else ' (changes by ' + scm.client_id + ' only)'}")
    job_id, message = scm.push(folders, description, admins)
    if message:
        log(message)

    deadline = time.monotonic() + timeout

    def sleep_or_timeout(label: str) -> None:
        if time.monotonic() > deadline:
            raise ScmError(f"Timed out waiting for {label}. Check Push Status in SCM (job {job_id}).")
        time.sleep(interval)

    while (parent := scm.job(job_id)).get("status_str") != "FIN":
        log(f"  push job {job_id}: {parent.get('status_str')} {parent.get('percent', '')}%")
        sleep_or_timeout("push job")
    log(f"Push job {job_id}: {parent.get('result_str')}")

    while True:
        children = scm.child_jobs(job_id)
        if all(j.get("status_str") == "FIN" for j in children):
            break
        sleep_or_timeout("device pushes")
    for j in children:
        log(f"  {j.get('device_name') or j.get('type_str')}: {j.get('result_str')} {j.get('summary', '')}".rstrip())

    failed = [j for j in [parent, *children] if j.get("result_str") not in ("OK", "WARN")]
    if failed:
        log(json.dumps(failed, indent=2))
        raise ScmError("Push failed. See job details above or Push Status in SCM.")
    log("Push complete.")
