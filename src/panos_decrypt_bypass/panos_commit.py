"""Commit on a locally managed firewall (MANAGEMENT=local), shared by the CLI
and the web GUI. The SCM equivalent is scm_api.push_and_wait."""

import os
import time
from collections.abc import Callable

from panos_decrypt_bypass.web.panos import Firewall, PanosError

REQUIRED_ENV = ("FIREWALL_HOST", "FIREWALL_API_KEY", "FIREWALL_USERNAME")


def firewall_from_env() -> Firewall:
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k, "").strip()]
    if missing:
        raise PanosError(f"Missing {', '.join(missing)} in the environment / .env.")
    verify = os.environ.get("FIREWALL_VERIFY_TLS", "").strip().lower() not in ("0", "false", "no", "off")
    return Firewall(
        os.environ["FIREWALL_HOST"].strip(),
        os.environ["FIREWALL_API_KEY"].strip(),
        verify_tls=verify,
        ca_file=os.environ.get("FIREWALL_CA_FILE", "").strip() or None,
    )


def job_lines(job) -> list[str]:
    """Detail and warning lines from a finished job."""
    sections = [job.find(tag) for tag in ("details", "warnings")]
    return [line.text.strip() for s in sections if s is not None for line in s.iter("line") if line.text and line.text.strip()]


def commit_and_wait(
    description: str,
    all_admins: bool = False,
    timeout: int = 900,
    interval: int = 5,
    log: Callable[[str], None] = print,
    firewall: Firewall | None = None,
    expect_changes: bool = False,
) -> None:
    """Commit the candidate config and wait for it. Raises PanosError on failure.

    expect_changes: Terraform just changed the candidate config, so "nothing
    to commit" means the changes belong to someone else (a wrong
    FIREWALL_USERNAME), not that they're already live."""
    fw = firewall or firewall_from_env()
    # Commit only the API admin's changes so another admin's half-finished
    # edits never go live along with a bypass.
    admin = os.environ.get("FIREWALL_USERNAME", "").strip()
    admins = None if all_admins else [admin]
    log(f"Committing{'' if all_admins else ' changes by ' + admin + ' only'}")
    job_id = fw.commit(description, admins)
    if job_id is None:
        if expect_changes and not all_admins:
            raise PanosError(
                f"The firewall found no changes by {admin} to commit, though Terraform just made some. "
                "Check that FIREWALL_USERNAME is the admin that owns FIREWALL_API_KEY."
            )
        log("Nothing to commit: the firewall's running config already has these changes.")
        return

    deadline = time.monotonic() + timeout
    while (job := fw.job(job_id)).findtext("status") != "FIN":
        log(f"  commit job {job_id}: {job.findtext('status')} {job.findtext('progress') or ''}%")
        if time.monotonic() > deadline:
            raise PanosError(f"Timed out waiting for commit job {job_id}. Check Tasks on the firewall.")
        time.sleep(interval)

    result = job.findtext("result")
    for line in job_lines(job):
        log(f"  {line}")
    log(f"Commit job {job_id}: {result}")
    if result != "OK":
        raise PanosError(f"Commit failed ({result}). See the job details above or Tasks on the firewall.")
    log("Commit complete.")
