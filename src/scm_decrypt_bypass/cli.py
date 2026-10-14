"""scm-decrypt-bypass: manage SSL decryption bypasses in Strata Cloud Manager.

    scm-decrypt-bypass                         # interactive menu
    scm-decrypt-bypass add url mybank.com --subdomains -d "Online banking"
    scm-decrypt-bypass remove url mybank.com
    scm-decrypt-bypass list
    scm-decrypt-bypass plan                    # show what would change in SCM
    scm-decrypt-bypass deploy                  # plan, confirm, apply, push to firewalls
    scm-decrypt-bypass push                    # push the candidate config without applying
    scm-decrypt-bypass serve                   # run the web GUI
    scm-decrypt-bypass init                    # create the data directory

add/remove/list only edit the bypass lists; nothing reaches SCM until you
deploy. Kinds you can add: url, category, destination, source, user.
Decryption exclusions are edited by hand, and can be listed and removed here.

Your settings, bypass lists and Terraform state live in DATA_DIR (/data in
the container, ./data otherwise). Credentials come from the environment or a
.env file in the current directory: SCM_CLIENT_ID, SCM_CLIENT_SECRET,
SCM_SCOPE (tsg_id:<id>), and optionally SCM_HOST and SCM_AUTH_URL.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from scm_decrypt_bypass import __version__, bypass_lists, scm_api
from scm_decrypt_bypass.bypass_lists import KINDS
from scm_decrypt_bypass.workspace import Workspace, terraform_env

PLAN_FILE = "tfplan"
ADDABLE = [k for k in KINDS if k != "exclusion"]
WS = Workspace.from_env()
BYPASS_DIR = WS.bypass_dir


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def drop_root() -> None:
    """In the container, `docker compose exec` runs as root. Re-run as the
    PUID/PGID user so files in /data keep the right owner."""
    puid = os.environ.get("PUID")
    if os.name != "posix" or os.geteuid() != 0 or not puid or not shutil.which("setpriv"):
        return
    pgid = os.environ.get("PGID", puid)
    argv = ["setpriv", f"--reuid={puid}", f"--regid={pgid}", "--clear-groups", sys.executable, "-m", "scm_decrypt_bypass", *sys.argv[1:]]
    os.execvp("setpriv", argv)  # noqa: S606 - fixed program, re-running this same command


def preflight() -> None:
    """Checks needed before anything talks to Terraform or SCM."""
    if not shutil.which("terraform"):
        sys.exit("terraform not found on PATH.")
    missing = [k for k in scm_api.REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        sys.exit(f"Missing {', '.join(missing)}. Set them in the environment or in .env (see .env.example).")
    if not WS.has_location():
        sys.exit(f"Set folder (or snippet) in {WS.tfvars} first.")


# --- Terraform ---------------------------------------------------------------


def terraform(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["terraform", *args],
        cwd=WS.tf_dir,
        env=terraform_env(),
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )


def terraform_init() -> None:
    WS.prepare_terraform()
    result = terraform("init", "-input=false", check=False, capture=True)
    if result.returncode:
        print(result.stdout)
        sys.exit("terraform init failed.")


def terraform_plan() -> bool:
    """Write a plan file. Returns True if there are changes."""
    result = terraform("plan", "-input=false", "-detailed-exitcode", f"-out={PLAN_FILE}", check=False)
    if result.returncode == 1:
        sys.exit("terraform plan failed.")
    return result.returncode == 2


def push_folders() -> list[str]:
    out = terraform("output", "-json", "push_folders", capture=True).stdout
    folders = json.loads(out)
    if not folders:
        sys.exit("No push folders. Set folder or push_folders in terraform.tfvars.")
    return folders


# --- Commands ----------------------------------------------------------------


def do_push(args: argparse.Namespace) -> None:
    try:
        scm_api.push_and_wait(push_folders(), args.description, args.all_admins, args.timeout)
    except scm_api.ScmError as e:
        sys.exit(str(e))


def cmd_plan(args: argparse.Namespace) -> None:
    preflight()
    terraform_init()
    terraform("plan", "-input=false")


def cmd_deploy(args: argparse.Namespace) -> None:
    preflight()
    terraform_init()
    try:
        changed = terraform_plan()
        if changed:
            if not args.auto_approve and input("\nApply these changes to SCM and push? [y/N] ").strip().lower() != "y":
                sys.exit("Cancelled.")
            terraform("apply", "-input=false", PLAN_FILE)
    finally:
        (WS.tf_dir / PLAN_FILE).unlink(missing_ok=True)

    if not changed and not args.force_push:
        print("No changes to apply, nothing to push. Use --force-push to push anyway.")
        return
    if args.no_push:
        print("Skipping push (--no-push). Run `scm-decrypt-bypass push` when ready.")
        return
    do_push(args)


def cmd_push(args: argparse.Namespace) -> None:
    preflight()
    terraform_init()
    do_push(args)


def cmd_init(args: argparse.Namespace) -> None:
    created = WS.ensure()
    for path in created:
        print(f"  created {path}")
    print(f"Data directory: {WS.data_dir}")
    if not WS.has_location():
        print(f"Next: set folder (or snippet) in {WS.tfvars}.")


def cmd_serve(args: argparse.Namespace) -> None:
    import tempfile

    import uvicorn

    from scm_decrypt_bypass.web.settings import Settings

    if os.environ.get("WEBGUI_DEMO", "").lower() in ("1", "true", "yes", "on") and not os.environ.get("DATA_DIR"):
        os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="scm-decrypt-bypass-demo-")
        print(f"Demo mode: using a throwaway data directory, {os.environ['DATA_DIR']}")
    errors = Settings.from_env().startup_errors()
    if errors:
        sys.exit("\n".join(errors))
    uvicorn.run("scm_decrypt_bypass.web.app:app", host=args.host, port=args.port, proxy_headers=True, forwarded_allow_ips="*", access_log=False)


def cmd_version(args: argparse.Namespace) -> None:
    print(__version__)


# --- Editing the bypass lists ------------------------------------------------


def clean_all(kind: str, raws: list[str]) -> list[str]:
    """Validate entries, printing notes and skipping (with a message) bad ones."""
    entries = []
    for raw in raws:
        try:
            entry, notes = bypass_lists.clean(kind, raw)
        except ValueError as e:
            print(f"  skipped: {e}")
            continue
        for note in notes:
            print(f"  {entry}: {note}")
        entries.append(entry)
    return entries


def apply_adds(kind: str, entries: list[str], description: str | None) -> int:
    added = 0
    for entry in entries:
        if bypass_lists.add(BYPASS_DIR, kind, entry, description):
            print(f"  + {entry}")
            added += 1
        else:
            print(f"  = {entry} (already listed)")
    return added


def print_lists(kinds: list[str] | None = None) -> list[tuple[str, bypass_lists.Entry]]:
    """Print entries grouped by kind, numbered. Returns them in display order."""
    numbered = []
    for kind in kinds or KINDS:
        entries = bypass_lists.read(BYPASS_DIR, kind)
        print(f"\n{KINDS[kind].label} ({KINDS[kind].file})")
        if not entries:
            print("    (none)")
        for e in entries:
            numbered.append((kind, e))
            desc = f"  # {e.description}" if e.description else ""
            print(f"  {len(numbered):>3}) {e.value}{desc}")
    return numbered


def split_entries(kind: str, values: list[str]) -> list[str]:
    """Split typed input into entries.

    Users are taken whole (LDAP DNs contain spaces and commas), categories split
    on commas only ("Financial Services" is one category), the rest on commas
    or whitespace.
    """
    if kind == "user":
        return [v.strip() for v in values if v.strip()]
    sep = r"," if kind == "category" else r"[\s,]+"
    return [part.strip() for v in values for part in re.split(sep, v) if part.strip()]


def cmd_add(args: argparse.Namespace) -> None:
    entries = clean_all(args.kind, split_entries(args.kind, args.entries))
    if args.subdomains and args.kind == "url":
        entries = bypass_lists.with_subdomains(entries)
    if not entries:
        sys.exit("Nothing to add.")
    added = apply_adds(args.kind, entries, args.description)
    finish_edit(added, args.deploy)


def cmd_remove(args: argparse.Namespace) -> None:
    removed = 0
    for raw in split_entries(args.kind, args.entries):
        if bypass_lists.remove(BYPASS_DIR, args.kind, raw):
            print(f"  - {bypass_lists.normalize(args.kind, raw)}")
            removed += 1
        else:
            print(f"  ? {raw} is not in {KINDS[args.kind].file}")
    finish_edit(removed, args.deploy)


def cmd_list(args: argparse.Namespace) -> None:
    print_lists([args.kind] if args.kind else None)


def finish_edit(changed: int, deploy: bool) -> None:
    if not changed:
        print("No changes.")
    elif deploy:
        cmd_deploy(build_parser().parse_args(["deploy"]))
    else:
        print(f"\n{changed} change(s) saved to {BYPASS_DIR}. Run `scm-decrypt-bypass deploy` to push them.")


# --- Interactive menu --------------------------------------------------------


def ask(prompt: str) -> str:
    return input(f"{prompt}: ").strip()


def confirm(prompt: str, default: bool = False) -> bool:
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not answer else answer.startswith("y")


def choose(prompt: str, options: list[tuple[str, str]]) -> str | None:
    """Numbered menu. Returns the chosen key, or None on blank input."""
    print(f"\n{prompt}")
    for i, (_, label) in enumerate(options, 1):
        print(f"  {i}) {label}")
    while True:
        answer = input("> ").strip()
        if not answer:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        print(f"  Enter 1-{len(options)}, or press Enter to go back.")


def interactive_add() -> int:
    target = choose(
        "What do you want to bypass?",
        [
            ("site", "A website / hostname"),
            ("destination", "A server IP, subnet or range (no hostname)"),
            ("source", "A client device or subnet (IoT, printers, lab boxes)"),
            ("user", "A user or group"),
            ("category", "A whole URL category (banking, health, ...)"),
        ],
    )
    if target is None:
        return 0

    kind = "url" if target == "site" else target
    if kind == "category":
        print("Common choices: " + ", ".join(bypass_lists.COMMON_CATEGORIES))

    info = KINDS[kind]
    if kind == "user":
        raws = [ask(f"Enter the {info.noun} exactly as User-ID shows it (e.g. {info.example})")]
    else:
        raws = [ask(f"Enter one or more {info.noun} (e.g. {info.example})")]
    entries = clean_all(kind, split_entries(kind, raws))
    if not entries:
        print("Nothing to add.")
        return 0

    if kind == "url" and any(not e.startswith("*.") for e in entries):
        example = next(e for e in entries if not e.startswith("*.")).removeprefix("www.")
        if confirm(f"Also cover subdomains ({example} + *.{example})?", default=True):
            entries = bypass_lists.with_subdomains(entries)

    description = ask("Description / reason (optional)") or None
    print(f"\nAdding to {info.file}:")
    for e in entries:
        print(f"  {e}")
    if not confirm("Save?", default=True):
        return 0
    return apply_adds(kind, entries, description)


def interactive_remove() -> int:
    numbered = print_lists()
    if not numbered:
        print("\nNothing to remove.")
        return 0
    answer = ask("\nNumbers to remove, separated by spaces (Enter to cancel)")
    picks = sorted({int(n) for n in re.split(r"[\s,]+", answer) if n.isdigit() and 1 <= int(n) <= len(numbered)})
    if not picks:
        return 0
    chosen = [numbered[n - 1] for n in picks]
    for kind, e in chosen:
        print(f"  {e.value}  ({KINDS[kind].label})")
    if not confirm("Remove these?"):
        return 0
    for kind, e in chosen:
        bypass_lists.remove(BYPASS_DIR, kind, e.value)
    return len(chosen)


def interactive() -> None:
    pending = 0
    print("SSL decryption bypass manager. Press Enter at any prompt to go back.")
    try:
        while True:
            status = f" ({pending} change(s) not deployed yet)" if pending else ""
            action = choose(
                f"What would you like to do?{status}",
                [
                    ("add", "Add a bypass"),
                    ("remove", "Remove a bypass"),
                    ("list", "List current bypasses"),
                    ("plan", "Preview changes in SCM (terraform plan)"),
                    ("deploy", "Deploy: apply to SCM and push to firewalls"),
                    ("quit", "Quit"),
                ],
            )
            if action in (None, "quit"):
                break
            if action == "list":
                print_lists()
            elif action in ("add", "remove"):
                changed = interactive_add() if action == "add" else interactive_remove()
                pending += changed
                if changed and confirm("\nDeploy now?"):
                    action = "deploy"
            if action in ("plan", "deploy"):
                args = build_parser().parse_args([action])
                try:
                    (cmd_plan if action == "plan" else cmd_deploy)(args)
                    if action == "deploy":
                        pending = 0
                except SystemExit as e:
                    # Failures and "Cancelled." return to the menu instead of quitting.
                    if e.code not in (None, 0):
                        print(e.code)
                except subprocess.CalledProcessError as e:
                    print(f"{e.cmd[0]} failed (exit {e.returncode}).")
    except (EOFError, KeyboardInterrupt):
        print()
    if pending:
        print(f"{pending} change(s) saved to {BYPASS_DIR} but not deployed. Run `scm-decrypt-bypass deploy` when ready.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    add = sub.add_parser("add", help="add entries to a bypass list")
    add.add_argument("kind", choices=ADDABLE)
    add.add_argument("entries", nargs="+", metavar="entry")
    add.add_argument("-d", "--description", help="description / reason stored with each entry")
    add.add_argument("--subdomains", action="store_true", help="also add *.<host> for each hostname; www.x.com becomes x.com + *.x.com (url)")
    add.add_argument("--deploy", action="store_true", help="deploy right after editing")

    remove = sub.add_parser("remove", help="remove entries from a bypass list")
    remove.add_argument("kind", choices=KINDS)
    remove.add_argument("entries", nargs="+", metavar="entry")
    remove.add_argument("--deploy", action="store_true", help="deploy right after editing")

    list_ = sub.add_parser("list", help="show current bypass entries")
    list_.add_argument("kind", nargs="?", choices=KINDS)

    sub.add_parser("plan", help="show what would change in SCM")

    push_opts = argparse.ArgumentParser(add_help=False)
    push_opts.add_argument("--description", default="SSL decryption bypass update via Terraform")
    push_opts.add_argument("--timeout", type=int, default=1800, help="seconds to wait for the push (default 1800)")
    push_opts.add_argument("--all-admins", action="store_true", help="push every admin's pending changes, not just this service account's")

    deploy = sub.add_parser("deploy", parents=[push_opts], help="apply changes to SCM and push to firewalls")
    deploy.add_argument("--auto-approve", action="store_true", help="skip the confirmation prompt")
    deploy.add_argument("--no-push", action="store_true", help="apply to SCM but do not push")
    deploy.add_argument("--force-push", action="store_true", help="push even if Terraform had nothing to change")

    sub.add_parser("push", parents=[push_opts], help="push the candidate config only")

    sub.add_parser("init", help="create the data directory and starter files")
    serve = sub.add_parser("serve", help="run the web GUI")
    serve.add_argument("--host", default=os.environ.get("WEBGUI_HOST", "127.0.0.1"), help="address to listen on (default 127.0.0.1, or WEBGUI_HOST)")
    serve.add_argument("--port", type=int, default=int(os.environ.get("WEBGUI_PORT", "8088")), help="port (default 8088, or WEBGUI_PORT)")
    sub.add_parser("version", help="print the version")
    return parser


def main() -> None:
    drop_root()
    load_env_file(Path.cwd() / ".env")
    args = build_parser().parse_args()
    commands = {
        "add": cmd_add,
        "remove": cmd_remove,
        "list": cmd_list,
        "plan": cmd_plan,
        "deploy": cmd_deploy,
        "push": cmd_push,
        "init": cmd_init,
        "serve": cmd_serve,
        "version": cmd_version,
    }
    if args.command not in ("version", "serve", "init"):
        WS.ensure()
    if args.command is None:
        interactive()
    else:
        commands[args.command](args)


if __name__ == "__main__":
    main()
