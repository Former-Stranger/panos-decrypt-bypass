"""Web GUI settings, read from the environment (Docker passes .env through).

Every variable is documented in docs/configuration.md.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

from panos_decrypt_bypass import scm_api
from panos_decrypt_bypass.workspace import MODES, Workspace


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    workspace: Workspace
    firewall_host: str
    api_key: str
    firewall_username: str
    verify_tls: bool
    ca_file: Path | None
    timezone: ZoneInfo
    poll_seconds: int
    lookback_hours: int
    retention_days: int
    extra_query: str
    demo: bool
    auth: str  # "password" or "none"
    password: str
    session_hours: int
    cookie_secure: str  # "auto", "true" or "false"

    @classmethod
    def from_env(cls) -> "Settings":
        tz = os.environ.get("FIREWALL_TIMEZONE") or os.environ.get("TZ") or "UTC"
        return cls(
            workspace=Workspace.from_env(),
            firewall_host=os.environ.get("FIREWALL_HOST", "").strip(),
            api_key=os.environ.get("FIREWALL_API_KEY", "").strip(),
            firewall_username=os.environ.get("FIREWALL_USERNAME", "").strip(),
            verify_tls=_bool(os.environ.get("FIREWALL_VERIFY_TLS"), True),
            ca_file=Path(os.environ["FIREWALL_CA_FILE"]) if os.environ.get("FIREWALL_CA_FILE") else None,
            timezone=ZoneInfo(tz),
            poll_seconds=int(os.environ.get("POLL_SECONDS", "300")),
            lookback_hours=int(os.environ.get("INITIAL_LOOKBACK_HOURS", "24")),
            retention_days=int(os.environ.get("RETENTION_DAYS", "7")),
            extra_query=os.environ.get("FIREWALL_LOG_QUERY", "").strip(),
            demo=_bool(os.environ.get("WEBGUI_DEMO"), False),
            auth=os.environ.get("WEBGUI_AUTH", "password").strip().lower(),
            password=os.environ.get("WEBGUI_PASSWORD", ""),
            session_hours=int(os.environ.get("WEBGUI_SESSION_HOURS", "12")),
            cookie_secure=os.environ.get("WEBGUI_COOKIE_SECURE", "auto").strip().lower(),
        )

    @property
    def db_path(self) -> Path:
        return Path(os.environ["WEBGUI_DB"]) if os.environ.get("WEBGUI_DB") else self.workspace.db_path

    @property
    def bypass_dir(self) -> Path:
        return self.workspace.bypass_dir

    def startup_errors(self) -> list[str]:
        """Problems that stop the app from starting at all."""
        errors = []
        if self.workspace.management not in MODES:
            errors.append(f"MANAGEMENT must be {' or '.join(MODES)}, not {self.workspace.management!r}.")
        if self.auth not in ("password", "none"):
            errors.append(f"WEBGUI_AUTH must be 'password' or 'none', not {self.auth!r}.")
        elif self.auth == "password" and not self.password:
            errors.append("Set WEBGUI_PASSWORD (or WEBGUI_AUTH=none to run without a login).")
        elif self.auth == "password" and len(self.password) < 12:
            errors.append("WEBGUI_PASSWORD must be at least 12 characters.")
        if self.cookie_secure not in ("auto", "true", "false"):
            errors.append("WEBGUI_COOKIE_SECURE must be auto, true or false.")
        return errors

    def problems(self) -> list[str]:
        """Problems shown in the GUI's status area."""
        if self.demo:
            return []
        required = [("FIREWALL_HOST", self.firewall_host), ("FIREWALL_API_KEY", self.api_key)]
        if self.workspace.management == "local":
            required.append(("FIREWALL_USERNAME", self.firewall_username))
        else:
            required += [(name, os.environ.get(name, "").strip()) for name in scm_api.REQUIRED_ENV]
        missing = [name for name, value in required if not value]
        problems = [f"{', '.join(missing)} not set. Add to .env (see .env.example)."] if missing else []
        if self.ca_file and not self.ca_file.exists():
            problems.append(f"FIREWALL_CA_FILE {self.ca_file} does not exist.")
        return problems
