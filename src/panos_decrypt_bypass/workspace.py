"""An install's own files, kept apart from the code.

    DATA_DIR/                      (/data in the container, ./data otherwise)
      terraform.tfvars             your settings (created from a template)
      bypass/*.txt                 the bypass lists
      decrypt.db                   decryption logs pulled by the web GUI
      terraform/                   Terraform working directory: state, providers,
                                   and a copy of the bundled module refreshed
                                   before every run

MANAGEMENT picks the bundled module: "scm" (the default) for firewalls managed
by Strata Cloud Manager, "local" for a firewall configured on its own. Files
you add to DATA_DIR/terraform/ yourself (for example backend.tf for remote
state) are left alone.
"""

import json
import os
import shutil
import ssl
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
TERRAFORM_DIR = PACKAGE_DIR / "terraform"
TEMPLATES_DIR = PACKAGE_DIR / "templates"
PATHS_FILE = "zz-panos-decrypt-bypass.auto.tfvars.json"
MANIFEST = ".managed-files"
CA_BUNDLE = ".ca-bundle.pem"
# What 0.1.0 copied in, before the manifest existed.
LEGACY_FILES = [
    "main.tf",
    "rules.tf",
    "variables.tf",
    "versions.tf",
    "outputs.tf",
    "modules/no-decrypt-rule/main.tf",
    ".terraform.lock.hcl",
    "zz-scm-decrypt-bypass.auto.tfvars.json",
]


@dataclass(frozen=True)
class Mode:
    name: str
    provider: str  # Terraform provider the module uses
    target: str  # where config is applied, for messages
    publish: str  # what makes it live on the firewall


MODES = {
    "scm": Mode("scm", "paloaltonetworks/scm", "SCM", "push"),
    "local": Mode("local", "paloaltonetworks/panos", "the firewall", "commit"),
}


class WorkspaceError(Exception):
    pass


def default_data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR") or Path.cwd() / "data").expanduser().resolve()


def management_from_env() -> str:
    return (os.environ.get("MANAGEMENT") or "scm").strip().lower()


@dataclass(frozen=True)
class Workspace:
    data_dir: Path
    management: str = "scm"

    @classmethod
    def from_env(cls) -> "Workspace":
        return cls(default_data_dir(), management_from_env())

    @property
    def mode(self) -> Mode:
        try:
            return MODES[self.management]
        except KeyError:
            raise WorkspaceError(f"MANAGEMENT must be {' or '.join(MODES)}, not {self.management!r}.") from None

    @property
    def module_dir(self) -> Path:
        return TERRAFORM_DIR / self.mode.name

    @property
    def bypass_dir(self) -> Path:
        return self.data_dir / "bypass"

    @property
    def tfvars(self) -> Path:
        return self.data_dir / "terraform.tfvars"

    @property
    def tf_dir(self) -> Path:
        return self.data_dir / "terraform"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "decrypt.db"

    @property
    def session_key(self) -> Path:
        return self.data_dir / ".session-key"

    def ensure(self) -> list[Path]:
        """Create the data directory and any missing starter files. Returns what was created."""
        created = []
        self.bypass_dir.mkdir(parents=True, exist_ok=True)
        for template in sorted((TEMPLATES_DIR / "bypass").glob("*.txt")):
            target = self.bypass_dir / template.name
            if not target.exists():
                shutil.copyfile(template, target)
                created.append(target)
        if not self.tfvars.exists():
            shutil.copyfile(TEMPLATES_DIR / f"{self.mode.name}.tfvars", self.tfvars)
            created.append(self.tfvars)
        return created

    def prepare_terraform(self) -> Path:
        """Refresh the Terraform working directory from the bundled module and
        the user's settings. Returns the directory to run terraform in."""
        self.ensure()
        self.check_state_matches_mode()
        self.tf_dir.mkdir(parents=True, exist_ok=True)

        copied = []
        for src in sorted(self.module_dir.rglob("*")):
            rel = src.relative_to(self.module_dir)
            if src.is_file() and rel.parts[0] not in ("tests", ".terraform") and (src.suffix == ".tf" or src.name == ".terraform.lock.hcl"):
                dst = self.tf_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
                copied.append(rel.as_posix())

        # Remove module files left by an earlier version or the other mode.
        manifest = self.tf_dir / MANIFEST
        try:
            previous = json.loads(manifest.read_text())
        except (OSError, ValueError):
            previous = LEGACY_FILES
        for rel in set(previous) - set(copied):
            (self.tf_dir / rel).unlink(missing_ok=True)
        manifest.write_text(json.dumps(copied, indent=1) + "\n")

        shutil.copyfile(self.tfvars, self.tf_dir / "terraform.tfvars")
        (self.tf_dir / PATHS_FILE).write_text(json.dumps({"bypass_dir": str(self.bypass_dir)}) + "\n")
        return self.tf_dir

    def check_state_matches_mode(self) -> None:
        """Refuse to run one mode's module against state the other mode wrote:
        Terraform would plan to destroy everything it created."""
        try:
            state = json.loads((self.tf_dir / "terraform.tfstate").read_text())
        except (OSError, ValueError):
            return
        providers = {r.get("provider", "") for r in state.get("resources", [])}
        for other in MODES.values():
            if other is not self.mode and any(p.endswith(f'/{other.provider}"]') for p in providers):
                raise WorkspaceError(
                    f"The Terraform state in {self.tf_dir} manages objects in {other.target} "
                    f"(MANAGEMENT={other.name}), but MANAGEMENT is {self.mode.name}. "
                    "Use a separate data directory for each mode, or set MANAGEMENT back."
                )

    def configured(self) -> bool:
        """True once terraform.tfvars says where the config goes. SCM needs a
        folder or snippet; a local firewall defaults to vsys1."""
        if self.mode.name == "local":
            return True
        try:
            text = self.tfvars.read_text()
        except OSError:
            return False
        return any(
            line.strip().split("=")[0].strip() in ("folder", "snippet") and "=" in line
            for line in text.splitlines()
            if not line.strip().startswith("#")
        )

    def terraform_env(self) -> dict[str, str]:
        env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
        if self.mode.name == "local":
            env.update(panos_provider_env(self.tf_dir))
        return env


def panos_provider_env(tf_dir: Path) -> dict[str, str]:
    """PAN-OS provider settings from the app's FIREWALL_* variables."""
    host = os.environ.get("FIREWALL_HOST", "").strip()
    parts = urllib.parse.urlsplit(f"//{host}")
    env = {"PANOS_HOSTNAME": parts.hostname or host, "PANOS_API_KEY": os.environ.get("FIREWALL_API_KEY", "").strip()}
    try:
        if parts.port:
            env["PANOS_PORT"] = str(parts.port)
    except ValueError:
        pass
    if os.environ.get("FIREWALL_VERIFY_TLS", "").strip().lower() in ("0", "false", "no", "off"):
        env["PANOS_SKIP_VERIFY_CERTIFICATE"] = "true"
    elif ca_file := os.environ.get("FIREWALL_CA_FILE", "").strip():
        # The provider has no CA option, but Go reads SSL_CERT_FILE on Linux.
        # Give it the system roots plus the firewall's CA.
        env["SSL_CERT_FILE"] = str(write_ca_bundle(tf_dir / CA_BUNDLE, Path(ca_file)))
    return env


def write_ca_bundle(path: Path, ca_file: Path) -> Path:
    system = ssl.get_default_verify_paths()
    parts = []
    for candidate in (system.cafile, system.openssl_cafile):
        if candidate and Path(candidate).is_file():
            parts.append(Path(candidate).read_text())
            break
    parts.append(ca_file.read_text())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(p.strip() for p in parts) + "\n")
    return path
