"""An install's own files, kept apart from the code.

    DATA_DIR/                      (/data in the container, ./data otherwise)
      terraform.tfvars             your settings (created from a template)
      bypass/*.txt                 the bypass lists
      decrypt.db                   decryption logs pulled by the web GUI
      terraform/                   Terraform working directory: state, providers,
                                   and a copy of the bundled module refreshed
                                   before every run

Files you add to DATA_DIR/terraform/ yourself (for example backend.tf for
remote state) are left alone.
"""

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
MODULE_DIR = PACKAGE_DIR / "terraform"
TEMPLATES_DIR = PACKAGE_DIR / "templates"
PATHS_FILE = "zz-panos-decrypt-bypass.auto.tfvars.json"


def default_data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR") or Path.cwd() / "data").expanduser().resolve()


@dataclass(frozen=True)
class Workspace:
    data_dir: Path

    @classmethod
    def from_env(cls) -> "Workspace":
        return cls(default_data_dir())

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
            shutil.copyfile(TEMPLATES_DIR / "terraform.tfvars", self.tfvars)
            created.append(self.tfvars)
        return created

    def prepare_terraform(self) -> Path:
        """Refresh the Terraform working directory from the bundled module and
        the user's settings. Returns the directory to run terraform in."""
        self.ensure()
        self.tf_dir.mkdir(parents=True, exist_ok=True)
        for src in MODULE_DIR.rglob("*"):
            if src.is_file() and (src.suffix == ".tf" or src.name == ".terraform.lock.hcl"):
                dst = self.tf_dir / src.relative_to(MODULE_DIR)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
        shutil.copyfile(self.tfvars, self.tf_dir / "terraform.tfvars")
        (self.tf_dir / PATHS_FILE).write_text(json.dumps({"bypass_dir": str(self.bypass_dir)}) + "\n")
        return self.tf_dir

    def has_location(self) -> bool:
        """True once terraform.tfvars sets a folder or snippet (uncommented)."""
        try:
            text = self.tfvars.read_text()
        except OSError:
            return False
        return any(
            line.strip().split("=")[0].strip() in ("folder", "snippet") and "=" in line
            for line in text.splitlines()
            if not line.strip().startswith("#")
        )


def terraform_env() -> dict[str, str]:
    return {**os.environ, "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
