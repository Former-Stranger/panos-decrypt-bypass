"""Read and edit the bypass list files in bypass/.

Line parsing and normalisation mirror the locals in main.tf, so an entry this
module treats as a duplicate is exactly one Terraform would merge. Edits only
append or delete entry lines; comments and headers are left alone.
"""

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Kind:
    name: str
    file: str
    label: str
    noun: str
    example: str


KINDS = {
    k.name: k
    for k in (
        Kind(
            "exclusion",
            "exclusion-hostnames.txt",
            "Decryption exclusions (breaks when decrypted)",
            "hostnames, separated by spaces or commas",
            "pinned.example.com",
        ),
        Kind("url", "no-decrypt-urls.txt", "No-decrypt hostnames", "hostnames, separated by spaces or commas", "mybank.com"),
        Kind("category", "no-decrypt-categories.txt", "No-decrypt URL categories", "category names, separated by commas", "financial-services"),
        Kind(
            "destination",
            "no-decrypt-destinations.txt",
            "No-decrypt destinations",
            "IPs, subnets, ranges or FQDNs, separated by spaces or commas",
            "203.0.113.0/24",
        ),
        Kind(
            "source",
            "no-decrypt-sources.txt",
            "No-decrypt sources",
            "IPs, subnets, ranges or FQDNs, separated by spaces or commas",
            "10.20.30.0/24",
        ),
        Kind("user", "no-decrypt-users.txt", "No-decrypt users/groups", "user or group", r"example\jsmith"),
    )
}

COMMON_CATEGORIES = (
    "financial-services",
    "health-and-medicine",
    "government",
    "legal",
    "personal-sites-and-blogs",
    "shopping",
    "online-storage-and-backup",
    "business-and-economy",
)

# Same pattern as the exclusion check block in main.tf.
HOST_RE = re.compile(r"^(\*\.)*[a-z0-9_-]+(\.[a-z0-9_*-]+)*$")
# Last label must start with a letter so IPs and IP ranges never pass as FQDNs.
FQDN_RE = re.compile(r"^([a-z0-9_-]+\.)+[a-z][a-z0-9-]*$")
CATEGORY_RE = re.compile(r"^[a-z0-9-]+$")


@dataclass(frozen=True)
class Entry:
    value: str
    description: str | None


def normalize(kind: str, entry: str) -> str:
    """The key Terraform uses for an entry (see local.bypass_grouped)."""
    entry = entry.strip()
    if kind == "user":
        return entry
    return re.sub(r"^https?://", "", entry.lower()).removesuffix("/")


def split_line(line: str) -> tuple[str, str]:
    entry, _, description = line.partition("#")
    return entry.strip(), description.strip()


def path_for(bypass_dir: Path, kind: str) -> Path:
    return bypass_dir / KINDS[kind].file


def read(bypass_dir: Path, kind: str) -> list[Entry]:
    path = path_for(bypass_dir, kind)
    if not path.exists():
        return []
    entries: dict[str, Entry] = {}
    for line in path.read_text().splitlines():
        value, description = split_line(line)
        if value:
            key = normalize(kind, value)
            if key not in entries or (not entries[key].description and description):
                entries[key] = Entry(key, description or None)
    return list(entries.values())


def clean(kind: str, raw: str) -> tuple[str, list[str]]:
    """Validate and tidy one user-supplied entry.

    Returns (entry, notes). Raises ValueError with a readable reason if the
    entry can't be used for this kind.
    """
    raw = raw.strip()
    notes: list[str] = []
    if not raw:
        raise ValueError("empty entry")
    if "#" in raw:
        raise ValueError(f"{raw!r}: '#' starts a comment in the list files")

    if kind in ("exclusion", "url"):
        value = raw.lower()
        if "://" in value:
            parts = urlsplit(value)
            host, rest = parts.hostname or "", parts.path + (f"?{parts.query}" if parts.query else "")
        else:
            host, slash, rest = value.partition("/")
            rest = slash + rest
            host = host.rsplit("@", 1)[-1]
            if host.count(":") == 1:
                host = host.split(":")[0]
        if rest not in ("", "/"):
            notes.append(f"dropped {rest!r}: only the hostname is visible before decryption")
        if _is_ip(host):
            raise ValueError(f"{raw!r} is an IP address; add it as a destination instead")
        if not HOST_RE.match(host):
            raise ValueError(f"{raw!r} is not a valid hostname (wildcards must be whole labels, e.g. *.example.com)")
        return host, notes

    if kind == "category":
        value = raw.lower().replace(" ", "-")
        if not CATEGORY_RE.match(value):
            raise ValueError(f"{raw!r} is not a URL category name (lowercase words joined by '-')")
        return value, notes

    if kind in ("destination", "source"):
        value = raw.lower()
        if _is_ip(value) or _is_cidr(value) or _is_range(value) or FQDN_RE.match(value):
            return value, notes
        raise ValueError(f"{raw!r} is not an IP, CIDR (a.b.c.d/nn), range (a.b.c.d-e.f.g.h) or FQDN")

    if kind == "user":
        return raw, notes

    raise ValueError(f"unknown kind {kind!r}")


def with_subdomains(entries: list[str]) -> list[str]:
    """Add *.<host> for each host. www.example.com becomes example.com + *.example.com."""
    out: list[str] = []
    for e in entries:
        base = e.removeprefix("www.")
        for value in (base,) if base.startswith("*.") else (base, f"*.{base}"):
            if value not in out:
                out.append(value)
    return out


def add(bypass_dir: Path, kind: str, entry: str, description: str | None = None) -> bool:
    """Append an entry. Returns False if it is already in the list."""
    key = normalize(kind, entry)
    if any(e.value == key for e in read(bypass_dir, kind)):
        return False
    path = path_for(bypass_dir, kind)
    text = path.read_text() if path.exists() else f"# {KINDS[kind].label}\n"
    if text and not text.endswith("\n"):
        text += "\n"
    line = entry
    if description:
        line = f"{entry:<30}# {description}" if len(entry) < 30 else f"{entry}  # {description}"
    path.write_text(text + line + "\n")
    return True


def remove(bypass_dir: Path, kind: str, entry: str) -> int:
    """Delete every line holding this entry. Returns how many were removed."""
    path = path_for(bypass_dir, kind)
    if not path.exists():
        return 0
    key = normalize(kind, entry)
    kept, removed = [], 0
    for line in path.read_text().splitlines(keepends=True):
        value, _ = split_line(line)
        if value and normalize(kind, value) == key:
            removed += 1
        else:
            kept.append(line)
    if removed:
        path.write_text("".join(kept))
    return removed


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    # Prefix length only: Terraform's classifier doesn't understand /255.255.255.0 masks.
    if not re.match(r"^[^/]+/\d{1,3}$", value):
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_range(value: str) -> bool:
    start, sep, end = value.partition("-")
    if not sep or not (_is_ip(start) and _is_ip(end)):
        return False
    a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
    return a.version == b.version and a <= b
