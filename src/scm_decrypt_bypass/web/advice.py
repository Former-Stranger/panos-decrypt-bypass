"""Explain decryption errors and check targets against the bypass lists."""

import ipaddress
import re
from pathlib import Path

from scm_decrypt_bypass import bypass_lists

# Alerts a client sends when it refuses the firewall's forward-proxy cert:
# the app pins its certificate, or this device doesn't trust the firewall CA.
CLIENT_REJECT = re.compile(r"(unknownca|certificateunknown|badcertificate|accessdenied|decrypterror|unsupportedcertificate)", re.I)


def explain(error: str, err_index: str, chain_status: str = "", root_status: str = "") -> dict:
    """A short diagnosis and the bypass kind that usually fits.

    kind is "exclusion" (breaks when decrypted: bypassing is the fix), "url"
    (a judgement call) or None (bypassing isn't the right fix). The GUI uses it
    to colour the diagnosis; every bypass goes to the no-decrypt URL list.
    """
    e, idx = (error or "").lower(), (err_index or "").lower()
    if idx == "none":
        idx = ""
    untrusted = any(s in (chain_status + root_status).lower() for s in ("untrusted", "incomplete"))

    if not e and not idx:
        return {"summary": "No error", "detail": "Handshake completed.", "kind": None}
    if "from client" in e and CLIENT_REJECT.search(e) and untrusted:
        return {
            "summary": "Firewall doesn't trust the server's certificate chain",
            "detail": "The firewall couldn't validate this site's certificate, so it presented the forward-untrust "
            "certificate and the client refused it. Either the site uses its own private CA (Signal does), "
            "in which case bypass it, or the firewall is missing a public intermediate/root CA, in which case "
            "importing that CA on the firewall is the real fix and a bypass is a stop-gap.",
            "kind": "url",
        }
    if "from client" in e and CLIENT_REJECT.search(e):
        return {
            "summary": "Client rejected the firewall's certificate",
            "detail": "The app pins its certificate, or this device doesn't trust your forward-trust CA. "
            "If the device trusts the CA for other sites, it's pinning: bypass it.",
            "kind": "exclusion",
        }
    if idx == "certificate" or "expired" in e or "untrusted" in e or untrusted:
        return {
            "summary": "Server certificate problem",
            "detail": "The site's own certificate is expired, self-signed or has an incomplete chain. "
            "Bypassing hides this from users, so only bypass sites you trust (e.g. internal ones).",
            "kind": "url",
        }
    if idx in ("cipher", "version", "protocol", "feature"):
        return {
            "summary": f"Firewall can't negotiate with the server ({err_index})",
            "detail": "The server uses TLS settings the decryption profile doesn't support (old/new version, "
            "cipher, client certs, oversized chain). Bypassing it is the usual fix.",
            "kind": "exclusion",
        }
    if idx == "resource":
        return {
            "summary": "Firewall ran out of decryption resources",
            "detail": "A capacity problem on the firewall, not this site. Bypassing won't fix the cause.",
            "kind": None,
        }
    if idx == "resume":
        return {"summary": "Session resumption failed", "detail": "Usually harmless; the client retries with a full handshake.", "kind": None}
    return {"summary": err_index or "Decryption error", "detail": error, "kind": "exclusion"}


def _host_matches(pattern: str, host: str, any_depth_leading_wildcard: bool) -> bool:
    if pattern == host:
        return True
    p_labels, h_labels = pattern.split("."), host.split(".")
    if any_depth_leading_wildcard and p_labels[0] == "*":
        # URL categories: a leading *. means one or more subdomains.
        rest = p_labels[1:]
        return len(h_labels) > len(rest) and _labels_match(rest, h_labels[-len(rest) :])
    return len(p_labels) == len(h_labels) and _labels_match(p_labels, h_labels)


def _labels_match(pattern: list[str], host: list[str]) -> bool:
    return all(p == "*" or p == h for p, h in zip(pattern, host, strict=True))


def _ip_in(entry: str, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if "-" in entry:
            start, end = (ipaddress.ip_address(x) for x in entry.split("-", 1))
            return start <= addr <= end
        return addr in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def bypass_status(bypass_dir: Path, host: str, src: str = "", dst: str = "") -> list[dict]:
    """Which bypass list entries already cover this session, if any."""
    host = host.lower()
    hits = []
    for kind, any_depth in (("url", True), ("exclusion", False)):
        for e in bypass_lists.read(bypass_dir, kind):
            if host and _host_matches(e.value, host, any_depth):
                hits.append({"kind": kind, "entry": e.value})
    for kind, ip in (("destination", dst), ("source", src)):
        if ip:
            hits += [{"kind": kind, "entry": e.value} for e in bypass_lists.read(bypass_dir, kind) if _ip_in(e.value, ip)]
    return hits
