"""On-demand facts about a destination, to help work out what it is.

For a hostname: who registered the domain (RDAP through rdap.org), where it
points (DNS), and the certificate the server presents. For an IP address:
who owns the network (RDAP) and its reverse DNS name. Nothing runs until
someone clicks Look up. The server is only contacted on 443, and never when
it resolves to a private or otherwise non-public address.
"""

import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

RDAP = "https://rdap.org"
TIMEOUT = 10
CACHE_SECONDS = 24 * 3600
MAX_SANS = 30
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")


def parse_target(target: str) -> tuple[str, str]:
    """("ip", address) or ("host", hostname). Raises ValueError for anything else."""
    value = target.strip().lower().rstrip(".").removeprefix("*.")
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not HOST_RE.match(value):
        raise ValueError(f"Not a hostname or IP address: {target!r}")
    return "host", value


def is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


# --- network calls (swapped out in tests and demo mode) ------------------------


def fetch_json(url: str) -> dict | None:
    """GET a JSON document; None if it doesn't exist (404)."""
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def resolve(host: str) -> dict:
    canonical = host
    try:
        canonical = socket.gethostbyname_ex(host)[0]
    except OSError:
        pass
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    addresses = list(dict.fromkeys(i[4][0] for i in infos))
    return {"canonical": canonical.lower().rstrip("."), "addresses": addresses}


def reverse_dns(address: str) -> str:
    try:
        return socket.gethostbyaddr(address)[0]
    except OSError:
        return ""


def get_certificate(address: str, server_name: str | None) -> dict:
    """The certificate a server presents. The chain must be trusted (so the
    fields can be read); whether the name matches is reported separately."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    with socket.create_connection((address, 443), timeout=TIMEOUT) as sock, ctx.wrap_socket(sock, server_hostname=server_name) as tls:
        return tls.getpeercert()


# --- parsing --------------------------------------------------------------------


def _vcard(entity: dict) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] in ("fn", "org"):
            value = item[3][0] if isinstance(item[3], list) else item[3]
            if isinstance(value, str) and value.strip():
                out[item[0]] = value.strip()
        elif len(item) >= 4 and item[0] == "adr":
            cc = (item[1] or {}).get("cc")
            label = item[3][-1] if isinstance(item[3], list) and item[3] else ""
            out.setdefault("country", cc or (label if isinstance(label, str) else ""))
    return out


def _entities(data: dict):
    for entity in data.get("entities") or []:
        yield entity
        yield from _entities(entity)


def _party(data: dict, role: str) -> str:
    for entity in _entities(data):
        if role in (entity.get("roles") or []):
            card = _vcard(entity)
            name = card.get("org") or card.get("fn")
            if name:
                country = card.get("country")
                return f"{name} ({country})" if country and len(country) <= 3 else name
    return ""


def _event(data: dict, action: str) -> str:
    return next((e.get("eventDate", "")[:10] for e in data.get("events") or [] if e.get("eventAction") == action), "")


def parse_domain(data: dict) -> dict:
    return {
        "domain": (data.get("ldhName") or "").lower(),
        "registrar": _party(data, "registrar"),
        "registrant": _party(data, "registrant"),
        "registered": _event(data, "registration"),
        "expires": _event(data, "expiration"),
        "nameservers": sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in data.get("nameservers") or []} - {""}),
    }


def parse_network(data: dict) -> dict:
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs") or []]
    span = ", ".join(cidrs) or "-".join(x for x in (data.get("startAddress"), data.get("endAddress")) if x)
    return {
        "network": data.get("name", ""),
        "range": span,
        "owner": _party(data, "registrant") or _party(data, "administrative"),
        "country": data.get("country", ""),
    }


def _name(pairs) -> dict:
    return {k: v for rdn in pairs or () for k, v in rdn}


def names_match(host: str, names: list[str]) -> bool:
    for name in names:
        name = name.lower()
        if name == host or (name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count(".")):
            return True
    return False


def parse_certificate(cert: dict, host: str | None) -> dict:
    subject, issuer = _name(cert.get("subject")), _name(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName") or () if k == "DNS"]
    out = {
        "subject": subject.get("commonName", ""),
        "organization": subject.get("organizationName", ""),
        "country": subject.get("countryName", ""),
        "issuer": " · ".join(x for x in (issuer.get("organizationName"), issuer.get("commonName")) if x),
        "expires": cert.get("notAfter", ""),
        "names": sans[:MAX_SANS],
        "more_names": max(0, len(sans) - MAX_SANS),
    }
    if host:
        out["matches"] = names_match(host, sans or [out["subject"]])
    return out


def links(kind: str, value: str, domain: str) -> list[dict]:
    q = urllib.parse.quote
    if kind == "ip":
        return [
            {"label": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{q(value)}"},
            {"label": "urlscan.io", "url": f"https://urlscan.io/search/#ip:{q(value)}"},
            {"label": "Web search", "url": f"https://duckduckgo.com/?q={q(chr(34) + value + chr(34))}"},
        ]
    return [
        {"label": "VirusTotal", "url": f"https://www.virustotal.com/gui/domain/{q(domain)}"},
        {"label": "urlscan.io", "url": f"https://urlscan.io/search/#domain:{q(domain)}"},
        {"label": "crt.sh", "url": f"https://crt.sh/?q={q(domain)}"},
        {"label": "Web search", "url": f"https://duckduckgo.com/?q={q(chr(34) + domain + chr(34))}"},
    ]


# --- the lookup -----------------------------------------------------------------


def _safe(fn: Callable[[], dict]) -> dict:
    try:
        return fn()
    except Exception as e:  # each section fails on its own; show why
        reason = getattr(e, "reason", None) or getattr(e, "verify_message", None) or e
        return {"error": str(reason) or type(e).__name__}


class Lookup:
    def __init__(self, fetch_json=fetch_json, resolve=resolve, reverse_dns=reverse_dns, get_certificate=get_certificate):
        self.fetch_json, self.resolve, self.reverse_dns, self.get_certificate = fetch_json, resolve, reverse_dns, get_certificate
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def lookup(self, target: str) -> dict:
        kind, value = parse_target(target)
        with self._lock:
            hit = self._cache.get(value)
            if hit and time.time() - hit[0] < CACHE_SECONDS:
                return hit[1]
        result = self._ip(value) if kind == "ip" else self._host(value)
        result |= {"target": value, "kind": kind, "looked_up": time.time()}
        with self._lock:
            if len(self._cache) > 500:
                self._cache.clear()
            self._cache[value] = (time.time(), result)
        return result

    def _host(self, host: str) -> dict:
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            registration = pool.submit(_safe, lambda: self.registration(host))
            dns = _safe(lambda: self.resolve(host))
            certificate = pool.submit(_safe, lambda: self.certificate(dns.get("addresses") or [], host))
            registration = registration.result()
        return {
            "registration": registration,
            "dns": dns,
            "certificate": certificate.result(),
            "links": links("host", host, registration.get("domain") or host),
        }

    def _ip(self, address: str) -> dict:
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            network = pool.submit(_safe, lambda: self.network(address))
            reverse = pool.submit(lambda: self.reverse_dns(address))
            certificate = pool.submit(_safe, lambda: self.certificate([address], None))
            return {
                "network": network.result(),
                "dns": {"reverse": reverse.result()},
                "certificate": certificate.result(),
                "links": links("ip", address, address),
            }

    def registration(self, host: str) -> dict:
        """The registered domain's RDAP record. Longest name first: registries
        answer "not found" for names that aren't registered, while a short
        candidate like co.uk would match the registry's own record."""
        labels = host.split(".")
        for n in range(min(len(labels), 4), 1, -1):
            candidate = ".".join(labels[-n:])
            data = self.fetch_json(f"{RDAP}/domain/{candidate}")
            if data and (data.get("ldhName") or "").lower() == candidate:
                return parse_domain(data)
        return {"error": "No registration record found."}

    def network(self, address: str) -> dict:
        if not is_public(address):
            return {"error": "Private or reserved address: no public registration."}
        data = self.fetch_json(f"{RDAP}/ip/{address}")
        return parse_network(data) if data else {"error": "No registration record found."}

    def certificate(self, addresses: list[str], host: str | None) -> dict:
        public = [a for a in addresses if is_public(a)]
        if not public:
            return {"skipped": "Not contacted: no public address."}
        return parse_certificate(self.get_certificate(public[0], host), host)


class DemoLookup(Lookup):
    """WEBGUI_DEMO: made-up but realistic answers, no network."""

    def __init__(self):
        super().__init__(
            fetch_json=lambda url: {
                "ldhName": url.rsplit("/", 1)[1],
                "entities": [
                    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]},
                    {"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Example Corp"], ["adr", {"cc": "US"}, "text", ""]]]},
                ],
                "events": [{"eventAction": "registration", "eventDate": "2014-03-02T00:00:00Z"}],
                "nameservers": [{"ldhName": "ns1.example.net"}, {"ldhName": "ns2.example.net"}],
                "name": "EXAMPLE-NET",
                "startAddress": "203.0.113.0",
                "endAddress": "203.0.113.255",
            },
            resolve=lambda host: {"canonical": f"{host}.edgekey.example", "addresses": ["93.184.215.14"]},
            reverse_dns=lambda address: "edge-1.example.net",
            get_certificate=lambda address, host: {
                "subject": ((("commonName", host or "edge.example.net"),), (("organizationName", "Example Corp"),)),
                "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example TLS CA 2026"),)),
                "subjectAltName": tuple(("DNS", n) for n in (host or "edge.example.net", f"*.{host or 'example.net'}", "example-cdn.net")),
                "notAfter": "Mar  1 12:00:00 2027 GMT",
            },
        )
