"""PAN-OS XML API client for decryption logs.

Log retrieval is a two-step job: type=log creates a query job, then
action=get polls it until status is FIN and returns <entry> elements.
"""

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass

# Decryption log fields, keyed by the name this app uses. Values are the XML
# tags to try, in order: syslog docs and XML output don't always agree
# (err_index vs error_index), so accept either.
FIELDS: dict[str, tuple[str, ...]] = {
    "receive_time": ("receive_time",),
    "time_generated": ("time_generated",),
    "serial": ("serial",),
    "seqno": ("seqno",),
    "device_name": ("device_name",),
    "src": ("src",),
    "dst": ("dst",),
    "sport": ("sport",),
    "dport": ("dport",),
    "srcuser": ("srcuser", "src_user"),
    "src_host": ("src_host",),
    "from_zone": ("from",),
    "to_zone": ("to",),
    "rule": ("rule",),
    "policy_name": ("policy_name",),
    "app": ("app",),
    "proxy_type": ("proxy_type",),
    "tls_version": ("tls_version",),
    "tls_enc": ("tls_enc",),
    "err_index": ("err_index", "error_index"),
    "error": ("error", "error_msg"),
    "chain_status": ("chain_status",),
    "root_status": ("root_status",),
    "sni": ("sni",),
    "cn": ("cn",),
    "issuer_cn": ("issuer_cn",),
    "root_cn": ("root_cn",),
    "notafter": ("notafter",),
    "hs_stage_c2f": ("hs_stage_c2f",),
    "hs_stage_f2s": ("hs_stage_f2s",),
}


class PanosError(Exception):
    pass


@dataclass
class LogEntry:
    uid: str
    fields: dict[str, str]
    raw: dict[str, str]


def fields_from_raw(raw: dict[str, str]) -> dict[str, str]:
    """Map raw log tags to this app's field names."""
    fields = {key: next((raw[t] for t in tags if raw.get(t)), "") for key, tags in FIELDS.items()}
    fields["sni_truncated"] = ""
    # Decryption logs cut the SNI at 31 characters; sni_len keeps the real
    # length. When the cert CN is that full name, use it.
    sni, sni_len, cn = fields["sni"], raw.get("sni_len", ""), fields["cn"]
    if sni and sni_len.isdigit() and int(sni_len) > len(sni):
        if cn.lower().startswith(sni.lower()) and len(cn) == int(sni_len):
            fields["sni"] = cn
        else:
            fields["sni_truncated"] = sni_len  # real length, for the GUI to show
    return fields


def parse_entries(xml_text: str) -> list[LogEntry]:
    """Parse the <entry> elements of a finished log job response."""
    root = ET.fromstring(xml_text)  # noqa: S314 - from the configured firewall; expat in Python 3.12+ resists entity expansion
    entries = []
    for el in root.iter("entry"):
        raw = {child.tag: (child.text or "").strip() for child in el}
        fields = fields_from_raw(raw)
        if fields["serial"] and fields["seqno"]:
            uid = f"{fields['serial']}:{fields['seqno']}"
        else:
            uid = el.get("logid") or str(hash(tuple(sorted(raw.items()))))
        entries.append(LogEntry(uid, fields, raw))
    return entries


class Firewall:
    def __init__(self, host: str, api_key: str, verify_tls: bool = True, ca_file: str | None = None, timeout: int = 30):
        self.base = f"https://{host}/api/"
        self.api_key = api_key
        self.timeout = timeout
        # ca_file: trust a private CA (e.g. the Home CA that signed the mgmt cert).
        self.context = ssl.create_default_context(cafile=ca_file)
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def _call(self, params: dict[str, str]) -> ET.Element:
        url = f"{self.base}?{urllib.parse.urlencode(params)}"
        # Key in a header (PAN-OS 9.0+) so it never lands in access logs.
        req = urllib.request.Request(url, headers={"X-PAN-KEY": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:
                body = resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            raise PanosError(f"HTTP {e.code} from firewall: {e.read().decode(errors='replace')[:300]}") from e
        except urllib.error.URLError as e:
            raise PanosError(f"Can't reach firewall at {self.base}: {e.reason}") from e
        root = ET.fromstring(body)  # noqa: S314 - see parse_entries
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())
            raise PanosError(f"Firewall API error: {msg or body[:300]}")
        root.set("_body", body)
        return root

    def query_decryption_logs(self, query: str, nlogs: int = 1000, job_timeout: int = 120) -> list[LogEntry]:
        """Run a decryption log query, oldest first, and return the entries."""
        params = {"type": "log", "log-type": "decryption", "nlogs": str(nlogs), "dir": "forward"}
        if query:
            params["query"] = query
        job = self._call(params).findtext(".//job")
        if not job:
            raise PanosError("Firewall did not return a log job id.")

        deadline = time.monotonic() + job_timeout
        while True:
            root = self._call({"type": "log", "action": "get", "job-id": job.strip()})
            if root.findtext(".//job/status") == "FIN":
                return parse_entries(root.get("_body"))
            if time.monotonic() > deadline:
                self._call({"type": "log", "action": "finish", "job-id": job.strip()})
                raise PanosError(f"Log query job {job} did not finish in {job_timeout}s.")
            time.sleep(1)
