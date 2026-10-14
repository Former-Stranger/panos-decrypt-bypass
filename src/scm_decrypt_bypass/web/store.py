"""SQLite store for decryption log events."""

import ipaddress
import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from scm_decrypt_bypass.web.panos import LogEntry, fields_from_raw

COLUMNS = (
    "receive_time",
    "device_name",
    "src",
    "dst",
    "dport",
    "srcuser",
    "src_host",
    "from_zone",
    "to_zone",
    "rule",
    "policy_name",
    "app",
    "proxy_type",
    "tls_version",
    "err_index",
    "error",
    "chain_status",
    "root_status",
    "sni",
    "cn",
    "issuer_cn",
    "root_cn",
    "notafter",
    "hs_stage_c2f",
    "hs_stage_f2s",
    "sni_truncated",
)

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS events (
    uid TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    target TEXT NOT NULL,
    failed INTEGER NOT NULL,
    {", ".join(f"{c} TEXT" for c in COLUMNS)},
    raw TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_target ON events (target, ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def firewall_time_to_epoch(value: str, tz: ZoneInfo) -> float:
    """PAN-OS log times look like 2026/09/29 10:01:02, in the firewall's local time."""
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz).timestamp()
    except ValueError:
        return time.time()


def sorted_ips(joined: str | None) -> list[str]:
    """Split a GROUP_CONCAT of IPs and sort them numerically (IPv4 before IPv6)."""

    def key(ip: str):
        try:
            a = ipaddress.ip_address(ip)
            return (a.version, int(a), ip)
        except ValueError:
            return (9, 0, ip)

    return sorted({ip for ip in (joined or "").split(",") if ip}, key=key)


def target_of(fields: dict[str, str]) -> str:
    """What the session was trying to reach: SNI, else cert CN, else destination IP."""
    return (fields.get("sni") or fields.get("cn") or fields.get("dst") or "unknown").lower()


def is_failure(fields: dict[str, str]) -> bool:
    # Successful handshakes log err_index as the literal string "None".
    return bool(fields.get("error")) or (fields.get("err_index") or "").strip().lower() not in ("", "none")


class Store:
    def __init__(self, path: Path, tz: ZoneInfo):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.tz = tz
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        # v2: rows stored before the err_index "None" fix were all marked failed.
        if self.get_meta("failed_v2") is None:
            with self.lock, self.db:
                self.db.execute("UPDATE events SET failed = (error != '' OR (err_index != '' AND lower(err_index) != 'none'))")
            self.set_meta("failed_v2", "1")
        # v3: SNI truncation handling (new column; repair rows stored before it).
        if self.get_meta("sni_v3") is None:
            with self.lock, self.db:
                cols = {r[1] for r in self.db.execute("PRAGMA table_info(events)")}
                if "sni_truncated" not in cols:
                    self.db.execute("ALTER TABLE events ADD COLUMN sni_truncated TEXT DEFAULT ''")
                for uid, raw in self.db.execute("SELECT uid, raw FROM events").fetchall():
                    f = fields_from_raw(json.loads(raw or "{}"))
                    if f["sni_truncated"] or f["sni"] != json.loads(raw or "{}").get("sni", ""):
                        self.db.execute(
                            "UPDATE events SET sni = ?, sni_truncated = ?, target = ? WHERE uid = ?",
                            (f["sni"], f["sni_truncated"], target_of(f), uid),
                        )
            self.set_meta("sni_v3", "1")

    def add(self, entries: list[LogEntry]) -> int:
        rows = [
            (
                e.uid,
                firewall_time_to_epoch(e.fields["receive_time"], self.tz),
                target_of(e.fields),
                int(is_failure(e.fields)),
                *(e.fields.get(c, "") for c in COLUMNS),
                json.dumps(e.raw),
            )
            for e in entries
        ]
        names = ", ".join(("uid", "ts", "target", "failed", *COLUMNS, "raw"))
        placeholders = ", ".join("?" * (4 + len(COLUMNS) + 1))
        with self.lock, self.db:
            before = self.db.total_changes
            # Column names and placeholders are fixed; values are bound parameters.
            self.db.executemany(f"INSERT OR IGNORE INTO events ({names}) VALUES ({placeholders})", rows)  # noqa: S608
            return self.db.total_changes - before

    def latest_receive_time(self) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT receive_time FROM events ORDER BY ts DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def prune(self, retention_days: int) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE ts < ?", (time.time() - retention_days * 86400,))

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def issues(self, since: float, failures_only: bool, search: str = "") -> list[dict]:
        """One row per target, newest problem first."""
        where = ["ts >= ?"]
        args: list = [since]
        if failures_only:
            where.append("failed = 1")
        if search:
            where.append("(target LIKE ? OR src LIKE ? OR dst LIKE ? OR error LIKE ? OR srcuser LIKE ?)")
            args += [f"%{search}%"] * 5
        # WHERE is built from fixed fragments; user input only goes in bound parameters.
        sql = f"""
            SELECT target,
                   COUNT(*) AS hits,
                   SUM(failed) AS failures,
                   COUNT(DISTINCT src) AS clients,
                   GROUP_CONCAT(DISTINCT src) AS client_ips,
                   GROUP_CONCAT(DISTINCT dst) AS dst_ips,
                   MIN(ts) AS first_seen,
                   MAX(ts) AS last_seen
            FROM events WHERE {" AND ".join(where)}
            GROUP BY target ORDER BY last_seen DESC LIMIT 500
        """  # noqa: S608
        with self.lock:
            groups = [dict(r) for r in self.db.execute(sql, args)]
            # Details from the most recent event per target (prefer a failure).
            for g in groups:
                latest = self.db.execute(
                    "SELECT * FROM events WHERE target = ? AND ts >= ? ORDER BY failed DESC, ts DESC LIMIT 1",
                    (g["target"], since),
                ).fetchone()
                g.update(
                    {
                        k: latest[k]
                        for k in (
                            "sni",
                            "sni_truncated",
                            "cn",
                            "dst",
                            "dport",
                            "error",
                            "err_index",
                            "policy_name",
                            "proxy_type",
                            "chain_status",
                            "root_status",
                            "issuer_cn",
                            "tls_version",
                        )
                    }
                )
                g["client_ips"] = sorted_ips(g["client_ips"])[:10]
                g["dst_ips"] = sorted_ips(g["dst_ips"])
        return groups

    def events(self, target: str, since: float, limit: int = 200) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE target = ? AND ts >= ? ORDER BY ts DESC LIMIT ?", (target, since, limit)).fetchall()
        return [{k: r[k] for k in r.keys() if k != "raw"} | {"raw": json.loads(r["raw"] or "{}")} for r in rows]  # noqa: SIM118 - sqlite3.Row `in` checks values

    def get_meta(self, key: str) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
