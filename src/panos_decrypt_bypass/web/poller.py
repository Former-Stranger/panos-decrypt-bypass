"""Background loop that pulls new decryption logs from the firewall."""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

from panos_decrypt_bypass.web.panos import Firewall, LogEntry, PanosError, parse_entries
from panos_decrypt_bypass.web.settings import Settings
from panos_decrypt_bypass.web.store import Store

log = logging.getLogger("panos_decrypt_bypass.poller")

PAGE_SIZE = 1000
MAX_PAGES = 10
DEMO_FIXTURE = Path(__file__).resolve().parent / "demo_logs.xml"


class Poller:
    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.wake = asyncio.Event()
        self.status: dict = {"last_poll": None, "last_success": None, "last_error": None, "last_added": 0, "polling": False}
        self.firewall = None
        if not settings.demo and not settings.problems():
            self.firewall = Firewall(
                settings.firewall_host,
                settings.api_key,
                verify_tls=settings.verify_tls,
                ca_file=str(settings.ca_file) if settings.ca_file else None,
            )

    def query(self) -> str:
        cursor = self.store.latest_receive_time()
        if cursor is None:
            start = datetime.now(self.settings.timezone) - timedelta(hours=self.settings.lookback_hours)
            cursor = start.strftime("%Y/%m/%d %H:%M:%S")
        # geq, not gt: the last second may have had more logs than we saw.
        # Duplicates are dropped by the store's primary key.
        q = f"(receive_time geq '{cursor}')"
        return f"{q} and ({self.settings.extra_query})" if self.settings.extra_query else q

    def poll_once(self) -> int:
        """Fetch everything since the newest stored log. Blocking; run in a thread."""
        if self.settings.demo:
            return self.store.add(demo_entries(self.settings))
        if self.firewall is None:
            raise PanosError("; ".join(self.settings.problems()))

        added = 0
        for _ in range(MAX_PAGES):
            before = self.store.latest_receive_time()
            entries = self.firewall.query_decryption_logs(self.query(), nlogs=PAGE_SIZE)
            added += self.store.add(entries)
            # A short page means we're caught up; an unchanged cursor means
            # one second holds more than a page and paging can't advance.
            if len(entries) < PAGE_SIZE or self.store.latest_receive_time() == before:
                break
        self.store.prune(self.settings.retention_days)
        return added

    async def run(self) -> None:
        while True:
            self.status.update(polling=True, last_poll=time.time())
            try:
                added = await asyncio.to_thread(self.poll_once)
                self.status.update(last_success=time.time(), last_error=None, last_added=added)
                if added:
                    log.info("stored %d new decryption log(s)", added)
            except Exception as e:  # keep polling through firewall/network hiccups
                log.warning("poll failed: %s", e)
                self.status["last_error"] = str(e)
            finally:
                self.status["polling"] = False
            self.wake.clear()
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=self.settings.poll_seconds)
            except TimeoutError:
                pass


def demo_entries(settings: Settings) -> list[LogEntry]:
    """Sample logs with timestamps moved to the last hour, for previewing the GUI."""
    entries = parse_entries(DEMO_FIXTURE.read_text())
    now = datetime.now(settings.timezone)
    for i, e in enumerate(entries):
        e.fields["receive_time"] = (now - timedelta(minutes=3 * i + 1)).strftime("%Y/%m/%d %H:%M:%S")
    return entries
