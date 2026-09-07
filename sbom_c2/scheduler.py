"""
Background CVE ingestion worker  (Capstone 1, Phase 2 — CVE Ingestion Worker)

Capstone 1 specified a background service polling vulnerability feeds on a
schedule. This implements that with an asyncio task inside the FastAPI process
rather than Celery, because Celery requires a message broker (Redis or RabbitMQ)
and that infrastructure buys nothing for a single-node deployment: the work is
periodic and idempotent, not a distributed queue.

The trade-off is honest and worth stating: this design does not survive a
process restart or scale across workers. For a production deployment across
many nodes, Celery with a broker would be the correct choice, and the poll
function below is already shaped to be called by one.
"""

import asyncio
import datetime as dt
import logging

log = logging.getLogger("sbom_c2.scheduler")

DEFAULT_INTERVAL_MINUTES = 60


class IngestionScheduler:
    """Periodically refreshes vulnerability data and Dependabot alert state."""

    def __init__(self, interval_minutes=DEFAULT_INTERVAL_MINUTES):
        self.interval = max(5, int(interval_minutes)) * 60
        self._task = None
        self.enabled = False
        self.last_run = None
        self.last_result = None
        self.last_error = None
        self.run_count = 0

    def start(self):
        if self._task is not None:
            return
        self.enabled = True
        self._task = asyncio.create_task(self._loop())
        log.info("ingestion scheduler started, interval %ds", self.interval)

    async def stop(self):
        self.enabled = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self):
        # Delay the first run so application startup is never blocked by it.
        await asyncio.sleep(30)
        while self.enabled:
            try:
                await asyncio.to_thread(self._run_once)
            except Exception as error:  # keep the loop alive on failure
                self.last_error = str(error)
                log.warning("scheduled ingestion failed: %s", error)
            await asyncio.sleep(self.interval)

    def _run_once(self):
        """
        One polling cycle: refresh alert state, then recompute impact.

        Deliberately does NOT re-run full SBOM ingestion. That is expensive and
        the inventory changes rarely; alert state changes continuously, which is
        what the measurement layer needs to see.
        """
        from .config import require_github
        from .db import SessionLocal
        from .github_client import GitHubClient
        from . import impact, remediation

        token, org = require_github()
        client = GitHubClient(token, org)
        session = SessionLocal()
        try:
            correlated = remediation.correlate_alerts(session, client)
            transitions = remediation.refresh_resolution_state(session, client)
            impact.capture_snapshot(session)

            self.last_run = dt.datetime.now(dt.timezone.utc).isoformat()
            self.last_result = {"correlated": correlated,
                                "transitions": transitions}
            self.last_error = None
            self.run_count += 1
            log.info("scheduled ingestion complete: %s", self.last_result)
        finally:
            session.close()

    def status(self):
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval,
            "run_count": self.run_count,
            "last_run": self.last_run,
            "last_result": self.last_result,
            "last_error": self.last_error,
        }


scheduler = IngestionScheduler()
