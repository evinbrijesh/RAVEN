"""RAVEN evaluation worker.

Claims jobs from the durable queue and drives the ScanEngine through the
bounded state machine. Runs as a separate process from the control plane
(blueprint §1). No Redis required for the MVP profile.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from app.infrastructure.db.repository import Repositories
from app.infrastructure.db.sqlite import Database

from evaluator.config import get_worker_settings
from evaluator.orchestration.phases import ScanEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("raven.worker")

JOB_KINDS = ("run_scan", "run_retest")


async def process_job(repos: Repositories, job: dict) -> None:
    kind = job["kind"]
    scan_id = job["payload"].get("scan_id", "")
    engine = ScanEngine(repos)
    if kind == "run_scan":
        logger.info("running scan %s", scan_id)
        await engine.run(scan_id)
    elif kind == "run_retest":
        logger.info("running retest %s", scan_id)
        await engine.run_retest(scan_id)
    else:  # pragma: no cover — guarded by JOB_KINDS
        logger.warning("unknown job kind: %s", kind)


async def main_loop() -> None:
    settings = get_worker_settings()
    db = Database(settings.database_path)
    db.migrate()
    repos = Repositories(db)
    logger.info(
        "RAVEN worker started (db=%s, concurrency=%d)",
        settings.database_path,
        settings.worker_concurrency,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    while not stop.is_set():
        job = repos.db and _claim(repos)
        if job is None:
            try:
                await asyncio.wait_for(stop.wait(), timeout=settings.poll_interval_seconds)
            except TimeoutError:
                pass
            continue
        try:
            await process_job(repos, job)
            _complete(repos, job["job_id"])
        except Exception as exc:
            logger.exception("job %s failed", job["job_id"])
            _fail(repos, job["job_id"], str(exc))

    logger.info("RAVEN worker stopped")


def _claim(repos: Repositories) -> dict | None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    queue = SqliteJobQueue(repos.db)
    return queue.claim(JOB_KINDS)


def _complete(repos: Repositories, job_id: str) -> None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    SqliteJobQueue(repos.db).complete(job_id)


def _fail(repos: Repositories, job_id: str, error: str) -> None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    SqliteJobQueue(repos.db).fail(job_id, error)


if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        sys.exit(0)
