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


def cleanup_orphaned_jobs(repos: Repositories, stale_timeout_seconds: float = 300.0) -> int:
    """Watchdog that identifies stuck/orphaned jobs after a hard crash or OOM."""
    from app.domain.entities import ScanEvent, utc_now
    from app.domain.enums import EventKind, ScanStatus
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    from evaluator.orchestration.state_machine import is_terminal

    queue = SqliteJobQueue(repos.db)
    stale_jobs = queue.cleanup_stale_jobs(stale_timeout_seconds=stale_timeout_seconds)
    cleaned_count = len(stale_jobs)

    for j in stale_jobs:
        if j.get("action") == "failed":
            payload = j.get("payload") or {}
            scan_id = payload.get("scan_id")
            if scan_id:
                scan = repos.scans.get(scan_id)
                if scan and not is_terminal(scan.status):
                    logger.warning("Marking orphaned scan %s as failed_partial due to worker crash", scan_id)
                    repos.scans.update_status(scan_id, ScanStatus.FAILED_PARTIAL)
                    repos.events.append(
                        ScanEvent(
                            scan_id=scan_id,
                            kind=EventKind.SCAN_FAILED,
                            payload={"status": "failed_partial", "error": "Worker process died or timed out"},
                            created_at=utc_now(),
                        )
                    )
    return cleaned_count


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


async def _worker_slot(
    semaphore: asyncio.Semaphore,
    repos: Repositories,
    job: dict,
    active_tasks: set[asyncio.Task],
) -> None:
    async with semaphore:
        try:
            await process_job(repos, job)
            _complete(repos, job["job_id"])
        except Exception as exc:
            import traceback

            tb_str = traceback.format_exc()
            logger.exception("job %s failed", job["job_id"])
            _fail(repos, job["job_id"], str(exc), traceback=tb_str)
        finally:
            current_task = asyncio.current_task()
            if current_task and current_task in active_tasks:
                active_tasks.remove(current_task)


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

    # Startup watchdog: detect and clean up any jobs left orphaned by worker crash
    orphaned_count = cleanup_orphaned_jobs(repos)
    if orphaned_count > 0:
        logger.warning("Cleaned up %d orphaned job(s) from previous worker session", orphaned_count)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    semaphore = asyncio.Semaphore(settings.worker_concurrency)
    active_tasks: set[asyncio.Task] = set()

    while not stop.is_set():
        # Prune done tasks
        active_tasks = {t for t in active_tasks if not t.done()}

        # Honor concurrency limit
        if len(active_tasks) >= settings.worker_concurrency:
            await asyncio.sleep(0.05)
            continue

        job = repos.db and _claim(repos)
        if job is None:
            try:
                await asyncio.wait_for(stop.wait(), timeout=settings.poll_interval_seconds)
            except TimeoutError:
                pass
            continue

        task = asyncio.create_task(_worker_slot(semaphore, repos, job, active_tasks))
        active_tasks.add(task)

    if active_tasks:
        logger.info("waiting for %d active job(s) to finish...", len(active_tasks))
        await asyncio.gather(*active_tasks, return_exceptions=True)

    logger.info("RAVEN worker stopped")



def _claim(repos: Repositories) -> dict | None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    queue = SqliteJobQueue(repos.db)
    return queue.claim(JOB_KINDS)


def _complete(repos: Repositories, job_id: str) -> None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    SqliteJobQueue(repos.db).complete(job_id)


def _fail(repos: Repositories, job_id: str, error: str, traceback: str | None = None) -> None:
    from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

    SqliteJobQueue(repos.db).fail(job_id, error, traceback=traceback)


if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        sys.exit(0)
