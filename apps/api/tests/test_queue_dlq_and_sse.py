"""Tests for atomic job queue leasing, dead-letter queue (DLQ) forensics, and SSE streaming."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from app.domain.entities import Scan, ScanConfig, ScanEvent, utc_now
from app.domain.enums import EventKind, ScanStatus
from app.domain.value_objects import TargetRef
from app.infrastructure.db.sqlite import Database
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue


def test_atomic_queue_claim_concurrency(tmp_path: pytest.TempPathFactory) -> None:
    """Verify concurrent workers claiming from the queue never double-claim or lose jobs."""
    db = Database(tmp_path / "test_queue.db")
    db.migrate()
    queue = SqliteJobQueue(db)

    # Enqueue 20 jobs
    job_ids = [queue.enqueue("run_scan", {"scan_index": i}) for i in range(20)]
    assert len(job_ids) == 20

    # 4 concurrent worker threads repeatedly claiming jobs
    claimed_jobs: list[str] = []

    def worker_claim_loop() -> list[str]:
        worker_claimed = []
        while True:
            job = queue.claim(("run_scan",))
            if not job:
                break
            worker_claimed.append(job["job_id"])
        return worker_claimed

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker_claim_loop) for _ in range(4)]
        for f in futures:
            claimed_jobs.extend(f.result())

    # Every job must be claimed exactly once
    assert len(claimed_jobs) == 20
    assert set(claimed_jobs) == set(job_ids)
    # Queue must now be empty
    assert queue.claim(("run_scan",)) is None


def test_job_dead_letter_escalation_and_forensics(tmp_path: pytest.TempPathFactory) -> None:
    """Verify that jobs exceeding max attempts land in the dead-letter queue with forensic telemetry."""
    db = Database(tmp_path / "test_dlq.db")
    db.migrate()
    queue = SqliteJobQueue(db)

    job_id = queue.enqueue("run_scan", {"scan_id": "scan_fail_1", "meta": "test"})

    # Attempt 1
    job1 = queue.claim(("run_scan",))
    assert job1 is not None and job1["attempts"] == 1
    queue.fail(job_id, "Attempt 1 failed", traceback="Traceback line 1", max_attempts=3)
    row1 = db.query_one("SELECT status, attempts FROM jobs WHERE job_id = ?", (job_id,))
    assert row1["status"] == "failed"
    assert row1["attempts"] == 1

    # Re-queue for attempt 2
    db.execute("UPDATE jobs SET status = 'queued' WHERE job_id = ?", (job_id,))
    job2 = queue.claim(("run_scan",))
    assert job2 is not None and job2["attempts"] == 2
    queue.fail(job_id, "Attempt 2 failed", traceback="Traceback line 2", max_attempts=3)

    # Re-queue for attempt 3 (reaches max_attempts)
    db.execute("UPDATE jobs SET status = 'queued' WHERE job_id = ?", (job_id,))
    job3 = queue.claim(("run_scan",))
    assert job3 is not None and job3["attempts"] == 3

    # Attempt 3 fails -> should escalate to Dead-Letter Queue
    fake_traceback = "Traceback (most recent call last):\n  File 'worker.py', line 42, in process_job\nFatalCrashError"
    queue.fail(job_id, "Fatal crash during attack execution", traceback=fake_traceback, max_attempts=3)

    # Job record updated
    row3 = db.query_one("SELECT status, error FROM jobs WHERE job_id = ?", (job_id,))
    assert row3["status"] == "failed"
    assert "Fatal crash" in row3["error"]

    # DLQ table contains the failure forensic record
    dead_letters = queue.list_dead_letters()
    assert len(dead_letters) == 1
    dl = dead_letters[0]
    assert dl["job_id"] == job_id
    assert dl["kind"] == "run_scan"
    assert dl["attempts"] == 3
    assert dl["payload"] == {"scan_id": "scan_fail_1", "meta": "test"}
    assert dl["error"] == "Fatal crash during attack execution"
    assert dl["traceback"] == fake_traceback
    assert dl["dead_lettered_at"] is not None


def test_cleanup_stale_jobs_dead_letters(tmp_path: pytest.TempPathFactory) -> None:
    """Verify watchdog stale job cleanup moves exhausted jobs into the DLQ."""
    db = Database(tmp_path / "test_stale_dlq.db")
    db.migrate()
    queue = SqliteJobQueue(db)

    stale_time = (utc_now() - timedelta(seconds=400)).isoformat()
    job_id = "job_stale_exhausted"
    db.execute(
        "INSERT INTO jobs (job_id, kind, payload_json, status, attempts, created_at, updated_at) "
        "VALUES (?, ?, ?, 'running', 3, ?, ?)",
        (job_id, "run_scan", '{"scan_id": "scan_orphaned"}', stale_time, stale_time),
    )

    cleaned = queue.cleanup_stale_jobs(stale_timeout_seconds=300.0, max_attempts=3)
    assert len(cleaned) == 1
    assert cleaned[0]["action"] == "failed"
    assert "dead_letter_id" in cleaned[0]

    # Verify DLQ record was created
    dead_letters = queue.list_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0]["job_id"] == job_id
    assert dead_letters[0]["error"] == "Worker timeout / orphaned job"


def test_sse_event_streaming_and_reconnection(client) -> None:
    """Verify live Server-Sent Events stream delivering event ids, types, and Last-Event-ID resume."""

    repos = client.app.state.repos

    # Create scan
    scan = Scan(
        scan_id="scan_sse_test",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
        status=ScanStatus.ATTACKING,
    )
    repos.scans.create(scan)

    # Append 3 events
    ev1 = repos.events.append(
        ScanEvent(scan_id=scan.scan_id, kind=EventKind.RECON_COMPLETED, payload={"phase": "recon"})
    )
    ev2 = repos.events.append(
        ScanEvent(scan_id=scan.scan_id, kind=EventKind.ATTACK_STARTED, payload={"attack_id": "A-01"})
    )
    ev3 = repos.events.append(
        ScanEvent(scan_id=scan.scan_id, kind=EventKind.ATTACK_FINISHED, payload={"attack_id": "A-01"})
    )

    # Now mark scan completed so SSE generator terminates gracefully
    repos.scans.update_status(scan.scan_id, ScanStatus.COMPLETED)

    # 1. Full stream from start
    response = client.get(f"/api/scans/{scan.scan_id}/events/stream")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    body = response.text

    assert f"id: {ev1.event_id}" in body
    assert f"id: {ev2.event_id}" in body
    assert f"id: {ev3.event_id}" in body
    assert "event: recon_completed" in body
    assert "event: attack_started" in body
    assert "event: attack_finished" in body
    assert "event: stream_end" in body

    # 2. Reconnection using Last-Event-ID header (resuming after event 2)
    response_resumed = client.get(
        f"/api/scans/{scan.scan_id}/events/stream",
        headers={"Last-Event-ID": str(ev2.event_id)},
    )
    assert response_resumed.status_code == 200
    resumed_body = response_resumed.text

    # ev1 and ev2 must NOT be repeated
    assert f"id: {ev1.event_id}" not in resumed_body
    assert f"id: {ev2.event_id}" not in resumed_body
    # ev3 must be delivered
    assert f"id: {ev3.event_id}" in resumed_body
    assert "event: attack_finished" in resumed_body
    assert "event: stream_end" in resumed_body
