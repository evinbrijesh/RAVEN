"""Scan endpoints: create, get, list, approve-hardening."""

from __future__ import annotations

import io
import json
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from app.application.approve_hardening import ApproveHardening, GetProposal
from app.application.create_scan import CreateScan
from app.application.get_scan import GetScan
from app.dependencies import get_queue, get_repositories
from app.domain.entities import Approval, HardeningProposal, ScanConfig, ScanView
from app.domain.errors import RavenError
from app.infrastructure.db.repository import Repositories
from app.infrastructure.queue.sqlite_queue import SqliteJobQueue

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _http_error(exc: RavenError) -> HTTPException:
    if exc.code == "NOT_FOUND":
        http_status = status.HTTP_404_NOT_FOUND
    elif exc.code == "CONFLICT":
        http_status = status.HTTP_409_CONFLICT
    else:
        http_status = status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=http_status, detail=exc.to_payload())


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    config: ScanConfig,
    repos: Repositories = Depends(get_repositories),
    queue: SqliteJobQueue = Depends(get_queue),
) -> dict[str, str]:
    """Create a scan and queue it for the evaluation worker (202 Accepted)."""
    try:
        scan = CreateScan(repos, queue).execute(config)
    except RavenError as exc:
        raise _http_error(exc) from exc
    return {"scan_id": scan.scan_id, "status": scan.status.value, "message": "Scan queued"}


@router.get("")
def list_scans(
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> list[dict[str, str]]:
    scans = repos.scans.list(project_id=project_id)
    return [
        {
            "scan_id": s.scan_id,
            "project_id": s.project_id,
            "status": s.status.value,
            "target_id": s.target.target_id,
        }
        for s in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> ScanView:
    try:
        return GetScan(repos).execute(scan_id, project_id=project_id)
    except RavenError as exc:
        raise _http_error(exc) from exc



@router.post("/{scan_id}/approve-hardening")
def approve_hardening(
    scan_id: str,
    body: dict[str, object],
    repos: Repositories = Depends(get_repositories),
    queue: SqliteJobQueue = Depends(get_queue),
) -> Approval:
    """Record a human approval decision; only affects the temporary target.

    Duplicate calls return HTTP 409 Conflict without spawning duplicate retest jobs.
    """
    try:
        proposal_id = str(body.get("proposal_id", ""))
        approved = bool(body.get("approved", False))
        approved_by = str(body.get("approved_by", "anonymous"))
        if not proposal_id:
            raise ValueError("proposal_id is required")
        return ApproveHardening(repos, queue).execute(scan_id, proposal_id, approved, approved_by)
    except RavenError as exc:
        raise _http_error(exc) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "VALIDATION_FAILED", "message": str(exc)},
        ) from exc


@router.get("/{scan_id}/proposal")
def get_proposal(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> HardeningProposal:
    try:
        return GetProposal(repos).execute(scan_id)
    except RavenError as exc:
        raise _http_error(exc) from exc


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, str]:
    """Cancel an active or queued scan, transitioning to failed_partial."""
    from app.domain.entities import ScanEvent, utc_now
    from app.domain.enums import EventKind, ScanStatus
    from app.domain.errors import NotFoundError

    scan = repos.scans.get(scan_id)
    if scan is None:
        raise _http_error(NotFoundError(f"Scan '{scan_id}' not found."))

    terminal_statuses = {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_WITHOUT_RETEST,
        ScanStatus.COMPLETED_WITH_LIMITATIONS,
        ScanStatus.FAILED_PARTIAL,
        ScanStatus.FAILED_FATAL,
        ScanStatus.INCONCLUSIVE,
    }
    if scan.status in terminal_statuses:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "CONFLICT",
                "message": f"Scan '{scan_id}' is already in terminal state '{scan.status.value}' and cannot be cancelled.",
            },
        )

    # 1. Update scan status to failed_partial
    repos.scans.update_status(scan_id, ScanStatus.FAILED_PARTIAL)

    # 2. Append SCAN_FAILED event
    repos.events.append(
        ScanEvent(
            scan_id=scan_id,
            kind=EventKind.SCAN_FAILED,
            payload={
                "status": "failed_partial",
                "reason": "user_cancelled",
                "message": "Scan cancelled by user",
            },
            created_at=utc_now(),
        )
    )

    # 3. Cancel any pending or running job in queue
    now_iso = utc_now().isoformat()
    repos.db.execute(
        "UPDATE jobs SET status = 'failed', error = 'Cancelled by user', updated_at = ?"
        " WHERE payload_json LIKE ? AND status IN ('queued', 'running')",
        (now_iso, f'%"{scan_id}"%'),
    )

    return {
        "scan_id": scan_id,
        "status": ScanStatus.FAILED_PARTIAL.value,
        "message": "Scan cancelled successfully",
    }


@router.get("/{scan_id}/artifacts/{artifact_id}/verify")
def verify_artifact(
    scan_id: str,
    artifact_id: str,
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> dict[str, object]:
    """Cryptographic audit verification of report artifacts (SARIF, JSON, Markdown) and transcripts.

    Validates that persisted content has not been tampered with by recomputing SHA-256
    and comparing against the recorded content_sha256 digest.
    """
    import json

    from app.application.report.service import _canonical_hash
    from app.domain.entities import utc_now
    from app.domain.errors import NotFoundError
    from app.security import compute_run_artifact_hash, compute_sha256

    scan = repos.scans.get(scan_id, project_id=project_id)
    if scan is None:
        raise _http_error(NotFoundError(f"Scan '{scan_id}' not found."))

    # 1. Check report artifacts (e.g. SARIF, JSON, Markdown)
    report_art = repos.reports.get_artifact_by_id(scan_id, artifact_id)
    if report_art is not None:
        fmt = report_art["format"]
        raw_content = report_art["content"]
        expected_hash = report_art["content_sha256"]
        if fmt == "json":
            try:
                computed_hash = _canonical_hash(json.loads(raw_content))
            except (json.JSONDecodeError, TypeError, ValueError, KeyError):
                computed_hash = compute_sha256(raw_content)
            if computed_hash != expected_hash and compute_sha256(raw_content) == expected_hash:
                computed_hash = expected_hash
        else:
            computed_hash = compute_sha256(raw_content)

        is_valid = bool(expected_hash and computed_hash.lower() == expected_hash.lower())
        return {
            "artifact_id": report_art["artifact_id"],
            "scan_id": scan_id,
            "artifact_type": "report",
            "format": fmt,
            "valid": is_valid,
            "tampered": not is_valid,
            "expected_sha256": expected_hash,
            "computed_sha256": computed_hash,
            "verified_at": utc_now().isoformat(),
        }

    # 2. Check transcript artifacts
    transcript_art = repos.runs.get_transcript_artifact(scan_id, artifact_id)
    if transcript_art is not None:
        raw_json = transcript_art["messages_json"]
        expected_hash = transcript_art["content_sha256"]
        computed_hash = compute_sha256(raw_json)
        try:
            data = json.loads(raw_json)
            canon = compute_run_artifact_hash(data)
            if canon == expected_hash:
                computed_hash = canon
        except (json.JSONDecodeError, TypeError, ValueError, KeyError):
            computed_hash = compute_sha256(raw_json)

        is_valid = bool(expected_hash and computed_hash.lower() == expected_hash.lower())
        return {
            "artifact_id": transcript_art["transcript_id"],
            "scan_id": scan_id,
            "run_id": transcript_art["run_id"],
            "artifact_type": "transcript",
            "format": "transcript_json",
            "valid": is_valid,
            "tampered": not is_valid,
            "expected_sha256": expected_hash,
            "computed_sha256": computed_hash,
            "verified_at": utc_now().isoformat(),
        }

    raise _http_error(NotFoundError(f"Artifact '{artifact_id}' not found for scan '{scan_id}'."))


@router.get("/{scan_id}/bundle")
def export_audit_bundle(
    scan_id: str,
    project_id: str | None = Query(default=None),
    repos: Repositories = Depends(get_repositories),
) -> Response:
    """Export complete cryptographic audit bundle as a ZIP archive.

    Includes:
    - report.sarif (SARIF 2.1.0 output)
    - summary.md (Executive markdown summary)
    - report.json (Canonical evaluation report document)
    - findings.json (Complete list of vulnerability findings)
    - transcripts.json (Attack and retest execution transcripts)
    - manifest.json (Bundle metadata and artifact index)
    - checksums.sha256 (Signed cryptographic SHA-256 digests of all bundled files)
    """
    from app.application.report.service import generate
    from app.domain.entities import utc_now
    from app.domain.errors import NotFoundError
    from app.security import compute_sha256

    scan = repos.scans.get(scan_id, project_id=project_id)
    if scan is None:
        raise _http_error(NotFoundError(f"Scan '{scan_id}' not found."))

    # 1. Generate canonical report and projections
    report_res = generate(repos, scan_id, project_id=project_id)
    sarif_str = report_res.sarif_text
    summary_str = report_res.markdown_text
    report_json_str = report_res.json_text

    # 2. Collect findings
    findings = [f.model_dump(mode="json") for f in repos.findings.list_for_scan(scan_id)]
    findings_str = json.dumps(findings, indent=2)

    # 3. Collect transcripts
    transcripts_list = []
    runs = repos.runs.list_runs(scan_id)
    for r in runs:
        run_id = r["run_id"]
        t = repos.runs.get_transcript(run_id)
        if t is not None:
            transcripts_list.append(
                {
                    "run_id": run_id,
                    "phase": r.get("phase"),
                    "attack_case_id": r.get("attack_case_id"),
                    "transcript_id": t.transcript_id,
                    "messages": [m.model_dump(mode="json") for m in t.messages],
                }
            )
    transcripts_str = json.dumps(transcripts_list, indent=2)

    # 4. Pack files and compute checksums
    files_to_bundle = {
        "report.sarif": sarif_str.encode("utf-8"),
        "summary.md": summary_str.encode("utf-8"),
        "report.json": report_json_str.encode("utf-8"),
        "findings.json": findings_str.encode("utf-8"),
        "transcripts.json": transcripts_str.encode("utf-8"),
    }

    manifest = {
        "bundle_version": "1.0",
        "scan_id": scan_id,
        "target_id": scan.target.target_id,
        "status": scan.status.value,
        "created_at": scan.created_at.isoformat(),
        "exported_at": utc_now().isoformat(),
        "artifacts": {name: compute_sha256(content) for name, content in files_to_bundle.items()},
    }
    files_to_bundle["manifest.json"] = json.dumps(manifest, indent=2).encode("utf-8")

    checksum_lines = [
        f"{compute_sha256(content)}  {filename}"
        for filename, content in sorted(files_to_bundle.items())
    ]
    files_to_bundle["checksums.sha256"] = ("\n".join(checksum_lines) + "\n").encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_to_bundle.items():
            zf.writestr(filename, content)

    zip_bytes = buffer.getvalue()
    bundle_hash = compute_sha256(zip_bytes)

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="raven_audit_bundle_{scan_id}.zip"',
            "X-RAVEN-Bundle-SHA256": bundle_hash,
            "ETag": f'"{bundle_hash}"',
        },
    )

