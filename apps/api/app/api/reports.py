"""Report endpoints (ADR 0001).

GET /api/scans/{scan_id}/report?format=json|markdown|sarif&download=false

- JSON is canonical; Markdown and SARIF 2.1.0 are pure projections.
- Artifacts are immutable and identified by SHA-256; repeated requests with
  unchanged evidence reuse the persisted artifact.
- `download=true` adds a Content-Disposition attachment header.
- Response headers expose the schema version, canonical content hash, and
  artifact id (X-RAVEN-Report-*).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse

from app.application.report.service import ReportResult, generate
from app.dependencies import get_repositories
from app.domain.errors import NotFoundError, RavenError
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["reports"])

_FORMATS = ("json", "markdown", "sarif")
_MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown",
    "sarif": "application/sarif+json",
}
_EXTENSIONS = {"json": "json", "markdown": "md", "sarif": "sarif"}


def _report_response(result: ReportResult, fmt: str, download: bool) -> PlainTextResponse:
    headers = {
        "X-RAVEN-Report-Schema": result.document.schema_version,
        "X-RAVEN-Report-SHA256": result.content_sha256,
        "X-RAVEN-Report-Artifact": result.artifact_id,
    }
    if download:
        filename = f"raven-{result.document.scan.scan_id}-report.{_EXTENSIONS[fmt]}"
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return PlainTextResponse(
        {"json": result.json_text, "markdown": result.markdown_text, "sarif": result.sarif_text}[fmt],
        media_type=_MEDIA_TYPES[fmt],
        headers=headers,
    )


@router.get("/{scan_id}/report")
def get_report(
    scan_id: str,
    report_format: str = Query(default="json", alias="format"),
    download: bool = Query(default=False),
    repos: Repositories = Depends(get_repositories),
):
    if report_format not in _FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "VALIDATION_FAILED",
                "message": "format must be one of json|markdown|sarif",
                "retryable": False,
                "details": {"format": report_format},
            },
        )
    try:
        result = generate(repos, scan_id)
    except NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_payload()
        ) from exc
    except RavenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_payload()
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "code": "REPORT_GENERATION_FAILED",
                "message": f"Report generation failed: {exc}",
                "retryable": True,
            },
        ) from exc
    return _report_response(result, report_format, download)
