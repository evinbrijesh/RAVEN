"""Report service (ADR 0001).

Orchestrates: collect persisted evidence → assemble canonical document →
redact at render time → hash (excluding report_id/generated_at/integrity) →
persist idempotent artifacts → produce Markdown/SARIF projections from the
same canonical document. Never calls targets or models.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.application.report.assembler import assemble, generator_version
from app.application.report.collector import EvidenceBundle, collect
from app.application.report.redaction import redact_payload, redact_text, truncate_transcripts
from app.application.report.renderers.json import render_json
from app.application.report.renderers.markdown import render_markdown
from app.application.report.renderers.sarif import render_sarif
from app.domain.errors import NotFoundError
from app.domain.report import ReportDocument
from app.infrastructure.db.repository import Repositories

# Fields excluded from the artifact content hash (ADR 0001 decision 3).
_HASH_EXCLUDED_FIELDS = ("report_id", "generated_at", "integrity")


@dataclass
class ReportResult:
    document: ReportDocument
    content_sha256: str
    artifact_id: str
    json_text: str
    markdown_text: str
    sarif_text: str


def _canonical_hash(payload: dict) -> str:
    canonical = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDED_FIELDS}
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def generate(repos: Repositories, scan_id: str, project_id: str | None = None) -> ReportResult:
    """Generate (or reuse) the report artifacts for a scan."""
    if project_id is not None:
        scan = repos.scans.get(scan_id, project_id=project_id)
        if scan is None:
            raise NotFoundError(f"Scan '{scan_id}' not found in project '{project_id}'.")

    bundle: EvidenceBundle = collect(repos, scan_id)
    document = assemble(bundle)

    # Redaction + truncation at render time: raw evidence stays in the DB.
    canary = bundle.profile.canary_token if bundle.profile else ""
    payload = truncate_transcripts(redact_payload(document.model_dump(mode="json"), canary))

    content_sha256 = _canonical_hash(payload)
    # Deterministic identity: the same evidence state must produce the same
    # report id and byte-identical projections, so artifact writes dedupe.
    report_id = f"rpt_{content_sha256[:12]}"
    payload["report_id"] = report_id
    payload["integrity"] = {
        "content_sha256": content_sha256,
        "source": "persisted_evidence_only",
    }

    # Revalidate: the redacted payload must still satisfy the v1.0 contract.
    final_document = ReportDocument.model_validate(payload)

    json_text = redact_text(render_json(final_document), canary)
    gen_version = generator_version()
    artifact_id = repos.reports.save_artifact(
        scan_id,
        "json",
        json_text,
        content_sha256=content_sha256,
        schema_version=final_document.schema_version,
        generator_version=gen_version,
    )

    markdown_text = redact_text(render_markdown(final_document), canary)
    repos.reports.save_artifact(
        scan_id,
        "markdown",
        markdown_text,
        content_sha256=hashlib.sha256(markdown_text.encode("utf-8")).hexdigest(),
        schema_version=final_document.schema_version,
        generator_version=gen_version,
    )

    sarif_text = redact_text(render_sarif(final_document), canary)
    repos.reports.save_artifact(
        scan_id,
        "sarif",
        sarif_text,
        content_sha256=hashlib.sha256(sarif_text.encode("utf-8")).hexdigest(),
        schema_version=final_document.schema_version,
        generator_version=gen_version,
    )

    return ReportResult(
        document=final_document,
        content_sha256=content_sha256,
        artifact_id=artifact_id,
        json_text=json_text,
        markdown_text=markdown_text,
        sarif_text=sarif_text,
    )

