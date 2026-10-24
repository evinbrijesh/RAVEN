"""GenerateReport use case — GET /api/scans/{scan_id}/report (API_CONTRACT §7).

Builds the report from persisted evidence only; a scan must never complete
with a blank result set, so generation fails loudly if evidence is missing.
"""

from __future__ import annotations

from typing import Any

from app.domain.entities import utc_now
from app.domain.enums import FindingLabel, TestRunKind
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories

SCHEMA_VERSION = "0.1"

MARKDOWN_TEMPLATE = """# RAVEN Security Report — {scan_id}

- Target: `{target_id}` (version {target_version})
- Generated: {generated_at}
- Coverage: {attack_cases} attack cases across {categories} categories

## Findings

{findings_table}

## Hardening

- Proposal: `{proposal_id}` — approved: {approved}

## Before / After

- Attack success rate (before): {before_rate}
- Attack success rate (after): {after_rate}
- Benign success rate: {benign_rate}

## Limitations

- Results cover only the selected cases and target configuration.
- A clean result means clean under the stated checks, not globally secure.
"""


class GenerateReport:
    def __init__(self, repos: Repositories) -> None:
        self._repos = repos

    def execute(self, scan_id: str, fmt: str = "json") -> dict[str, Any] | str:
        scan = self._repos.scans.get(scan_id)
        if scan is None:
            raise NotFoundError(f"Scan '{scan_id}' not found.")
        report = self._build(scan_id)
        if fmt == "markdown":
            content = report_to_markdown(report)
            self._repos.reports.save_artifact(scan_id, "markdown", content)
            return content
        artifact = self._repos.reports.save_artifact(scan_id, "json", _to_json(report))
        report["artifact_id"] = artifact
        return report

    def _build(self, scan_id: str) -> dict[str, Any]:
        scan = self._repos.scans.get(scan_id)
        assert scan is not None  # checked by caller
        findings = self._repos.findings.list_for_scan(scan_id)
        proposal = self._repos.proposals.latest_for_scan(scan_id)
        approval = (
            self._repos.approvals.get_for_proposal(proposal.proposal_id)
            if proposal
            else None
        )
        before = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_BEFORE)
        after = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
        utility = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY)

        def rate(runs: list, key: str) -> float | None:
            if not runs:
                return None
            return float(runs[-1].metrics.get(key, 0.0))

        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "scan_id": scan_id,
            "status": scan.status.value,
            "target": {
                "id": scan.target.target_id,
                "version": scan.target.version,
            },
            "coverage": {
                "attack_cases": len({f.attack_id for f in findings}) or None,
                "categories": len({f.category for f in findings}) or None,
            },
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "attack_id": f.attack_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "label": f.label.value,
                    "confidence": f.confidence,
                    "summary": f.summary,
                    "evidence_refs": [r.ref_id for r in f.evidence_refs],
                    "needs_review": f.needs_review,
                }
                for f in findings
            ],
            "hardening": {
                "proposal": proposal.model_dump(mode="json") if proposal else None,
                "approved": approval.approved if approval else None,
            },
            "before_after": {
                "before_attack_success_rate": rate(before, "attack_success_rate"),
                "after_attack_success_rate": rate(after, "attack_success_rate"),
            },
            "benign_regression": {
                "benign_success_rate": rate(utility, "benign_success_rate"),
                "cases": len(utility[-1].results) if utility else 0,
            },
            "limitations": [
                "Results cover only the selected cases and target configuration.",
                "A clean result means clean under the stated checks, not globally secure.",
            ],
            "generated_at": utc_now().isoformat(),
        }
        return report


def _to_json(report: dict[str, Any]) -> str:
    import json

    return json.dumps(report, indent=2, default=str)


def report_to_markdown(report: dict[str, Any]) -> str:
    """Render a JSON report dict as Markdown (export format)."""
    findings = report.get("findings", [])
    rows = "\n".join(
        f"| {f['finding_id']} | {f['attack_id']} | {f['category']} |"
        f" {f['severity']} | {f['label']} |"
        for f in findings
    )
    findings_table = (
        "| finding | attack | category | severity | label |\n|---|---|---|---|---|\n"
        + (rows or "| (none) | | | | |")
    )
    hardening = report.get("hardening", {})
    proposal = hardening.get("proposal") or {}
    before_after = report.get("before_after", {})
    benign = report.get("benign_regression", {})
    return MARKDOWN_TEMPLATE.format(
        scan_id=report.get("scan_id", "unknown"),
        target_id=report.get("target", {}).get("id", "unknown"),
        target_version=report.get("target", {}).get("version", "?"),
        generated_at=report.get("generated_at", ""),
        attack_cases=report.get("coverage", {}).get("attack_cases", 0),
        categories=report.get("coverage", {}).get("categories", 0),
        findings_table=findings_table,
        proposal_id=proposal.get("proposal_id", "none"),
        approved=hardening.get("approved"),
        before_rate=before_after.get("before_attack_success_rate"),
        after_rate=before_after.get("after_attack_success_rate"),
        benign_rate=benign.get("benign_success_rate"),
    )
