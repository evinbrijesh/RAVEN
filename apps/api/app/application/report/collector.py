"""Evidence collection for the report pipeline (ADR 0001).

Reads persisted tables only. Never calls a target, model, or the filesystem
beyond the database. Raises NotFoundError when the scan does not exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.domain.entities import (
    Approval,
    Finding,
    HardeningProposal,
    Scan,
    TargetProfile,
    TestRun,
    Transcript,
    Verdict,
)
from app.domain.enums import TestRunKind
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories


@dataclass
class EvidenceBundle:
    """Everything the assembler needs, gathered in one pass."""

    scan: Scan
    profile: TargetProfile | None
    findings: list[Finding]
    verdicts: list[Verdict]
    runs: list[dict[str, Any]]
    transcripts: dict[str, Transcript] = field(default_factory=dict)
    before_run: TestRun | None = None
    after_run: TestRun | None = None
    utility_before: TestRun | None = None
    utility_after: TestRun | None = None
    proposal: HardeningProposal | None = None
    approval: Approval | None = None
    regressions: list[dict[str, Any]] = field(default_factory=list)


def collect(repos: Repositories, scan_id: str) -> EvidenceBundle:
    scan = repos.scans.get(scan_id)
    if scan is None:
        raise NotFoundError(f"Scan '{scan_id}' not found.")

    findings = repos.findings.list_for_scan(scan_id)
    verdicts = repos.runs.list_verdicts(scan_id)
    runs = repos.runs.list_runs(scan_id)

    # Transcripts for runs referenced by findings (bounded, evidence-linked).
    transcripts: dict[str, Transcript] = {}
    for finding in findings:
        for ref in finding.evidence_refs:
            if ref.kind == "run" and ref.ref_id not in transcripts:
                transcript = repos.runs.get_transcript(ref.ref_id)
                if transcript is not None:
                    transcripts[ref.ref_id] = transcript

    proposal = repos.proposals.latest_for_scan(scan_id)
    approval = (
        repos.approvals.get_for_proposal(proposal.proposal_id) if proposal else None
    )

    return EvidenceBundle(
        scan=scan,
        profile=repos.profiles.get(scan_id),
        findings=findings,
        verdicts=verdicts,
        runs=runs,
        transcripts=transcripts,
        before_run=repos.test_runs.latest_for_scan(scan_id, TestRunKind.SECURITY_BEFORE),
        after_run=repos.test_runs.latest_for_scan(scan_id, TestRunKind.SECURITY_AFTER),
        utility_before=repos.test_runs.latest_for_scan(scan_id, TestRunKind.UTILITY_BEFORE),
        utility_after=repos.test_runs.latest_for_scan(scan_id, TestRunKind.UTILITY),
        proposal=proposal,
        approval=approval,
        regressions=repos.regressions.list_active(scan.target.target_id),
    )
