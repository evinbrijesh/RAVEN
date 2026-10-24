"""ApproveHardening use case — POST /api/scans/{scan_id}/approve-hardening.

docs/API_CONTRACT.md §6. Approval only changes the temporary demo target; it
never deploys to an external system (safety rule 5).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from app.domain.entities import Approval, HardeningProposal, ScanEvent, utc_now
from app.domain.enums import EventKind, ScanStatus
from app.domain.errors import NotFoundError, ValidationFailed
from app.infrastructure.db.repository import Repositories


class JobQueueLike(Protocol):
    def enqueue(self, kind: str, payload: dict[str, object]) -> str: ...


class ApproveHardening:
    def __init__(self, repos: Repositories, queue: JobQueueLike | None = None) -> None:
        self._repos = repos
        self._queue = queue

    def execute(
        self, scan_id: str, proposal_id: str, approved: bool, approved_by: str
    ) -> Approval:
        import hashlib

        scan = self._repos.scans.get(scan_id)
        if scan is None:
            raise NotFoundError(f"Scan '{scan_id}' not found.")
        proposal = self._repos.proposals.get(proposal_id)
        if proposal is None or proposal.scan_id != scan_id:
            raise NotFoundError(f"Proposal '{proposal_id}' not found for scan.")

        # Ensure proposal has not been superseded by a newer proposal for this scan
        latest = self._repos.proposals.latest_for_scan(scan_id)
        if latest is not None and latest.proposal_id != proposal_id:
            raise ValidationFailed(
                f"Proposal '{proposal_id}' has been superseded by '{latest.proposal_id}' and cannot be approved."
            )

        # Idempotency check: if already approved/decided for this proposal
        existing = self._repos.approvals.get_for_proposal(proposal_id)
        if existing is not None:
            # If the scan has already advanced, return existing record idempotently
            if scan.status in (ScanStatus.RETESTING, ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITHOUT_RETEST):
                return existing

        if scan.status != ScanStatus.AWAITING_APPROVAL:
            raise ValidationFailed(
                f"Scan is in status '{scan.status.value}'; approval requires 'awaiting_approval'."
            )

        # Compute tamper-evident hash of proposal diffs
        proposal_content = f"{proposal.prompt_diff}:{proposal.policy_diff}:{proposal.rationale}"
        proposal_hash = hashlib.sha256(proposal_content.encode("utf-8")).hexdigest()[:16]

        approval = Approval(
            approval_id=f"appr_{uuid.uuid4().hex[:12]}",
            proposal_id=proposal_id,
            scan_id=scan_id,
            approved=approved,
            approved_by=approved_by,
            proposal_hash=proposal_hash,
            decision="approved" if approved else "rejected",
            created_at=utc_now(),
        )
        self._repos.approvals.save(approval)
        self._repos.events.append(
            ScanEvent(
                scan_id=scan_id,
                kind=EventKind.APPROVAL_RECEIVED,
                payload={
                    "proposal_id": proposal_id,
                    "approved": approved,
                    "approved_by": approved_by,
                    "decision": approval.decision,
                    "proposal_hash": proposal_hash,
                },
            )
        )
        next_status = (
            ScanStatus.RETESTING if approved else ScanStatus.COMPLETED_WITHOUT_RETEST
        )
        self._repos.scans.update_status(scan_id, next_status)
        if approved and self._queue is not None:
            self._queue.enqueue("run_retest", {"scan_id": scan_id})
        return approval


class GetProposal:
    """Fetch the latest hardening proposal for a scan (diff viewer)."""

    def __init__(self, repos: Repositories) -> None:
        self._repos = repos

    def execute(self, scan_id: str) -> HardeningProposal:
        proposal = self._repos.proposals.latest_for_scan(scan_id)
        if proposal is None:
            raise NotFoundError(f"No hardening proposal for scan '{scan_id}'.")
        return proposal
