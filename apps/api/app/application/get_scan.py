"""GetScan use case — GET /api/scans/{scan_id} (docs/API_CONTRACT.md §3)."""

from __future__ import annotations

from app.domain.entities import ScanCounts, ScanView, SecurityMetrics
from app.domain.enums import FindingLabel, TestRunKind
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories


class GetScan:
    """Scan view with verdict counts and before/after security metrics."""

    def __init__(self, repos: Repositories) -> None:
        self._repos = repos

    def execute(self, scan_id: str) -> ScanView:
        scan = self._repos.scans.get(scan_id)
        if scan is None:
            raise NotFoundError(f"Scan '{scan_id}' not found.")
        findings = self._repos.findings.list_for_scan(scan_id)
        profile = self._repos.profiles.get(scan_id)
        return ScanView(
            scan_id=scan.scan_id,
            status=scan.status,
            phase=scan.status.value,
            progress=scan.progress,
            target_id=scan.target.target_id,
            counts=self._counts(findings),
            security_metrics=self._security_metrics(scan_id),
            profile=profile,
        )

    @staticmethod
    def _counts(findings: list) -> ScanCounts:
        return ScanCounts(
            total=len(findings),
            confirmed_failures=sum(
                1 for f in findings if f.label == FindingLabel.CONFIRMED_FAILURE
            ),
            blocked=sum(1 for f in findings if f.label == FindingLabel.ATTACK_BLOCKED),
            needs_review=sum(
                1 for f in findings if f.label == FindingLabel.NEEDS_REVIEW
            ),
            not_evaluated=sum(
                1 for f in findings if f.label == FindingLabel.NOT_EVALUATED
            ),
        )

    def _security_metrics(self, scan_id: str) -> SecurityMetrics:
        before = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_BEFORE)
        after = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
        utility = self._repos.test_runs.list_for_scan(scan_id, TestRunKind.UTILITY)

        def rate(runs: list, key: str) -> float | None:
            if not runs:
                return None
            return float(runs[-1].metrics.get(key, 0.0))

        return SecurityMetrics(
            before_attack_success_rate=rate(before, "attack_success_rate"),
            after_attack_success_rate=rate(after, "attack_success_rate"),
            benign_success_rate=rate(utility, "benign_success_rate"),
        )
