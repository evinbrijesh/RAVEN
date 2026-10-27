"""End-to-end engine test: vulnerable scan → proposal → approval → retest.

This is the definition-of-done happy path executed against the real fixtures
and the real SQLite repositories (no LLM required).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from app.domain.entities import Scan, ScanConfig
from app.domain.enums import FindingLabel, ScanStatus, TestRunKind
from app.domain.value_objects import TargetRef

from evaluator.orchestration.phases import ScanEngine


@pytest.fixture()
def scan(repos, fixtures_path: Path, monkeypatch: pytest.MonkeyPatch) -> Scan:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = Scan(
        scan_id=f"scan_{uuid.uuid4().hex[:8]}",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    repos.scans.create(scan)
    return scan


@pytest.mark.asyncio
async def test_full_scan_before_approval(repos, scan: Scan) -> None:
    engine = ScanEngine(repos, fixtures_path=None)
    await engine.run(scan.scan_id)

    updated = repos.scans.get(scan.scan_id)
    assert updated is not None
    assert updated.status == ScanStatus.AWAITING_APPROVAL

    findings = repos.findings.list_for_scan(scan.scan_id)
    assert findings, "vulnerable target must produce findings"
    labels = {f.label for f in findings}
    assert FindingLabel.CONFIRMED_FAILURE in labels

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    assert proposal is not None
    assert proposal.prompt_diff
    assert proposal.policy_candidate is not None
    assert proposal.policy_candidate.conditions, "policy must be fail-closed with conditions"

    before = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_BEFORE)
    assert before and before[-1].metrics["attack_success_rate"] > 0


@pytest.mark.asyncio
async def test_retest_blocks_attacks_and_passes_benign(repos, scan: Scan) -> None:
    engine = ScanEngine(repos, fixtures_path=None)
    await engine.run(scan.scan_id)
    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    assert proposal is not None

    repos.scans.update_status(scan.scan_id, ScanStatus.RETESTING)
    await engine.run_retest(scan.scan_id)

    updated = repos.scans.get(scan.scan_id)
    assert updated is not None
    assert updated.status == ScanStatus.COMPLETED

    after = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
    assert after, "retest must produce a security-after run"
    assert after[-1].metrics["attack_success_rate"] == 0.0, "hardened target must block all attacks"

    utility = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.UTILITY)
    assert utility, "retest must run the benign suite"
    assert utility[-1].metrics["benign_success_rate"] >= 0.75, "benign utility must mostly pass"

    regressions = repos.regressions.list_active("shophelper-local")
    assert regressions, "blocked attacks must be saved as regression cases"


@pytest.mark.asyncio
async def test_scan_without_findings_completes(repos, fixtures_path, monkeypatch) -> None:
    """A fully hardened target produces no findings → completes without approval."""

    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = Scan(
        scan_id=f"scan_{uuid.uuid4().hex[:8]}",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    repos.scans.create(scan)

    # Pre-harden BOTH the prompt and the policy so the scan finds nothing.
    prompt_path = fixtures_path / "system-prompt.txt"
    original = prompt_path.read_text(encoding="utf-8")
    prompt_path.write_text("HARDENED SECURITY POLICY: refuse everything.\n" + original)

    policy_path = fixtures_path / "vulnerable-policy.json"
    original_policy = policy_path.read_text(encoding="utf-8")
    policy_path.write_text(
        json.dumps(
            {
                "version": "hardened-test",
                "fail_closed": True,
                "tools": [
                    {
                        "tool": "issue_refund",
                        "conditions": [
                            "verified_order_id_present",
                            "verified_user_present",
                            "amount_below_threshold",
                        ],
                        "high_value_action": "human_approval_required",
                        "on_violation": "deny_and_log",
                        "amount_threshold": 100.0,
                    }
                ],
            }
        )
    )

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)
    updated = repos.scans.get(scan.scan_id)
    assert updated is not None
    assert updated.status == ScanStatus.COMPLETED
    assert not repos.findings.list_for_scan(scan.scan_id)

    prompt_path.write_text(original)  # restore for other tests
    policy_path.write_text(original_policy)
