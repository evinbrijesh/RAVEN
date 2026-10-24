"""Tests for report data prerequisites (ADR 0001 "Data prerequisites").

- UTILITY_BEFORE benign baseline is persisted before hardening.
- Security/utility results carry case metadata for the report collector.
- Regression-only selection is fail-closed (B6).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from app.domain.entities import AttackCase, Scan, ScanConfig
from app.domain.enums import (
    AttackCategory,
    FindingLabel,
    ScanStatus,
    Severity,
    TestRunKind,
)
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
async def test_utility_before_baseline_persisted(repos, scan: Scan) -> None:
    """The pre-hardening benign baseline must exist for the over-refusal delta."""
    engine = ScanEngine(repos, fixtures_path=None)
    await engine.run(scan.scan_id)

    baselines = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.UTILITY_BEFORE)
    assert baselines, "benign baseline (utility_before) must be persisted before hardening"
    baseline = baselines[-1]
    assert baseline.metrics.get("phase") == "before"
    assert baseline.results, "baseline must contain benign case results"
    for result in baseline.results:
        assert "case_id" in result and "passed" in result
        assert "goal" in result and "expected" in result and "version" in result


@pytest.mark.asyncio
async def test_security_results_carry_case_metadata(repos, scan: Scan) -> None:
    """Every security result must expose the metadata the report needs."""
    engine = ScanEngine(repos, fixtures_path=None)
    await engine.run(scan.scan_id)

    before = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_BEFORE)
    assert before
    for result in before[-1].results:
        for key in (
            "attack_id",
            "category",
            "goal",
            "success_rule",
            "references",
            "attack_version",
            "severity",
            "label",
            "attempt",
        ):
            assert key in result, f"result missing '{key}': {result}"


@pytest.mark.asyncio
async def test_regression_only_selection_is_fail_closed(repos, scan: Scan) -> None:
    """Regression-only mode with no saved regressions must run zero cases,
    never fall back to arbitrary attacks (B6)."""
    engine = ScanEngine(repos, fixtures_path=None)
    selected = engine._select_regression_cases(scan)
    assert selected == []

    # With a saved regression for the target, selection contains exactly that
    # case (capped by budget).
    repos.regressions.save_case(
        "shophelper-local",
        _stub_case("A-01"),
        '{"attack_case_id": "A-01", "expected": "attack_blocked"}',
    )
    selected = engine._select_regression_cases(scan)
    assert [case.id for case in selected] == ["A-01"]


def _stub_case(case_id: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        category=AttackCategory.DIRECT_INJECTION,
        goal="stub",
        seed_prompt="stub",
        success_rule="stub",
        severity=Severity.HIGH,
        references=[],
        version="v1",
    )


@pytest.mark.asyncio
async def test_regression_save_count_matches_saved_cases(repos, scan: Scan) -> None:
    """The REGRESSION_SAVED event count must equal saved cases, not all results."""
    engine = ScanEngine(repos, fixtures_path=None)
    await engine.run(scan.scan_id)
    repos.scans.update_status(scan.scan_id, ScanStatus.RETESTING)
    await engine.run_retest(scan.scan_id)

    events = repos.events.list_for_scan(scan.scan_id)
    saved_events = [e for e in events if e.kind.value == "regression_saved"]
    assert saved_events, "retest must emit regression_saved"
    regressions = repos.regressions.list_active("shophelper-local")
    blocked_count = sum(
        1
        for run in repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
        for result in run.results
        if result.get("label") == FindingLabel.ATTACK_BLOCKED.value
    )
    assert saved_events[-1].payload["count"] == len(regressions)
    assert saved_events[-1].payload["count"] <= blocked_count or blocked_count == 0
