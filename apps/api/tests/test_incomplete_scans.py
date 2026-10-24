"""Tests verifying incomplete scans cannot be misread as clean (Item 10)."""

from __future__ import annotations

from app.application.report.assembler import _decide_verdict
from app.domain.entities import TestRun
from app.domain.enums import ScanStatus, TestRunKind
from app.domain.report import (
    ReportCounts,
    ReportSecurityMetrics,
    ReportUtilityMetrics,
    ReportVerdict,
)


def _base_counts(**kwargs) -> ReportCounts:
    defaults = {
        "attack_cases": 12,
        "evaluated": 12,
        "not_evaluated": 0,
        "confirmed_failure": 0,
        "likely_failure": 0,
        "attack_blocked": 12,
        "needs_review": 0,
        "benign_cases": 10,
        "benign_passed": 10,
        "regressions": 0,
    }
    defaults.update(kwargs)
    return ReportCounts(**defaults)


def _security_metrics(before=0.33, after=0.08) -> ReportSecurityMetrics:
    return ReportSecurityMetrics(
        before_attack_success_rate=before,
        after_attack_success_rate=after,
        delta=after - before if before is not None and after is not None else None,
        before_blocked_rate=1.0 - before if before is not None else None,
        after_blocked_rate=1.0 - after if after is not None else None,
        per_category=[],
    )


def _utility_metrics() -> ReportUtilityMetrics:
    return ReportUtilityMetrics(
        before_benign_success_rate=1.0,
        after_benign_success_rate=1.0,
        delta=0.0,
        cases=[],
        over_refusal_case_ids=[],
    )


def test_failed_partial_scan_verdict_is_partial():
    counts = _base_counts()
    before_run = TestRun(test_run_id="tr_1", scan_id="s_1", kind=TestRunKind.SECURITY_BEFORE)
    after_run = TestRun(test_run_id="tr_2", scan_id="s_1", kind=TestRunKind.SECURITY_AFTER)

    verdict = _decide_verdict(
        scan_status=ScanStatus.FAILED_PARTIAL,
        before_run=before_run,
        after_run=after_run,
        attack_cases=12,
        counts=counts,
        semantic_available=True,
        security=_security_metrics(),
        utility=_utility_metrics(),
    )
    assert verdict == ReportVerdict.PARTIAL


def test_failed_fatal_scan_verdict_is_partial():
    counts = _base_counts()
    verdict = _decide_verdict(
        scan_status=ScanStatus.FAILED_FATAL,
        before_run=None,
        after_run=None,
        attack_cases=12,
        counts=counts,
        semantic_available=True,
        security=_security_metrics(None, None),
        utility=_utility_metrics(),
    )
    assert verdict == ReportVerdict.PARTIAL


def test_un_evaluated_cases_yields_inconclusive_never_clean():
    # Even if 11 cases were blocked, having 1 not_evaluated makes it INCONCLUSIVE
    counts = _base_counts(evaluated=11, not_evaluated=1, attack_blocked=11)
    before_run = TestRun(test_run_id="tr_1", scan_id="s_1", kind=TestRunKind.SECURITY_BEFORE)
    after_run = TestRun(test_run_id="tr_2", scan_id="s_1", kind=TestRunKind.SECURITY_AFTER)

    verdict = _decide_verdict(
        scan_status=ScanStatus.COMPLETED,
        before_run=before_run,
        after_run=after_run,
        attack_cases=12,
        counts=counts,
        semantic_available=True,
        security=_security_metrics(0.0, 0.0),
        utility=_utility_metrics(),
    )
    assert verdict == ReportVerdict.INCONCLUSIVE
    assert verdict != ReportVerdict.NO_CONFIRMED_FINDINGS


def test_empty_attack_cases_is_inconclusive():
    counts = _base_counts(attack_cases=0, evaluated=0, attack_blocked=0)
    before_run = TestRun(test_run_id="tr_1", scan_id="s_1", kind=TestRunKind.SECURITY_BEFORE)
    after_run = TestRun(test_run_id="tr_2", scan_id="s_1", kind=TestRunKind.SECURITY_AFTER)

    verdict = _decide_verdict(
        scan_status=ScanStatus.COMPLETED,
        before_run=before_run,
        after_run=after_run,
        attack_cases=0,
        counts=counts,
        semantic_available=True,
        security=_security_metrics(None, None),
        utility=_utility_metrics(),
    )
    assert verdict == ReportVerdict.INCONCLUSIVE
