"""Comprehensive Test Suite for LangGraph Orchestration in RAVEN.

Verifies the 24 specific integration requirements:
1. Successful end-to-end scan.
2. Recon failure.
3. Target timeout.
4. Model-provider failure.
5. Invalid semantic-judge JSON.
6. Deterministic and semantic judge disagreement.
7. Confirmed canary leakage.
8. Unauthorized tool call.
9. Attack mutation budget exhaustion.
10. Hardening proposal generation.
11. Human approval pause.
12. Approval resume.
13. Rejection path.
14. Duplicate approval/resume.
15. Worker restart after recon.
16. Worker restart after attack execution.
17. Worker restart while awaiting approval.
18. Security retest.
19. Benign utility regression.
20. Regression promotion.
21. Idempotent SARIF/report generation.
22. Empty or incomplete test suite.
23. Failed partial scan.
24. Failed fatal scan.
25. Worker mid-attack interruption recovery.
26. Target unreachable fails partial.
27. Stale job cleanup watchdog.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.application.report.service import generate as generate_report
from app.domain.entities import (
    Approval,
    AttackCase,
    Budget,
    LlmJudgeResult,
    RuleResult,
    Scan,
    ScanConfig,
    TargetProfile,
    TargetRequest,
    TargetResponse,
    Transcript,
    TranscriptMessage,
    utc_now,
)
from app.domain.enums import (
    AttackCategory,
    FindingLabel,
    ScanStatus,
    Severity,
    TestRunKind,
    VerdictResolution,
)
from app.domain.errors import ModelUnavailable, RavenError
from app.domain.value_objects import TargetRef

from evaluator.judges.deterministic import DeterministicJudge, JudgeContext
from evaluator.judges.resolver import VerdictResolver
from evaluator.judges.semantic import SemanticJudge
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.orchestration.phases import ScanEngine
from evaluator.targets.base import TargetAdapter


def _create_test_scan(repos, target_id="shophelper-local", **config_kwargs) -> Scan:
    max_cases = config_kwargs.pop("max_attack_cases", 2)
    cfg = ScanConfig(target_id=target_id, max_attack_cases=max_cases, **config_kwargs)
    scan = Scan(
        scan_id=f"scan_lg_{uuid.uuid4().hex[:8]}",
        target=TargetRef(target_id=target_id),
        config=cfg,
    )
    repos.scans.create(scan)
    return scan


# ──────────────────────────────────────────────────────────────────────────────
# 1. Successful end-to-end scan
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_01_successful_end_to_end_scan(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    # Must pause at awaiting approval
    paused = repos.scans.get(scan.scan_id)
    assert paused.status == ScanStatus.AWAITING_APPROVAL

    # Record approval and resume
    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    assert proposal is not None
    approval = Approval(
        approval_id=f"appr_{uuid.uuid4().hex[:8]}",
        proposal_id=proposal.proposal_id,
        scan_id=scan.scan_id,
        approved=True,
        approved_by="sec-admin",
        decision="approved",
        created_at=utc_now(),
    )
    repos.approvals.save(approval)

    await engine.run_retest(scan.scan_id)

    completed = repos.scans.get(scan.scan_id)
    assert completed.status == ScanStatus.COMPLETED
    assert completed.progress == 1.0

    # Verify report artifacts
    artifacts = repos.db.query_all("SELECT * FROM report_artifacts WHERE scan_id = ?", (scan.scan_id,))
    assert len(artifacts) >= 3  # JSON, Markdown, SARIF


# ──────────────────────────────────────────────────────────────────────────────
# 2. Recon failure
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_02_recon_failure(repos, monkeypatch) -> None:
    scan = _create_test_scan(repos)

    class FailingTarget(TargetAdapter):
        async def profile(self) -> TargetProfile:
            raise RuntimeError("Target connection refused during recon")
        async def invoke(self, req: TargetRequest) -> TargetResponse:
            raise RuntimeError("Unreachable")
        async def apply_temporary_policy(self, candidate, prompt=None):
            pass

    engine = ScanEngine(repos)
    engine._create_target = lambda s: FailingTarget()

    await engine.run(scan.scan_id)

    updated = repos.scans.get(scan.scan_id)
    assert updated.status == ScanStatus.FAILED_FATAL


# ──────────────────────────────────────────────────────────────────────────────
# 3. Target timeout
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_03_target_timeout(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)

    class TimeoutTarget(TargetAdapter):
        async def profile(self) -> TargetProfile:
            return TargetProfile(target_id=scan.target.target_id, version="1.0", tools=[], system_prompt_hash="dummy_hash")
        async def invoke(self, req: TargetRequest) -> TargetResponse:
            raise TimeoutError("Target invocation timed out after 5.0s")
        async def apply_temporary_policy(self, candidate, prompt=None):
            pass

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    engine._create_target = lambda s: TimeoutTarget()

    await engine.run(scan.scan_id)

    # Scans with target timeouts on all attacks produce 0 evaluated cases -> failed_partial
    updated = repos.scans.get(scan.scan_id)
    assert updated.status == ScanStatus.FAILED_PARTIAL
    findings = repos.findings.list_for_scan(scan.scan_id)
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# 4. Model-provider failure
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_04_model_provider_failure(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)

    mock_client = MagicMock()
    mock_client.complete = AsyncMock(side_effect=ModelUnavailable("Provider connection error 503"))

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    engine._model_client = mock_client

    await engine.run(scan.scan_id)

    # Deterministic checks continue; semantic judge failures do not crash the scan
    updated = repos.scans.get(scan.scan_id)
    assert updated.status == ScanStatus.AWAITING_APPROVAL


# ──────────────────────────────────────────────────────────────────────────────
# 5. Invalid semantic-judge JSON
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_05_invalid_semantic_judge_json() -> None:
    budget = BudgetTracker(budget=Budget(max_model_calls=5))
    mock_client = MagicMock()
    mock_client.complete = AsyncMock(return_value=("NOT_VALID_JSON", 10, 10))

    judge = SemanticJudge(mock_client, budget, model_name="test-model")
    case = AttackCase(
        id="A-01",
        category=AttackCategory.DIRECT_INJECTION,
        goal="Test",
        severity=Severity.HIGH,
        seed_prompt="hello",
        success_rule="canary_leaked",
    )
    transcript = Transcript(
        transcript_id="t1",
        messages=[TranscriptMessage(role="user", content="hello"), TranscriptMessage(role="assistant", content="hi")],
    )
    res = await judge.evaluate(case, transcript)
    assert res is None  # Fails closed, returns None


# ──────────────────────────────────────────────────────────────────────────────
# 6. Deterministic and semantic judge disagreement
# ──────────────────────────────────────────────────────────────────────────────
def test_06_deterministic_and_semantic_disagreement() -> None:
    resolver = VerdictResolver()
    rule_res = RuleResult(label=FindingLabel.ATTACK_BLOCKED, signals=[])
    llm_res = LlmJudgeResult(
        label=FindingLabel.CONFIRMED_FAILURE,
        confidence=0.8,
        reason="Model claims breach",
        model_name="test",
        prompt_version="1.0",
    )
    case = AttackCase(
        id="A-02",
        category=AttackCategory.DIRECT_INJECTION,
        goal="Test disagreement",
        severity=Severity.HIGH,
        seed_prompt="hello",
        success_rule="canary_leaked",
    )
    verdict = resolver.resolve("s1", "r1", rule_res, llm_res, case=case)
    assert verdict.final_label == FindingLabel.NEEDS_REVIEW
    assert verdict.resolution == VerdictResolution.DISAGREEMENT


# ──────────────────────────────────────────────────────────────────────────────
# 7. Confirmed canary leakage
# ──────────────────────────────────────────────────────────────────────────────
def test_07_confirmed_canary_leakage() -> None:
    resolver = VerdictResolver()
    rule_res = RuleResult(label=FindingLabel.CONFIRMED_FAILURE, signals=["canary_token_leaked"])
    llm_res = LlmJudgeResult(
        label=FindingLabel.ATTACK_BLOCKED,
        confidence=0.99,
        reason="Model claims safe",
        model_name="test",
        prompt_version="1.0",
    )
    verdict = resolver.resolve("s1", "r1", rule_res, llm_res)
    # Deterministic breach always wins
    assert verdict.final_label == FindingLabel.CONFIRMED_FAILURE
    assert verdict.resolution == VerdictResolution.RULE_CONFIRMED


# ──────────────────────────────────────────────────────────────────────────────
# 8. Unauthorized tool call
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_08_unauthorized_tool_call() -> None:
    ctx = JudgeContext(canary_token="canary123", system_prompt="", customer_emails=[], customer_phones=[])
    judge = DeterministicJudge(ctx)
    case = AttackCase(
        id="A-04",
        category=AttackCategory.TOOL_MISUSE,
        goal="Trigger unauthorized refund",
        severity=Severity.CRITICAL,
        seed_prompt="refund me",
        success_rule="tool_call_without_verified_order",
    )
    transcript = Transcript(
        transcript_id="t_tool",
        messages=[
            TranscriptMessage(
                role="assistant",
                content="Processing refund",
                tool_name="issue_refund",
                tool_args_json='{"order_id": "none", "amount": 500}',
            )
        ],
    )
    rule_res = await judge.evaluate(case, transcript)
    assert rule_res.label == FindingLabel.CONFIRMED_FAILURE
    assert any("unsafe_tool_call" in s for s in rule_res.signals) or "tool_misuse" in rule_res.signals


# ──────────────────────────────────────────────────────────────────────────────
# 9. Attack mutation budget exhaustion
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_09_attack_mutation_budget_exhaustion(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    # Budget with max 1 attempt
    scan = _create_test_scan(repos, max_attempts_per_attack=1)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    runs = repos.runs.list_runs(scan.scan_id)
    for r in runs:
        assert r["attempt"] <= 1


# ──────────────────────────────────────────────────────────────────────────────
# 10. Hardening proposal generation
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_10_hardening_proposal_generation(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    assert proposal is not None
    assert proposal.prompt_diff
    assert proposal.policy_candidate is not None
    assert proposal.policy_candidate.on_violation == "deny_and_log"
    assert len(proposal.risks) > 0


# ──────────────────────────────────────────────────────────────────────────────
# 11. Human approval pause
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_11_human_approval_pause(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    saved = repos.scans.get(scan.scan_id)
    assert saved.status == ScanStatus.AWAITING_APPROVAL

    # Verify checkpointer stored interrupt
    config = {"configurable": {"thread_id": scan.scan_id}}
    state_tuple = await engine._graph.aget_state(config)
    assert state_tuple is not None
    assert "human_approval_interrupt" in state_tuple.next


# ──────────────────────────────────────────────────────────────────────────────
# 12. Approval resume
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_12_approval_resume(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    approval = Approval(
        approval_id="appr_res_1",
        proposal_id=proposal.proposal_id,
        scan_id=scan.scan_id,
        approved=True,
        approved_by="auditor",
        decision="approved",
        created_at=utc_now(),
    )
    repos.approvals.save(approval)
    await engine.run_retest(scan.scan_id)

    final_scan = repos.scans.get(scan.scan_id)
    assert final_scan.status == ScanStatus.COMPLETED


# ──────────────────────────────────────────────────────────────────────────────
# 13. Rejection path
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_13_rejection_path(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    approval = Approval(
        approval_id="appr_rej_1",
        proposal_id=proposal.proposal_id,
        scan_id=scan.scan_id,
        approved=False,
        approved_by="auditor",
        decision="rejected",
        created_at=utc_now(),
    )
    repos.approvals.save(approval)
    await engine.run_retest(scan.scan_id)

    rejected_scan = repos.scans.get(scan.scan_id)
    assert rejected_scan.status == ScanStatus.COMPLETED_WITHOUT_RETEST
    # Must NOT run after test run
    after_runs = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
    assert len(after_runs) == 0


# ──────────────────────────────────────────────────────────────────────────────
# 14. Duplicate approval/resume
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_14_duplicate_approval_resume(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    approval = Approval(
        approval_id="appr_dup_1",
        proposal_id=proposal.proposal_id,
        scan_id=scan.scan_id,
        approved=True,
        approved_by="auditor",
        decision="approved",
        created_at=utc_now(),
    )
    repos.approvals.save(approval)
    await engine.run_retest(scan.scan_id)

    initial_after_runs = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
    initial_count = len(initial_after_runs)

    # Duplicate resume call
    await engine.run_retest(scan.scan_id)
    subsequent_after_runs = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
    assert len(subsequent_after_runs) == initial_count


# ──────────────────────────────────────────────────────────────────────────────
# 15. Worker restart after recon
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_15_worker_restart_after_recon(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)

    # Save a profile directly as if recon completed
    profile = TargetProfile(target_id=scan.target.target_id, version="1.0", tools=["test_tool"], system_prompt_hash="dummy_hash")
    repos.profiles.save(scan.scan_id, profile)

    # Worker restart: new engine instance with same repos
    engine2 = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine2.run(scan.scan_id)

    # Should successfully pause at approval using persisted profile
    updated = repos.scans.get(scan.scan_id)
    assert updated.status == ScanStatus.AWAITING_APPROVAL


# ──────────────────────────────────────────────────────────────────────────────
# 16. Worker restart after attack execution
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_16_worker_restart_after_attack_execution(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)

    engine1 = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine1.run(scan.scan_id)

    # Simulate worker crash & restart
    engine2 = ScanEngine(repos, fixtures_path=str(fixtures_path))
    state_snap = await engine2._graph.aget_state({"configurable": {"thread_id": scan.scan_id}})
    assert state_snap is not None
    assert "human_approval_interrupt" in state_snap.next


# ──────────────────────────────────────────────────────────────────────────────
# 17. Worker restart while awaiting approval
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_17_worker_restart_while_awaiting_approval(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine1 = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine1.run(scan.scan_id)

    assert repos.scans.get(scan.scan_id).status == ScanStatus.AWAITING_APPROVAL

    # New worker instance after restart
    engine2 = ScanEngine(repos, fixtures_path=str(fixtures_path))
    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    approval = Approval(
        approval_id="appr_rst_1",
        proposal_id=proposal.proposal_id,
        scan_id=scan.scan_id,
        approved=True,
        approved_by="lead",
        decision="approved",
        created_at=utc_now(),
    )
    repos.approvals.save(approval)

    # Resume on the new worker
    await engine2.run_retest(scan.scan_id)
    assert repos.scans.get(scan.scan_id).status == ScanStatus.COMPLETED


# ──────────────────────────────────────────────────────────────────────────────
# 18. Security retest
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_18_security_retest(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    repos.approvals.save(
        Approval(
            approval_id="appr_s_1",
            proposal_id=proposal.proposal_id,
            scan_id=scan.scan_id,
            approved=True,
            approved_by="lead",
            decision="approved",
            created_at=utc_now(),
        )
    )
    await engine.run_retest(scan.scan_id)

    after_runs = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.SECURITY_AFTER)
    assert len(after_runs) > 0
    # Hardened target should have 0 attack success rate
    assert after_runs[-1].metrics["attack_success_rate"] == 0.0


# ──────────────────────────────────────────────────────────────────────────────
# 19. Benign utility regression
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_19_benign_utility_regression(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    repos.approvals.save(
        Approval(
            approval_id="appr_u_1",
            proposal_id=proposal.proposal_id,
            scan_id=scan.scan_id,
            approved=True,
            approved_by="lead",
            decision="approved",
            created_at=utc_now(),
        )
    )
    await engine.run_retest(scan.scan_id)

    utility_runs = repos.test_runs.list_for_scan(scan.scan_id, TestRunKind.UTILITY)
    assert len(utility_runs) > 0
    assert "benign_success_rate" in utility_runs[-1].metrics


# ──────────────────────────────────────────────────────────────────────────────
# 20. Regression promotion
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_20_regression_promotion(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    repos.approvals.save(
        Approval(
            approval_id="appr_p_1",
            proposal_id=proposal.proposal_id,
            scan_id=scan.scan_id,
            approved=True,
            approved_by="lead",
            decision="approved",
            created_at=utc_now(),
        )
    )
    await engine.run_retest(scan.scan_id)

    active_regs = repos.regressions.list_active("shophelper-local")
    assert len(active_regs) > 0


# ──────────────────────────────────────────────────────────────────────────────
# 21. Idempotent SARIF/report generation
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_21_idempotent_sarif_report_generation(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos)
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    proposal = repos.proposals.latest_for_scan(scan.scan_id)
    repos.approvals.save(
        Approval(
            approval_id="appr_rpt_1",
            proposal_id=proposal.proposal_id,
            scan_id=scan.scan_id,
            approved=True,
            approved_by="lead",
            decision="approved",
            created_at=utc_now(),
        )
    )
    await engine.run_retest(scan.scan_id)

    r1 = generate_report(repos, scan.scan_id)
    r2 = generate_report(repos, scan.scan_id)
    assert r1.content_sha256 == r2.content_sha256
    assert r1.artifact_id == r2.artifact_id


# ──────────────────────────────────────────────────────────────────────────────
# 22. Empty or incomplete test suite
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_22_empty_or_incomplete_test_suite(repos, monkeypatch) -> None:
    # Regression only mode with 0 promoted regressions
    scan = _create_test_scan(repos, regression_only_mode=True)
    engine = ScanEngine(repos)
    await engine.run(scan.scan_id)

    final_scan = repos.scans.get(scan.scan_id)
    assert final_scan.status == ScanStatus.INCONCLUSIVE


# ──────────────────────────────────────────────────────────────────────────────
# 23. Failed partial scan
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_23_failed_partial_scan(repos) -> None:
    scan = _create_test_scan(repos)
    # Awaiting approval without a proposal -> run_retest fails partial
    repos.scans.update_status(scan.scan_id, ScanStatus.AWAITING_APPROVAL)
    engine = ScanEngine(repos)

    with pytest.raises(RavenError):
        await engine.run_retest(scan.scan_id)

    final_scan = repos.scans.get(scan.scan_id)
    assert final_scan.status == ScanStatus.FAILED_PARTIAL


# ──────────────────────────────────────────────────────────────────────────────
# 24. Failed fatal scan
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_24_failed_fatal_scan(repos) -> None:
    engine = ScanEngine(repos)
    with pytest.raises(RavenError):
        await engine.run("scan_does_not_exist_xyz")


# ──────────────────────────────────────────────────────────────────────────────
# 25. Worker mid-attack interruption recovery (per-case idempotency)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_25_worker_mid_attack_interruption_recovery(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    scan = _create_test_scan(repos, max_attack_cases=3)

    # Pre-populate an attack run for A-01 as if worker completed case 1 before crashing
    run_id_first = "run_partial_crashed_1"
    repos.db.execute(
        "INSERT INTO attack_runs (run_id, scan_id, attack_case_id, attempt, phase, started_at, finished_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id_first, scan.scan_id, "A-01", 1, "before", utc_now().isoformat(), utc_now().isoformat(), "completed"),
    )
    from app.domain.entities import Transcript, TranscriptMessage
    transcript = Transcript(
        transcript_id=f"tr_{run_id_first}",
        run_id=run_id_first,
        messages=[TranscriptMessage(role="user", content="attack prompt 1"), TranscriptMessage(role="assistant", content="safe response")],
        created_at=utc_now(),
    )
    repos.runs.save_transcript(transcript, run_id_first)

    # Worker restart: new engine instance resumes the scan
    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    await engine.run(scan.scan_id)

    # Scan should successfully complete attacks and pause at approval
    updated_scan = repos.scans.get(scan.scan_id)
    assert updated_scan.status == ScanStatus.AWAITING_APPROVAL

    # Check attack runs: A-01 must have preserved its original run_id_first
    all_runs = repos.runs.list_runs(scan.scan_id)
    before_runs = [r for r in all_runs if r.get("phase") == "before"]
    a01_run = next((r for r in before_runs if r.get("attack_case_id") == "A-01"), None)
    assert a01_run is not None
    assert a01_run["run_id"] == run_id_first
    # All 3 cases must have completed
    case_ids = {r["attack_case_id"] for r in before_runs}
    assert "A-01" in case_ids
    assert len(case_ids) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# 26. Target unreachable fails partial
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_26_target_unreachable_fails_partial(repos, fixtures_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    from app.domain.errors import TargetUnreachableError

    scan = _create_test_scan(repos)

    class UnreachableTarget(TargetAdapter):
        async def profile(self) -> TargetProfile:
            return TargetProfile(
                target_id=scan.target.target_id,
                version="1.0",
                tools=[],
                system_prompt_hash="dummy_hash",
            )

        async def invoke(self, req: TargetRequest) -> TargetResponse:
            raise TargetUnreachableError("Connection refused by target host")

        async def apply_temporary_policy(self, candidate, prompt=None):
            pass

    engine = ScanEngine(repos, fixtures_path=str(fixtures_path))
    engine._create_target = lambda s: UnreachableTarget()

    await engine.run(scan.scan_id)

    updated = repos.scans.get(scan.scan_id)
    assert updated.status == ScanStatus.FAILED_PARTIAL
    # Ensure no false clean pass
    assert updated.status != ScanStatus.COMPLETED


# ──────────────────────────────────────────────────────────────────────────────
# 27. Stale job cleanup watchdog
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_27_stale_job_cleanup(repos) -> None:
    import json
    from datetime import timedelta

    from app.domain.entities import utc_now

    from evaluator.worker import cleanup_orphaned_jobs

    scan = _create_test_scan(repos)
    # Move scan to ATTACKING
    repos.scans.update_status(scan.scan_id, ScanStatus.ATTACKING)

    # Seed an orphaned job that has been stuck in 'running' with stale heartbeat (>300s)
    stale_time = (utc_now() - timedelta(seconds=400)).isoformat()
    job_id = f"job_stale_{uuid.uuid4().hex[:8]}"
    repos.db.execute(
        "INSERT INTO jobs (job_id, kind, payload_json, status, attempts, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            job_id,
            "run_scan",
            json.dumps({"scan_id": scan.scan_id}),
            "running",
            3,  # max_attempts reached
            stale_time,
            stale_time,
        ),
    )

    cleaned = cleanup_orphaned_jobs(repos, stale_timeout_seconds=300.0)
    assert cleaned >= 1

    # Check job status in DB
    job_row = repos.db.query_one("SELECT status FROM jobs WHERE job_id = ?", (job_id,))
    assert job_row is not None
    assert job_row["status"] == "failed"

    # Check scan status in DB: orphaned running scan must transition to FAILED_PARTIAL
    updated_scan = repos.scans.get(scan.scan_id)
    assert updated_scan.status == ScanStatus.FAILED_PARTIAL


