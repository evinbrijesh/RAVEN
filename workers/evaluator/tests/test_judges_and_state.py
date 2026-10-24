"""Judge, resolver, budget, and state machine tests."""

from __future__ import annotations

import pytest
from app.domain.entities import (
    AttackCase,
    RuleResult,
    Scan,
    ScanConfig,
    Transcript,
    TranscriptMessage,
)
from app.domain.enums import (
    AttackCategory,
    FindingLabel,
    ScanStatus,
    Severity,
    VerdictResolution,
)
from app.domain.errors import BudgetExceeded, InvalidTransition
from app.domain.value_objects import Budget, TargetRef

from evaluator.judges.deterministic import DeterministicJudge, JudgeContext
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.orchestration.state_machine import can_transition, transition


def _case(rule: str) -> AttackCase:
    return AttackCase(
        id="A-01",
        category=AttackCategory.DIRECT_INJECTION,
        goal="test",
        seed_prompt="seed",
        success_rule=rule,
        severity=Severity.HIGH,
    )


def _transcript(text: str) -> Transcript:
    return Transcript(
        transcript_id="t1",
        messages=[TranscriptMessage(role="assistant", content=text)],
    )


@pytest.fixture()
def judge_ctx() -> JudgeContext:
    return JudgeContext(
        canary_token="RAVEN-CANARY-7f3a9c",
        system_prompt="CANARY TOKEN: RAVEN-CANARY-7f3a9c\n" + "x" * 60,
        customer_emails=["customer.one@example.com"],
        customer_phones=["555-010-0001"],
    )


@pytest.mark.asyncio
async def test_deterministic_canary_leak(judge_ctx: JudgeContext) -> None:
    judge = DeterministicJudge(judge_ctx)
    result = await judge.evaluate(_case("canary_leaked"), _transcript("leak: RAVEN-CANARY-7f3a9c"))
    assert result.label == FindingLabel.CONFIRMED_FAILURE


@pytest.mark.asyncio
async def test_deterministic_blocked(judge_ctx: JudgeContext) -> None:
    judge = DeterministicJudge(judge_ctx)
    result = await judge.evaluate(_case("canary_leaked"), _transcript("I can't share that."))
    assert result.label == FindingLabel.ATTACK_BLOCKED


@pytest.mark.asyncio
async def test_unknown_rule_never_passes(judge_ctx: JudgeContext) -> None:
    judge = DeterministicJudge(judge_ctx)
    result = await judge.evaluate(_case("made_up_rule"), _transcript("anything"))
    assert result.label == FindingLabel.NOT_EVALUATED


@pytest.mark.asyncio
async def test_pii_disclosure_detected(judge_ctx: JudgeContext) -> None:
    judge = DeterministicJudge(judge_ctx)
    result = await judge.evaluate(
        _case("pii_disclosed"), _transcript("sure: customer.one@example.com")
    )
    assert result.label == FindingLabel.CONFIRMED_FAILURE
    assert "customer_email_disclosed" in result.signals


def test_resolver_rule_beats_model(judge_ctx: JudgeContext) -> None:
    resolver = VerdictResolver()
    verdict = resolver.resolve(
        "s1", "r1",
        RuleResult(label=FindingLabel.CONFIRMED_FAILURE, signals=["x"]),
        None,
    )
    assert verdict.final_label == FindingLabel.CONFIRMED_FAILURE
    assert verdict.resolution == VerdictResolution.RULE_CONFIRMED


def test_resolver_disagreement_needs_review() -> None:
    from app.domain.entities import LlmJudgeResult

    resolver = VerdictResolver()
    verdict = resolver.resolve(
        "s1", "r1",
        RuleResult(label=FindingLabel.ATTACK_BLOCKED, signals=[]),
        LlmJudgeResult(label=FindingLabel.LIKELY_FAILURE, confidence=0.9, reason="r"),
    )
    assert verdict.final_label == FindingLabel.NEEDS_REVIEW
    assert verdict.resolution == VerdictResolution.DISAGREEMENT


def test_resolver_no_evidence_not_passed() -> None:
    resolver = VerdictResolver()
    verdict = resolver.resolve("s1", "r1", None, None)
    assert verdict.final_label == FindingLabel.NOT_EVALUATED
    assert verdict.resolution == VerdictResolution.NO_EVIDENCE


def test_resolver_semantic_unavailable_marks_blocked() -> None:
    resolver = VerdictResolver()
    verdict = resolver.resolve(
        "s1", "r1", RuleResult(label=FindingLabel.ATTACK_BLOCKED, signals=[]), None
    )
    assert verdict.final_label == FindingLabel.ATTACK_BLOCKED
    assert verdict.resolution == VerdictResolution.SEMANTIC_UNAVAILABLE


def test_budget_attempts_enforced() -> None:
    tracker = BudgetTracker(budget=Budget(max_attempts_per_attack=2))
    tracker.consume_attempt("A-01")
    tracker.consume_attempt("A-01")
    with pytest.raises(BudgetExceeded):
        tracker.consume_attempt("A-01")


def test_budget_model_calls_enforced() -> None:
    tracker = BudgetTracker(budget=Budget(max_model_calls=1))
    tracker.consume_model_call(10)
    with pytest.raises(BudgetExceeded):
        tracker.consume_model_call(10)


def test_state_machine_happy_path() -> None:
    scan = Scan(
        scan_id="s1",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    for status in (
        ScanStatus.RECONNING,
        ScanStatus.ATTACKING,
        ScanStatus.JUDGING,
        ScanStatus.HARDENING_PROPOSED,
        ScanStatus.AWAITING_APPROVAL,
        ScanStatus.RETESTING,
        ScanStatus.COMPLETED,
    ):
        transition(scan, status)
    assert scan.status == ScanStatus.COMPLETED


def test_state_machine_rejects_illegal_jump() -> None:
    scan = Scan(
        scan_id="s1",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    with pytest.raises(InvalidTransition):
        transition(scan, ScanStatus.COMPLETED)


def test_state_machine_rejection_path() -> None:
    scan = Scan(
        scan_id="s1",
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    transition(scan, ScanStatus.RECONNING)
    transition(scan, ScanStatus.ATTACKING)
    transition(scan, ScanStatus.JUDGING)
    transition(scan, ScanStatus.HARDENING_PROPOSED)
    transition(scan, ScanStatus.AWAITING_APPROVAL)
    transition(scan, ScanStatus.COMPLETED_WITHOUT_RETEST)
    assert not can_transition(scan.status, ScanStatus.RETESTING)


@pytest.mark.asyncio
async def test_semantic_judge_openrouter_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test SemanticJudge handles OpenRouter JSON completions properly."""
    import httpx

    from evaluator.judges.semantic import OpenRouterModelClient, SemanticJudge

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            content = (
                b'{"choices": [{"message": {"content": "{\\"label\\": \\"confirmed_failure\\", '
                b'\\"confidence\\": 0.95, \\"reason\\": \\"Canary was disclosed.\\"}"}}], '
                b'"usage": {"prompt_tokens": 120, "completion_tokens": 30}}'
            )
            return httpx.Response(200, content=content, request=request)

    client = OpenRouterModelClient(api_key="test-key", model_name="test-model")
    # Patch httpx.AsyncClient to use our mock transport
    original_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = MockTransport()
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    tracker = BudgetTracker(budget=Budget(max_model_calls=5))
    judge = SemanticJudge(client, tracker, model_name="test-model")

    case = _case("never-leak-canary")
    transcript = _transcript("I found the secret canary: RAVEN-CANARY-123")

    result = await judge.evaluate(case, transcript)
    assert result is not None
    assert result.label == FindingLabel.CONFIRMED_FAILURE
    assert result.confidence == 0.95
    assert "Canary" in result.reason
    assert len(judge.calls) == 1
    assert judge.calls[0].status == "ok"


def test_get_model_client_factory() -> None:
    from evaluator.judges.semantic import OpenRouterModelClient, get_model_client

    assert get_model_client("none") is None
    assert get_model_client("") is None
    client = get_model_client("openrouter", api_key="sk-test", model_name="meta-llama/llama-3.3-70b-instruct:free")
    assert isinstance(client, OpenRouterModelClient)
    assert client.api_key == "sk-test"
    assert client.model_name == "meta-llama/llama-3.3-70b-instruct:free"

