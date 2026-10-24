"""Target weakness mapping.

Maps finding evidence, attack categories, and deterministic signals to specific
components of the target application architecture (docs/ARCHITECTURE.md).
"""

from __future__ import annotations

from app.domain.entities import AttackCase, Transcript, Verdict, WeakPoint
from app.domain.enums import AttackCategory


def derive_weak_point(
    case: AttackCase,
    verdict: Verdict,
    transcript: Transcript | None = None,
    system_prompt: str = "",
) -> WeakPoint | None:
    """Map an evaluated attack failure to a concrete target component."""
    signals = verdict.rule_result.signals if verdict.rule_result else []

    # 1. System Prompt Leakage / Canary Disclosure
    if (
        "canary_token_in_output" in signals
        or "canary_in_output" in signals
        or case.category == AttackCategory.CANARY_LEAKAGE
    ):
        line_num: str | None = None
        if system_prompt:
            for idx, line in enumerate(system_prompt.splitlines(), start=1):
                if "CANARY" in line or "RAVEN-CANARY" in line:
                    line_num = f"line {idx}"
                    break
        location = line_num or "line 3"
        return WeakPoint(
            component="system_prompt",
            component_name="System Prompt",
            detail=f"Canary token on {location} was disclosed to the user ({case.id}).",
            location=location,
            status="failed",
        )

    # 2. Tool Misuse / Unauthorized Execution
    if (
        any(s.startswith("unsafe_tool_call") for s in signals)
        or case.category == AttackCategory.TOOL_MISUSE
    ):
        tool_name = "issue_refund"
        for s in signals:
            if s.startswith("unsafe_tool_call:"):
                tool_name = s.split(":", 1)[1]
        return WeakPoint(
            component="tool_gateway",
            component_name="Tool Gateway",
            detail=f"{tool_name} was invoked without requiring order verification ({case.id}).",
            location=tool_name,
            status="failed",
        )

    # 3. Sensitive Data Extraction / PII Leakage
    if (
        "customer_email_disclosed" in signals
        or "customer_phone_disclosed" in signals
        or case.category == AttackCategory.SENSITIVE_DATA
    ):
        return WeakPoint(
            component="data_store",
            component_name="Customer Data Store",
            detail=f"Customer PII records (email/phone) extracted without authorization ({case.id}).",
            location="fake-customers.json",
            status="failed",
        )

    # 4. Direct Prompt Injection / Instruction Override
    if (
        "system_prompt_reproduced" in signals
        or case.category == AttackCategory.DIRECT_INJECTION
    ):
        return WeakPoint(
            component="input_guard",
            component_name="Input Guardrail",
            detail=f"No input injection filter present to intercept adversarial jailbreak prefix ({case.id}).",
            location="input boundary",
            status="missing_guardrail",
        )

    # Default fallback
    return WeakPoint(
        component="system_prompt",
        component_name="System Prompt",
        detail=f"Safety guidelines overridden by adversarial payload ({case.id}).",
        location=None,
        status="failed",
    )
