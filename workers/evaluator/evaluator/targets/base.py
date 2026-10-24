"""Target plane protocols and value types (blueprint §5)."""

from __future__ import annotations

from typing import Any, Protocol

from app.domain.entities import (
    AttackCase,
    BenignCase,
    PolicyCandidate,
    TargetProfile,
    TargetRequest,
    TargetResponse,
)


class ToolContext:
    """Context passed to the policy gateway for a tool authorization decision."""

    def __init__(
        self,
        user_message: str,
        order_id: str | None = None,
        amount: float | None = None,
        verified_order_id: bool = False,
        verified_user: bool = False,
    ) -> None:
        self.user_message = user_message
        self.order_id = order_id
        self.amount = amount
        self.verified_order_id = verified_order_id
        self.verified_user = verified_user


class PolicyDecision:
    def __init__(self, allowed: bool, reason: str, policy_source: str = "") -> None:
        self.allowed = allowed
        self.reason = reason
        self.policy_source = policy_source


class TargetAdapter(Protocol):
    """Narrow target interface (blueprint §5). No shell, no network, no side effects."""

    async def profile(self) -> TargetProfile: ...
    async def invoke(self, request: TargetRequest) -> TargetResponse: ...
    async def reset(self) -> None: ...
    async def apply_temporary_policy(self, policy: PolicyCandidate, prompt_patch: str | None = None) -> None: ...
    async def clear_temporary_policy(self) -> None: ...


class Judge(Protocol):
    """Judge interface (blueprint §5)."""

    async def evaluate(self, attack_case: AttackCase, transcript: Any) -> Any: ...


class RegressionRunner(Protocol):
    async def run_security(self, target: TargetAdapter, cases: list[AttackCase]) -> Any: ...
    async def run_utility(self, target: TargetAdapter, cases: list[BenignCase]) -> Any: ...
