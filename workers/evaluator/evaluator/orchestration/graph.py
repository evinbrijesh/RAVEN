"""LangGraph architectural representation of the RAVEN Security Regression Engine.

Formalizes the closed-loop architecture:
Recon -> Attack -> Judge (Deterministic + Semantic) -> Mutate (if blocked) ->
Harden -> Human Approval Gate (Interrupt) -> Retest & Utility -> Report.

Note on Orchestration Priority (P0.3):
ScanEngine serves as the canonical runtime executor for durability, recovery, and
restart safety. This graph defines the formal state topology and step contracts.
"""

from __future__ import annotations

import logging
from typing import Any, TypedDict

from app.domain.entities import Finding, TargetProfile
from app.domain.enums import ScanStatus
from langgraph.graph import END, StateGraph

from evaluator.orchestration.phases import ScanEngine

logger = logging.getLogger("raven.langgraph")


class RavenGraphState(TypedDict, total=False):
    scan_id: str
    target_id: str
    phase: str
    profile: dict[str, Any]
    findings: list[dict[str, Any]]
    proposal: dict[str, Any] | None
    approved: bool
    status: str
    metrics: dict[str, Any]


def create_raven_graph(engine: ScanEngine) -> Any:
    """Build the compiled LangGraph workflow for RAVEN."""
    workflow = StateGraph(RavenGraphState)

    # 1. Recon Node
    async def recon_node(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("LangGraph [recon_node] for scan %s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        if not scan:
            return {"status": "error"}
        from evaluator.orchestration.budgets import BudgetTracker
        from evaluator.targets.shophelper import ShopHelperLocalAdapter

        target = ShopHelperLocalAdapter(engine._fixtures_path or None)
        budget = BudgetTracker(budget=scan.config.budget)
        profile = await engine._phase_recon(scan_id, target, budget)
        return {
            "phase": "recon_completed",
            "profile": profile.model_dump(),
        }

    # 2. Attack & Judge Node
    async def attack_and_judge_node(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("LangGraph [attack_and_judge_node] for scan %s", scan_id)
        scan = engine._repos.scans.get(scan_id)
        assert scan is not None
        from evaluator.orchestration.budgets import BudgetTracker
        from evaluator.targets.shophelper import ShopHelperLocalAdapter

        target = ShopHelperLocalAdapter(engine._fixtures_path or None)
        budget = BudgetTracker(budget=scan.config.budget)
        profile = TargetProfile(**state["profile"])

        findings = await engine._phase_attack_and_judge(scan_id, target, budget, profile)
        return {
            "phase": "judging_completed",
            "findings": [f.model_dump() for f in findings],
        }

    # 3. Hardening Node
    async def hardening_node(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("LangGraph [hardening_node] for scan %s", scan_id)
        findings = [Finding(**f) for f in state.get("findings", [])]
        await engine._phase_hardening(scan_id, findings)
        latest_proposal = engine._repos.proposals.latest_for_scan(scan_id)
        return {
            "phase": "awaiting_approval",
            "proposal": latest_proposal.model_dump() if latest_proposal else None,
        }

    # 4. Approval Gate Node (Checks database if human approved)
    async def approval_gate_node(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        proposal = engine._repos.proposals.latest_for_scan(scan_id)
        if not proposal:
            return {"approved": False}
        approval = engine._repos.approvals.get_for_proposal(proposal.proposal_id)
        return {"approved": approval.approved if approval else False}

    # 5. Retest Node
    async def retest_node(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        logger.info("LangGraph [retest_node] for scan %s", scan_id)
        await engine.run_retest(scan_id)
        scan = engine._repos.scans.get(scan_id)
        return {
            "phase": "completed",
            "status": scan.status.value if scan else "completed",
        }

    # 6. Complete Without Retest Node
    async def complete_without_retest(state: RavenGraphState) -> dict[str, Any]:
        scan_id = state["scan_id"]
        engine._set_status(scan_id, ScanStatus.COMPLETED_WITHOUT_RETEST, 1.0)
        return {"phase": "completed_without_retest", "status": "completed_without_retest"}

    # Define nodes in graph
    workflow.add_node("recon", recon_node)
    workflow.add_node("attack_and_judge", attack_and_judge_node)
    workflow.add_node("propose_hardening", hardening_node)
    workflow.add_node("approval_gate", approval_gate_node)
    workflow.add_node("retest", retest_node)
    workflow.add_node("complete_without_retest", complete_without_retest)

    # Define edges
    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "attack_and_judge")

    # Conditional edge after judging: if findings exist -> propose hardening, else END
    def check_findings(state: RavenGraphState) -> str:
        if state.get("findings"):
            return "propose_hardening"
        return "complete_without_retest"

    workflow.add_conditional_edges(
        "attack_and_judge",
        check_findings,
        {
            "propose_hardening": "propose_hardening",
            "complete_without_retest": "complete_without_retest",
        },
    )

    workflow.add_edge("propose_hardening", "approval_gate")

    # Conditional edge on human approval
    def check_approval(state: RavenGraphState) -> str:
        if state.get("approved"):
            return "retest"
        return "complete_without_retest"

    workflow.add_conditional_edges(
        "approval_gate",
        check_approval,
        {
            "retest": "retest",
            "complete_without_retest": "complete_without_retest",
        },
    )

    workflow.add_edge("retest", END)
    workflow.add_edge("complete_without_retest", END)

    return workflow.compile()
