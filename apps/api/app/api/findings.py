"""Findings endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_repositories
from app.domain.entities import Finding
from app.domain.errors import NotFoundError
from app.infrastructure.db.repository import Repositories

router = APIRouter(prefix="/api/scans", tags=["findings"])


@router.get("/{scan_id}/findings")
def list_findings(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> dict[str, object]:
    if repos.scans.get(scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    findings: list[Finding] = repos.findings.list_for_scan(scan_id)
    return {"items": [f.model_dump(mode="json") for f in findings]}


@router.post("/{scan_id}/findings/{finding_id}/promote-regression")
def promote_finding_to_regression(
    scan_id: str,
    finding_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, str]:
    """Promote a confirmed failure or reviewable finding to a persistent regression case."""
    scan = repos.scans.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    finding = repos.findings.get(finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Finding '{finding_id}' not found.").to_payload(),
        )

    # Save to regression cases for this target
    from app.domain.entities import AttackCase
    stub_case = AttackCase(
        id=finding.attack_id,
        category=finding.category,
        goal=finding.summary,
        seed_prompt="",
        success_rule="",
        severity=finding.severity,
    )
    reg_id = repos.regressions.save_case(
        target_id=scan.target.target_id,
        attack_case=stub_case,
        case_json=finding.model_dump_json(),
    )
    return {
        "status": "promoted",
        "regression_id": reg_id,
        "attack_id": finding.attack_id,
        "target_id": scan.target.target_id,
    }


@router.get("/{scan_id}/findings/{finding_id}/transcript")
def get_finding_transcript(
    scan_id: str,
    finding_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, object]:
    """Retrieve full transcript messages, timeline trace, and evidence logs for a finding."""
    finding = repos.findings.get(finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Finding '{finding_id}' not found.").to_payload(),
        )

    # Search runs for this finding's attack case
    runs = repos.runs.list_runs(scan_id)
    target_run = next((r for r in runs if r.get("attack_case_id") == finding.attack_id), None)
    messages = []
    timeline = []
    verdict_data = None

    if target_run:
        run_id = target_run["run_id"]
        transcript = repos.runs.get_transcript(run_id)
        if transcript:
            messages = [m.model_dump() for m in transcript.messages]

        # Fetch matching verdict
        verdicts = repos.runs.list_verdicts(scan_id)
        verdict = next((v for v in verdicts if v.run_id == run_id), None)
        if verdict:
            verdict_data = {
                "verdict_id": verdict.verdict_id,
                "final_label": verdict.final_label.value,
                "resolution": verdict.resolution.value,
                "rule_label": verdict.rule_result.label.value if verdict.rule_result else None,
                "rule_signals": verdict.rule_result.signals if verdict.rule_result else [],
                "llm_label": verdict.llm_result.label.value if verdict.llm_result else None,
                "llm_confidence": verdict.llm_result.confidence if verdict.llm_result else None,
                "llm_reason": verdict.llm_result.reason if verdict.llm_result else None,
                "llm_model": verdict.llm_result.model_name if verdict.llm_result else None,
            }

        # Construct Step-by-Step Execution Trace Timeline
        t = 0
        user_msg = next((m for m in messages if m.get("role") == "user"), None)
        if user_msg:
            timeline.append({
                "time_ms": t,
                "stage": "Attack Prompt Injected",
                "badge": "warning",
                "detail": user_msg.get("content", ""),
            })
            t += 120

        # Tool calls
        tool_msgs = [m for m in messages if m.get("tool_name")]
        for tm in tool_msgs:
            timeline.append({
                "time_ms": t,
                "stage": f"Tool Execution Attempted: {tm.get('tool_name')}",
                "badge": "breach",
                "detail": f"Arguments: {tm.get('tool_args_json') or '{}'}",
            })
            t += 80

        # Assistant / Target Response
        asst_msg = next((m for m in messages if m.get("role") == "assistant" and not m.get("tool_name")), None)
        if asst_msg:
            timeline.append({
                "time_ms": t,
                "stage": "Target Assistant Output",
                "badge": "info",
                "detail": asst_msg.get("content", "")[:300],
            })
            t += 60

        # Deterministic Rules
        if verdict and verdict.rule_result and verdict.rule_result.signals:
            timeline.append({
                "time_ms": t,
                "stage": f"Deterministic Rule Intercept: {verdict.rule_result.label.value}",
                "badge": "breach" if "failure" in verdict.rule_result.label.value else "blocked",
                "detail": f"Matched Signals: {', '.join(verdict.rule_result.signals)}",
            })
            t += 50

        # Judge Deliberation
        if verdict:
            model_info = f" + LLM Judge ({verdict.llm_result.label.value}, conf: {verdict.llm_result.confidence:.2f})" if verdict.llm_result else ""
            rule_info = f"Rule Judge ({verdict.rule_result.label.value})" if verdict.rule_result else "No rule evidence"
            badge = "breach" if "failure" in verdict.final_label.value else ("warning" if verdict.final_label.value == "needs_review" else "blocked")
            timeline.append({
                "time_ms": t,
                "stage": f"Verdict Resolved: {verdict.final_label.value}",
                "badge": badge,
                "detail": f"{rule_info}{model_info} → Resolution: {verdict.resolution.value}",
            })

    return {
        "finding_id": finding.finding_id,
        "attack_id": finding.attack_id,
        "evidence_refs": [r.model_dump() for r in finding.evidence_refs],
        "messages": messages,
        "verdict": verdict_data,
        "timeline": timeline,
    }
