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


@router.get("/{scan_id}/topology")
def get_target_topology(
    scan_id: str, repos: Repositories = Depends(get_repositories)
) -> dict[str, object]:
    """Return the ShopHelper target architecture component map pinned to scan findings."""
    scan = repos.scans.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )

    findings: list[Finding] = repos.findings.list_for_scan(scan_id)
    is_hardened = scan.status.value in ("hardening_approved", "completed", "retesting", "retest_completed")

    # Map findings by component
    findings_by_comp: dict[str, list[dict[str, object]]] = {
        "user_input": [],
        "input_guard": [],
        "system_prompt": [],
        "llm_core": [],
        "tool_gateway": [],
        "data_store": [],
        "output_guard": [],
    }
    for f in findings:
        comp = f.weak_point.component if f.weak_point else None
        if not comp:
            # Infer from category if not explicitly set
            if f.category.value == "canary_leakage":
                comp = "system_prompt"
            elif f.category.value == "tool_misuse":
                comp = "tool_gateway"
            elif f.category.value == "sensitive_data":
                comp = "data_store"
            else:
                comp = "input_guard"
        if comp in findings_by_comp:
            findings_by_comp[comp].append({
                "finding_id": f.finding_id,
                "attack_id": f.attack_id,
                "severity": f.severity.value,
                "summary": f.summary,
                "weak_point": f.weak_point.model_dump(mode="json") if f.weak_point else None,
            })

    # Build architecture component nodes
    components = [
        {
            "id": "user_input",
            "name": "User Input",
            "role": "Entrypoint",
            "status": "normal",
            "description": "Customer message payload ingress",
            "findings_count": len(findings_by_comp["user_input"]),
            "findings": findings_by_comp["user_input"],
        },
        {
            "id": "input_guard",
            "name": "Input Guardrail",
            "role": "Boundary Defense",
            "status": "blocked" if is_hardened else ("missing_guardrail" if findings_by_comp["input_guard"] else "normal"),
            "description": "Pre-execution prompt injection & jailbreak filter" if is_hardened else "No input guardrail present in baseline",
            "findings_count": len(findings_by_comp["input_guard"]),
            "findings": findings_by_comp["input_guard"],
        },
        {
            "id": "system_prompt",
            "name": "System Prompt",
            "role": "Context & Constraints",
            "status": "blocked" if is_hardened else ("failed" if findings_by_comp["system_prompt"] else "normal"),
            "description": "Instructions with canary token at line 3 (hardened with anti-leakage constraints)" if is_hardened else "Canary token on line 3 vulnerable to prompt extraction",
            "findings_count": len(findings_by_comp["system_prompt"]),
            "findings": findings_by_comp["system_prompt"],
        },
        {
            "id": "llm_core",
            "name": "LLM Core",
            "role": "Generation Engine",
            "status": "normal",
            "description": "Inference runtime generating assistant actions & tool calls",
            "findings_count": 0,
            "findings": [],
        },
        {
            "id": "tool_gateway",
            "name": "Tool Gateway",
            "role": "Action Authorization",
            "status": "blocked" if is_hardened else ("failed" if findings_by_comp["tool_gateway"] else "normal"),
            "description": "Order verification policy enforced before issue_refund" if is_hardened else "issue_refund permitted without verified order number",
            "findings_count": len(findings_by_comp["tool_gateway"]),
            "findings": findings_by_comp["tool_gateway"],
        },
        {
            "id": "data_store",
            "name": "Customer Data Store",
            "role": "Persistence Layer",
            "status": "blocked" if is_hardened else ("failed" if findings_by_comp["data_store"] else "normal"),
            "description": "Restricted customer lookup with role-based masking" if is_hardened else "Customer records (#1001-#1004) exposed via unconstrained tool queries",
            "findings_count": len(findings_by_comp["data_store"]),
            "findings": findings_by_comp["data_store"],
        },
        {
            "id": "output_guard",
            "name": "Output Guardrail",
            "role": "Egress Redaction",
            "status": "blocked" if is_hardened else ("missing_guardrail" if (findings_by_comp["system_prompt"] or findings_by_comp["data_store"]) else "normal"),
            "description": "Real-time PII & canary regex redaction active" if is_hardened else "No egress redaction filter active",
            "findings_count": len(findings_by_comp["output_guard"]),
            "findings": findings_by_comp["output_guard"],
        },
    ]

    return {
        "scan_id": scan_id,
        "target_id": scan.target.target_id,
        "is_hardened": is_hardened,
        "disclaimer": "The map displays where this test suite found weaknesses. An unmarked component indicates no failure was detected in the tested cases, not proof of universal security.",
        "components": components,
    }


@router.post("/{scan_id}/findings/{finding_id}/promote-regression")
def promote_finding_to_regression(
    scan_id: str,
    finding_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, str]:
    """Promote a reviewable finding to a persistent regression case.

    Safety (ADR 0001 review gate B5): the finding must belong to the scan,
    only actionable labels may be promoted, the persisted case is the real
    versioned catalog case (never a stub), and promotion is deduplicated per
    target.
    """
    from app.application.catalog import load_catalog_case
    from app.domain.enums import FindingLabel
    from app.domain.errors import RavenError

    scan = repos.scans.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Scan '{scan_id}' not found.").to_payload(),
        )
    finding = repos.findings.get(finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(
                f"Finding '{finding_id}' not found in scan '{scan_id}'."
            ).to_payload(),
        )

    promotable = {
        FindingLabel.CONFIRMED_FAILURE,
        FindingLabel.LIKELY_FAILURE,
        FindingLabel.NEEDS_REVIEW,
    }
    if finding.label not in promotable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "VALIDATION_FAILED",
                "message": f"Label '{finding.label.value}' cannot be promoted to a regression case.",
                "retryable": False,
                "details": {"label": finding.label.value},
            },
        )

    try:
        catalog_case = load_catalog_case(finding.attack_id)
    except RavenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_payload()
        ) from exc
    if catalog_case is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "VALIDATION_FAILED",
                "message": f"Attack '{finding.attack_id}' is not in the versioned catalog.",
                "retryable": False,
                "details": {"attack_id": finding.attack_id},
            },
        )

    # Dedupe per target: one active regression case per attack id.
    target_id = scan.target.target_id
    existing = next(
        (
            row
            for row in repos.regressions.list_active(target_id)
            if row["attack_case_id"] == finding.attack_id
        ),
        None,
    )
    if existing is not None:
        return {
            "status": "already_active",
            "regression_id": str(existing["regression_id"]),
            "attack_id": finding.attack_id,
            "target_id": target_id,
        }

    reg_id = repos.regressions.save_case(
        target_id=target_id,
        attack_case=catalog_case,
        case_json=catalog_case.model_dump_json(),
    )
    return {
        "status": "promoted",
        "regression_id": reg_id,
        "attack_id": finding.attack_id,
        "target_id": target_id,
    }


@router.get("/{scan_id}/findings/{finding_id}/transcript")
def get_finding_transcript(
    scan_id: str,
    finding_id: str,
    repos: Repositories = Depends(get_repositories),
) -> dict[str, object]:
    """Retrieve full transcript messages, timeline trace, and evidence logs for a finding.

    Everything leaving through this endpoint is redacted at render time
    (canary token, API keys, PII); raw evidence stays in the database.
    """
    from app.application.report.redaction import redact_text

    finding = repos.findings.get(finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NotFoundError(f"Finding '{finding_id}' not found.").to_payload(),
        )
    profile = repos.profiles.get(scan_id)
    canary = profile.canary_token if profile else ""

    def scrub(value: str) -> str:
        return redact_text(value, canary)

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
            messages = [
                {
                    **m.model_dump(),
                    "content": scrub(m.content),
                    **(
                        {"tool_args_json": scrub(m.tool_args_json)}
                        if m.tool_args_json
                        else {}
                    ),
                }
                for m in transcript.messages
            ]

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
                "detail": scrub(str(user_msg.get("content", ""))),
            })
            t += 120

        # Tool calls
        tool_msgs = [m for m in messages if m.get("tool_name")]
        for tm in tool_msgs:
            timeline.append({
                "time_ms": t,
                "stage": f"Tool Execution Attempted: {tm.get('tool_name')}",
                "badge": "breach",
                "detail": scrub(f"Arguments: {tm.get('tool_args_json') or '{}'}"),
            })
            t += 80

        # Assistant / Target Response
        asst_msg = next((m for m in messages if m.get("role") == "assistant" and not m.get("tool_name")), None)
        if asst_msg:
            timeline.append({
                "time_ms": t,
                "stage": "Target Assistant Output",
                "badge": "info",
                "detail": scrub(str(asst_msg.get("content", "")))[:300],
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
