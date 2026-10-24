"""Markdown renderer (ADR 0001).

Pure projection of the canonical ReportDocument: every fact rendered here
must exist in the document; nothing is added, recomputed, or omitted where
the document carries it.
"""

from __future__ import annotations

from app.domain.report import ReportDocument, ReportFinding

_ACTIONABLE_LABELS = {
    "confirmed_failure": "Confirmed failure",
    "likely_failure": "Likely failure",
    "attack_blocked": "Attack blocked",
    "needs_review": "Needs review",
    "partial_mitigation": "Partial mitigation",
    "regression_detected": "Regression detected",
    "not_evaluated": "Not evaluated",
    "verified_under_stated_checks": "Verified under stated checks",
}


def _pct(value: float | None) -> str:
    return f"{round(value * 100)}%" if value is not None else "n/a"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell.replace("\n", " ") for cell in row) + " |")
    return "\n".join(out)


def _finding_section(finding: ReportFinding) -> str:
    lines = [
        f"### {finding.attack_id} — {_ACTIONABLE_LABELS.get(finding.label.value, finding.label.value)}",
        "",
        f"- **Finding ID:** `{finding.finding_id}`",
        f"- **Category:** {finding.category.value}",
        f"- **Severity:** {finding.severity.value}",
        f"- **Confidence:** {finding.confidence:.2f}",
        f"- **Needs review:** {'yes' if finding.needs_review else 'no'}",
        f"- **Evidence complete:** {'yes' if finding.evidence_complete else 'no'}",
        "",
        finding.summary,
        "",
    ]
    if finding.attack is not None:
        lines += [
            f"- **Goal:** {finding.attack.goal}",
            f"- **Success rule:** {finding.attack.success_rule}",
            f"- **Attack version:** {finding.attack.version}",
        ]
        if finding.attack.references:
            lines.append(f"- **References:** {', '.join(finding.attack.references)}")
    if finding.deterministic is not None:
        label = (
            finding.deterministic.label.value
            if finding.deterministic.label
            else "none"
        )
        lines.append(f"- **Deterministic check:** {label}")
        for signal in finding.deterministic.signals:
            lines.append(f"  - signal: {signal}")
    if finding.semantic.available:
        lines.append(
            f"- **Semantic judge:** {finding.semantic.label.value if finding.semantic.label else 'none'}"
            f" (confidence {finding.semantic.confidence:.2f},"
            f" model {finding.semantic.model_name or 'n/a'},"
            f" prompt {finding.semantic.prompt_version or 'n/a'})"
        )
        if finding.semantic.reason:
            lines.append(f"  - reason: {finding.semantic.reason}")
    else:
        lines.append("- **Semantic judge:** unavailable")
    if finding.resolution is not None:
        lines.append(f"- **Resolution:** {finding.resolution.value}")
    if finding.run is not None:
        lines.append(
            f"- **Run:** `{finding.run.run_id}` (attempt {finding.run.attempt},"
            f" phase {finding.run.phase}, status {finding.run.status})"
        )
    if finding.evidence_refs:
        lines.append("- **Evidence refs:**")
        for ref in finding.evidence_refs:
            lines.append(f"  - `{ref.ref_id}` ({ref.kind})")
    return "\n".join(lines)


def render_markdown(document: ReportDocument) -> str:
    scan = document.scan
    summary = document.summary
    security = document.before_after.security
    utility = document.before_after.utility

    parts: list[str] = []
    parts.append(f"# RAVEN Security Report — `{scan.scan_id}`")
    parts.append("")
    parts.append(
        f"Generated {document.generated_at.isoformat()} by {document.generator.name} "
        f"{document.generator.version} (report schema {document.schema_version})."
    )
    parts.append("")
    parts.append(
        f"**Target:** {scan.target.id} (version {scan.target.version}) · "
        f"**Scan status:** {scan.status.value}"
    )
    parts.append("")
    parts.append(f"## Summary — {summary.verdict.value}")
    parts.append("")
    parts.append(summary.headline)
    parts.append("")
    counts = summary.counts
    parts.append(
        _table(
            ["Metric", "Count"],
            [
                ["Attack cases", str(counts.attack_cases)],
                ["Evaluated", str(counts.evaluated)],
                ["Not evaluated", str(counts.not_evaluated)],
                ["Confirmed failures", str(counts.confirmed_failure)],
                ["Likely failures", str(counts.likely_failure)],
                ["Attacks blocked", str(counts.attack_blocked)],
                ["Needs review", str(counts.needs_review)],
                ["Benign cases", str(counts.benign_cases)],
                ["Benign passed", str(counts.benign_passed)],
                ["Regressions saved", str(counts.regressions)],
            ],
        )
    )
    parts.append("")
    judge = summary.judge
    parts.append(
        f"**Judges:** deterministic {'available' if judge.deterministic_available else 'unavailable'}, "
        f"semantic {'available' if judge.semantic_available else 'unavailable'}"
        + (f" ({judge.model_name}, prompt {judge.prompt_version})" if judge.model_name else "")
        + f", disagreements: {judge.disagreements}"
    )
    parts.append("")

    parts.append("## Coverage")
    parts.append("")
    coverage = document.coverage
    parts.append(
        f"- Attack cases: {coverage.attack_cases} across "
        f"{', '.join(c.value for c in coverage.categories) or 'no categories'}"
    )
    parts.append(f"- Benign cases: {coverage.benign_cases}")
    parts.append(
        f"- Catalog versions: attacks {coverage.attack_catalog_version}, "
        f"benign {coverage.benign_catalog_version}"
    )
    parts.append("")

    parts.append("## Findings")
    parts.append("")
    if document.findings:
        parts.append(
            _table(
                ["Attack", "Category", "Severity", "Label", "Needs review"],
                [
                    [
                        f.attack_id,
                        f.category.value,
                        f.severity.value,
                        _ACTIONABLE_LABELS.get(f.label.value, f.label.value),
                        "yes" if f.needs_review else "no",
                    ]
                    for f in document.findings
                ],
            )
        )
        parts.append("")
        for finding in document.findings:
            parts.append(_finding_section(finding))
            parts.append("")
    else:
        parts.append("No findings recorded for this scan.")
        parts.append("")

    parts.append("## Before / After")
    parts.append("")
    parts.append(
        _table(
            ["Security metric", "Before", "After", "Delta"],
            [
                [
                    "Attack success rate",
                    _pct(security.before_attack_success_rate),
                    _pct(security.after_attack_success_rate),
                    _pct(security.delta),
                ],
                [
                    "Blocked rate",
                    _pct(security.before_blocked_rate),
                    _pct(security.after_blocked_rate),
                    "n/a",
                ],
            ],
        )
    )
    parts.append("")
    if security.per_category:
        parts.append(
            _table(
                ["Category", "Before", "After", "Delta"],
                [
                    [
                        c.category.value,
                        _pct(c.before_success_rate),
                        _pct(c.after_success_rate),
                        _pct(c.delta),
                    ]
                    for c in security.per_category
                ],
            )
        )
        parts.append("")
    parts.append(
        _table(
            ["Utility metric", "Before", "After", "Delta"],
            [
                [
                    "Benign success rate",
                    _pct(utility.before_benign_success_rate),
                    _pct(utility.after_benign_success_rate),
                    _pct(utility.delta),
                ]
            ],
        )
    )
    parts.append("")
    if utility.cases:
        parts.append(
            _table(
                ["Case", "Goal", "Before", "After", "Over-refusal"],
                [
                    [
                        c.case_id,
                        c.goal,
                        "pass" if c.passed_before else ("fail" if c.passed_before is False else "n/a"),
                        "pass" if c.passed_after else ("fail" if c.passed_after is False else "n/a"),
                        "yes" if c.over_refusal else "no",
                    ]
                    for c in utility.cases
                ],
            )
        )
        parts.append("")

    parts.append("## Hardening")
    parts.append("")
    proposal = document.hardening.proposal
    if proposal is None:
        parts.append("No hardening proposal was generated for this scan.")
    else:
        parts.append(f"- **Proposal ID:** `{proposal.proposal_id}`")
        parts.append(f"- **Rationale:** {proposal.rationale}")
        if proposal.affected_cases:
            parts.append(f"- **Affected cases:** {', '.join(proposal.affected_cases)}")
        if proposal.risks:
            parts.append(f"- **Risks:** {', '.join(proposal.risks)}")
        parts.append("")
        parts.append("```diff")
        parts.append(proposal.prompt_diff)
        parts.append("```")
        if proposal.policy_candidate is not None:
            pc = proposal.policy_candidate
            parts.append("")
            parts.append(
                f"**Policy candidate:** tool `{pc.tool}`, high-value action "
                f"`{pc.high_value_action}`, on violation `{pc.on_violation}`"
            )
            for condition in pc.conditions:
                parts.append(f"- condition: {condition}")
    parts.append("")
    approval = document.hardening.approval
    if approval is not None:
        parts.append(
            f"**Approval:** {'approved' if approval.approved else 'rejected'} by "
            f"`{approval.approved_by}` at {approval.created_at.isoformat()}; "
            f"applied to: {document.hardening.applied_to}."
        )
    else:
        parts.append("**Approval:** none recorded.")
    parts.append("")

    parts.append("## Evidence")
    parts.append("")
    if document.evidence:
        parts.append(
            _table(
                ["Ref", "Kind", "Description"],
                [
                    [f"`{e.ref_id}`", e.kind, e.description]
                    for e in document.evidence
                ],
            )
        )
    else:
        parts.append("No evidence entries recorded.")
    parts.append("")

    parts.append("## Model usage")
    parts.append("")
    usage = document.model_usage
    parts.append(
        f"- Semantic judge {'available' if usage.semantic_judge_available else 'unavailable'}"
        + (f" ({usage.model_name}, prompt {usage.prompt_version})" if usage.model_name else "")
    )
    parts.append(f"- Judge calls: {usage.calls}")
    parts.append("")

    parts.append("## Limitations")
    parts.append("")
    for limitation in document.limitations:
        parts.append(f"- {limitation}")
    parts.append("")

    redaction = document.redaction
    parts.append(
        f"**Redaction:** {'applied' if redaction.applied else 'not applied'} at render "
        f"time (fields: {', '.join(redaction.redacted_fields)}; transcript excerpt "
        f"limit {redaction.transcript_excerpt_chars} chars)."
    )
    parts.append("")
    parts.append(
        f"**Integrity:** SHA-256 `{document.integrity.content_sha256}` "
        f"({document.integrity.source})."
    )
    parts.append("")
    return "\n".join(parts)
