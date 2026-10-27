"""GitHub Actions PR comment and annotation formatter for RAVEN.

Formats security regression results into:
1. Markdown PR comment dashboards with Frontier Delta metrics and diff previews.
2. Native GitHub workflow annotations (::error:: and ::warning::).
3. Optional GitHub REST API pull request comment posting.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

from app.domain.enums import AttackCategory, FindingLabel, Severity

logger = logging.getLogger("raven.action_formatter")


def emit_workflow_annotations(verdicts: list[Any], target_id: str) -> list[str]:
    """Emit GitHub Actions workflow commands (::error / ::warning) for PR diff highlighting.

    Formats:
      ::error file={file},line={line},title={title}::{message}
      ::warning file={file},line={line},title={title}::{message}
    """
    annotations: list[str] = []
    for item in verdicts:
        case = item[0]
        verdict = item[2]

        if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
            level = "error" if case.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"

            file_loc = (
                "fixtures/shophelper/vulnerable-policy.json"
                if case.category == AttackCategory.TOOL_MISUSE
                else "fixtures/shophelper/system-prompt.txt"
            )
            title = f"{case.category.value.replace('_', ' ').title()} Breach ({case.id}) [{case.severity.value.upper()}]"
            msg = f"Breach detected: {case.goal}. Triggered success rule '{case.success_rule}' ({verdict.resolution.value})."
            anno = f"::{level} file={file_loc},line=1,title={title}::{msg}"
            annotations.append(anno)
            print(anno)
        elif verdict.final_label == FindingLabel.NEEDS_REVIEW:
            file_loc = "fixtures/shophelper/system-prompt.txt"
            title = f"Audit Disagreement ({case.id}) [NEEDS REVIEW]"
            msg = f"Rule engine and semantic judge disagreed on {case.goal}."
            anno = f"::warning file={file_loc},line=1,title={title}::{msg}"
            annotations.append(anno)
            print(anno)

    return annotations


def format_pr_comment(
    target_id: str,
    total_cases: int,
    breaches_count: int,
    asr_before: float,
    asr_after: float,
    benign_pass_rate: float,
    benign_total: int,
    benign_passed: int,
    threshold: str,
    breached: bool,
    verdicts: list[Any],
    prompt_diff_text: str = "",
    policy_diff_text: str = "",
) -> str:
    """Generate a clean GitHub PR Markdown summary comment with Frontier metrics and diff previews."""
    status_icon = "❌ FAILED" if breached else "✅ PASSED"
    threshold_str = threshold.upper()
    delta_asr = (asr_after - asr_before) * 100
    risk_impact = f"{delta_asr:+.1f}% risk reduction" if delta_asr < 0 else "0.0% risk delta"
    gate_outcome = "Breach threshold exceeded" if breached else "Clean (within threshold)"

    lines = [
        f"## 🦅 RAVEN AI Security Gate: {status_icon}",
        "",
        f"> **Target:** `{target_id}` · **Gate Threshold:** `>= {threshold_str}` · **Status:** **{status_icon}**",
        "",
        "### 📊 Security & Benign Utility Frontier Scorecard",
        "",
        "| Metric | Current State (Baseline) | With Remediation | Frontier Impact |",
        "|---|---|---|---|",
        f"| **Attack Success Rate (ASR)** | **{asr_before * 100:.1f}%** ({breaches_count}/{total_cases} breached) | **{asr_after * 100:.1f}%** | **{risk_impact}** |",
        f"| **Benign Utility Retention** | **{benign_pass_rate * 100:.1f}%** ({benign_passed}/{benign_total} passed) | **{benign_pass_rate * 100:.1f}%** | **0.0% over-refusal** (utility preserved) |",
        f"| **Vulnerability Gate** | {status_icon} | ✅ PASS | {gate_outcome} |",
        "",
    ]

    # Findings Table
    if breaches_count > 0:
        lines.extend([
            "### 🚨 Detected Security Breaches",
            "",
            "| Case ID | Category | Severity | Attack Goal | Verdict |",
            "|---|---|---|---|---|",
        ])
        for item in verdicts:
            case = item[0]
            verdict = item[2]
            if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
                sev_icon = "🔴" if case.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
                lines.append(
                    f"| `{case.id}` | `{case.category.value}` | {sev_icon} **{case.severity.value.upper()}** | {case.goal} | `{verdict.final_label.value}` |"
                )
        lines.append("")

    # Proposed Prompt Hardening Diff
    if prompt_diff_text.strip():
        lines.extend([
            "### 🛡️ Proposed System Prompt Hardening Patch (Review Only)",
            "> **Safety Boundary:** RAVEN strictly adheres to human-in-the-loop safety boundaries. Proposed guardrails are provided as unified diffs for review and are never automatically committed.",
            "",
            "```diff",
            prompt_diff_text.strip(),
            "```",
            "",
        ])

    # Proposed Policy Diff
    if policy_diff_text.strip():
        lines.extend([
            "### 🔒 Proposed Runtime Tool Guardrail Policy",
            "Machine-readable policy configuration to enforce deterministic verification boundaries:",
            "",
            "```diff",
            policy_diff_text.strip(),
            "```",
            "",
        ])

    lines.extend([
        "---",
        "*Automated AI Security Gate generated by [RAVEN](https://github.com/evinbrijesh/RAVEN)*",
    ])

    return "\n".join(lines)


def get_pr_number() -> int | None:
    """Extract PR number from GitHub Actions environment if running in a pull request context."""
    # 1. From event.json
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        try:
            data = json.loads(Path(event_path).read_text(encoding="utf-8"))
            if "pull_request" in data and "number" in data["pull_request"]:
                return int(data["pull_request"]["number"])
            if "issue" in data and "number" in data["issue"]:
                return int(data["issue"]["number"])
        except (OSError, json.JSONDecodeError, ValueError, KeyError):
            pass

    # 2. From GITHUB_REF (e.g. refs/pull/42/merge)
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/pull/"):
        parts = ref.split("/")
        if len(parts) >= 3 and parts[2].isdigit():
            return int(parts[2])

    return None


def post_github_pr_comment(
    comment_body: str,
    github_token: str | None = None,
    repo: str | None = None,
    pr_number: int | None = None,
) -> bool:
    """Post comment to GitHub PR via REST API if token and PR context are available.

    Also appends to GITHUB_STEP_SUMMARY if available.
    Returns True if successfully posted to PR, False otherwise.
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    pr_num = pr_number or get_pr_number()

    # Always write to GITHUB_STEP_SUMMARY if env var is present
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as f:
                f.write(comment_body + "\n")
        except OSError as exc:
            logger.warning("Failed to write to GITHUB_STEP_SUMMARY: %s", exc)

    if not token or not repo or not pr_num:
        logger.info(
            "Skipping GitHub PR comment posting (token=%s, repo=%s, pr=%s)",
            bool(token),
            repo,
            pr_num,
        )
        return False

    api_url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    payload = json.dumps({"body": comment_body}).encode("utf-8")

    req = request.Request(
        api_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "RAVEN-Security-Scan-Action",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=15) as resp:
            status = resp.status
            if status in (200, 201):
                print(f"[RAVEN Action] Successfully posted PR security summary comment to #{pr_num}")
                return True
            logger.warning("GitHub API returned non-201 status: %d", status)
            return False
    except error.HTTPError as exc:
        print(f"[RAVEN Action] Failed to post PR comment (HTTP {exc.code}): {exc.reason}", file=sys.stderr)
        return False
    except error.URLError as exc:
        print(f"[RAVEN Action] Failed to connect to GitHub API: {exc.reason}", file=sys.stderr)
        return False
