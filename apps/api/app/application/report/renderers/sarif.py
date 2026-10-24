"""SARIF 2.1.0 renderer (ADR 0001).

Pure projection of the canonical ReportDocument. Emits only actionable
labels as results (confirmed_failure, likely_failure, regression_detected,
needs_review); blocked/not-evaluated appear as counts in run.properties.
Rules are category-level and stable across scans.
"""

from __future__ import annotations

import hashlib

from app.domain.report import ReportDocument, ReportFinding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.sarif.org/schema/2.1.0/sarif-schema.json"
DRIVER_NAME = "RAVEN"
DRIVER_URI = "https://github.com/raven/raven"

# Category → stable rule id (MITRE ATLAS LLM mapping per ADR 0001).
_CATEGORY_RULES = {
    "prompt_injection": "RAVEN/LLM01-prompt-injection",
    "system_prompt_leak": "RAVEN/LLM07-system-prompt-leakage",
    "sensitive_disclosure": "RAVEN/LLM06-sensitive-information-disclosure",
    "excessive_agency": "RAVEN/LLM08-excessive-agency",
}

_ACTIONABLE_LABELS = {"confirmed_failure", "likely_failure", "regression_detected", "needs_review"}
_ERROR_LABELS = {"confirmed_failure", "regression_detected"}

_RULE_HELP = {
    "RAVEN/LLM01-prompt-injection": "Direct or indirect prompt injection succeeded against the target.",
    "RAVEN/LLM07-system-prompt-leakage": "The target disclosed its system prompt or configuration.",
    "RAVEN/LLM06-sensitive-information-disclosure": "The target disclosed sensitive data (PII, secrets, canary).",
    "RAVEN/LLM08-excessive-agency": "The target performed or offered an unauthorized high-value action.",
}


def _fingerprint(finding: ReportFinding, target_id: str) -> str:
    """Stable fingerprint: sha256(target_id:attack_id:category:success_rule)."""
    success_rule = finding.attack.success_rule if finding.attack else ""
    material = f"{target_id}:{finding.attack_id}:{finding.category.value}:{success_rule}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _rules_for(document: ReportDocument) -> list[dict]:
    categories = {
        finding.category.value
        for finding in document.findings
        if finding.label.value in _ACTIONABLE_LABELS
    }
    rules = []
    for category in sorted(categories):
        rule_id = _CATEGORY_RULES.get(category, f"RAVEN/{category}")
        rules.append(
            {
                "id": rule_id,
                "name": category,
                "shortDescription": {"text": rule_id.split("/", 1)[1]},
                "fullDescription": {"text": _RULE_HELP.get(rule_id, category)},
                "defaultConfiguration": {"level": "error"},
            }
        )
    return rules


def render_sarif(document: ReportDocument) -> str:
    import json

    target_id = document.scan.target.id
    rules = _rules_for(document)
    rule_ids = {rule["id"] for rule in rules}

    results = []
    for finding in document.findings:
        if finding.label.value not in _ACTIONABLE_LABELS:
            continue
        rule_id = _CATEGORY_RULES.get(finding.category.value, f"RAVEN/{finding.category.value}")
        if rule_id not in rule_ids:  # defensive: rule must exist for every result
            continue
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.label.value in _ERROR_LABELS else "warning",
                "message": {"text": finding.summary},
                "fingerprint": {"RAVEN/stableFingerprint/v1": _fingerprint(finding, target_id)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"raven://target/{target_id}/attack/{finding.attack_id}"
                            }
                        }
                    }
                ],
                "properties": {
                    "label": finding.label.value,
                    "attackId": finding.attack_id,
                    "severity": finding.severity.value,
                    "needsReview": finding.needs_review,
                    "evidenceComplete": finding.evidence_complete,
                    "findingId": finding.finding_id,
                    **({"runId": finding.run.run_id} if finding.run else {}),
                },
            }
        )

    counts = document.summary.counts
    run = {
        "tool": {
            "driver": {
                "name": DRIVER_NAME,
                "version": document.generator.version,
                "informationUri": DRIVER_URI,
                "rules": rules,
            }
        },
        "invocations": [
            {
                "executionSuccessful": document.scan.status.value == "completed",
                "executionComplete": document.scan.status.value == "completed",
            }
        ],
        "results": results,
        "properties": {
            "verdict": document.summary.verdict.value,
            "attackCases": counts.attack_cases,
            "evaluated": counts.evaluated,
            "attackBlocked": counts.attack_blocked,
            "notEvaluated": counts.not_evaluated,
            "benignCases": counts.benign_cases,
            "benignPassed": counts.benign_passed,
            "scanId": document.scan.scan_id,
            "reportId": document.report_id,
            "contentSha256": document.integrity.content_sha256,
        },
    }
    sarif = {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
