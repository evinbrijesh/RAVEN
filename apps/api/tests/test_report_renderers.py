"""Renderer tests: Markdown sections, SARIF structure, stable fingerprints.

Renderers are pure projections of the canonical document: they must not add
facts, and SARIF must emit only actionable labels.
"""

from __future__ import annotations

import json

from app.application.report.renderers.json import render_json
from app.application.report.renderers.markdown import render_markdown
from app.application.report.renderers.sarif import render_sarif
from app.domain.enums import FindingLabel, TestRunKind
from app.domain.report import ReportDocument
from tests.test_report_assembler import (
    CANARY,
    TARGET_ID,
    _bundle,
    _finding,
    _security_run,
    _utility_run,
    _verdict,
)


def _document() -> ReportDocument:
    before = _security_run(
        TestRunKind.SECURITY_BEFORE,
        [FindingLabel.CONFIRMED_FAILURE, FindingLabel.ATTACK_BLOCKED],
        0.5,
    )
    after = _security_run(
        TestRunKind.SECURITY_AFTER, [FindingLabel.ATTACK_BLOCKED], 0.0
    )
    finding = _finding(FindingLabel.CONFIRMED_FAILURE)
    verdict = _verdict("run_1", FindingLabel.CONFIRMED_FAILURE, llm=True)
    doc = assemble_document(
        _bundle(
            before=before,
            after=after,
            utility_before=_utility_run(TestRunKind.UTILITY_BEFORE, [True, True]),
            utility_after=_utility_run(TestRunKind.UTILITY, [True, True]),
            findings=[finding],
            verdicts=[verdict],
        )
    )
    return doc


def assemble_document(bundle) -> ReportDocument:
    from app.application.report.assembler import assemble

    return assemble(bundle)


# --- JSON ---------------------------------------------------------------------


def test_render_json_round_trips() -> None:
    doc = _document()
    text = render_json(doc)
    parsed = json.loads(text)
    assert parsed["schema_version"] == "1.0"
    assert parsed["summary"]["verdict"] == "improved"
    # Canonical JSON must revalidate into the same document.
    assert ReportDocument.model_validate(parsed) == doc


# --- Markdown -----------------------------------------------------------------


def test_markdown_contains_all_sections() -> None:
    text = render_markdown(_document())
    for section in (
        "# RAVEN Security Report",
        "## Summary",
        "## Coverage",
        "## Findings",
        "## Before / After",
        "## Hardening",
        "## Evidence",
        "## Model usage",
        "## Limitations",
        "## Redaction and integrity",
    ):
        assert section in text, f"missing section: {section}"


def test_markdown_renders_findings_and_deltas() -> None:
    doc = _document()
    text = render_markdown(doc)
    assert "A-01" in text
    assert "Confirmed failure" in text
    assert "Attack success reduced from 50% to 0%" in text
    assert doc.integrity.content_sha256 in text


def test_markdown_no_hardening_proposal_section_content() -> None:
    text = render_markdown(_document())
    assert "No hardening proposal was generated" in text


# --- SARIF --------------------------------------------------------------------


def test_sarif_structure_and_actionable_labels_only() -> None:
    doc = _document()
    sarif = json.loads(render_sarif(doc))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "RAVEN"
    labels = {result["properties"]["label"] for result in run["results"]}
    assert labels <= {"confirmed_failure", "likely_failure", "regression_detected", "needs_review"}
    assert run["results"][0]["level"] == "error"
    # Blocked/not-evaluated are counts in run.properties, not results.
    assert run["properties"]["attackBlocked"] >= 1
    assert run["properties"]["verdict"] == "improved"


def test_sarif_category_rules_and_fingerprints() -> None:
    doc = _document()
    sarif = json.loads(render_sarif(doc))
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"RAVEN/LLM01-prompt-injection"}
    result = run["results"][0]
    assert result["ruleId"] == "RAVEN/LLM01-prompt-injection"
    fingerprint = result["fingerprint"]["RAVEN/stableFingerprint/v1"]
    assert len(fingerprint) == 64
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        f"raven://target/{TARGET_ID}/attack/A-01"
    )


def test_sarif_fingerprint_is_stable_across_scan_ids() -> None:
    """Same target/attack/category/success_rule → same fingerprint."""
    doc_a = _document()
    doc_b = _document()
    assert (
        json.loads(render_sarif(doc_a))["runs"][0]["results"][0]["fingerprint"]
        == json.loads(render_sarif(doc_b))["runs"][0]["results"][0]["fingerprint"]
    )


def test_sarif_no_findings_emits_empty_results() -> None:
    before = _security_run(TestRunKind.SECURITY_BEFORE, [FindingLabel.ATTACK_BLOCKED], 0.0)
    after = _security_run(TestRunKind.SECURITY_AFTER, [FindingLabel.ATTACK_BLOCKED], 0.0)
    doc = assemble_document(
        _bundle(
            before=before,
            after=after,
            utility_before=_utility_run(TestRunKind.UTILITY_BEFORE, [True]),
            utility_after=_utility_run(TestRunKind.UTILITY, [True]),
        )
    )
    sarif = json.loads(render_sarif(doc))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_canary_never_reaches_renderers_via_document() -> None:
    """The document itself must not carry the raw canary token."""
    doc = _document()
    assert CANARY not in render_json(doc)
    assert CANARY not in render_markdown(doc)
    assert CANARY not in render_sarif(doc)
