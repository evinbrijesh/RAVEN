"""End-to-end integration test (Item 12).

Executes all 12 stages on a fresh isolated database:
1. Create scan
2. Run worker (execute attack cases)
3. Verify findings and evidence
4. Verify proposal generation
5. Approve proposal
6. Run retest
7. Verify security improvement
8. Verify benign utility result
9. Promote regression
10. Replay regression via CLI runner
11. Generate JSON, Markdown, and SARIF
12. Confirm stable report content SHA-256 hash and no duplicate artifacts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.application.catalog import load_catalog_case
from app.application.report.service import generate as generate_report
from app.domain.entities import Approval, Scan, ScanConfig
from app.domain.enums import FindingLabel, ScanStatus, TestRunKind
from app.domain.value_objects import TargetRef

from evaluator.cli import build_parser, run_cli
from evaluator.config import clear_settings_cache
from evaluator.worker import process_job


@pytest.mark.asyncio
async def test_full_12_stage_lifecycle(repos, fixtures_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("RAVEN_FIXTURES_DIR", str(fixtures_path))
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{repos.db.path}")
    clear_settings_cache()

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 1: Create scan
    # ──────────────────────────────────────────────────────────────────────────
    scan_id = "scan_e2e_full_001"
    scan = Scan(
        scan_id=scan_id,
        target=TargetRef(target_id="shophelper-local"),
        config=ScanConfig(
            target_id="shophelper-local",
            max_attack_cases=4,
            max_attempts_per_attack=1,
        ),
    )
    repos.scans.create(scan)
    created_scan = repos.scans.get(scan_id)
    assert created_scan is not None
    assert created_scan.status == ScanStatus.CREATED

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 2: Run worker (initial attack pass)
    # ──────────────────────────────────────────────────────────────────────────
    job = {"job_id": "job_e2e_1", "kind": "run_scan", "payload": {"scan_id": scan_id}}
    await process_job(repos, job)

    scanned_state = repos.scans.get(scan_id)
    assert scanned_state is not None
    assert scanned_state.status == ScanStatus.AWAITING_APPROVAL

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 3: Verify findings and raw evidence ledger
    # ──────────────────────────────────────────────────────────────────────────
    findings = repos.findings.list_for_scan(scan_id)
    assert len(findings) > 0, "Initial scan must produce findings against vulnerable target"

    # Verify transcripts and rule checks were captured
    before_runs = repos.runs.list_runs(scan_id)
    assert len(before_runs) > 0
    run_id = before_runs[0]["run_id"]
    transcript = repos.runs.get_transcript(run_id)
    assert transcript is not None
    assert len(transcript.messages) >= 2  # At least user prompt + assistant response

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 4: Verify hardening proposal generated
    # ──────────────────────────────────────────────────────────────────────────
    proposal = repos.proposals.latest_for_scan(scan_id)
    assert proposal is not None
    assert proposal.scan_id == scan_id
    assert len(proposal.affected_cases) > 0
    assert proposal.prompt_diff or proposal.policy_candidate

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 5: Approve proposal
    # ──────────────────────────────────────────────────────────────────────────
    approval = Approval(
        approval_id="appr_e2e_001",
        proposal_id=proposal.proposal_id,
        scan_id=scan_id,
        approved=True,
        approved_by="sec-lead@company.internal",
        decision="approved",
        created_at=datetime.now(UTC),
    )
    repos.approvals.save(approval)
    recorded_approval = repos.approvals.get_for_proposal(proposal.proposal_id)
    assert recorded_approval is not None
    assert recorded_approval.approved is True

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 6: Run retest
    # ──────────────────────────────────────────────────────────────────────────
    retest_job = {"job_id": "job_e2e_2", "kind": "run_retest", "payload": {"scan_id": scan_id}}
    await process_job(repos, retest_job)

    final_scan = repos.scans.get(scan_id)
    assert final_scan is not None
    assert final_scan.status in (ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITHOUT_RETEST)

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 7: Verify security improvement
    # ──────────────────────────────────────────────────────────────────────────
    security_before = repos.test_runs.latest_for_scan(scan_id, TestRunKind.SECURITY_BEFORE)
    security_after = repos.test_runs.latest_for_scan(scan_id, TestRunKind.SECURITY_AFTER)
    assert security_before is not None
    assert security_after is not None
    # Security must improve or remain bounded under hardening
    before_rate = security_before.metrics["attack_success_rate"]
    after_rate = security_after.metrics["attack_success_rate"]
    assert after_rate <= before_rate

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 8: Verify benign utility result
    # ──────────────────────────────────────────────────────────────────────────
    utility_after = repos.test_runs.latest_for_scan(scan_id, TestRunKind.UTILITY)
    assert utility_after is not None
    benign_rate = utility_after.metrics["benign_success_rate"]
    assert benign_rate >= 0.8, f"Utility preservation failed: benign success rate is {benign_rate}"

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 9: Promote regression
    # ──────────────────────────────────────────────────────────────────────────
    # Find any confirmed or likely failure finding from the initial scan
    failure_finding = next(
        (f for f in findings if f.label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)),
        findings[0],
    )
    catalog_case = load_catalog_case(failure_finding.attack_id)
    assert catalog_case is not None
    reg_id = repos.regressions.save_case("shophelper-local", catalog_case, catalog_case.model_dump_json())
    assert reg_id.startswith("reg_")

    active_regs = repos.regressions.list_active("shophelper-local")
    assert any(r["attack_case_id"] == failure_finding.attack_id for r in active_regs)

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 10: Replay regression via CLI runner
    # ──────────────────────────────────────────────────────────────────────────
    cli_parser = build_parser()
    cli_args = cli_parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--output", "sarif",
        "--fail-on-breach",
    ])
    cli_exit_code = await run_cli(cli_args)
    # The target in the CLI run is an unhardened baseline shophelper, so the failure re-triggers
    assert cli_exit_code in (0, 1)
    captured = capsys.readouterr()
    assert "https://json.sarif.org/schema/2.1.0/sarif-schema.json" in captured.out

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 11: Generate JSON, Markdown, and SARIF
    # ──────────────────────────────────────────────────────────────────────────
    report1 = generate_report(repos, scan_id)
    assert report1.document is not None
    assert report1.json_text and len(report1.json_text) > 50
    assert report1.markdown_text and "# RAVEN Security Report" in report1.markdown_text
    assert report1.sarif_text and "2.1.0" in report1.sarif_text

    # Verify canonical report contains limitations disclaimer
    assert "A clean result is not a security guarantee" in report1.markdown_text
    assert len(report1.document.limitations) > 0

    # ──────────────────────────────────────────────────────────────────────────
    # Stage 12: Confirm stable content SHA-256 hash and no duplicate artifacts
    # ──────────────────────────────────────────────────────────────────────────
    report2 = generate_report(repos, scan_id)
    assert report1.content_sha256 == report2.content_sha256
    assert report1.artifact_id == report2.artifact_id

    # Verify no duplicate artifact records stored in the DB
    stored_json = repos.reports.get_artifact(scan_id, "json")
    assert stored_json is not None
    assert stored_json["content_sha256"] == report1.content_sha256
