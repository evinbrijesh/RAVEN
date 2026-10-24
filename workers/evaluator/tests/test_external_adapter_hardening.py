"""Tests for external adapter hardening semantics (Item 9)."""

from __future__ import annotations

import pytest
from app.domain.entities import PolicyCandidate, Scan, ScanConfig
from app.domain.enums import ScanStatus
from app.domain.value_objects import TargetRef

from evaluator.orchestration.phases import ScanEngine
from evaluator.targets.http_adapter import HttpTargetAdapter, TargetHardeningNotSupported


@pytest.fixture(autouse=True)
def bypass_dns_in_unit_tests(monkeypatch):
    monkeypatch.setattr("app.security.ssrf.validate_target_url", lambda url, **kw: None)
    monkeypatch.setattr("evaluator.targets.http_adapter.validate_target_url", lambda url, **kw: None)


def test_http_adapter_defaults_to_evaluation_only():
    adapter = HttpTargetAdapter(
        endpoint_url="https://api.example.com/v1/chat",
        headers={"X-Raven-Scan-Consent": "true"},
    )
    assert adapter.mode == "evaluation_only"


@pytest.mark.asyncio
async def test_apply_hardening_to_evaluation_only_raises():
    adapter = HttpTargetAdapter(
        endpoint_url="https://api.example.com/v1/chat",
        headers={"X-Raven-Scan-Consent": "true"},
        mode="evaluation_only",
    )
    candidate = PolicyCandidate(tool="issue_refund", conditions=["verified_order_id_present"])
    with pytest.raises(TargetHardeningNotSupported) as exc_info:
        await adapter.apply_temporary_policy(candidate, prompt_patch="test patch")
    assert "evaluation_only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_staged_target_accepts_temporary_policy():
    adapter = HttpTargetAdapter(
        endpoint_url="https://api.example.com/v1/chat",
        headers={"X-Raven-Scan-Consent": "true"},
        mode="staged_target",
    )
    candidate = PolicyCandidate(tool="issue_refund", conditions=["verified_order_id_present"])
    await adapter.apply_temporary_policy(candidate, prompt_patch="test patch")
    assert adapter._temporary_policy == candidate
    assert adapter._temporary_prompt_patch == "test patch"


@pytest.mark.asyncio
async def test_retest_on_evaluation_only_completes_without_retest(repos, monkeypatch):
    scan_id = "scan_ext_1"
    scan = Scan(
        scan_id=scan_id,
        status=ScanStatus.AWAITING_APPROVAL,
        target=TargetRef(
            target_id="https://api.example.com/v1/chat",
            kind="http",
            endpoint_url="https://api.example.com/v1/chat",
            mode="evaluation_only",
        ),
        config=ScanConfig(target_id="https://api.example.com/v1/chat"),
    )
    repos.scans.create(scan)

    # Seed a proposal so run_retest has one
    from app.domain.entities import HardeningProposal
    repos.proposals.save(
        HardeningProposal(
            proposal_id="prop_ext_1",
            scan_id=scan_id,
            prompt_diff="--- a\n+++ b",
            rationale="test",
        )
    )

    engine = ScanEngine(repos)
    await engine.run_retest(scan_id)

    updated = repos.scans.get(scan_id)
    assert updated is not None
    assert updated.status == ScanStatus.COMPLETED_WITHOUT_RETEST
