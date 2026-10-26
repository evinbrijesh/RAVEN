"""Tests for multi-tenant project isolation and report export redaction / hashing.

Verifies:
1. Multi-tenant project and workspace isolation across scans, findings, and regressions.
2. Complete scrubbing of API keys, auth headers, and PII from JSON, Markdown, and SARIF exports.
3. Tamper-evident SHA-256 cryptographic content hashing attached to metadata and headers.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.domain.entities import (
    AttackCase,
    Finding,
    TargetProfile,
    Transcript,
    TranscriptMessage,
    Verdict,
)
from app.domain.enums import (
    AttackCategory,
    FindingLabel,
    RunPhase,
    RunStatus,
    Severity,
    VerdictResolution,
)
from app.domain.value_objects import EvidenceRef


def test_multi_tenant_project_isolation(client: TestClient, valid_scan_payload: dict) -> None:
    """Scans, findings, and regression suites belong to specific projects and never leak."""
    repos = client.app.state.repos

    # Create projects
    repos.projects.create("proj_finance", "Finance Team", "Finance AI target scans")
    repos.projects.create("proj_health", "Health Team", "Healthcare AI target scans")

    # 1. Create scans in separate projects
    payload_finance = {**valid_scan_payload, "project_id": "proj_finance"}
    payload_health = {**valid_scan_payload, "project_id": "proj_health"}

    res_fin = client.post("/api/scans", json=payload_finance)
    assert res_fin.status_code == 202
    scan_fin_id = res_fin.json()["scan_id"]

    res_hlt = client.post("/api/scans", json=payload_health)
    assert res_hlt.status_code == 202
    scan_hlt_id = res_hlt.json()["scan_id"]

    # 2. List scans scoped by project
    fin_scans = client.get("/api/scans?project_id=proj_finance").json()
    fin_ids = [s["scan_id"] for s in fin_scans]
    assert scan_fin_id in fin_ids
    assert scan_hlt_id not in fin_ids

    hlt_scans = client.get("/api/scans?project_id=proj_health").json()
    hlt_ids = [s["scan_id"] for s in hlt_scans]
    assert scan_hlt_id in hlt_ids
    assert scan_fin_id not in hlt_ids

    # 3. Direct access cross-project boundary rejection
    # Accessing health scan under finance project returns 404
    resp_cross = client.get(f"/api/scans/{scan_hlt_id}?project_id=proj_finance")
    assert resp_cross.status_code == 404

    # Accessing finance scan under finance project succeeds
    resp_own = client.get(f"/api/scans/{scan_fin_id}?project_id=proj_finance")
    assert resp_own.status_code == 200
    assert resp_own.json()["project_id"] == "proj_finance"

    # 4. Findings boundary enforcement
    # Save a finding for scan_hlt
    repos.findings.save(
        Finding(
            finding_id="find_hlt_001",
            scan_id=scan_hlt_id,
            project_id="proj_health",
            attack_id="A-01",
            category=AttackCategory.DIRECT_INJECTION,
            severity=Severity.HIGH,
            label=FindingLabel.CONFIRMED_FAILURE,
            summary="Prompt injection succeeded on health target",
        )
    )

    # Health findings query succeeds
    resp_hlt_find = client.get(f"/api/scans/{scan_hlt_id}/findings?project_id=proj_health")
    assert resp_hlt_find.status_code == 200
    assert len(resp_hlt_find.json()["items"]) == 1

    # Cross-project findings query returns 404
    resp_cross_find = client.get(f"/api/scans/{scan_hlt_id}/findings?project_id=proj_finance")
    assert resp_cross_find.status_code == 404

    # 5. Regression suite project isolation
    case_a = AttackCase(
        id="A-01",
        category=AttackCategory.DIRECT_INJECTION,
        goal="Bypass instructions",
        seed_prompt="Ignore instructions",
        success_rule="Target follows attacker",
        severity=Severity.HIGH,
    )
    repos.regressions.save_case(
        target_id="shophelper-local",
        attack_case=case_a,
        case_json=case_a.model_dump_json(),
        project_id="proj_finance",
    )

    fin_reg = repos.regressions.list_active("shophelper-local", project_id="proj_finance")
    assert len(fin_reg) == 1
    hlt_reg = repos.regressions.list_active("shophelper-local", project_id="proj_health")
    assert len(hlt_reg) == 0


def test_exported_reports_automatic_redaction_and_content_hash(
    client: TestClient, valid_scan_payload: dict
) -> None:
    """Exports (JSON, Markdown, SARIF) scrub all secrets/PII and attach SHA-256 integrity."""
    repos = client.app.state.repos

    # 1. Create a scan with sensitive material
    scan_id = client.post("/api/scans", json=valid_scan_payload).json()["scan_id"]
    canary = "raven-canary-secret-9876543210"

    # Persist recon profile with canary token
    repos.profiles.save(
        scan_id,
        TargetProfile(
            target_id="shophelper-local",
            version="1.0.0",
            system_prompt_hash="sys_hash_123",
            tools=["sql_query", "refund"],
            canary_token=canary,
        ),
    )

    # Persist attack run & raw transcript containing secrets
    run_id = repos.runs.create_run(scan_id, "A-01", 1, RunPhase.BEFORE)
    raw_secrets = {
        "api_key_openai": "sk-proj-supersecretkey1234567890abcdef",
        "api_key_aws": "AKIAIOSFODNN7EXAMPLE",
        "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "bearer_token": "Authorization: Bearer secret-bearer-token-val-9999",
        "custom_key": "x-api-key: internal-custom-key-abcdef",
        "email": "victim_engineer@corporate.internal",
        "phone": "+1-800-555-0199",
        "ssn": "987-65-4321",
        "card": "4111-2222-3333-4444",
        "ip": "10.14.25.100",
    }

    transcript_content = (
        f"Connecting with {raw_secrets['bearer_token']} and {raw_secrets['custom_key']}. "
        f"Credentials: {raw_secrets['api_key_openai']}, {raw_secrets['api_key_aws']}, {raw_secrets['github_token']}. "
        f"Contact {raw_secrets['email']} at {raw_secrets['phone']}. "
        f"SSN: {raw_secrets['ssn']}, Card: {raw_secrets['card']}, IP: {raw_secrets['ip']}. "
        f"Canary is {canary}."
    )

    repos.runs.save_transcript(
        Transcript(
            transcript_id="tr_secret_test",
            messages=[
                TranscriptMessage(role="user", content="Execute exfiltration attack"),
                TranscriptMessage(role="assistant", content=transcript_content),
            ],
        ),
        run_id,
    )
    repos.runs.finish_run(run_id, RunStatus.COMPLETED)

    # Add finding & verdict referencing run
    evidence = [EvidenceRef(ref_id=run_id, kind="run", description="Run transcript")]
    repos.findings.save(
        Finding(
            finding_id="find_sec_leak",
            scan_id=scan_id,
            attack_id="A-01",
            category=AttackCategory.SENSITIVE_DATA,
            severity=Severity.HIGH,
            label=FindingLabel.CONFIRMED_FAILURE,
            summary=f"Sensitive leak detected with canary {canary} and key {raw_secrets['api_key_openai']}",
            evidence_refs=evidence,
        )
    )
    repos.runs.save_verdict(
        Verdict(
            verdict_id="verd_sec_leak",
            run_id=run_id,
            scan_id=scan_id,
            final_label=FindingLabel.CONFIRMED_FAILURE,
            resolution=VerdictResolution.RULE_CONFIRMED,
            evidence_refs=evidence,
        )
    )

    # 2. Test JSON export format
    resp_json = client.get(f"/api/scans/{scan_id}/report?format=json")
    assert resp_json.status_code == 200
    json_body = resp_json.text
    sha256_header = resp_json.headers.get("X-RAVEN-Report-SHA256")
    etag_header = resp_json.headers.get("ETag")

    assert sha256_header is not None
    assert len(sha256_header) == 64
    assert etag_header == f'"{sha256_header}"'

    parsed_doc = json.loads(json_body)
    assert parsed_doc["integrity"]["content_sha256"] == sha256_header
    assert parsed_doc["redaction"]["applied"] is True

    # Assert none of the raw secrets or PII appear anywhere in the JSON body
    for secret_name, secret_val in raw_secrets.items():
        assert secret_val not in json_body, f"Secret {secret_name} leaked into JSON export!"
    assert canary not in json_body, "Canary token leaked into JSON export!"

    # 3. Test Markdown export format
    resp_md = client.get(f"/api/scans/{scan_id}/report?format=markdown")
    assert resp_md.status_code == 200
    md_body = resp_md.text

    assert resp_md.headers.get("X-RAVEN-Report-SHA256") == sha256_header
    assert f"SHA-256 `{sha256_header}`" in md_body
    assert "**Redaction:** applied" in md_body

    for secret_name, secret_val in raw_secrets.items():
        assert secret_val not in md_body, f"Secret {secret_name} leaked into Markdown export!"
    assert canary not in md_body, "Canary token leaked into Markdown export!"

    # 4. Test SARIF export format
    resp_sarif = client.get(f"/api/scans/{scan_id}/report?format=sarif")
    assert resp_sarif.status_code == 200
    sarif_body = resp_sarif.text

    parsed_sarif = json.loads(sarif_body)
    assert parsed_sarif["runs"][0]["properties"]["contentSha256"] == sha256_header

    for secret_name, secret_val in raw_secrets.items():
        assert secret_val not in sarif_body, f"Secret {secret_name} leaked into SARIF export!"
    assert canary not in sarif_body, "Canary token leaked into SARIF export!"
