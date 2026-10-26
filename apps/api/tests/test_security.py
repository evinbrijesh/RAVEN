"""Redaction and limit enforcement tests."""

from __future__ import annotations

from app.domain.entities import ScanConfig
from app.domain.errors import TargetNotAllowed, ValidationFailed
from app.domain.value_objects import Budget
from app.security.limits import clamp_budget, validate_scan_config
from app.security.redaction import redact, redact_mapping
from app.security.ssrf import SSRFValidationError


def test_redact_email_and_api_key() -> None:
    text = "contact demo@example.com or key sk-abcdef1234567890"
    out = redact(text)
    assert "demo@example.com" not in out
    assert "sk-abcdef" not in out
    assert "[REDACTED:email]" in out
    assert "[REDACTED:api_key]" in out


def test_redact_mapping() -> None:
    out = redact_mapping({"note": "call 555-123-4567", "count": 2})
    assert "555-123-4567" not in out["note"]  # type: ignore[operator]
    assert out["count"] == 2


def test_clamp_budget_enforces_hard_caps() -> None:
    clamped = clamp_budget(
        Budget(max_attack_cases=99, max_attempts_per_attack=9, max_model_calls=9999)
    )
    assert clamped.max_attack_cases == 12
    assert clamped.max_attempts_per_attack == 2
    assert clamped.max_model_calls == 200


def test_validate_scan_config_rejects_unknown_target() -> None:
    try:
        validate_scan_config(ScanConfig(target_id="http://attacker.example"))
    except (TargetNotAllowed, SSRFValidationError):
        pass  # expected
    else:
        raise AssertionError("unknown target must be rejected")


def test_validate_scan_config_rejects_mutation_without_model_budget() -> None:
    config = ScanConfig(
        target_id="shophelper-local",
        enable_mutation=True,
        budget=Budget(max_model_calls=0),
    )
    try:
        validate_scan_config(config)
    except ValidationFailed:
        pass  # expected
    else:
        raise AssertionError("mutation with zero model budget must be rejected")


def test_validate_scan_config_clamps_budget() -> None:
    config = validate_scan_config(
        ScanConfig(
            target_id="shophelper-local",
            budget=Budget(max_attack_cases=50, max_attempts_per_attack=7),
        )
    )
    assert config.budget.max_attack_cases == 12
    assert config.budget.max_attempts_per_attack == 2


def test_ssrf_validation() -> None:
    import pytest

    from app.security.ssrf import SSRFValidationError, assert_consent_header, validate_target_url

    # Local / loopback addresses should be rejected
    with pytest.raises(SSRFValidationError):
        validate_target_url("http://127.0.0.1:8080/chat")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://10.0.0.1/chat")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://169.254.169.254/latest/meta-data")

    # Consent header requirement
    from app.security.ssrf import MissingConsentError
    with pytest.raises(MissingConsentError):
        assert_consent_header({"some-header": "value"})

    assert_consent_header({"x-raven-scan-consent": "true"})


def test_deterministic_redaction_pipeline_credentials_and_pii() -> None:
    from app.security.redaction import RedactionPipeline, redact

    pipeline = RedactionPipeline()

    raw_text = (
        "Headers:\n"
        "Authorization: Bearer my-secret-bearer-token-12345678\n"
        "x-api-key: ak_test_abcdef1234567890\n"
        "Keys:\n"
        "sk-proj-1234567890abcdef\n"
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
        "AKIAIOSFODNN7EXAMPLE\n"
        "xoxb-1234567890-1234567890123\n"
        "PII:\n"
        "user@corp.example.com\n"
        "Call +1-800-555-0199 or 555-123-4567\n"
        "SSN: 123-45-6789\n"
        "Card: 4111-1111-1111-1111\n"
        "IP: 192.168.1.100\n"
    )

    redacted = pipeline.redact(raw_text)

    # Assert no secrets or PII remain in text
    assert "my-secret-bearer-token-12345678" not in redacted
    assert "ak_test_abcdef1234567890" not in redacted
    assert "sk-proj-1234567890abcdef" not in redacted
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "xoxb-1234567890-1234567890123" not in redacted
    assert "user@corp.example.com" not in redacted
    assert "123-45-6789" not in redacted
    assert "4111-1111-1111-1111" not in redacted
    assert "192.168.1.100" not in redacted

    # Assert deterministic output
    assert redact(raw_text) == redacted
    assert pipeline.redact(raw_text) == redacted


def test_redact_transcript_sanitizes_messages_and_tool_args() -> None:
    import json

    from app.domain.entities import Transcript, TranscriptMessage
    from app.security.redaction import redact_transcript

    transcript = Transcript(
        transcript_id="tr_123",
        messages=[
            TranscriptMessage(
                role="user",
                content="Please query user bob@corp.internal with token sk-secret12345678",
            ),
            TranscriptMessage(
                role="assistant",
                content="Executing lookup with authorization header",
                tool_name="lookup_user",
                tool_args_json=json.dumps({
                    "email": "alice@example.com",
                    "api_key": "raw_super_secret_key",
                    "metadata": {"ip": "10.0.0.42", "ssn": "987-65-4321"},
                }),
            ),
        ],
    )

    sanitized = redact_transcript(transcript)
    assert sanitized.transcript_id == "tr_123"
    assert len(sanitized.messages) == 2

    user_msg = sanitized.messages[0]
    assert "bob@corp.internal" not in user_msg.content
    assert "sk-secret12345678" not in user_msg.content
    assert "[REDACTED:email]" in user_msg.content
    assert "[REDACTED:api_key]" in user_msg.content

    assistant_msg = sanitized.messages[1]
    parsed_args = json.loads(assistant_msg.tool_args_json or "{}")
    assert parsed_args["api_key"] == "[REDACTED:api_key]"
    assert parsed_args["email"] == "[REDACTED:email]"
    assert parsed_args["metadata"]["ssn"] == "[REDACTED:ssn]"
    assert parsed_args["metadata"]["ip"] == "[REDACTED:ip_address]"


def test_cryptographic_run_artifact_hashing() -> None:
    from app.domain.entities import Transcript, TranscriptMessage
    from app.security.hashing import (
        compute_run_artifact_hash,
        compute_sha256,
        hash_transcript,
        verify_run_artifact_hash,
    )

    # 1. String & raw byte hashing
    text = "raven-immutable-run-artifact-payload"
    expected = compute_sha256(text)
    assert len(expected) == 64
    assert compute_run_artifact_hash(text) == expected
    assert verify_run_artifact_hash(text, expected) is True
    assert verify_run_artifact_hash(text, "invalid_hash") is False

    # 2. Canonical JSON dict hashing is independent of key order
    dict_a = {"z_field": 1, "a_field": 2, "nested": {"k2": "v2", "k1": "v1"}}
    dict_b = {"a_field": 2, "nested": {"k1": "v1", "k2": "v2"}, "z_field": 1}
    hash_a = compute_run_artifact_hash(dict_a)
    hash_b = compute_run_artifact_hash(dict_b)
    assert hash_a == hash_b

    # 3. Transcript entity hashing
    tr = Transcript(
        transcript_id="tr_hash_test",
        messages=[TranscriptMessage(role="user", content="hello target")],
    )
    tr_hash = hash_transcript(tr)
    assert len(tr_hash) == 64
    assert verify_run_artifact_hash(tr, tr_hash) is True


def test_transcript_storage_redaction_and_sha256_persistence(tmp_path) -> None:
    from app.domain.entities import Transcript, TranscriptMessage
    from app.domain.enums import RunPhase
    from app.infrastructure.db.repository import RunRepository
    from app.infrastructure.db.sqlite import Database
    from app.security.hashing import compute_run_artifact_hash

    db_path = str(tmp_path / "test_raven.db")
    db = Database(db_path)
    db.migrate()
    run_repo = RunRepository(db)

    # Create run
    run_id = run_repo.create_run(
        scan_id="scan_sec_test",
        attack_case_id="A-01",
        attempt=1,
        phase=RunPhase.BEFORE,
    )

    raw_transcript = Transcript(
        transcript_id="tr_persist_1",
        messages=[
            TranscriptMessage(
                role="user",
                content="Admin token Authorization: Bearer sk-secret-token-abcdef12345",
            ),
        ],
    )

    # Save transcript
    run_repo.save_transcript(raw_transcript, run_id)

    # Verify persisted transcript is sanitized
    persisted = run_repo.get_transcript(run_id)
    assert persisted is not None
    assert "sk-secret-token-abcdef12345" not in persisted.messages[0].content
    assert "[REDACTED:authorization_header]" in persisted.messages[0].content

    # Verify SHA-256 artifact hash is stored and matches sanitized content
    expected_hash = compute_run_artifact_hash(persisted)
    db_hash = run_repo.get_transcript_hash(run_id)
    assert db_hash == expected_hash

    # Check attack_runs row contains artifact_sha256
    row = db.query_one("SELECT artifact_sha256, transcript_json FROM attack_runs WHERE run_id = ?", (run_id,))
    assert row is not None
    assert row["artifact_sha256"] == expected_hash
    assert "sk-secret-token-abcdef12345" not in row["transcript_json"]


