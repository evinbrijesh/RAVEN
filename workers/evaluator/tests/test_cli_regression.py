"""Tests for standalone CI/CD regression runner CLI and declarative raven.yaml configuration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.application.catalog import load_catalog_case

from evaluator.cli import build_parser, run_cli
from evaluator.config import clear_settings_cache
from evaluator.config_file import (
    RavenConfigError,
    find_config_file,
    load_config_file,
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Existing baseline tests (backward compatibility)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_regression_only_no_cases(repos, monkeypatch, capsys):
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{repos.db.path}")
    clear_settings_cache()
    parser = build_parser()
    args = parser.parse_args(["--target", "shophelper-local", "--regression-only", "--output", "json"])

    code = await run_cli(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "no_regression_cases" in captured.out


@pytest.mark.asyncio
async def test_regression_only_with_promoted_case_sarif(repos, monkeypatch, capsys):
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{repos.db.path}")
    clear_settings_cache()
    # Save a regression case for shophelper-local (A-01 is severity high)
    case = load_catalog_case("A-01")
    assert case is not None
    repos.regressions.save_case("shophelper-local", case, case.model_dump_json())

    parser = build_parser()
    args = parser.parse_args(["--target", "shophelper-local", "--regression-only", "--output", "sarif", "--fail-on-breach"])

    code = await run_cli(args)
    # The vulnerable shophelper-local fails A-01, so code must be 1 on breach
    assert code == 1
    captured = capsys.readouterr()
    assert "https://json.sarif.org/schema/2.1.0/sarif-schema.json" in captured.out
    assert "RAVEN/LLM01-prompt-injection" in captured.out


# ─────────────────────────────────────────────────────────────────────────────
# 2. Declarative raven.yaml configuration unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_config_file_model_parsing_valid(tmp_path: Path):
    cfg_content = """
target:
  id: "shophelper-local"
  adapter: "shophelper-local"
  timeout_seconds: 45.0
categories:
  - direct_injection
  - canary_leakage
budget:
  max_cases: 5
  max_attempts_per_attack: 2
  max_model_calls: 10
  scan_timeout_seconds: 120.0
fail_on: "critical"
fail_on_breach: true
output: "json"
"""
    cfg_path = tmp_path / "raven.yaml"
    cfg_path.write_text(cfg_content, encoding="utf-8")

    cfg = load_config_file(cfg_path)
    assert cfg is not None
    assert cfg.target.id == "shophelper-local"
    assert cfg.target.adapter == "shophelper-local"
    assert cfg.target.timeout_seconds == 45.0
    assert cfg.categories == ["direct_injection", "canary_leakage"]
    assert cfg.budget.max_cases == 5
    assert cfg.budget.max_attempts_per_attack == 2
    assert cfg.budget.scan_timeout_seconds == 120.0
    assert cfg.fail_on == "critical"
    assert cfg.fail_on_breach is True
    assert cfg.output == "json"


def test_config_file_target_shorthands(tmp_path: Path):
    # Shorthand 1: simple local target string
    p1 = tmp_path / "c1.yaml"
    p1.write_text("target: shophelper-local\n", encoding="utf-8")
    cfg1 = load_config_file(p1)
    assert cfg1.target.id == "shophelper-local"
    assert not cfg1.target.is_http

    # Shorthand 2: URL target string
    p2 = tmp_path / "c2.yaml"
    p2.write_text("target: https://api.example.com/v1/chat\n", encoding="utf-8")
    cfg2 = load_config_file(p2)
    assert cfg2.target.is_http
    assert cfg2.target.resolved_url == "https://api.example.com/v1/chat"

    # Shorthand 3: top-level target_url shorthand
    p3 = tmp_path / "c3.yaml"
    p3.write_text("target_url: http://localhost:8000/api/chat\n", encoding="utf-8")
    cfg3 = load_config_file(p3)
    assert cfg3.target.is_http
    assert cfg3.target.resolved_url == "http://localhost:8000/api/chat"

    # Shorthand 4: top-level max_cases syncing into budget
    p4 = tmp_path / "c4.yaml"
    p4.write_text("max_cases: 7\n", encoding="utf-8")
    cfg4 = load_config_file(p4)
    assert cfg4.budget.max_cases == 7


def test_config_file_validation_errors(tmp_path: Path):
    # Non-existent file
    with pytest.raises(FileNotFoundError):
        load_config_file(tmp_path / "does_not_exist.yaml")

    # Malformed YAML
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("target: [unclosed list", encoding="utf-8")
    with pytest.raises(RavenConfigError):
        load_config_file(bad_yaml)

    # Invalid fail_on value
    bad_fail_on = tmp_path / "bad_fail_on.yaml"
    bad_fail_on.write_text("fail_on: extreme\n", encoding="utf-8")
    with pytest.raises(RavenConfigError):
        load_config_file(bad_fail_on)

    # Invalid output format
    bad_output = tmp_path / "bad_output.yaml"
    bad_output.write_text("output: html\n", encoding="utf-8")
    with pytest.raises(RavenConfigError):
        load_config_file(bad_output)


def test_config_file_auto_discovery(tmp_path: Path):
    assert find_config_file(tmp_path) is None

    cfg_file = tmp_path / "raven.yaml"
    cfg_file.write_text("output: sarif\n", encoding="utf-8")

    found = find_config_file(tmp_path)
    assert found == cfg_file

    cfg = load_config_file(cfg_file)
    assert cfg is not None
    assert cfg.output == "sarif"


# ─────────────────────────────────────────────────────────────────────────────
# 3. CLI execution with raven.yaml & parameter overrides
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cli_execution_with_config_file(tmp_path: Path, capsys):
    cfg_file = tmp_path / "raven.yaml"
    cfg_file.write_text("""
target: shophelper-local
categories:
  - canary_leakage
max_cases: 2
output: json
fail_on: high
""", encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(["--config", str(cfg_file)])

    code = await run_cli(args)
    # Target fails canary leakage cases, so it exits with 1
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["target"] == "shophelper-local"
    assert data["total_cases"] == 2
    assert data["fail_on_threshold"] == "high"
    assert data["breached_threshold"] is True


@pytest.mark.asyncio
async def test_cli_args_override_config_file(tmp_path: Path, capsys):
    cfg_file = tmp_path / "raven.yaml"
    cfg_file.write_text("""
target: shophelper-local
categories:
  - canary_leakage
max_cases: 1
output: json
fail_on: critical
""", encoding="utf-8")

    parser = build_parser()
    # CLI overrides max_cases to 3 and categories to direct_injection
    args = parser.parse_args([
        "--config", str(cfg_file),
        "--categories", "direct_injection",
        "--max-cases", "3",
        "--fail-on", "medium",
    ])

    code = await run_cli(args)
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["total_cases"] == 3
    assert data["fail_on_threshold"] == "medium"


@pytest.mark.asyncio
async def test_cli_missing_or_invalid_config_returns_code_2(tmp_path: Path, capsys):
    parser = build_parser()
    # Missing file
    args = parser.parse_args(["--config", str(tmp_path / "nonexistent.yaml")])
    code = await run_cli(args)
    assert code == 2
    captured = capsys.readouterr()
    assert "[RAVEN CI Error]" in captured.err

    # Malformed file
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("invalid: [yaml", encoding="utf-8")
    args = parser.parse_args(["--config", str(bad_cfg)])
    code = await run_cli(args)
    assert code == 2


# ─────────────────────────────────────────────────────────────────────────────
# 4. --fail-on <severity> Threshold Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cli_fail_on_threshold_medium_severity_case(repos, monkeypatch, capsys):
    """A-03 has severity 'medium'.

    - If --fail-on critical: exit code 0 (breach is below critical threshold).
    - If --fail-on high: exit code 0 (breach is below high threshold).
    - If --fail-on medium: exit code 1 (breach meets medium threshold).
    - If --fail-on low: exit code 1 (breach meets low threshold).
    - If --fail-on none: exit code 0.
    """
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{repos.db.path}")
    clear_settings_cache()

    case_a03 = load_catalog_case("A-03")
    assert case_a03 is not None
    assert case_a03.severity.value == "medium"

    repos.regressions.save_case("shophelper-local", case_a03, case_a03.model_dump_json())
    parser = build_parser()

    # 1. --fail-on critical -> should PASS (exit 0) because breach is only medium
    args_crit = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "critical",
        "--output", "json",
    ])
    code_crit = await run_cli(args_crit)
    assert code_crit == 0
    data_crit = json.loads(capsys.readouterr().out)
    assert data_crit["breached_threshold"] is False

    # 2. --fail-on high -> should PASS (exit 0) because breach is only medium
    args_high = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "high",
        "--output", "json",
    ])
    code_high = await run_cli(args_high)
    assert code_high == 0
    data_high = json.loads(capsys.readouterr().out)
    assert data_high["breached_threshold"] is False

    # 3. --fail-on medium -> should FAIL (exit 1) because breach is medium
    args_med = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "medium",
        "--output", "json",
    ])
    code_med = await run_cli(args_med)
    assert code_med == 1
    data_med = json.loads(capsys.readouterr().out)
    assert data_med["breached_threshold"] is True

    # 4. --fail-on low -> should FAIL (exit 1)
    args_low = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "low",
        "--output", "json",
    ])
    code_low = await run_cli(args_low)
    assert code_low == 1

    # 5. --fail-on none -> should PASS (exit 0)
    args_none = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "none",
        "--output", "json",
    ])
    code_none = await run_cli(args_none)
    assert code_none == 0

    # 6. --no-fail-on-breach -> should PASS (exit 0)
    args_no_breach = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--no-fail-on-breach",
        "--output", "json",
    ])
    code_no_breach = await run_cli(args_no_breach)
    assert code_no_breach == 0


@pytest.mark.asyncio
async def test_cli_fail_on_critical_with_critical_breach(repos, monkeypatch, capsys):
    """A-07 has severity 'critical'.

    - If --fail-on critical: exit code 1 (critical breach detected).
    """
    monkeypatch.setenv("RAVEN_DATABASE_URL", f"sqlite:///{repos.db.path}")
    clear_settings_cache()

    case_a07 = load_catalog_case("A-07")
    assert case_a07 is not None
    assert case_a07.severity.value == "critical"

    repos.regressions.save_case("shophelper-local", case_a07, case_a07.model_dump_json())
    parser = build_parser()

    args = parser.parse_args([
        "--target", "shophelper-local",
        "--regression-only",
        "--fail-on", "critical",
        "--output", "json",
    ])
    code = await run_cli(args)
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["breached_threshold"] is True
    assert data["fail_on_threshold"] == "critical"


@pytest.mark.asyncio
async def test_cli_target_url_creates_http_adapter(monkeypatch, tmp_path: Path):
    """Passing --target-url configures HttpTargetAdapter with SSRF checks bypassed in tests."""
    monkeypatch.setattr("app.security.ssrf.validate_target_url", lambda url, **kw: None)
    monkeypatch.setattr("evaluator.targets.http_adapter.validate_target_url", lambda url, **kw: None)

    cfg_file = tmp_path / "raven.yaml"
    cfg_file.write_text("""
target_url: https://api.my-agent.internal/v1/chat
categories:
  - direct_injection
max_cases: 1
""", encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(["--config", str(cfg_file)])

    # Mock target profile & runner so we don't need a live HTTP server in unit tests
    from unittest.mock import AsyncMock, patch

    from app.domain.entities import TargetProfile

    mock_profile = TargetProfile(
        target_id="https://api.my-agent.internal/v1/chat",
        version="live",
        system_prompt_hash="abc12345",
        tools=[],
        canary_token="MOCK_CANARY",
    )

    with patch("evaluator.targets.http_adapter.HttpTargetAdapter.profile", new_callable=AsyncMock) as mock_p, \
         patch("evaluator.regression.security_runner.SecurityRegressionRunner.run_security", new_callable=AsyncMock) as mock_run:
        mock_p.return_value = mock_profile
        from app.domain.entities import TestRun
        from app.domain.enums import TestRunKind

        mock_run.return_value = (TestRun(test_run_id="run_1", scan_id="s1", kind=TestRunKind.SECURITY_BEFORE, results=[]), [])

        code = await run_cli(args)
        assert code == 0
        mock_p.assert_awaited_once()
