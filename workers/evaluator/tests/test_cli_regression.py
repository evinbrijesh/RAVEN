"""Tests for the standalone raven-test regression runner CLI (Item 11)."""

from __future__ import annotations

import pytest
from app.application.catalog import load_catalog_case

from evaluator.cli import build_parser, run_cli
from evaluator.config import clear_settings_cache


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
    # Save a regression case for shophelper-local
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
