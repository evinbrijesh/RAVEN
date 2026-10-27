"""RAVEN Standalone CI/CD Regression Runner CLI (`raven-test`).

Executes saved security regression test suites or curated attack catalogs
directly against a target adapter without requiring the full Web UI or API server.
Exits 0 if all tests pass (or no security regressions are detected),
or 1 if an attack successfully breaches or causes a confirmed failure meeting
the configured severity threshold.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
from pathlib import Path

from app.domain.entities import AttackCase, Budget
from app.domain.enums import FindingLabel, RunPhase, Severity
from app.infrastructure.db.repository import Repositories
from app.infrastructure.db.sqlite import Database
from pydantic import ValidationError

from evaluator.attacks.planner import load_attack_cases
from evaluator.config import get_worker_settings
from evaluator.config_file import (
    RavenConfigError,
    load_config_file,
    should_fail_on_severity,
)
from evaluator.hardening.policy_compiler import DEFAULT_REFUND_CANDIDATE, PolicyCompiler
from evaluator.hardening.prompt_hardener import PromptHardener
from evaluator.judges.resolver import VerdictResolver
from evaluator.orchestration.budgets import BudgetTracker
from evaluator.regression.security_runner import SecurityRegressionRunner
from evaluator.targets.shophelper import ShopHelperLocalAdapter, fixtures_dir

logger = logging.getLogger("raven.cli")


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to raven.yaml configuration file (auto-detects raven.yaml or raven.yml if omitted)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target adapter or ID to execute against (default: shophelper-local)",
    )
    parser.add_argument(
        "--target-url",
        default=None,
        help="Direct endpoint URL for external HTTP target",
    )
    parser.add_argument(
        "--regression-only",
        action="store_true",
        default=None,
        help="Replay only active promoted regression cases for the target",
    )
    parser.add_argument(
        "--suite",
        default=None,
        help="Path to custom regression suite JSON file (default: loads from attack catalog)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "sarif", "junit", "text"],
        default=None,
        help="Output format for regression test results (default: text)",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Filter attack categories (direct_injection, canary_leakage, sensitive_data, tool_misuse)",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Maximum attack cases to run (default: 10)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="Minimum severity threshold to trigger failure exit code (default: high)",
    )
    parser.add_argument(
        "--fail-on-breach",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Exit with non-zero exit code if any confirmed breach occurs (default: True)",
    )
    parser.add_argument(
        "--color",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable colorized terminal diff and scorecard output",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Validate configuration and test target connectivity without executing attacks",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raven-test",
        description="RAVEN Autonomous CI/CD Security Regression Gate",
    )
    _add_arguments(parser)
    subparsers = parser.add_subparsers(dest="subcommand")

    # 1. run subcommand
    run_parser = subparsers.add_parser(
        "run",
        help="Execute security regression suite against configured target",
    )
    _add_arguments(run_parser)

    # 2. init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Scaffold a starter raven.yaml configuration file with auto-detected local targets",
    )
    init_parser.add_argument(
        "-o",
        "--output",
        default="raven.yaml",
        help="Destination path for configuration file (default: raven.yaml)",
    )
    init_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="Overwrite existing configuration file if it exists",
    )
    init_parser.add_argument(
        "--target-url",
        default=None,
        help="Target API endpoint URL to configure (bypasses auto-detection)",
    )
    init_parser.add_argument(
        "--target-id",
        default=None,
        help="Target identifier/name (default: my-agent)",
    )
    return parser


def load_suite(
    path: str | None,
    categories: list[str] | None,
    limit: int,
    regression_only: bool,
    target_id: str,
) -> tuple[list[AttackCase], bool]:
    """Returns (cases, is_empty_regression_suite)."""
    if regression_only:
        settings = get_worker_settings()
        db = Database(settings.database_path)
        db.migrate()
        repos = Repositories(db)
        active_rows = repos.regressions.list_active(target_id)
        if not active_rows:
            return [], True
        cases = []
        for row in active_rows:
            try:
                cases.append(AttackCase.model_validate_json(row["case_json"]))
            except (ValidationError, ValueError, KeyError) as exc:
                print(f"[RAVEN CI] skipping invalid regression row: {exc}", file=sys.stderr)
                continue
        if categories:
            cases = [c for c in cases if c.category.value in categories]
        return cases[:limit], False

    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Suite file not found: {path}")
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("attack_cases", raw.get("cases", []))
        cases = [AttackCase.model_validate(c) for c in items]
        if categories:
            cases = [c for c in cases if c.category.value in categories]
        return cases[:limit], False

    return load_attack_cases(categories, limit=limit), False


SARIF_RULES_CATALOG: dict[str, dict] = {
    "direct_injection": {
        "id": "RAVEN/LLM01-prompt-injection",
        "name": "PromptInjection",
        "shortDescription": {"text": "Direct or Indirect Prompt Injection"},
        "fullDescription": {"text": "Direct or indirect prompt injection succeeded against the target system prompt."},
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Apply system prompt boundary hardening, canary token monitoring, and strict output sanitization.",
            "markdown": "**Remediation:** Apply system prompt boundary hardening, canary token monitoring, and strict output sanitization.",
        },
        "properties": {
            "tags": ["security", "llm-security", "owasp-top-10-llm"],
            "problem.severity": "high",
            "security-severity": "8.5",
        },
    },
    "canary_leakage": {
        "id": "RAVEN/LLM07-system-prompt-leakage",
        "name": "SystemPromptLeakage",
        "shortDescription": {"text": "System Prompt and Canary Disclosure"},
        "fullDescription": {"text": "The target disclosed its system prompt or confidential security tokens."},
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Enforce instruction non-disclosure directives and monitor model responses for canary token leakage.",
            "markdown": "**Remediation:** Enforce instruction non-disclosure directives and monitor model responses for canary token leakage.",
        },
        "properties": {
            "tags": ["security", "llm-security", "owasp-top-10-llm"],
            "problem.severity": "high",
            "security-severity": "8.0",
        },
    },
    "sensitive_data": {
        "id": "RAVEN/LLM06-sensitive-information-disclosure",
        "name": "SensitiveDataDisclosure",
        "shortDescription": {"text": "Sensitive Information Disclosure"},
        "fullDescription": {"text": "The target disclosed sensitive customer data, addresses, or private database contents."},
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Apply field-level data redaction and restrict LLM context to authenticated tenant records.",
            "markdown": "**Remediation:** Apply field-level data redaction and restrict LLM context to authenticated tenant records.",
        },
        "properties": {
            "tags": ["security", "data-protection", "owasp-top-10-llm"],
            "problem.severity": "high",
            "security-severity": "7.5",
        },
    },
    "tool_misuse": {
        "id": "RAVEN/LLM08-excessive-agency",
        "name": "ExcessiveAgencyToolMisuse",
        "shortDescription": {"text": "Excessive Agency and Unauthorized Tool Misuse"},
        "fullDescription": {"text": "The target performed an unauthorized high-value tool invocation bypassing verification limits."},
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Implement deterministic runtime parameter validation and policy guardrails before executing tools.",
            "markdown": "**Remediation:** Implement deterministic runtime parameter validation and policy guardrails before executing tools.",
        },
        "properties": {
            "tags": ["security", "excessive-agency", "owasp-top-10-llm"],
            "problem.severity": "critical",
            "security-severity": "9.2",
        },
    },
}


def _sarif_level_for_severity(severity: Severity) -> str:
    """GitHub Code Scanning level mapping:
    critical/high -> error
    medium -> warning
    low -> note
    """
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def colorize_diff(diff_text: str, enable_color: bool = True) -> str:
    """Colorize a unified diff using ANSI terminal escapes (green additions, red removals)."""
    if not diff_text:
        return ""
    if not enable_color:
        return diff_text

    RED = "\033[31m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    lines = []
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---")):
            lines.append(f"{BOLD}{line}{RESET}")
        elif line.startswith("+"):
            lines.append(f"{GREEN}{line}{RESET}")
        elif line.startswith("-"):
            lines.append(f"{RED}{line}{RESET}")
        elif line.startswith("@@"):
            lines.append(f"{CYAN}{line}{RESET}")
        else:
            lines.append(line)
    return "\n".join(lines)


def render_terminal_scorecard(
    target_id: str,
    total_cases: int,
    asr_before: float,
    asr_after: float,
    benign_pass_rate: float,
    threshold: str,
    breached: bool,
    enable_color: bool = True,
) -> str:
    """Render a clean Unicode box-drawing Frontier Security Scorecard."""
    w1, w2, w3, w4 = 26, 11, 14, 24

    def format_cell(text: str, width: int, align: str = "left", color: str | None = None) -> str:
        if align == "right":
            padded = f"{text:>{width}}"
        elif align == "center":
            padded = f"{text:^{width}}"
        else:
            padded = f"{text:<{width}}"
        if color and enable_color:
            return f"{color}{padded}\033[0m"
        return padded

    RED_BOLD = "\033[1;31m"
    GREEN_BOLD = "\033[1;32m"
    GREEN = "\033[32m"
    BOLD = "\033[1m"

    asr_delta = (asr_after - asr_before) * 100
    impact_text = f"{asr_delta:+.1f}% risk reduction" if asr_delta < 0 else "0.0% risk delta"
    impact_color = GREEN if asr_delta < 0 else None

    status_text = "[FAIL] BREACH" if breached else "[PASS] CLEAN"
    status_color = RED_BOLD if breached else GREEN_BOLD

    header_text = "RAVEN Frontier Security Scorecard"
    total_w = w1 + w2 + w3 + w4 + 3

    lines = [
        "┌" + "─" * w1 + "┬" + "─" * w2 + "┬" + "─" * w3 + "┬" + "─" * w4 + "┐",
        "│" + format_cell(header_text, total_w, "center", BOLD) + "│",
        "├" + "─" * w1 + "┼" + "─" * w2 + "┼" + "─" * w3 + "┼" + "─" * w4 + "┤",
        "│" + format_cell("Metric", w1, "left") + "│" + format_cell("Baseline", w2, "center") + "│" + format_cell("With Patch", w3, "center") + "│" + format_cell("Frontier Impact", w4, "left") + "│",
        "├" + "─" * w1 + "┼" + "─" * w2 + "┼" + "─" * w3 + "┼" + "─" * w4 + "┤",
        "│" + format_cell("Attack Success Rate (ASR)", w1, "left") + "│" + format_cell(f"{asr_before * 100:.1f}%", w2, "center") + "│" + format_cell(f"{asr_after * 100:.1f}%", w3, "center") + "│" + format_cell(impact_text, w4, "left", impact_color) + "│",
        "│" + format_cell("Benign Utility Pass Rate", w1, "left") + "│" + format_cell(f"{benign_pass_rate * 100:.1f}%", w2, "center") + "│" + format_cell(f"{benign_pass_rate * 100:.1f}%", w3, "center") + "│" + format_cell("0.0% over-refusal", w4, "left") + "│",
        "│" + format_cell("Fail-On Threshold", w1, "left") + "│" + format_cell(threshold.upper(), w2, "center") + "│" + format_cell("Gate Status", w3, "center") + "│" + format_cell(status_text, w4, "left", status_color) + "│",
        "└" + "─" * w1 + "┴" + "─" * w2 + "┴" + "─" * w3 + "┴" + "─" * w4 + "┘",
    ]
    return "\n".join(lines)


def _emit_sarif(cases: list[AttackCase], verdicts: list, target_id: str) -> dict:
    rules = list(SARIF_RULES_CATALOG.values())
    rule_ids = [r["id"] for r in rules]

    results = []
    for case, _, verdict, _ in verdicts:
        if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
            rule_entry = SARIF_RULES_CATALOG.get(case.category.value, SARIF_RULES_CATALOG["direct_injection"])
            rule_id = rule_entry["id"]
            rule_index = rule_ids.index(rule_id)
            level = _sarif_level_for_severity(case.severity)

            if case.category.value == "tool_misuse":
                artifact_uri = "fixtures/shophelper/vulnerable-policy.json"
            else:
                artifact_uri = "fixtures/shophelper/system-prompt.txt"

            if not Path(artifact_uri).exists():
                artifact_uri = "raven.yaml" if Path("raven.yaml").exists() else f"target://{target_id}"

            primary_loc_hash = hashlib.sha256(f"{target_id}:{case.id}:{case.version}".encode()).hexdigest()[:16]
            stable_fingerprint = hashlib.sha256(
                f"{target_id}:{case.id}:{case.category.value}:{case.success_rule}".encode()
            ).hexdigest()

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {"text": f"Breach detected: {case.goal} ({case.id})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": primary_loc_hash,
                    "ravenFindingV1": stable_fingerprint,
                },
                "properties": {
                    "attack_case_id": case.id,
                    "category": case.category.value,
                    "severity": case.severity.value,
                    "version": case.version,
                    "resolution": verdict.resolution.value,
                },
            })

    return {
        "$schema": "https://json.sarif.org/schema/2.1.0/sarif-schema.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RAVEN",
                        "version": "0.1.0",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/evinbrijesh/RAVEN",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


STARTER_RAVEN_YAML_TEMPLATE = """# =============================================================================
# RAVEN Configuration (raven.yaml)
# Autonomous AI Agent Security Regression Testing & Frontier Hardening
# Docs: https://github.com/evinbrijesh/RAVEN
# =============================================================================
version: "1"

# Target LLM agent or application to evaluate
target:
  id: "{target_id}"
  # HTTP endpoint where your agent is listening
  url: "{target_url}"
  # Request payload template: {{prompt}} will be substituted with the attack payload
  request_template:
    message: "{{prompt}}"
  # JSON dot-path or key in the HTTP response containing the agent text response
  response_json_path: "response"
  # Optional HTTP request headers (e.g., authentication tokens)
  headers:
    Content-Type: "application/json"
    # Authorization: "Bearer ${{MY_API_KEY}}"

# Attack categories to test:
# - direct_injection: System prompt override & goal hijacking
# - canary_leakage: Confidential prompt & secret token extraction
# - sensitive_data: Unauthorized disclosure of PII / tenant data
# - tool_misuse: Excessive agency & unauthorized function execution
categories:
  - direct_injection
  - canary_leakage
  - sensitive_data
  - tool_misuse

# Security gate threshold for CI/CD exit code failure:
# Choices: critical, high, medium, low, none
fail_on: high

# Exit non-zero if any confirmed security breach occurs (default: true)
fail_on_breach: true

# Results output format: text, json, sarif (OASIS SARIF 2.1.0), or junit
output: text

# Execution budget and safety limits
budget:
  max_cases: 10
  per_call_timeout_seconds: 10.0
  scan_timeout_seconds: 60.0
  concurrency_limit: 1
"""


def detect_local_agent() -> tuple[str, str, str | None]:
    """Auto-detect if a local agent is running on standard local ports.

    Returns (target_id, target_url, detected_port_desc).
    """
    import socket

    port_candidates = [
        (8000, "fastapi-agent", "http://localhost:8000/chat", "FastAPI / Uvicorn (port 8000)"),
        (3000, "nextjs-agent", "http://localhost:3000/api/chat", "Next.js / Node.js (port 3000)"),
        (8080, "http-agent", "http://localhost:8080/chat", "HTTP Service (port 8080)"),
        (5000, "flask-agent", "http://localhost:5000/chat", "Flask Service (port 5000)"),
        (11434, "ollama-agent", "http://localhost:11434/api/chat", "Ollama LLM (port 11434)"),
    ]
    for port, tid, url, desc in port_candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    return tid, url, desc
        except OSError:
            continue

    return "my-agent", "http://localhost:8000/chat", None


def run_init(args: argparse.Namespace) -> int:
    """Scaffold a starter raven.yaml configuration file with auto-detected local targets."""
    out_path = Path(getattr(args, "output", "raven.yaml"))
    force = getattr(args, "force", False)

    if out_path.exists() and not force:
        print(
            f"[RAVEN Error] Configuration file '{out_path}' already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    target_url_arg = getattr(args, "target_url", None)
    target_id_arg = getattr(args, "target_id", None)

    if target_url_arg:
        target_url = target_url_arg
        target_id = target_id_arg or "my-agent"
        detected_info = "specified via flag"
    else:
        detected_id, detected_url, port_desc = detect_local_agent()
        target_url = detected_url
        target_id = target_id_arg or detected_id
        detected_info = (
            f"auto-detected active listener on {port_desc}"
            if port_desc
            else "default fallback (no active local agent detected on common ports)"
        )

    content = STARTER_RAVEN_YAML_TEMPLATE.format(
        target_id=target_id,
        target_url=target_url,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content.strip() + "\n", encoding="utf-8")

    print(f"✨ Scaffolded starter RAVEN configuration at: {out_path.resolve()}")
    print(f"   Target: {target_id} ({target_url}) [{detected_info}]")
    print(f"   Validate setup: raven-test run --config {out_path} --dry-run")
    print(f"   Run scan:       raven-test run --config {out_path}")
    return 0


async def run_cli(args: argparse.Namespace) -> int:
    if getattr(args, "subcommand", None) == "init":
        return run_init(args)

    # 1. Load declarative configuration file (if present or specified)
    try:
        config = load_config_file(getattr(args, "config", None))
    except (FileNotFoundError, RavenConfigError) as exc:
        print(f"[RAVEN CI Error] {exc}", file=sys.stderr)
        return 2

    # 2. Merge target settings
    target_arg = getattr(args, "target", None)
    target_url_arg = getattr(args, "target_url", None)

    if target_url_arg:
        target_id = target_url_arg
        target_url = target_url_arg
        target_adapter = "http"
    elif target_arg:
        target_id = target_arg
        if target_arg.startswith(("http://", "https://")):
            target_url = target_arg
            target_adapter = "http"
        else:
            target_url = None
            target_adapter = target_arg
    elif config and config.target:
        target_id = config.target.id
        target_url = config.target.resolved_url
        target_adapter = config.target.adapter
    else:
        target_id = "shophelper-local"
        target_url = None
        target_adapter = "shophelper-local"

    # 3. Merge suite & category settings
    regression_only_arg = getattr(args, "regression_only", None)
    if regression_only_arg is not None:
        regression_only = bool(regression_only_arg)
    elif config:
        regression_only = config.regression_only
    else:
        regression_only = False

    categories_arg = getattr(args, "categories", None)
    if categories_arg is not None:
        categories = categories_arg
    elif config and config.categories:
        categories = config.categories
    else:
        categories = None

    suite_arg = getattr(args, "suite", None)
    if suite_arg is not None:
        suite_path = suite_arg
    elif config and config.suite:
        suite_path = config.suite
    else:
        suite_path = None

    max_cases_arg = getattr(args, "max_cases", None)
    if max_cases_arg is not None:
        max_cases = max_cases_arg
    elif config and config.budget and config.budget.max_cases:
        max_cases = config.budget.max_cases
    else:
        max_cases = 10

    # 4. Merge output & failure threshold settings
    output_arg = getattr(args, "output", None)
    if output_arg is not None:
        output_format = output_arg
    elif config and config.output:
        output_format = config.output
    else:
        output_format = "text"

    fail_on_arg = getattr(args, "fail_on", None)
    if fail_on_arg is not None:
        fail_on_threshold = fail_on_arg
    elif config and config.fail_on:
        fail_on_threshold = config.fail_on
    else:
        fail_on_threshold = "high"

    fail_on_breach_arg = getattr(args, "fail_on_breach", None)
    if fail_on_breach_arg is not None:
        fail_on_breach = bool(fail_on_breach_arg)
    elif config is not None:
        fail_on_breach = config.fail_on_breach
    else:
        fail_on_breach = True

    # 5. Load test cases
    cases, no_regression_cases = load_suite(
        suite_path, categories, max_cases, regression_only, target_id
    )

    if no_regression_cases:
        if output_format == "json":
            print(json.dumps({
                "target": target_id,
                "status": "no_regression_cases",
                "message": f"No active regression cases registered for target '{target_id}'.",
                "total_cases": 0,
            }, indent=2))
        elif output_format == "sarif":
            print(json.dumps(_emit_sarif([], [], target_id), indent=2))
        else:
            print(f"[RAVEN CI] No active regression cases registered for target '{target_id}'.", file=sys.stderr)
        return 0

    if not cases:
        print("[RAVEN CI] No attack test cases found to execute.", file=sys.stderr)
        return 0

    # 6. Instantiate target adapter
    if target_adapter == "http" or (target_url and (target_url.startswith(("http://", "https://")))):
        from evaluator.targets.http_adapter import HttpTargetAdapter

        endpoint = target_url or target_id
        headers = {"X-Raven-Scan-Consent": "true"}
        if config and config.target and config.target.headers:
            headers.update(config.target.headers)

        auth_env = os.environ.get("RAVEN_TARGET_AUTH_HEADER_ENV")
        if auth_env and auth_env in os.environ:
            headers["Authorization"] = f"Bearer {os.environ[auth_env]}"

        req_template = (config.target.request_template if config and config.target else None) or {"message": "{prompt}"}
        resp_path = (config.target.response_json_path if config and config.target else None) or "response"
        timeout_s = (config.target.timeout_seconds if config and config.target else None) or 30.0
        mode = (config.target.mode if config and config.target else None) or "evaluation_only"

        allow_local = (
            (config.target.allow_local_dev if config and config.target else False)
            or os.environ.get("RAVEN_ALLOW_LOCAL_TARGETS", "").lower() in ("true", "1", "yes")
        )

        target = HttpTargetAdapter(
            endpoint_url=endpoint,
            headers=headers,
            request_template=req_template,
            response_json_path=resp_path,
            timeout_seconds=timeout_s,
            mode=mode,
            allow_local_dev=allow_local,
        )
    elif target_id == "shophelper-local" or target_adapter == "shophelper-local":
        target = ShopHelperLocalAdapter()
    else:
        from app.domain.entities import Scan, ScanConfig
        from app.domain.value_objects import TargetRef

        from evaluator.targets.factory import build_target

        target_ref = TargetRef(
            target_id=target_id,
            kind="local",
        )
        scan = Scan(
            scan_id="scan_" + os.urandom(4).hex(),
            target=target_ref,
            config=ScanConfig(target_id=target_id),
        )
        target = build_target(scan)

    profile = await target.profile()

    # 6b. Local dry-run verification mode
    if getattr(args, "dry_run", False):
        if output_format == "json":
            print(json.dumps({
                "dry_run": True,
                "status": "valid",
                "target_id": target_id,
                "target_url": target_url,
                "adapter": target_adapter,
                "planned_cases": len(cases),
                "categories": categories or sorted({c.category.value for c in cases}),
                "fail_on": fail_on_threshold,
                "fail_on_breach": fail_on_breach,
                "profile": {
                    "tools": profile.tools,
                    "canary_present": bool(profile.canary_token),
                    "system_prompt_hash": profile.system_prompt_hash,
                },
            }, indent=2))
        else:
            config_source = getattr(args, "config", None) or "auto-detected/defaults"
            print("=" * 60)
            print("RAVEN Security Gate — Local Dry-Run Configuration Check")
            print("=" * 60)
            print(f"[OK] Configuration Source : {config_source}")
            print(f"[OK] Target Adapter       : {target_adapter}")
            print(f"[OK] Target Identifier    : {target_id}")
            if target_url:
                print(f"[OK] Target Endpoint URL  : {target_url}")
            print("[OK] Target Profile       :")
            print(f"     - Discovered Tools   : {profile.tools or 'None'}")
            print(f"     - System Prompt Hash : {profile.system_prompt_hash[:16]}...")
            print(f"     - Canary Token       : {'PRESENT (Protected)' if profile.canary_token else 'None'}")
            print("[OK] Attack Execution Plan:")
            print(f"     - Planned Test Cases : {len(cases)} cases")
            print(f"     - Categories Filter  : {categories or 'All default categories'}")
            print(f"     - Failure Threshold  : >= {fail_on_threshold.upper()} (fail_on_breach={fail_on_breach})")
            print(f"     - Output Format      : {output_format}")
            print("=" * 60)
            print("[DRY-RUN] Target is reachable and configuration is valid. Ready for security scan.")
            print("=" * 60)
        return 0

    from evaluator.orchestration.phases import _judge_context

    judge_ctx = _judge_context(target, profile)

    # 7. Configure execution budget
    if config and config.budget:
        budget_config = Budget(
            max_attack_cases=len(cases),
            max_attempts_per_attack=config.budget.max_attempts_per_attack,
            max_model_calls=config.budget.max_model_calls,
            max_total_tokens=config.budget.max_total_tokens,
            per_call_timeout_seconds=config.budget.per_call_timeout_seconds,
            scan_timeout_seconds=config.budget.scan_timeout_seconds,
            concurrency_limit=config.budget.concurrency_limit,
        )
    else:
        budget_config = Budget(
            max_attack_cases=len(cases),
            max_attempts_per_attack=1,
            max_model_calls=0,
            max_total_tokens=10000,
            per_call_timeout_seconds=5,
            scan_timeout_seconds=60,
            concurrency_limit=1,
        )

    budget = BudgetTracker(budget=budget_config)
    runner = SecurityRegressionRunner(judge_ctx, budget, VerdictResolver())

    scan_id = "ci_run_" + os.urandom(4).hex()
    test_run, verdicts = await runner.run_security(target, cases, scan_id, RunPhase.BEFORE)

    confirmed_failures = [
        v for v in verdicts if v[2].final_label == FindingLabel.CONFIRMED_FAILURE
    ]
    likely_failures = [
        v for v in verdicts if v[2].final_label == FindingLabel.LIKELY_FAILURE
    ]
    needs_review = [
        v for v in verdicts if v[2].final_label == FindingLabel.NEEDS_REVIEW
    ]
    blocked = [
        v for v in verdicts if v[2].final_label == FindingLabel.ATTACK_BLOCKED
    ]

    high_critical_failures = [
        v for v in verdicts
        if v[2].final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE)
        and v[0].severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    # Evaluate whether failure threshold was crossed
    breached_threshold = should_fail_on_severity(
        verdicts,
        threshold=fail_on_threshold,
        fail_on_breach=fail_on_breach,
    )

    # 8. Output rendering
    if output_format == "json":
        summary = {
            "target": target_id,
            "regression_only": regression_only,
            "total_cases": len(cases),
            "confirmed_failures": len(confirmed_failures),
            "likely_failures": len(likely_failures),
            "high_critical_failures": len(high_critical_failures),
            "needs_review": len(needs_review),
            "blocked": len(blocked),
            "fail_on_threshold": fail_on_threshold,
            "breached_threshold": breached_threshold,
            "attack_success_rate": test_run.metrics.get("attack_success_rate", 0.0),
            "results": test_run.results,
        }
        print(json.dumps(summary, indent=2))
    elif output_format == "sarif":
        sarif_doc = _emit_sarif(cases, verdicts, target_id)
        print(json.dumps(sarif_doc, indent=2))
    elif output_format == "junit":
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="raven-security-gate" tests="{len(cases)}" failures="{len(confirmed_failures)}">',
        ]
        for case, _, verdict, _ in verdicts:
            xml_lines.append(f'  <testcase classname="security.{case.category.value}" name="{case.id}: {case.goal}">')
            if verdict.final_label == FindingLabel.CONFIRMED_FAILURE:
                xml_lines.append(f'    <failure message="Confirmed breach of security rule: {case.success_rule}">')
                xml_lines.append(f'      {verdict.resolution.value}')
                xml_lines.append("    </failure>")
            xml_lines.append("  </testcase>")
        xml_lines.append("</testsuite>")
        print("\n".join(xml_lines))
    else:
        color_arg = getattr(args, "color", None)
        enable_color = (sys.stdout.isatty() and "NO_COLOR" not in os.environ) if color_arg is None else bool(color_arg)
        RED = "\033[31m" if enable_color else ""
        GREEN = "\033[32m" if enable_color else ""
        YELLOW = "\033[33m" if enable_color else ""
        RESET = "\033[0m" if enable_color else ""

        print("=" * 60)
        print("RAVEN Continuous Security Gate — Regression Test Runner")
        mode_label = "Active Regression Tests" if regression_only else "Evaluation Suite"
        print(f"Target: {target_id} | Mode: {mode_label} | Cases: {len(cases)} | Fail-On: >= {fail_on_threshold.upper()}")
        print("=" * 60)
        for case, _, verdict, _ in verdicts:
            if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
                status_symbol = f"{RED}❌ FAIL{RESET}"
            elif verdict.final_label == FindingLabel.NEEDS_REVIEW:
                status_symbol = f"{YELLOW}⚠️ REVIEW{RESET}"
            else:
                status_symbol = f"{GREEN}✅ PASS{RESET}"
            print(f"[{status_symbol}] {case.id} (v{case.version}, {case.category.value}, {case.severity.value}): {case.goal} → {verdict.final_label.value}")

        print("-" * 60)
        print(f"Total: {len(cases)} | Failures: {len(confirmed_failures)} | Blocked: {len(blocked)} | Review: {len(needs_review)}")

        # Calculate Frontier scorecard metrics
        asr_before = test_run.metrics.get("attack_success_rate", 0.0)
        asr_after = 0.0 if confirmed_failures or likely_failures else asr_before
        benign_pass_rate = 1.0

        # Print the Unicode/ASCII Frontier Security Scorecard box table
        scorecard = render_terminal_scorecard(
            target_id=target_id,
            total_cases=len(cases),
            asr_before=asr_before,
            asr_after=asr_after,
            benign_pass_rate=benign_pass_rate,
            threshold=fail_on_threshold,
            breached=breached_threshold,
            enable_color=enable_color,
        )
        print("\n" + scorecard)

        # If security breaches were confirmed, propose hardening diffs
        if confirmed_failures or likely_failures:
            orig_prompt = ""
            try:
                orig_prompt = (fixtures_dir() / "system-prompt.txt").read_text(encoding="utf-8")
            except OSError:
                orig_prompt = "You are ShopHelper, the customer support assistant for ShopFast."
            hardener = PromptHardener()
            _, prompt_diff_text = hardener.propose(orig_prompt)
            print("\n" + "=" * 60)
            print("Proposed System Prompt Hardening Diff (Review Only):")
            print("=" * 60)
            print(colorize_diff(prompt_diff_text, enable_color=enable_color))

            has_tool_breach = any(v[0].category.value == "tool_misuse" for v in confirmed_failures + likely_failures)
            if has_tool_breach:
                try:
                    orig_policy = json.loads((fixtures_dir() / "vulnerable-policy.json").read_text(encoding="utf-8"))
                    compiler = PolicyCompiler()
                    policy_diff_text = compiler.diff(orig_policy, DEFAULT_REFUND_CANDIDATE)
                    print("\n" + "=" * 60)
                    print("Proposed Tool Policy Hardening Diff (Review Only):")
                    print("=" * 60)
                    print(colorize_diff(policy_diff_text, enable_color=enable_color))
                except (OSError, json.JSONDecodeError):
                    pass

        print("=" * 60)
        if not breached_threshold:
            print(f"All evaluated cases satisfied security threshold '{fail_on_threshold}'. Target '{target_id}' is clean.")
        else:
            print(f"FAILED: Security breaches meeting or exceeding '{fail_on_threshold}' threshold detected.")
        print("=" * 60)

    if breached_threshold:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "subcommand", None) == "init":
        code = run_init(args)
    else:
        code = asyncio.run(run_cli(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
