"""Declarative configuration file (raven.yaml) parser and models.

Allows developers and CI/CD pipelines to configure targets, attack categories,
execution budgets, output formats, and failure thresholds via raven.yaml or raven.yml.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from app.domain.enums import FindingLabel, Severity
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("raven.config_file")

CONFIG_FILENAMES: list[str] = ["raven.yaml", "raven.yml", ".raven.yaml", ".raven.yml"]

SEVERITY_LEVELS: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}


class RavenConfigError(ValueError):
    """Raised when a raven.yaml configuration file cannot be read or validated."""


class TargetConfig(BaseModel):
    """Configuration for evaluation target adapter or HTTP endpoint."""

    id: str = "shophelper-local"
    adapter: str = "shophelper-local"
    url: str | None = None
    endpoint_url: str | None = None
    mode: str = "evaluation_only"
    timeout_seconds: float = 30.0
    request_template: dict[str, Any] | None = None
    response_json_path: str = "response"
    headers: dict[str, str] = Field(default_factory=dict)

    @property
    def resolved_url(self) -> str | None:
        return self.url or self.endpoint_url

    @property
    def is_http(self) -> bool:
        url = self.resolved_url or self.id
        return (
            self.adapter == "http"
            or (isinstance(url, str) and (url.startswith(("http://", "https://"))))
        )


class BudgetConfig(BaseModel):
    """Execution budgets and rate limits for regression scanning."""

    max_cases: int = Field(default=10, ge=1)
    max_attempts_per_attack: int = Field(default=1, ge=1)
    max_model_calls: int = Field(default=0, ge=0)
    max_total_tokens: int = Field(default=10_000, ge=0)
    per_call_timeout_seconds: float = Field(default=5.0, gt=0)
    scan_timeout_seconds: float = Field(default=60.0, gt=0)
    concurrency_limit: int = Field(default=1, ge=1)


class RavenConfigFile(BaseModel):
    """Declarative root configuration model for raven.yaml."""

    version: str = "1"
    target: TargetConfig = Field(default_factory=TargetConfig)
    categories: list[str] | None = None
    suite: str | None = None
    regression_only: bool = False
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    max_cases: int | None = None
    fail_on: str = "high"
    fail_on_breach: bool = True
    output: str = "text"

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, v: str) -> str:
        norm = (v or "high").strip().lower()
        if norm not in SEVERITY_LEVELS:
            allowed = ", ".join(SEVERITY_LEVELS.keys())
            raise ValueError(f"Invalid fail_on threshold '{v}'. Must be one of: {allowed}")
        return norm

    @field_validator("output")
    @classmethod
    def validate_output(cls, v: str) -> str:
        norm = (v or "text").strip().lower()
        allowed = {"text", "json", "sarif", "junit"}
        if norm not in allowed:
            raise ValueError(f"Invalid output format '{v}'. Must be one of: {', '.join(sorted(allowed))}")
        return norm

    @model_validator(mode="before")
    @classmethod
    def preprocess_config(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Allow target: "shophelper-local" or target: "https://..."
        target_raw = data.get("target")
        if isinstance(target_raw, str):
            is_url = target_raw.startswith(("http://", "https://"))
            data["target"] = {
                "id": target_raw,
                "adapter": "http" if is_url else target_raw,
                "url": target_raw if is_url else None,
            }
        elif isinstance(target_raw, dict):
            # Check if url / endpoint_url is set or id is a URL
            target_dict = dict(target_raw)
            url = target_dict.get("url") or target_dict.get("endpoint_url")
            if url and not target_dict.get("adapter"):
                target_dict["adapter"] = "http"
            if url and not target_dict.get("id"):
                target_dict["id"] = url
            data["target"] = target_dict

        # Support top-level target_url / url shorthand
        top_url = data.get("target_url") or data.get("url")
        if top_url:
            current_target = data.get("target") or {}
            if isinstance(current_target, dict):
                current_target["url"] = top_url
                current_target["adapter"] = "http"
                if not current_target.get("id") or current_target.get("id") == "shophelper-local":
                    current_target["id"] = top_url
                data["target"] = current_target

        # Sync top-level max_cases with budget.max_cases if specified
        if "max_cases" in data and data["max_cases"] is not None:
            budget_raw = data.get("budget") or {}
            if isinstance(budget_raw, dict) and "max_cases" not in budget_raw:
                budget_raw["max_cases"] = data["max_cases"]
                data["budget"] = budget_raw

        return data


def find_config_file(start_dir: Path | str | None = None) -> Path | None:
    """Search for raven.yaml, raven.yml, .raven.yaml, or .raven.yml in the target directory."""
    base = Path(start_dir).resolve() if start_dir else Path.cwd()
    for fname in CONFIG_FILENAMES:
        candidate = base / fname
        if candidate.is_file():
            return candidate
    return None


def load_config_file(path: Path | str | None = None) -> RavenConfigFile | None:
    """Load and validate raven.yaml configuration file.

    If path is provided, it must exist or FileNotFoundError is raised.
    If path is None, auto-searches the current directory for CONFIG_FILENAMES.
    Returns None if no config file is found and path was None.
    Raises RavenConfigError if the file contains invalid YAML or fails validation.
    """
    config_path: Path | None = None

    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        config_path = p
    else:
        config_path = find_config_file()

    if config_path is None:
        return None

    try:
        text = config_path.read_text(encoding="utf-8")
        if not text.strip():
            return RavenConfigFile()
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RavenConfigError(f"Malformed YAML in '{config_path}': {exc}") from exc
    except OSError as exc:
        raise RavenConfigError(f"Could not read config file '{config_path}': {exc}") from exc

    if not isinstance(parsed, dict):
        raise RavenConfigError(f"Configuration root in '{config_path}' must be a mapping/dict, got {type(parsed).__name__}")

    try:
        return RavenConfigFile.model_validate(parsed)
    except Exception as exc:
        raise RavenConfigError(f"Validation error in '{config_path}': {exc}") from exc


def should_fail_on_severity(
    verdicts: list[Any],
    threshold: str = "high",
    fail_on_breach: bool = True,
) -> bool:
    """Determine whether any breach verdict meets or exceeds the severity threshold.

    Threshold hierarchy:
      critical (4) > high (3) > medium (2) > low (1) > none (0)

    Returns True if an exit code 1 should be triggered, False otherwise.
    """
    if not fail_on_breach:
        return False

    norm_threshold = (threshold or "high").strip().lower()
    if norm_threshold == "none":
        return False

    min_weight = SEVERITY_LEVELS.get(norm_threshold, 3)

    for item in verdicts:
        # Expected tuple shape from SecurityRegressionRunner: (case, attempt, verdict, transcript)
        case = item[0]
        verdict = item[2]

        if verdict.final_label in (FindingLabel.CONFIRMED_FAILURE, FindingLabel.LIKELY_FAILURE):
            sev_val = getattr(case, "severity", Severity.HIGH)
            sev_str = (sev_val.value if hasattr(sev_val, "value") else str(sev_val)).lower()
            weight = SEVERITY_LEVELS.get(sev_str, 2)
            if weight >= min_weight:
                return True

    return False
