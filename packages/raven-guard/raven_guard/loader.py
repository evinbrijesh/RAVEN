"""Policy file loader supporting JSON and YAML formats compiled by RAVEN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from raven_guard.errors import PolicyConfigurationError
from raven_guard.models import PolicyDocument

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


DEFAULT_POLICY_NAMES = (
    "raven-policy.yaml",
    "raven-policy.yml",
    "raven-policy.json",
    ".raven/policy.yaml",
    ".raven/policy.json",
)


def load_policy(source: str | Path | dict[str, Any] | PolicyDocument) -> PolicyDocument:
    """Load and validate a PolicyDocument from a file path, YAML/JSON text, dict, or document."""
    if isinstance(source, PolicyDocument):
        return source

    if isinstance(source, dict):
        return PolicyDocument.from_dict(source)

    if isinstance(source, Path) or (
        isinstance(source, str)
        and (source.endswith((".yaml", ".yml", ".json")) or "\n" not in source)
    ):
        path = Path(source)
        if path.is_file():
            return load_policy_file(path)

    # Treat source as raw text (YAML or JSON)
    if isinstance(source, str):
        return parse_policy_string(source)

    raise PolicyConfigurationError(f"Unsupported policy source type: {type(source).__name__}")


def load_policy_file(path: str | Path) -> PolicyDocument:
    """Load a policy from a file path."""
    p = Path(path)
    if not p.is_file():
        raise PolicyConfigurationError(f"Policy file not found: {p}")

    content = p.read_text(encoding="utf-8")
    return parse_policy_string(content, filename=str(p))


def parse_policy_string(content: str, filename: str = "<string>") -> PolicyDocument:
    """Parse JSON or YAML string into a PolicyDocument."""
    text = content.strip()
    if not text:
        raise PolicyConfigurationError(f"Empty policy definition in {filename}")

    data: Any = None
    # If it starts with { or [, try JSON first
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as err:
            # Fall through to YAML if json decode fails
            if not HAS_YAML:
                raise PolicyConfigurationError(f"Invalid JSON policy in {filename}: {err}") from err

    if data is None:
        if HAS_YAML:
            try:
                data = yaml.safe_load(text)
            except Exception as err:
                raise PolicyConfigurationError(f"Failed to parse YAML policy in {filename}: {err}") from err
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as err:
                raise PolicyConfigurationError(
                    f"PyYAML is not installed and content is not valid JSON in {filename}: {err}"
                ) from err

    if not isinstance(data, dict):
        raise PolicyConfigurationError(f"Policy root must be an object/dict in {filename}, got {type(data).__name__}")

    return PolicyDocument.from_dict(data)


def find_default_policy(search_dir: Path | str | None = None) -> Path | None:
    """Searches current directory and parent directories for default policy files."""
    base = Path(search_dir) if search_dir else Path.cwd()
    current = base.resolve()

    # Search current and up to 3 parent directories
    for _ in range(4):
        for name in DEFAULT_POLICY_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if current.parent == current:
            break
        current = current.parent

    return None
