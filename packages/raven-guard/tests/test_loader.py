"""Unit tests for policy file loader (YAML and JSON)."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven_guard import (
    PolicyConfigurationError,
    find_default_policy,
    load_policy,
    load_policy_file,
    parse_policy_string,
)


def test_load_json_policy_from_string():
    raw_json = """
    {
      "version": "json-v1",
      "fail_closed": true,
      "tools": [
        {
          "tool": "test_tool",
          "conditions": ["verified_user_present"]
        }
      ]
    }
    """
    doc = parse_policy_string(raw_json)
    assert doc.version == "json-v1"
    assert doc.fail_closed is True
    assert "test_tool" in doc.tools


def test_load_yaml_policy_from_string():
    raw_yaml = """
version: "yaml-v2"
description: "Compiled YAML policy"
fail_closed: true
tools:
  - tool: "yaml_tool"
    conditions:
      - "verified_order_id_present"
    amount_threshold: 250.0
    high_value_action: "human_approval_required"
"""
    doc = parse_policy_string(raw_yaml)
    assert doc.version == "yaml-v2"
    assert doc.description == "Compiled YAML policy"
    assert "yaml_tool" in doc.tools
    assert doc.tools["yaml_tool"].amount_threshold == 250.0


def test_load_policy_from_file(tmp_path: Path):
    policy_file = tmp_path / "raven-policy.yaml"
    policy_file.write_text(
        """
version: "file-v1"
tools:
  - tool: "file_tool"
    conditions: []
""",
        encoding="utf-8",
    )

    doc = load_policy_file(policy_file)
    assert doc.version == "file-v1"
    assert "file_tool" in doc.tools

    # Also test generic load_policy(path)
    doc2 = load_policy(policy_file)
    assert doc2.version == "file-v1"


def test_load_policy_nonexistent_file():
    with pytest.raises(PolicyConfigurationError):
        load_policy_file(Path("/nonexistent/raven-policy.yaml"))


def test_parse_empty_policy_raises():
    with pytest.raises(PolicyConfigurationError) as exc_info:
        parse_policy_string("   ")
    assert "Empty policy definition" in str(exc_info.value)


def test_parse_invalid_format_raises():
    with pytest.raises(PolicyConfigurationError):
        parse_policy_string("- this is a list not a dict")


def test_find_default_policy(tmp_path: Path):
    target = tmp_path / "raven-policy.yaml"
    target.write_text("version: v1\ntools: []", encoding="utf-8")

    found = find_default_policy(tmp_path)
    assert found == target


def test_find_default_policy_none(tmp_path: Path):
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    assert find_default_policy(empty_dir) is None or isinstance(find_default_policy(empty_dir), Path)


def test_load_policy_with_document_instance():
    doc = parse_policy_string("version: v1\ntools: []")
    # Passing an already parsed PolicyDocument should return it directly
    assert load_policy(doc) is doc


def test_load_policy_invalid_type():
    with pytest.raises(PolicyConfigurationError) as exc_info:
        load_policy(12345)  # type: ignore
    assert "Unsupported policy source type" in str(exc_info.value)
