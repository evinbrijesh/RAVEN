"""Redaction before persistence and external telemetry.

Rule 10 (docs/CLAUDE.md): never log API keys or raw sensitive headers.
Rule 4: fixtures contain synthetic canaries/PII only — but even synthetic
sensitive markers are redacted from logs and telemetry paths.
"""

from __future__ import annotations

import re

# Patterns are intentionally conservative; extend as new fixture data lands.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key", re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]{8,})")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("authorization_header", re.compile(r"(?i)authorization:\s*\S+")),
)


def redact(text: str) -> str:
    """Redact known sensitive patterns. Applied before logging/telemetry."""
    redacted = text
    for name, pattern in _PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted


def redact_mapping(payload: dict[str, object]) -> dict[str, object]:
    """Redact all string values in a flat payload (non-recursive by design)."""
    return {
        key: redact(value) if isinstance(value, str) else value
        for key, value in payload.items()
    }
