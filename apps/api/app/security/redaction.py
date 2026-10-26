"""Deterministic redaction pipeline before persistence and external telemetry.

Rule 10 (docs/CLAUDE.md): never log API keys or raw sensitive headers.
Rule 4: fixtures contain synthetic canaries/PII only — but even synthetic
sensitive markers are redacted from logs, telemetry paths, and transcripts before storage.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.domain.entities import Transcript

# Patterns are applied in strict deterministic order.
# Each entry is (label, compiled_pattern).
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # 1. Authorization headers and bearer/basic tokens
    (
        "authorization_header",
        re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer\s+|basic\s+|token\s+)?\S+"),
    ),
    (
        "authorization_header",
        re.compile(r"(?i)\b(?:x-api-key|x-auth-token)\s*:\s*\S+"),
    ),
    (
        "authorization_header",
        re.compile(r"(?i)\b(?:Bearer\s+[A-Za-z0-9._\-~+/]+=*|Basic\s+[A-Za-z0-9+/=]{8,})"),
    ),
    # 2. Known API key signatures
    (
        "api_key",
        re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{8,})"),
    ),
    (
        "api_key",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,})\b"),
    ),
    (
        "api_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "api_key",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "api_key",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_.\-~+/]{8,})['\"]?"),
    ),
    # 3. PII - Emails
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    ),
    # 4. PII - Phone numbers
    (
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
    ),
    (
        "phone",
        re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),
    ),
    # 5. PII - Social Security Numbers (SSN)
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    # 6. PII - Payment cards (13 to 16 digits, with optional spaces/dashes)
    (
        "card",
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    ),
    # 7. PII - IPv4 addresses
    (
        "ip_address",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    ),
)

# Payload keys whose values must never reach storage or report artifacts,
# regardless of whether the value matches a regex pattern above.
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "x-api-key",
        "authorization",
        "authorization_header",
        "proxy-authorization",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "canary_token",
    }
)


class RedactionPipeline:
    """Deterministic redaction pipeline to sanitize credentials and PII.

    Guarantees:
    - Pure and deterministic: same input string produces identical redacted output.
    - Patterns are ordered by specificity to prevent partial-token mismatches.
    - Redacts strings, mappings, and structured Transcript models before storage.
    """

    def __init__(self, patterns: tuple[tuple[str, re.Pattern[str]], ...] = _PATTERNS) -> None:
        self._patterns = patterns

    def redact(self, text: str) -> str:
        """Deterministically sanitize sensitive patterns from a string."""
        if not text:
            return text
        redacted = text
        for name, pattern in self._patterns:
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
        return redacted

    def redact_mapping(self, payload: dict[str, object]) -> dict[str, object]:
        """Redact string values in a flat payload dictionary."""
        return {
            key: self.redact(value) if isinstance(value, str) else value
            for key, value in payload.items()
        }

    def redact_payload(self, payload: Any) -> Any:
        """Recursively redact nested JSON-like structures (dicts, lists, primitives)."""
        if isinstance(payload, str):
            return self.redact(payload)
        if isinstance(payload, dict):
            out: dict[str, Any] = {}
            for key, value in payload.items():
                k_lower = str(key).lower()
                if k_lower in SENSITIVE_KEYS:
                    out[key] = f"[REDACTED:{k_lower}]"
                else:
                    out[key] = self.redact_payload(value)
            return out
        if isinstance(payload, list):
            return [self.redact_payload(item) for item in payload]
        return payload

    def redact_transcript(self, transcript: Transcript) -> Transcript:
        """Sanitize an in-memory transcript before storage.

        Redacts content and tool arguments across all messages while preserving
        roles and structure.
        """
        from app.domain.entities import Transcript as TranscriptEntity
        from app.domain.entities import TranscriptMessage as MsgEntity

        sanitized_messages: list[MsgEntity] = []
        for msg in transcript.messages:
            sanitized_content = self.redact(msg.content)

            sanitized_tool_args = msg.tool_args_json
            if sanitized_tool_args:
                try:
                    parsed_args = json.loads(sanitized_tool_args)
                    sanitized_args = self.redact_payload(parsed_args)
                    sanitized_tool_args = json.dumps(sanitized_args, separators=(",", ":"))
                except (json.JSONDecodeError, ValueError, TypeError):
                    sanitized_tool_args = self.redact(sanitized_tool_args)

            sanitized_messages.append(
                MsgEntity(
                    role=msg.role,
                    content=sanitized_content,
                    tool_name=msg.tool_name,
                    tool_args_json=sanitized_tool_args,
                )
            )

        return TranscriptEntity(
            transcript_id=transcript.transcript_id,
            messages=sanitized_messages,
        )


# Global default pipeline instance
_DEFAULT_PIPELINE = RedactionPipeline()


def redact(text: str) -> str:
    """Redact known sensitive patterns. Applied before logging/telemetry."""
    return _DEFAULT_PIPELINE.redact(text)


def redact_mapping(payload: dict[str, object]) -> dict[str, object]:
    """Redact all string values in a flat payload (non-recursive by design)."""
    return _DEFAULT_PIPELINE.redact_mapping(payload)


def redact_payload(payload: Any) -> Any:
    """Recursively redact sensitive strings and keys in any JSON-serializable structure."""
    return _DEFAULT_PIPELINE.redact_payload(payload)


def redact_transcript(transcript: Transcript) -> Transcript:
    """Sanitize all messages in a transcript before database persistence."""
    return _DEFAULT_PIPELINE.redact_transcript(transcript)
