"""Report-time redaction and truncation (ADR 0001 decision 5).

Raw evidence stays in the database. Everything that leaves through a report
artifact passes through here first: canary tokens (dynamic, from the target
profile), API keys, authorization headers, email/phone/card patterns, and
transcript truncation.
"""

from __future__ import annotations

from typing import Any

from app.security.redaction import SENSITIVE_KEYS, redact

CANARY_PLACEHOLDER = "[REDACTED:canary]"
MAX_MESSAGE_CHARS = 4_000
MAX_EVIDENCE_CHARS = 12_000

REDACTED_FIELDS = [
    "canary_token",
    "api_key",
    "authorization_header",
    "email",
    "phone",
    "card",
]


def redact_text(text: str, canary_token: str = "") -> str:
    """Redact known sensitive patterns plus the scan's own canary token."""
    redacted = text
    if canary_token and canary_token in redacted:
        redacted = redacted.replace(canary_token, CANARY_PLACEHOLDER)
    return redact(redacted)


def redact_payload(payload: Any, canary_token: str = "") -> Any:
    """Recursively redact every string in a JSON-serializable structure.

    Unlike app.security.redaction.redact_mapping (flat by design), report
    evidence is nested and must be walked in full.
    """
    if isinstance(payload, str):
        return redact_text(payload, canary_token)
    if isinstance(payload, dict):
        return {
            key: redact_payload(value, canary_token)
            for key, value in payload.items()
            # Never emit sensitive-keyed values (canary, api keys, tokens,
            # secrets), even if one sneaks into a payload.
            if str(key).lower() not in SENSITIVE_KEYS
        }
    if isinstance(payload, list):
        return [redact_payload(item, canary_token) for item in payload]
    return payload


def truncate_transcripts(payload: Any) -> Any:
    """Walk a report payload and truncate every embedded transcript bundle.

    Applies the per-message and per-bundle caps to any dict shaped like a
    ReportTranscript (has a `messages` list and a `truncated` flag), keeping
    the advertised `transcript_excerpt_chars` honest.
    """
    if isinstance(payload, dict):
        messages = payload.get("messages")
        if isinstance(messages, list) and "truncated" in payload:
            truncated_messages, truncated = truncate_messages(messages)
            return {
                **payload,
                "messages": [
                    truncate_transcripts(message) for message in truncated_messages
                ],
                "truncated": truncated or bool(payload.get("truncated")),
            }
        return {key: truncate_transcripts(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [truncate_transcripts(item) for item in payload]
    return payload


def truncate_messages(
    messages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """Truncate transcript messages to the report excerpt budget.

    Returns (messages, truncated). Per-message cap is MAX_MESSAGE_CHARS; the
    whole bundle is capped at MAX_EVIDENCE_CHARS.
    """
    truncated = False
    out: list[dict[str, Any]] = []
    total = 0
    for message in messages:
        content = str(message.get("content", ""))
        if len(content) > MAX_MESSAGE_CHARS:
            content = content[:MAX_MESSAGE_CHARS]
            truncated = True
        if total + len(content) > MAX_EVIDENCE_CHARS:
            remaining = max(0, MAX_EVIDENCE_CHARS - total)
            if remaining == 0:
                truncated = True
                break
            content = content[:remaining]
            truncated = True
        total += len(content)
        out.append({**message, "content": content})
    return out, truncated
