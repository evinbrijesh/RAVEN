"""Canonical JSON renderer (ADR 0001).

JSON is the canonical projection: it renders the validated document as-is
with no added or removed facts.
"""

from __future__ import annotations

import json

from app.domain.report import ReportDocument


def render_json(document: ReportDocument) -> str:
    """Render the canonical JSON artifact text."""
    return json.dumps(document.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
