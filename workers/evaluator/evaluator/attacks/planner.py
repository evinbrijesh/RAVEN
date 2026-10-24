"""Attack planner: selects cases from the versioned catalog only.

The planner cannot invent arbitrary external actions (docs/ARCHITECTURE.md §3).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from app.domain.entities import AttackCase
from app.domain.enums import AttackCategory, Severity
from app.domain.errors import RavenError


class CatalogMissing(RavenError):
    code = "CATALOG_MISSING"


def catalog_dir() -> Path:
    override = os.environ.get("RAVEN_CATALOG_DIR")
    if override:
        return Path(override)
    # evaluator/attacks/planner.py -> evaluator(pkg) -> evaluator(project) -> workers -> RAVEN
    return Path(__file__).resolve().parents[3] / "packages" / "attack-catalog"


def load_attack_cases(categories: list[str] | None = None, limit: int | None = None) -> list[AttackCase]:
    path = catalog_dir() / "attacks" / "attacks-v1.json"
    if not path.exists():
        raise CatalogMissing(f"Attack catalog not found at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = [AttackCase.model_validate(c) for c in data["attack_cases"]]
    if categories:
        wanted = {AttackCategory(c) for c in categories}
        cases = [c for c in cases if c.category in wanted]
    if limit is not None:
        cases = cases[:limit]
    return cases


def load_benign_cases(limit: int | None = None) -> list:
    path = catalog_dir() / "benign" / "benign-v1.json"
    if not path.exists():
        raise CatalogMissing(f"Benign catalog not found at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    from app.domain.entities import BenignCase

    cases = [BenignCase.model_validate(c) for c in data["benign_cases"]]
    if limit is not None:
        cases = cases[:limit]
    return cases


class AttackPlanner:
    """Selects the approved case list for a scan, respecting the budget."""

    def select(self, categories: list[str], max_cases: int) -> list[AttackCase]:
        return load_attack_cases(categories or None, limit=max_cases)
