"""Attack catalog access for the API layer.

The catalog (packages/attack-catalog) is the only source of attack cases;
promotions and reports must never invent cases. Mirrors the worker's
evaluator.attacks.planner path resolution.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from app.domain.entities import AttackCase
from app.domain.errors import RavenError


class CatalogMissing(RavenError):
    code = "CATALOG_MISSING"


def catalog_dir() -> Path:
    override = os.environ.get("RAVEN_CATALOG_DIR")
    if override:
        return Path(override)
    # catalog.py -> application -> app -> api -> apps -> RAVEN root
    return Path(__file__).resolve().parents[4] / "packages" / "attack-catalog"


def load_catalog_cases() -> list[AttackCase]:
    path = catalog_dir() / "attacks" / "attacks-v1.json"
    if not path.exists():
        raise CatalogMissing(f"Attack catalog not found at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return [AttackCase.model_validate(case) for case in data["attack_cases"]]


def load_catalog_case(attack_id: str) -> AttackCase | None:
    """Return the versioned catalog case for an attack id, or None."""
    return next((case for case in load_catalog_cases() if case.id == attack_id), None)
