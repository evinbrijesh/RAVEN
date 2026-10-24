"""Shared worker test fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))


@pytest.fixture()
def fixtures_path(tmp_path: Path) -> Path:
    """Copy the real fixtures so tests never mutate repo data."""
    src = REPO_ROOT / "fixtures" / "shophelper"
    dst = tmp_path / "shophelper"
    dst.mkdir()
    for f in src.iterdir():
        (dst / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


@pytest.fixture()
def catalog_path(tmp_path: Path) -> Path:
    """Point the planner at the real catalog (read-only)."""
    return REPO_ROOT / "packages" / "attack-catalog"


@pytest.fixture()
def repos(tmp_path: Path):
    from app.infrastructure.db.repository import Repositories
    from app.infrastructure.db.sqlite import Database

    db = Database(tmp_path / "test.db")
    db.migrate()
    return Repositories(db)


@pytest.fixture()
def customers(fixtures_path: Path) -> list[dict]:
    return json.loads((fixtures_path / "fake-customers.json").read_text(encoding="utf-8"))
