"""Target factory and execution core tests (P0.1, P0.2, P0.4, P0.5)."""

from __future__ import annotations

import pytest
from app.domain.entities import Scan, ScanConfig
from app.domain.errors import TargetNotAllowed
from app.domain.value_objects import TargetRef

from evaluator.targets.factory import build_target
from evaluator.targets.shophelper import ShopHelperLocalAdapter


def test_build_target_shophelper_local() -> None:
    scan = Scan(
        scan_id="scan_test_1",
        target=TargetRef(target_id="shophelper-local", kind="local"),
        config=ScanConfig(target_id="shophelper-local"),
    )
    adapter = build_target(scan)
    assert isinstance(adapter, ShopHelperLocalAdapter)


def test_build_target_unsupported_scheme() -> None:
    # Defense-in-depth: Scan validator catches disallowed target immediately
    with pytest.raises(TargetNotAllowed):
        Scan(
            scan_id="scan_test_2",
            target=TargetRef(target_id="ftp://attacker.com", kind="ftp"),
            config=ScanConfig(target_id="shophelper-local"),
        )


def test_target_ref_immutability_and_hash() -> None:
    ref1 = TargetRef(target_id="shophelper-local", kind="local")
    ref2 = TargetRef(target_id="shophelper-local", kind="local")
    assert ref1.config_hash == ref2.config_hash
    assert len(ref1.config_hash) > 0

    ref_http = TargetRef(target_id="https://api.example.com/chat", kind="http")
    assert ref_http.config_hash != ref1.config_hash
