"""Backward-compatible re-export of scan endpoints.

Canonical implementation lives in `app.api.endpoints.scans`.
"""

from app.api.endpoints.scans import (
    _http_error,
    approve_hardening,
    create_scan,
    get_proposal,
    get_scan,
    list_scans,
    router,
    verify_artifact,
)

__all__ = [
    "_http_error",
    "approve_hardening",
    "create_scan",
    "get_proposal",
    "get_scan",
    "list_scans",
    "router",
    "verify_artifact",
]
