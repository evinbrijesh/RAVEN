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
)

__all__ = [
    "router",
    "create_scan",
    "list_scans",
    "get_scan",
    "approve_hardening",
    "get_proposal",
    "_http_error",
]
