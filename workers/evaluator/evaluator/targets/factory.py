"""Target factory.

The single canonical factory for building target adapters based on the persisted,
immutable TargetRef specification in a Scan (P0.1 requirement).
"""

from __future__ import annotations

import os

from app.domain.entities import Scan
from app.domain.errors import TargetNotAllowed

from evaluator.targets.base import TargetAdapter


def build_target(scan: Scan, fixtures_path: str | None = None) -> TargetAdapter:
    """Build the target adapter for a scan.
    
    Acceptance criteria:
    - ShopHelper scans pass all tests via ShopHelperLocalAdapter.
    - External HTTP targets instantiate HttpTargetAdapter with SSRF protection and consent headers.
    - Unsupported target types raise TargetNotAllowed.
    - Never stores or logs raw secrets.
    """
    target = scan.target

    # Mode 1: Built-in local demo bot (ShopHelper)
    if target.target_id == "shophelper-local":
        from evaluator.targets.shophelper import ShopHelperLocalAdapter
        return ShopHelperLocalAdapter(fixtures_path=fixtures_path or None)

    # Mode 2: External HTTP Endpoint
    if target.kind == "http" or target.target_id.startswith("http://") or target.target_id.startswith("https://"):
        from evaluator.targets.http_adapter import HttpTargetAdapter

        endpoint = target.endpoint_url or target.target_id
        # Headers never contain raw secrets stored in DB; dynamically attach consent header
        headers = {"X-Raven-Scan-Consent": "true"}
        
        # If external target requires an auth bearer token, resolve it strictly from environment
        auth_env_var = os.environ.get("RAVEN_TARGET_AUTH_HEADER_ENV")
        if auth_env_var and auth_env_var in os.environ:
            headers["Authorization"] = f"Bearer {os.environ[auth_env_var]}"

        return HttpTargetAdapter(
            endpoint_url=endpoint,
            headers=headers,
            request_template=target.request_template or {"message": "{prompt}"},
            response_json_path=target.response_json_path or "response",
            timeout_seconds=target.timeout_seconds or 30.0,
            mode=getattr(target, "mode", "evaluation_only"),
        )

    # Mode 3: Model Context Protocol (MCP) Server
    if target.kind == "mcp" or target.target_id.startswith(("mcp://", "stdio://")) or target.target_id == "mcp-local":
        from evaluator.targets.mcp_adapter import McpTargetAdapter

        transport = "in_process"
        command = None
        if target.target_id.startswith("stdio://"):
            transport = "stdio"
            command = target.target_id.replace("stdio://", "").split()

        return McpTargetAdapter(
            target_id=target.target_id,
            transport=transport,
            command=command,
            endpoint_url=target.endpoint_url,
        )

    raise TargetNotAllowed(
        f"Unsupported target '{target.target_id}' with kind '{target.kind}'.",
        details={"allowed_targets": ["shophelper-local", "http://*", "https://*", "mcp://*", "stdio://*", "mcp-local"]},
    )
