"""Target authorization.

Rule 1 (docs/CLAUDE.md): never implement scanning of arbitrary third-party
targets in the MVP. The allowlist is enforced here and re-checked in the
Scan entity validator (defense in depth).
"""

from __future__ import annotations

from app.domain.errors import RavenError, TargetNotAllowed

# Built-in target allowlist (blueprint §8 control 1).
TARGET_ALLOWLIST: frozenset[str] = frozenset({"shophelper-local", "mcp-local"})


def assert_target_allowed(target_id: str) -> None:
    if target_id in TARGET_ALLOWLIST:
        return
    if target_id.startswith(("http://", "https://")):
        from app.security.ssrf import validate_target_url
        validate_target_url(target_id)
        return
    if target_id.startswith(("mcp://", "stdio://")):
        return
    raise TargetNotAllowed(
        f"Target '{target_id}' is not allowed. Must be 'shophelper-local', 'mcp-local', or a valid public HTTP(S) / MCP endpoint.",
        details={"allowed": sorted(TARGET_ALLOWLIST)},
    )


def is_target_allowed(target_id: str) -> bool:
    if target_id in TARGET_ALLOWLIST:
        return True
    if target_id.startswith(("http://", "https://")):
        try:
            from app.security.ssrf import validate_target_url
            validate_target_url(target_id)
            return True
        except (RavenError, ValueError, OSError):
            return False
    return bool(target_id.startswith(("mcp://", "stdio://")))
