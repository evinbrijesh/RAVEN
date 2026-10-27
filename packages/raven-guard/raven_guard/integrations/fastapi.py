"""FastAPI and Starlette middleware for raven-guard context propagation and policy binding."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Sequence
from typing import Any

from raven_guard.context import security_context
from raven_guard.errors import ApprovalRequiredError, PolicyViolationError
from raven_guard.gateway import PolicyGateway
from raven_guard.models import SecurityContext

try:
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.types import ASGIApp
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    BaseHTTPMiddleware = object  # type: ignore
    Request = Any  # type: ignore
    ASGIApp = Any  # type: ignore
    RequestResponseEndpoint = Any  # type: ignore


class RavenGuardMiddleware(BaseHTTPMiddleware):
    """Starlette/FastAPI middleware for binding request claims to raven-guard SecurityContext.

    Intercepts HTTP requests, extracts user identity and claims from headers or JWT tokens,
    and sets the async contextvar for downstream tool executions and endpoint handlers.
    """

    def __init__(
        self,
        app: ASGIApp,
        gateway: PolicyGateway | None = None,
        claims_extractor: Callable[[Request], SecurityContext | dict[str, Any] | None] | None = None,
        extract_jwt: bool = True,
        jwt_header: str = "authorization",
        excluded_paths: Sequence[str] | None = None,
        catch_violations: bool = True,
    ) -> None:
        super().__init__(app)
        self.gateway = gateway
        self.claims_extractor = claims_extractor
        self.extract_jwt = extract_jwt
        self.jwt_header = jwt_header.lower()
        self.excluded_paths = set(
            excluded_paths or ("/health", "/ready", "/metrics", "/docs", "/openapi.json", "/favicon.ico")
        )
        self.catch_violations = catch_violations

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Any:
        path = request.url.path
        if path in self.excluded_paths:
            return await call_next(request)

        ctx = self._extract_security_context(request)

        # Attach context to request state
        request.state.security_context = ctx
        if self.gateway is not None:
            request.state.raven_gateway = self.gateway

        # Run downstream in active async context
        try:
            with security_context(ctx):
                response = await call_next(request)
                return response
        except ApprovalRequiredError as exc:
            if not self.catch_violations:
                raise
            return JSONResponse(
                status_code=403,
                content={
                    "error": "approval_required",
                    "code": "HUMAN_APPROVAL_REQUIRED",
                    "tool": exc.tool,
                    "reason": exc.reason,
                    "message": str(exc),
                },
            )
        except PolicyViolationError as exc:
            if not self.catch_violations:
                raise
            return JSONResponse(
                status_code=403,
                content={
                    "error": "policy_violation",
                    "code": "SECURITY_POLICY_VIOLATION",
                    "tool": exc.tool,
                    "reason": exc.reason,
                    "message": str(exc),
                },
            )

    def _extract_security_context(self, request: Request) -> SecurityContext:
        """Extracts claims from custom extractor, JWT bearer, or standard headers."""
        # 1. Custom extractor if provided
        if self.claims_extractor is not None:
            try:
                res = self.claims_extractor(request)
                if res is not None:
                    return SecurityContext.from_any(res)
            except (ValueError, TypeError, AttributeError, KeyError):
                pass

        headers = request.headers
        claims: dict[str, Any] = {}
        roles: list[str] = []

        # 2. JWT Bearer token claims extraction
        if self.extract_jwt:
            auth_header = headers.get(self.jwt_header, "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                jwt_claims = self._parse_jwt_payload(token)
                if jwt_claims:
                    claims.update(jwt_claims)
                    if "roles" in jwt_claims and isinstance(jwt_claims["roles"], list):
                        roles.extend(jwt_claims["roles"])
                    elif "role" in jwt_claims:
                        roles.append(str(jwt_claims["role"]))

        # 3. Standard HTTP Headers extraction
        user_id = headers.get("x-user-id") or headers.get("x-user") or claims.get("user_id") or claims.get("sub")
        tenant_id = headers.get("x-tenant-id") or headers.get("x-tenant") or claims.get("tenant_id")
        session_id = headers.get("x-session-id") or claims.get("session_id")
        order_id = headers.get("x-order-id") or claims.get("order_id")

        header_roles = headers.get("x-roles") or headers.get("x-role")
        if header_roles:
            for r in header_roles.split(","):
                r_clean = r.strip()
                if r_clean and r_clean not in roles:
                    roles.append(r_clean)

        verified_user_val = headers.get("x-verified-user", "").lower()
        verified_user = verified_user_val in ("true", "1", "yes") or bool(claims.get("verified_user", False))

        verified_order_val = headers.get("x-verified-order", headers.get("x-verified-order-id", "")).lower()
        verified_order = verified_order_val in ("true", "1", "yes") or bool(claims.get("verified_order_id", False))

        # Mirror core fields into claims dict
        if user_id:
            claims["user_id"] = user_id
        if tenant_id:
            claims["tenant_id"] = tenant_id
        if session_id:
            claims["session_id"] = session_id
        if order_id:
            claims["order_id"] = order_id

        return SecurityContext(
            verified_user=verified_user,
            verified_order_id=verified_order,
            user_id=user_id,
            order_id=order_id,
            roles=roles,
            session_id=session_id,
            claims=claims,
            extra={"tenant_id": tenant_id} if tenant_id else {},
        )

    @staticmethod
    def _parse_jwt_payload(token: str) -> dict[str, Any] | None:
        """Decodes JWT payload without requiring external cryptographic dependencies."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            payload_segment = parts[1]
            padded = payload_segment + "=" * (-len(payload_segment) % 4)
            data_bytes = base64.urlsafe_b64decode(padded)
            payload = json.loads(data_bytes)
            return payload if isinstance(payload, dict) else None
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None
