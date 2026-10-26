"""HTTP Target Adapter (Mode A).

Enables RAVEN to evaluate live HTTP endpoints while strictly enforcing:
1. SSRF prevention (blocking private/loopback/metadata addresses).
2. Mandatory consent header ('X-Raven-Scan-Consent: true').
3. Per-call timeouts and rate limits.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from app.domain.entities import (
    PolicyCandidate,
    TargetProfile,
    TargetRequest,
    TargetResponse,
)
from app.domain.errors import RavenError
from app.security.ssrf import assert_consent_header, validate_target_url

from evaluator.targets.base import TargetAdapter


class TargetHardeningNotSupported(RavenError):
    code = "TARGET_HARDENING_NOT_SUPPORTED"


class HttpTargetAdapter(TargetAdapter):
    """Adapter for testing external HTTP LLM endpoints."""

    def __init__(
        self,
        endpoint_url: str,
        headers: dict[str, str] | None = None,
        request_template: dict[str, Any] | None = None,
        response_json_path: str = "response",
        timeout_seconds: float = 30.0,
        allow_local_dev: bool = False,
        mode: str = "evaluation_only",
    ) -> None:
        self.endpoint_url = endpoint_url
        self.headers = headers or {}
        self.request_template = request_template or {"message": "{prompt}"}
        self.response_json_path = response_json_path
        self.timeout_seconds = timeout_seconds
        self.mode = mode

        # Step 0: Pre-flight security verification
        validate_target_url(self.endpoint_url, allow_local_in_dev=allow_local_dev)
        assert_consent_header(self.headers)

        self._temporary_prompt_patch: str | None = None
        self._temporary_policy: PolicyCandidate | None = None

    async def profile(self) -> TargetProfile:
        import hashlib
        return TargetProfile(
            target_id=self.endpoint_url,
            version="live",
            system_prompt_hash=hashlib.sha256(self.endpoint_url.encode()).hexdigest()[:16],
            tools=[],
            canary_token="",
            refusal_behavior="http_endpoint",
            notes=["External HTTP target; dynamic evaluation."],
        )

    async def invoke(self, request: TargetRequest) -> TargetResponse:
        # Interpolate prompt into template
        body = {}
        for k, v in self.request_template.items():
            if isinstance(v, str) and "{prompt}" in v:
                body[k] = v.replace("{prompt}", request.message)
            else:
                body[k] = v

        if "message" not in body and "{prompt}" not in str(self.request_template):
            body["message"] = request.message

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(
                self.endpoint_url,
                json=body,
                headers=self.headers,
            )
            resp.raise_for_status()
            data = resp.json()

        # Extract reply text from path
        reply_text = ""
        if isinstance(data, dict):
            reply_text = str(data.get(self.response_json_path, data.get("message", json.dumps(data))))
        else:
            reply_text = str(data)

        return TargetResponse(
            scan_id=request.scan_id,
            run_id=request.run_id,
            message=reply_text,
            tool_calls=[],
        )

    async def reset(self) -> None:
        self._temporary_prompt_patch = None
        self._temporary_policy = None

    async def apply_temporary_policy(
        self, policy: PolicyCandidate | None, prompt_patch: str | None = None
    ) -> None:
        if self.mode == "evaluation_only":
            raise TargetHardeningNotSupported(
                "External HTTP target is in 'evaluation_only' mode. "
                "Hardening diffs cannot be applied to remote applications without an authorized staging contract."
            )
        self._temporary_policy = policy
        self._temporary_prompt_patch = prompt_patch

    async def clear_temporary_policy(self) -> None:
        await self.reset()
