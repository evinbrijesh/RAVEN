"""SSRF protection and HTTP target validation.

Ensures that external HTTP targets:
1. Do not target private/loopback/link-local/multicast IP addresses (SSRF defense).
2. Use valid http or https schemes.
3. Require the explicit consent header 'X-Raven-Scan-Consent: true'.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.domain.errors import RavenError


class SSRFValidationError(RavenError):
    code = "SSRF_VALIDATION_FAILED"


class MissingConsentError(RavenError):
    code = "MISSING_SCAN_CONSENT"


def validate_target_url(url: str, allow_local_in_dev: bool = False) -> None:
    """Validate that the target URL is safe and not resolving to a private/internal network."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SSRFValidationError(f"Invalid URL scheme '{parsed.scheme}'. Must be http or https.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Target URL must have a valid hostname.")

    if allow_local_in_dev:
        return

    # Check for direct IP address literals
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise SSRFValidationError(
                f"Target IP {hostname} is a private, loopback, or reserved network address."
            )
        return
    except ValueError:
        pass

    # Resolve domain to IP and check
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise SSRFValidationError(
                    f"Target host '{hostname}' resolves to private/reserved IP {ip_str}."
                )
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Could not resolve hostname '{hostname}': {exc}") from exc


def assert_consent_header(headers: dict[str, str]) -> None:
    """Verify that the caller provided the required authorization consent header."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    consent = lower_headers.get("x-raven-scan-consent", "").strip().lower()
    if consent != "true":
        raise MissingConsentError(
            "External HTTP targets require header 'X-Raven-Scan-Consent: true' to verify authorization."
        )
