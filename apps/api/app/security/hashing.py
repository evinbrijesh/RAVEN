"""Cryptographic SHA-256 run artifact hashing.

Provides deterministic, tamper-evident content hashing for run artifacts,
transcripts, and evidence outputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def compute_sha256(data: str | bytes) -> str:
    """Compute the hexadecimal SHA-256 digest of string or raw bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def compute_run_artifact_hash(artifact: Any) -> str:
    """Compute a deterministic cryptographic SHA-256 digest for any run artifact.

    Supports:
    - str / bytes: direct SHA-256
    - BaseModel: serialized to dict, sorted keys canonical JSON
    - dict / list: sorted keys canonical JSON with no whitespace
    """
    if isinstance(artifact, (str, bytes)):
        return compute_sha256(artifact)

    if isinstance(artifact, BaseModel):
        payload = artifact.model_dump(mode="json")
    elif isinstance(artifact, (dict, list)):
        payload = artifact
    else:
        payload = str(artifact)

    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return compute_sha256(canonical_json)


def verify_run_artifact_hash(artifact: Any, expected_sha256: str) -> bool:
    """Verify that an artifact matches an expected cryptographic SHA-256 digest."""
    if not expected_sha256:
        return False
    actual = compute_run_artifact_hash(artifact)
    return actual.lower() == expected_sha256.lower()


def hash_transcript(transcript: Any) -> str:
    """Compute cryptographic SHA-256 hash for a transcript entity."""
    return compute_run_artifact_hash(transcript)
