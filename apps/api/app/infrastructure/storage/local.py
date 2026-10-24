"""Local evidence artifact storage.

MVP stores report artifacts on the local volume (blueprint §2). The interface
is storage-agnostic so S3-compatible storage can replace it later.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LocalEvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, scan_id: str, name: str, content: str) -> Path:
        scan_dir = self.root / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        path = scan_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def save_json(self, scan_id: str, name: str, payload: dict[str, Any]) -> Path:
        return self.save(scan_id, name, json.dumps(payload, indent=2, default=str))

    def load(self, scan_id: str, name: str) -> str | None:
        path = self.root / scan_id / name
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")
