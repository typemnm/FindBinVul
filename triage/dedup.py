from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from triage.normalize import normalize_stderr

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def dedup_key_for(crash_tag: Optional[str], stderr_text: str) -> str:
    if crash_tag:
        return f"tag:{crash_tag}"
    norm = normalize_stderr(stderr_text)
    return f"stderr:{sha256_text(norm)}"

@dataclass
class DedupHit:
    dedup_key: str
    is_new: bool
    representative: str
    count: int

class GlobalDedupIndex:
    """
    JSON file:
    {
      "version": 1,
      "updated_at": "...",
      "by_key": {
        "<dedup_key>": {"first_seen": "...", "representative": "...", "count": N}
      }
    }
    """
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, Any] = {"version": 1, "updated_at": utc_now_iso(), "by_key": {}}

    def load(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            return
        self.data = json.loads(self.path.read_text(encoding="utf-8"))

        if "by_key" not in self.data or not isinstance(self.data["by_key"], dict):
            raise ValueError(f"Invalid dedup index format: {self.path}")

    def save(self) -> None:
        self.data["updated_at"] = utc_now_iso()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def register(self, dedup_key: str, crash_relpath: str) -> DedupHit:
        by_key: dict[str, Any] = self.data.setdefault("by_key", {})
        entry = by_key.get(dedup_key)
        if entry is None:
            by_key[dedup_key] = {
                "first_seen": utc_now_iso(),
                "representative": crash_relpath,
                "count": 1,
            }
            return DedupHit(dedup_key=dedup_key, is_new=True, representative=crash_relpath, count=1)

        entry["count"] = int(entry.get("count", 0)) + 1
        return DedupHit(
            dedup_key=dedup_key,
            is_new=False,
            representative=str(entry.get("representative", "")),
            count=int(entry["count"]),
        )