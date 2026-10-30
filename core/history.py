from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DEFAULT_HISTORY_PATH = Path(__file__).resolve().parent.parent / "reports" / "recent_targets.json"


class RecentTargetStore:
    """Track the last N targets scanned by the application."""

    def __init__(self, path: str | Path = DEFAULT_HISTORY_PATH, limit: int = 5):
        self.path = Path(path)
        self.limit = max(1, int(limit))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"targets": []}
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("targets", []), list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return {"targets": []}

    def _save(self, data: Dict[str, Any]) -> None:
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    def add_target(
        self,
        target: str,
        scan_mode: str = "quick",
        status: str = "success",
        source: str = "scan",
    ) -> List[str]:
        cleaned = str(target or "").strip()
        if not cleaned:
            return self.get_recent()

        data = self._load()
        items: List[Dict[str, Any]] = data.get("targets", [])

        items = [item for item in items if str(item.get("target", "")).strip() != cleaned]
        record = {
            "target": cleaned,
            "scan_mode": str(scan_mode or "quick"),
            "status": str(status or "success"),
            "source": str(source or "scan"),
            "last_used": datetime.now(timezone.utc).isoformat(),
        }
        items.insert(0, record)
        data["targets"] = items[: self.limit]
        self._save(data)
        return self.get_recent()

    def get_recent(self) -> List[str]:
        data = self._load()
        items = data.get("targets", [])
        return [str(item.get("target", "")).strip() for item in items if str(item.get("target", "")).strip()]

    def clear(self) -> None:
        self._save({"targets": []})

    def __len__(self) -> int:
        return len(self.get_recent())


if __name__ == "__main__":
    store = RecentTargetStore()
    print(store.get_recent())
