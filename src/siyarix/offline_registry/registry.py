# SPDX-License-Identifier: AGPL-3.0-or-later

"""Response registry — loads, caches, and hot-reloads response entries."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_PACK = "responses.json"
_PACK_DIR = "responses"


@dataclass
class ResponseEntry:
    id: str
    priority: int
    triggers: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    template: str = ""
    match_threshold: float = 0.75
    locale: str = "en"
    metadata: dict[str, Any] = field(default_factory=dict)


def _load_single(path: Path) -> list[ResponseEntry]:
    """Parse a response pack JSON file and return entries."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Skipping %s: %s", path, exc)
        return []

    entries: list[ResponseEntry] = []
    for raw in data.get("responses", []):
        if not isinstance(raw, dict) or not raw.get("id"):
            continue
        entries.append(
            ResponseEntry(
                id=str(raw["id"]),
                priority=int(raw.get("priority", 50)),
                triggers=list(raw.get("triggers", [])),
                patterns=list(raw.get("patterns", [])),
                template=str(raw.get("template", "")),
                match_threshold=float(raw.get("match_threshold", 0.75)),
                locale=str(raw.get("locale", "en")),
                metadata=raw.get("metadata", {}),
            )
        )
    return entries


class ResponseRegistry:
    """Loads response packs and supports hot-reloading on file change."""

    def __init__(self, pack_dir: str | Path | None = None) -> None:
        self._pack_dir = Path(pack_dir) if pack_dir else Path(__file__).parent
        self._entries: list[ResponseEntry] = []
        self._mtime_map: dict[Path, float] = {}
        self._loaded = False

    def _discover_packs(self) -> list[Path]:
        packs: list[Path] = []

        default = self._pack_dir / _DEFAULT_PACK
        if default.exists():
            packs.append(default)

        subdir = self._pack_dir / _PACK_DIR
        if subdir.is_dir():
            for f in sorted(subdir.iterdir()):
                if f.suffix.lower() == ".json" and f.is_file():
                    packs.append(f)

        return packs

    def load(self, force: bool = False) -> None:
        """Load (or reload) all response packs."""
        entries: list[ResponseEntry] = []
        mtime_map: dict[Path, float] = {}

        for path in self._discover_packs():
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            mtime_map[path] = mtime
            entries.extend(_load_single(path))

        entries.sort(key=lambda e: e.priority, reverse=True)
        self._entries = entries
        self._mtime_map = mtime_map
        self._loaded = True
        logger.debug("Loaded %d response entries from %d packs", len(entries), len(mtime_map))

    def reload_if_changed(self) -> bool:
        """Check file mtimes and reload if any pack changed. Returns True if reloaded."""
        if not self._loaded:
            self.load()
            return True

        for path, old_mtime in self._mtime_map.items():
            try:
                if path.stat().st_mtime != old_mtime:
                    self.load(force=True)
                    return True
            except OSError:
                continue
        return False

    @property
    def entries(self) -> list[ResponseEntry]:
        if not self._loaded:
            self.load()
        return self._entries

    def entry_count(self) -> int:
        return len(self.entries)

    def pack_count(self) -> int:
        return len(self._mtime_map)
