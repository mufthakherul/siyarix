# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-layer memory system with persistent storage and retrieval."""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import math
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)


class MemoryLayer(StrEnum):
    SESSION = "session"
    PROJECT = "project"
    PERSISTENT = "persistent"
    TOOL = "tool"
    WORKFLOW = "workflow"


@dataclass
class MemoryEntry:
    key: str
    value: str
    layer: MemoryLayer
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: float = 0.0

    @property
    def expired(self) -> bool:
        if self.ttl <= 0:
            return False
        return (time.time() - self.created_at) > self.ttl

    @functools.cached_property
    def content_hash(self) -> str:
        return hashlib.sha256(f"{self.key}:{self.value}".encode()).hexdigest()[:16]


class MemoryStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._session_memory: dict[str, MemoryEntry] = {}
        self._lock = threading.Lock()
        if db_path:
            self._init_db()

    def _init_db(self) -> None:
        if not self._db_path:
            return
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS memories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        layer TEXT NOT NULL,
                        tags TEXT DEFAULT '[]',
                        metadata TEXT DEFAULT '{}',
                        created_at REAL NOT NULL,
                        accessed_at REAL NOT NULL,
                        access_count INTEGER DEFAULT 0,
                        ttl REAL DEFAULT 0,
                        content_hash TEXT,
                        UNIQUE(key, layer)
                    )
                """)
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memories_layer ON memories(layer)"
                )
                self._conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key)")
                self._conn.commit()
        except Exception:
            logger.exception("Failed to initialize memory DB")
            self._conn = None

    def store(self, entry: MemoryEntry) -> None:
        try:
            from siyarix.opsec import opsec_manager

            if opsec_manager.status.memory_only:
                entry.layer = MemoryLayer.SESSION
        except ImportError:
            pass

        if entry.layer == MemoryLayer.SESSION:
            self._session_memory[entry.key] = entry
            return
        if not self._conn:
            return
        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO memories
                    (key, value, layer, tags, metadata, created_at, accessed_at, access_count, ttl, content_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry.key,
                        entry.value,
                        entry.layer.value,
                        json.dumps(entry.tags),
                        json.dumps(entry.metadata),
                        entry.created_at,
                        entry.accessed_at,
                        entry.access_count,
                        entry.ttl,
                        entry.content_hash,
                    ),
                )
                self._conn.commit()
        except Exception:
            logger.exception("Failed to store memory: %s", entry.key)

    def retrieve(self, key: str, layer: MemoryLayer | None = None) -> MemoryEntry | None:
        if layer == MemoryLayer.SESSION or layer is None:
            if key in self._session_memory:
                entry = self._session_memory[key]
                if not entry.expired:
                    entry.accessed_at = time.time()
                    entry.access_count += 1
                    return entry
                del self._session_memory[key]
        if not self._conn:
            return None
        try:
            with self._lock:
                if layer:
                    cursor = self._conn.execute(
                        "SELECT * FROM memories WHERE key = ? AND layer = ?", (key, layer.value)
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT * FROM memories WHERE key = ? ORDER BY created_at DESC LIMIT 1",
                        (key,),
                    )
                row = cursor.fetchone()
                if not row:
                    return None
                entry = self._row_to_entry(row)
                if entry.expired:
                    self._conn.execute(
                        "DELETE FROM memories WHERE key = ? AND layer = ?", (key, entry.layer.value)
                    )
                    self._conn.commit()
                    return None
                entry.accessed_at = time.time()
                entry.access_count += 1
                self._conn.execute(
                    "UPDATE memories SET accessed_at = ?, access_count = ? WHERE key = ? AND layer = ?",
                    (entry.accessed_at, entry.access_count, key, entry.layer.value),
                )
                self._conn.commit()
            return entry
        except Exception:
            logger.exception("Failed to retrieve memory: %s", key)
            return None

    def search(
        self, query: str, layer: MemoryLayer | None = None, limit: int = 10
    ) -> list[MemoryEntry]:
        candidates: list[MemoryEntry] = []
        query_lower = query.lower().strip()
        tokens = [t for t in re.split(r"\W+", query_lower) if t]

        # 1. Session memory candidates
        for entry in self._session_memory.values():
            if entry.expired or (layer and entry.layer != layer):
                continue
            candidates.append(entry)

        # 2. SQLite candidates
        if self._conn:
            try:
                with self._lock:
                    if layer:
                        cursor = self._conn.execute(
                            "SELECT * FROM memories WHERE layer = ? AND (key LIKE ? OR value LIKE ? OR tags LIKE ?) ORDER BY accessed_at DESC LIMIT ?",
                            (layer.value, f"%{query}%", f"%{query}%", f"%{query}%", limit * 4),
                        )
                    else:
                        cursor = self._conn.execute(
                            "SELECT * FROM memories WHERE key LIKE ? OR value LIKE ? OR tags LIKE ? ORDER BY accessed_at DESC LIMIT ?",
                            (f"%{query}%", f"%{query}%", f"%{query}%", limit * 4),
                        )
                    rows = cursor.fetchall()
                for row in rows:
                    entry = self._row_to_entry(row)
                    if not entry.expired and entry.key not in {e.key for e in candidates}:
                        candidates.append(entry)
            except Exception:
                logger.exception("Failed to search memories")

        # 3. BM25 / TF-IDF relevance scoring
        scored: list[tuple[float, MemoryEntry]] = []
        now = time.time()
        for entry in candidates:
            k_lower = entry.key.lower()
            v_lower = entry.value.lower()
            tags_lower = [t.lower() for t in entry.tags]
            k_tokens = set(re.split(r"\W+", k_lower))
            v_tokens = set(re.split(r"\W+", v_lower))

            score = 0.0
            # Substring match (exact phrase match)
            if query_lower in k_lower:
                score += 10.0
            if query_lower in v_lower:
                score += 5.0
            if any(query_lower in t for t in tags_lower):
                score += 6.0

            # Token-based match against token sets
            for token in tokens:
                if token in k_tokens:
                    score += 3.0
                if token in v_tokens:
                    score += 1.5
                if token in tags_lower:
                    score += 2.0

            if score > 0.0:
                # Recency factor
                age_hours = max(0.0, (now - entry.accessed_at) / 3600.0)
                recency_boost = max(0.5, 1.0 - (age_hours / 168.0))
                # Frequency factor
                freq_boost = 1.0 + 0.1 * math.log1p(entry.access_count)
                final_score = score * recency_boost * freq_boost
                scored.append((final_score, entry))

        # Sort by relevance score descending
        scored.sort(key=lambda item: item[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    def list_entries(self, layer: MemoryLayer | None = None, limit: int = 50) -> list[MemoryEntry]:
        """List stored memories ordered by accessed_at descending."""
        entries: list[MemoryEntry] = []
        for entry in self._session_memory.values():
            if not entry.expired and (layer is None or entry.layer == layer):
                entries.append(entry)
        if self._conn:
            try:
                with self._lock:
                    if layer:
                        cursor = self._conn.execute(
                            "SELECT * FROM memories WHERE layer = ? ORDER BY accessed_at DESC LIMIT ?",
                            (layer.value, limit),
                        )
                    else:
                        cursor = self._conn.execute(
                            "SELECT * FROM memories ORDER BY accessed_at DESC LIMIT ?",
                            (limit,),
                        )
                    rows = cursor.fetchall()
                for row in rows:
                    entry = self._row_to_entry(row)
                    if not entry.expired and entry.key not in {e.key for e in entries}:
                        entries.append(entry)
            except Exception:
                logger.exception("Failed to list memories")
        entries.sort(key=lambda e: e.accessed_at, reverse=True)
        return entries[:limit]

    def clear_layer(self, layer: MemoryLayer) -> None:
        if layer == MemoryLayer.SESSION:
            self._session_memory.clear()
            return
        if self._conn:
            try:
                with self._lock:
                    self._conn.execute("DELETE FROM memories WHERE layer = ?", (layer.value,))
                    self._conn.commit()
            except Exception:
                logger.exception("Failed to clear memory layer: %s", layer)

    def stats(self) -> dict[str, Any]:
        result: dict[str, Any] = {"session": len(self._session_memory), "persistent": {}}
        if self._conn:
            try:
                with self._lock:
                    cursor = self._conn.execute(
                        "SELECT layer, COUNT(*) FROM memories GROUP BY layer"
                    )
                    rows = cursor.fetchall()
                for row in rows:
                    result["persistent"][row[0]] = row[1]
            except Exception:
                logger.warning("Failed to query memory stats", exc_info=True)
        return result

    def _row_to_entry(self, row: sqlite3.Row) -> MemoryEntry:
        return MemoryEntry(
            key=row["key"],
            value=row["value"],
            layer=MemoryLayer(row["layer"]),
            tags=json.loads(row["tags"]) if row["tags"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
            accessed_at=row["accessed_at"],
            access_count=row["access_count"],
            ttl=row["ttl"],
        )

    def close(self) -> None:
        if self._conn:
            with self._lock:
                self._conn.close()
                self._conn = None


class MemoryManager:
    def __init__(self, base_path: Path | None = None) -> None:
        self._base_path = base_path or get_config_dir()
        self._stores: dict[MemoryLayer, MemoryStore] = {}
        self._stores[MemoryLayer.SESSION] = MemoryStore()
        db_path = self._base_path / "memory.db"
        for layer in (
            MemoryLayer.PROJECT,
            MemoryLayer.PERSISTENT,
            MemoryLayer.TOOL,
            MemoryLayer.WORKFLOW,
        ):
            self._stores[layer] = MemoryStore(db_path)

    def store(
        self,
        key: str,
        value: str,
        layer: MemoryLayer = MemoryLayer.SESSION,
        tags: list[str] | None = None,
        ttl: float = 0.0,
        **metadata: Any,
    ) -> None:
        self._stores[layer].store(
            MemoryEntry(
                key=key, value=value, layer=layer, tags=tags or [], ttl=ttl, metadata=metadata
            )
        )

    def retrieve(self, key: str, layer: MemoryLayer | None = None) -> MemoryEntry | None:
        if layer:
            return self._stores[layer].retrieve(key)
        for store in self._stores.values():
            entry = store.retrieve(key)
            if entry:
                return entry
        return None

    def search(
        self, query: str, layer: MemoryLayer | None = None, limit: int = 10
    ) -> list[MemoryEntry]:
        if layer:
            return self._stores[layer].search(query, limit=limit)
        results: list[MemoryEntry] = []
        for store in self._stores.values():
            results.extend(store.search(query, limit=limit))
        results.sort(key=lambda e: e.accessed_at, reverse=True)
        return results[:limit]

    def stats(self) -> dict[str, Any]:
        return {layer.value: store.stats() for layer, store in self._stores.items()}

    def list_entries(self, layer: MemoryLayer | None = None, limit: int = 50) -> list[MemoryEntry]:
        if layer:
            return self._stores[layer].list_entries(layer=layer, limit=limit)
        all_entries: list[MemoryEntry] = []
        for store in self._stores.values():
            all_entries.extend(store.list_entries(limit=limit))
        all_entries.sort(key=lambda e: e.accessed_at, reverse=True)
        return all_entries[:limit]

    def clear(self, layer: MemoryLayer | None = None) -> None:
        if layer:
            self._stores[layer].clear_layer(layer)
        else:
            for lyr, store in self._stores.items():
                store.clear_layer(lyr)

    def save_context(self, entry: dict[str, Any]) -> None:
        import json

        key = f"context_{time.time()}_{hashlib.md5(str(entry).encode(), usedforsecurity=False).hexdigest()[:8]}"
        self.store(
            key=key,
            value=json.dumps(entry),
            layer=MemoryLayer.PROJECT,
            tags=["context"],
        )

    def load_context(self) -> list[dict[str, Any]]:
        import json

        store = self._stores.get(MemoryLayer.PROJECT)
        if not store or not store._conn:
            return []

        try:
            with store._lock:
                cursor = store._conn.execute(
                    "SELECT value FROM memories WHERE layer = ? AND tags LIKE ? ORDER BY created_at ASC",
                    (MemoryLayer.PROJECT.value, '%"context"%'),
                )
                rows = cursor.fetchall()

            history = []
            for row in rows:
                try:
                    history.append(json.loads(row["value"]))
                except json.JSONDecodeError:
                    pass
            return history
        except Exception:
            return []

    def remember_target(
        self, target: str, data: dict[str, Any], tags: list[str] | None = None
    ) -> None:
        """Persist target intelligence across sessions."""
        key = f"target:{target.lower().strip()}"
        self.store(
            key=key,
            value=json.dumps(data),
            layer=MemoryLayer.PERSISTENT,
            tags=["target", target.lower().strip()] + (tags or []),
        )

    def recall_target(self, target: str) -> dict[str, Any] | None:
        """Recall stored intelligence for a target."""
        key = f"target:{target.lower().strip()}"
        entry = self.retrieve(key, layer=MemoryLayer.PERSISTENT)
        if entry and entry.value:
            try:
                res = json.loads(entry.value)
                return res if isinstance(res, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def associate_finding(self, target: str, finding: dict[str, Any]) -> None:
        """Associate a vulnerability finding with target in persistent memory."""
        target_clean = target.lower().strip()
        target_data = self.recall_target(target_clean) or {
            "target": target_clean,
            "findings": [],
            "ports": [],
        }
        findings_list = target_data.setdefault("findings", [])
        f_title = finding.get("title", "")
        if not any(f.get("title") == f_title for f in findings_list):
            findings_list.append(finding)
        if finding.get("port"):
            ports_list = target_data.setdefault("ports", [])
            if finding["port"] not in ports_list:
                ports_list.append(finding["port"])
        self.remember_target(target_clean, target_data)

    def get_target_findings(self, target: str) -> list[dict[str, Any]]:
        """Retrieve all persistent findings associated with target."""
        data = self.recall_target(target)
        return data.get("findings", []) if data else []

    def close(self) -> None:
        for store in self._stores.values():
            store.close()


__all__ = [
    "MemoryLayer",
    "MemoryEntry",
    "MemoryStore",
    "MemoryManager",
]
