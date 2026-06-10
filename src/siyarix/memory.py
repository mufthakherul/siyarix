# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-layer memory system with persistent storage and retrieval."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

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

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(f"{self.key}:{self.value}".encode()).hexdigest()[:16]


class MemoryStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._session_memory: dict[str, MemoryEntry] = {}
        if db_path:
            self._init_db()

    def _init_db(self) -> None:
        if not self._db_path:
            return
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
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
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_layer ON memories(layer)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key)")
            self._conn.commit()
        except Exception:
            logger.exception("Failed to initialize memory DB")
            self._conn = None

    def store(self, entry: MemoryEntry) -> None:
        if entry.layer == MemoryLayer.SESSION:
            self._session_memory[entry.key] = entry
            return
        if not self._conn:
            return
        try:
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
            if layer:
                cursor = self._conn.execute(
                    "SELECT * FROM memories WHERE key = ? AND layer = ?", (key, layer.value)
                )
            else:
                cursor = self._conn.execute(
                    "SELECT * FROM memories WHERE key = ? ORDER BY created_at DESC LIMIT 1", (key,)
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
        results: list[MemoryEntry] = []
        query_lower = query.lower()
        for entry in self._session_memory.values():
            if entry.expired or (layer and entry.layer != layer):
                continue
            if query_lower in entry.key.lower() or query_lower in entry.value.lower():
                results.append(entry)
        if self._conn:
            try:
                if layer:
                    cursor = self._conn.execute(
                        "SELECT * FROM memories WHERE layer = ? AND (key LIKE ? OR value LIKE ?) ORDER BY accessed_at DESC LIMIT ?",
                        (layer.value, f"%{query}%", f"%{query}%", limit),
                    )
                else:
                    cursor = self._conn.execute(
                        "SELECT * FROM memories WHERE key LIKE ? OR value LIKE ? ORDER BY accessed_at DESC LIMIT ?",
                        (f"%{query}%", f"%{query}%", limit),
                    )
                for row in cursor.fetchall():
                    entry = self._row_to_entry(row)
                    if not entry.expired and entry.key not in {e.key for e in results}:
                        results.append(entry)
            except Exception:
                logger.exception("Failed to search memories")
        return results[:limit]

    def clear_layer(self, layer: MemoryLayer) -> None:
        if layer == MemoryLayer.SESSION:
            self._session_memory.clear()
            return
        if self._conn:
            try:
                self._conn.execute("DELETE FROM memories WHERE layer = ?", (layer.value,))
                self._conn.commit()
            except Exception:
                logger.exception("Failed to clear memory layer: %s", layer)

    def stats(self) -> dict[str, Any]:
        result: dict[str, Any] = {"session": len(self._session_memory), "persistent": {}}
        if self._conn:
            try:
                cursor = self._conn.execute("SELECT layer, COUNT(*) FROM memories GROUP BY layer")
                for row in cursor.fetchall():
                    result["persistent"][row[0]] = row[1]
            except Exception:
                pass
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
            self._conn.close()
            self._conn = None


class MemoryManager:
    def __init__(self, base_path: Path | None = None) -> None:
        self._base_path = base_path or Path.home() / ".siyarix"
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

    def close(self) -> None:
        for store in self._stores.values():
            store.close()
