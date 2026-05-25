"""Phalanx Session Manager — Persistent session state, snapshots, and history.

Provides:
  • **CommandHistory** — SQLite-backed cross-session command history
  • **SessionRegistry** — Track, list, tag, and search all sessions
  • **SessionSnapshot** — Save/restore complete session state

Usage::

    from phalanx.session_manager import command_history, session_registry
    command_history.add("nmap -sV 10.0.0.1", session_id="abc123")
    sessions = session_registry.list_sessions()
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = [
    "SessionMeta",
    "CommandHistory",
    "SessionRegistry",
    "command_history",
    "session_registry",
]

logger = logging.getLogger(__name__)

_PHALANX_DIR = Path(os.getenv("PHALANX_CONFIG_DIR", str(Path.home() / ".phalanx")))


@dataclass
class SessionMeta:
    """Metadata about a Phalanx session."""

    session_id: str
    name: str = ""
    mode: str = "integrated"
    target: str = ""
    created_at: str = ""
    last_active: str = ""
    message_count: int = 0
    tags: list[str] = field(default_factory=list)
    notes: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# CommandHistory — persistent cross-session command history
# ═══════════════════════════════════════════════════════════════════════════


class CommandHistory:
    """SQLite-backed persistent command history."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or (_PHALANX_DIR / "command_history.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command TEXT NOT NULL,
                    session_id TEXT DEFAULT '',
                    result TEXT DEFAULT 'success',
                    timestamp TEXT NOT NULL,
                    duration_ms REAL DEFAULT 0.0,
                    metadata_json TEXT DEFAULT '{}'
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_history_ts
                ON command_history(timestamp DESC)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_history_cmd
                ON command_history(command)
            """
            )

    def add(
        self,
        command: str,
        session_id: str = "",
        result: str = "success",
        duration_ms: float = 0.0,
        **metadata: Any,
    ) -> None:
        """Record a command execution."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO command_history
                   (command, session_id, result, timestamp, duration_ms, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    command,
                    session_id,
                    result,
                    datetime.now().isoformat(),
                    duration_ms,
                    json.dumps(metadata) if metadata else "{}",
                ),
            )

    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Search history by keyword."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT command, session_id, result, timestamp, duration_ms
                   FROM command_history
                   WHERE command LIKE ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (f"%{query}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get most recent commands."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT command, session_id, result, timestamp, duration_ms
                   FROM command_history
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def most_used(self, limit: int = 20) -> list[tuple[str, int]]:
        """Get the most frequently used commands."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT command, COUNT(*) as cnt
                   FROM command_history
                   GROUP BY command
                   ORDER BY cnt DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [(r["command"], r["cnt"]) for r in rows]

    def clear(self) -> None:
        """Delete all history entries."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM command_history")

    def count(self) -> int:
        """Total history entries."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM command_history").fetchone()
        return row[0] if row else 0


# ═══════════════════════════════════════════════════════════════════════════
# SessionRegistry — track all Phalanx sessions
# ═══════════════════════════════════════════════════════════════════════════


class SessionRegistry:
    """Registry of all Phalanx CLI sessions, backed by SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or (_PHALANX_DIR / "sessions.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    mode TEXT DEFAULT 'integrated',
                    target TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0,
                    tags_json TEXT DEFAULT '[]',
                    notes TEXT DEFAULT ''
                )
            """
            )

    def register(self, meta: SessionMeta) -> None:
        """Register or update a session."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO sessions
                   (session_id, name, mode, target, created_at, last_active,
                    message_count, tags_json, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    meta.session_id,
                    meta.name,
                    meta.mode,
                    meta.target,
                    meta.created_at or datetime.now().isoformat(),
                    meta.last_active or datetime.now().isoformat(),
                    meta.message_count,
                    json.dumps(meta.tags),
                    meta.notes,
                ),
            )

    def update_active(self, session_id: str, message_count: int = 0) -> None:
        """Touch the last_active timestamp and message count."""
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE sessions SET last_active = ?, message_count = ?
                   WHERE session_id = ?""",
                (datetime.now().isoformat(), message_count, session_id),
            )

    def list_sessions(self, limit: int = 20) -> list[SessionMeta]:
        """List sessions, most recently active first."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM sessions ORDER BY last_active DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._row_to_meta(r) for r in rows]

    def get_session(self, session_id: str) -> SessionMeta | None:
        """Retrieve a single session by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return self._row_to_meta(row) if row else None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session from the registry."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE session_id = ?",
                (session_id,),
            )
        return cursor.rowcount > 0

    def tag_session(self, session_id: str, *tags: str) -> None:
        """Add tags to a session."""
        meta = self.get_session(session_id)
        if not meta:
            return
        existing = set(meta.tags)
        existing.update(tags)
        meta.tags = sorted(existing)
        self.register(meta)

    def find_by_target(self, target: str) -> list[SessionMeta]:
        """Find sessions that targeted a specific host/IP."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM sessions WHERE target LIKE ?
                   ORDER BY last_active DESC""",
                (f"%{target}%",),
            ).fetchall()
        return [self._row_to_meta(r) for r in rows]

    def find_by_tag(self, tag: str) -> list[SessionMeta]:
        """Find sessions by tag."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM sessions WHERE tags_json LIKE ?
                   ORDER BY last_active DESC""",
                (f'%"{tag}"%',),
            ).fetchall()
        return [self._row_to_meta(r) for r in rows]

    @staticmethod
    def _row_to_meta(row: sqlite3.Row) -> SessionMeta:
        return SessionMeta(
            session_id=row["session_id"],
            name=row["name"],
            mode=row["mode"],
            target=row["target"],
            created_at=row["created_at"],
            last_active=row["last_active"],
            message_count=row["message_count"],
            tags=json.loads(row["tags_json"]) if row["tags_json"] else [],
            notes=row["notes"],
        )


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singletons
# ═══════════════════════════════════════════════════════════════════════════

command_history = CommandHistory()
session_registry = SessionRegistry()
