from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, cast

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)


@dataclass
class QueuedCommand:
    id: str = ""
    instruction: str = ""
    target: str = ""
    mode: str = "offline"
    status: str = "pending"
    created_at: str = ""
    attempts: int = 0
    max_attempts: int = 3
    last_error: str = ""
    result_summary: str = ""
    dependencies: list[str] = field(default_factory=list)


class OfflineCommandQueue:
    _DB_PATH = get_config_dir() / "offline_queue.db"

    def __init__(self, db_path: str | Path | None = None) -> None:
        path = Path(db_path) if db_path else self._DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        try:
            self._init_db()
        except sqlite3.OperationalError:
            time.sleep(0.1)
            self._init_db()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return cast(sqlite3.Connection, self._local.conn)

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS queued_commands (
                id TEXT PRIMARY KEY,
                instruction TEXT NOT NULL,
                target TEXT DEFAULT '',
                mode TEXT DEFAULT 'offline',
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT (datetime('now')),
                attempts INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                last_error TEXT DEFAULT '',
                result_summary TEXT DEFAULT '',
                dependencies TEXT DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_queue_status ON queued_commands(status);
            CREATE INDEX IF NOT EXISTS idx_queue_created ON queued_commands(created_at);
        """)
        conn.commit()

    def enqueue(
        self,
        instruction: str,
        target: str = "",
        mode: str = "offline",
        max_attempts: int = 3,
        dependencies: list[str] | None = None,
    ) -> str:
        cmd_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            conn.execute(
                "INSERT INTO queued_commands (id, instruction, target, mode, status, created_at, max_attempts, dependencies) "
                "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
                (
                    cmd_id,
                    instruction,
                    target,
                    mode,
                    now,
                    max_attempts,
                    json.dumps(dependencies or []),
                ),
            )
        logger.info("Queued command %s: %s", cmd_id, instruction[:60])
        return cmd_id

    def dequeue(self, batch_size: int = 5) -> list[QueuedCommand]:
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT * FROM queued_commands WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?",
                (batch_size,),
            ).fetchall()
            result = []
            for row in rows:
                cmd = QueuedCommand(
                    id=row["id"],
                    instruction=row["instruction"],
                    target=row["target"],
                    mode=row["mode"],
                    status=row["status"],
                    created_at=row["created_at"],
                    attempts=row["attempts"],
                    max_attempts=row["max_attempts"],
                    last_error=row["last_error"],
                    result_summary=row["result_summary"],
                    dependencies=json.loads(row["dependencies"]),
                )
                result.append(cmd)
            return result

    def mark_processing(self, cmd_id: str) -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                "UPDATE queued_commands SET status = 'processing', attempts = attempts + 1 WHERE id = ?",
                (cmd_id,),
            )

    def mark_completed(self, cmd_id: str, summary: str = "") -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                "UPDATE queued_commands SET status = 'completed', result_summary = ? WHERE id = ?",
                (summary, cmd_id),
            )

    def mark_failed(self, cmd_id: str, error: str) -> None:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT attempts, max_attempts FROM queued_commands WHERE id = ?", (cmd_id,)
            ).fetchone()
            if row and row["attempts"] >= row["max_attempts"]:
                conn.execute(
                    "UPDATE queued_commands SET status = 'failed', last_error = ? WHERE id = ?",
                    (error, cmd_id),
                )
            else:
                conn.execute(
                    "UPDATE queued_commands SET status = 'pending', last_error = ? WHERE id = ?",
                    (error, cmd_id),
                )

    def get_pending_count(self) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM queued_commands WHERE status IN ('pending', 'processing')"
        ).fetchone()
        return row["c"] if row else 0

    def get_failed_count(self) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM queued_commands WHERE status = 'failed'"
        ).fetchone()
        return row["c"] if row else 0

    def get_completed_count(self) -> int:
        conn = self._conn()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM queued_commands WHERE status = 'completed'"
        ).fetchone()
        return row["c"] if row else 0

    def get_all(self, limit: int = 50) -> list[QueuedCommand]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM queued_commands ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for row in rows:
            cmd = QueuedCommand(
                id=row["id"],
                instruction=row["instruction"],
                target=row["target"],
                mode=row["mode"],
                status=row["status"],
                created_at=row["created_at"],
                attempts=row["attempts"],
                max_attempts=row["max_attempts"],
                last_error=row["last_error"],
                result_summary=row["result_summary"],
                dependencies=json.loads(row["dependencies"]),
            )
            result.append(cmd)
        return result

    def retry_failed(self, max_items: int = 10) -> int:
        with self._lock:
            conn = self._conn()
            conn.execute(
                "UPDATE queued_commands SET status = 'pending', attempts = 0 WHERE status = 'failed' LIMIT ?",
                (max_items,),
            )
            count = conn.total_changes
            return count

    def clear_completed(self, older_than_days: int = 7) -> int:
        with self._lock:
            conn = self._conn()
            conn.execute(
                "DELETE FROM queued_commands WHERE status = 'completed' AND created_at < datetime('now', ?)",
                (f"-{older_than_days} days",),
            )
            return conn.total_changes

    def stats(self) -> dict[str, int]:
        self._conn()
        return {
            "pending": self.get_pending_count(),
            "completed": self.get_completed_count(),
            "failed": self.get_failed_count(),
        }


class OfflineCommandReplay:
    def __init__(
        self,
        queue: OfflineCommandQueue,
        executor_fn: Callable[[QueuedCommand], Any] | None = None,
    ) -> None:
        self._queue = queue
        self._executor_fn = executor_fn
        self._running = False

    async def replay_all(
        self,
        executor_fn: Callable[[QueuedCommand], Any] | None = None,
        batch_size: int = 3,
        interval: float = 1.0,
    ) -> tuple[int, int]:
        fn = executor_fn or self._executor_fn
        if not fn:
            raise ValueError("No executor function provided")

        success_count = 0
        fail_count = 0

        while True:
            commands = self._queue.dequeue(batch_size)
            if not commands:
                break

            for cmd in commands:
                self._queue.mark_processing(cmd.id)
                try:
                    result = await fn(cmd)
                    self._queue.mark_completed(cmd.id, str(result)[:200])
                    success_count += 1
                except Exception as exc:
                    self._queue.mark_failed(cmd.id, str(exc))
                    fail_count += 1
                await asyncio.sleep(interval)

        return success_count, fail_count


__all__ = [
    "OfflineCommandQueue",
    "OfflineCommandReplay",
    "QueuedCommand",
]
