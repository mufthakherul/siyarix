from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Generator, cast

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
            # isolation_level=None → autocommit; explicit BEGIN/COMMIT via _transaction.
            self._local.conn = sqlite3.connect(
                self._db_path, timeout=30, check_same_thread=False, isolation_level=None
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return cast(sqlite3.Connection, self._local.conn)

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Explicit SQLite transaction: COMMIT on success, ROLLBACK on error."""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                logger.debug("ROLLBACK failed after transaction error", exc_info=True)
            raise

    def _init_db(self) -> None:
        with self._transaction() as conn:
            conn.execute("""
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
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_status ON queued_commands(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_created ON queued_commands(created_at)"
            )
            try:
                conn.execute(
                    "ALTER TABLE queued_commands ADD COLUMN claimed_at TEXT DEFAULT ''"
                )
            except sqlite3.OperationalError:
                pass  # column already present on upgraded DBs

    def enqueue(
        self,
        instruction: str,
        target: str = "",
        mode: str = "offline",
        max_attempts: int = 3,
        dependencies: list[str] | None = None,
    ) -> str:
        cmd_id = uuid.uuid4().hex
        with self._lock:
            with self._transaction() as conn:
                # Use SQLite datetime('now') so age filters (clear/reclaim) compare
                # against the same timestamp format.
                conn.execute(
                    "INSERT INTO queued_commands "
                    "(id, instruction, target, mode, status, created_at, max_attempts, dependencies) "
                    "VALUES (?, ?, ?, ?, 'pending', datetime('now'), ?, ?)",
                    (
                        cmd_id,
                        instruction,
                        target,
                        mode,
                        max_attempts,
                        json.dumps(dependencies or []),
                    ),
                )
        logger.info("Queued command %s: %s", cmd_id, instruction[:60])
        return cmd_id

    def dequeue(self, batch_size: int = 5) -> list[QueuedCommand]:
        """Atomically claim up to *batch_size* pending commands as processing.

        Claim happens in one transaction so concurrent flush/replay workers
        cannot dequeue the same row twice.
        """
        with self._lock:
            with self._transaction() as conn:
                rows = conn.execute(
                    "SELECT id FROM queued_commands WHERE status = 'pending' "
                    "ORDER BY created_at ASC LIMIT ?",
                    (batch_size,),
                ).fetchall()
                ids = [row["id"] for row in rows]
                if not ids:
                    return []
                placeholders = ",".join("?" * len(ids))
                conn.execute(
                    f"UPDATE queued_commands SET status = 'processing', "
                    f"attempts = attempts + 1, claimed_at = datetime('now') "
                    f"WHERE id IN ({placeholders}) "
                    f"AND status = 'pending'",
                    ids,
                )
                claimed = conn.execute(
                    f"SELECT * FROM queued_commands WHERE id IN ({placeholders}) "
                    f"AND status = 'processing'",
                    ids,
                ).fetchall()
                result = []
                for row in claimed:
                    result.append(
                        QueuedCommand(
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
                    )
                return result

    def mark_processing(self, cmd_id: str) -> None:
        """Ensure *cmd_id* is marked processing.

        Safe to call after :meth:`dequeue` (already claimed) — does not
        double-increment attempts when status is already ``processing``.
        """
        with self._lock:
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE queued_commands SET status = 'processing', "
                    "attempts = attempts + 1 WHERE id = ? AND status = 'pending'",
                    (cmd_id,),
                )

    def reclaim_stale_processing(self, older_than_seconds: int = 3600) -> int:
        """Return stuck ``processing`` rows to ``pending`` after a crash/TTL.

        Ages on ``claimed_at`` (set at dequeue). Rows without ``claimed_at``
        fall back to ``created_at`` for pre-migration databases.
        """
        with self._lock:
            with self._transaction() as conn:
                cutoff = f"-{int(older_than_seconds)} seconds"
                cur = conn.execute(
                    "UPDATE queued_commands SET status = 'pending', claimed_at = '' "
                    "WHERE status = 'processing' AND ("
                    "  (claimed_at IS NOT NULL AND claimed_at != '' "
                    "   AND claimed_at < datetime('now', ?))"
                    "  OR ((claimed_at IS NULL OR claimed_at = '') "
                    "   AND created_at < datetime('now', ?))"
                    ")",
                    (cutoff, cutoff),
                )
                return cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0

    def mark_completed(self, cmd_id: str, summary: str = "") -> None:
        with self._lock:
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE queued_commands SET status = 'completed', result_summary = ? WHERE id = ?",
                    (summary, cmd_id),
                )

    def mark_failed(self, cmd_id: str, error: str) -> None:
        with self._lock:
            with self._transaction() as conn:
                row = conn.execute(
                    "SELECT attempts, max_attempts FROM queued_commands WHERE id = ?",
                    (cmd_id,),
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
            with self._transaction() as conn:
                # SQLite UPDATE…LIMIT is not portable; select then update.
                rows = conn.execute(
                    "SELECT id FROM queued_commands WHERE status = 'failed' "
                    "ORDER BY created_at ASC LIMIT ?",
                    (max_items,),
                ).fetchall()
                ids = [row["id"] for row in rows]
                if not ids:
                    return 0
                placeholders = ",".join("?" * len(ids))
                conn.execute(
                    f"UPDATE queued_commands SET status = 'pending', attempts = 0 "
                    f"WHERE id IN ({placeholders})",
                    ids,
                )
                return len(ids)

    def clear_completed(self, older_than_days: int = 7) -> int:
        with self._lock:
            with self._transaction() as conn:
                cur = conn.execute(
                    "DELETE FROM queued_commands WHERE status = 'completed' "
                    "AND created_at < datetime('now', ?)",
                    (f"-{older_than_days} days",),
                )
                return cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0

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
        # Bound retries so a poisoned/misconfigured queue cannot spin forever.
        pending_hint = max(self._queue.get_pending_count(), 1)
        max_cycles = max(pending_hint * 8, batch_size * 8, 32)
        cycles = 0

        while cycles < max_cycles:
            cycles += 1
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

        if cycles >= max_cycles and self._queue.get_pending_count() > 0:
            logger.warning(
                "Offline replay stopped after %d cycles with %d pending remaining",
                cycles,
                self._queue.get_pending_count(),
            )

        return success_count, fail_count


__all__ = [
    "OfflineCommandQueue",
    "OfflineCommandReplay",
    "QueuedCommand",
]
