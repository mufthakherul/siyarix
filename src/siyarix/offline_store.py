from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)

_ASYNC_EXECUTOR: Any = None


def _get_async_executor() -> Any:
    global _ASYNC_EXECUTOR
    if _ASYNC_EXECUTOR is None:
        from concurrent.futures import ThreadPoolExecutor

        _ASYNC_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="offline_store")
    return _ASYNC_EXECUTOR


_SCHEMA_VERSION = 2


class OfflineStore:
    _DB_PATH = get_config_dir() / "offline_store.db"

    def __init__(self, db_path: str | Path | None = None) -> None:
        path = Path(db_path) if db_path else self._DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');

            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT DEFAULT 'registry',
                plan_id TEXT,
                status TEXT DEFAULT 'completed',
                started_at TEXT,
                completed_at TEXT,
                duration_ms REAL DEFAULT 0,
                tool_count INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                tool TEXT NOT NULL,
                target TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                title TEXT DEFAULT '',
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                port INTEGER DEFAULT 0,
                service TEXT DEFAULT '',
                technology TEXT DEFAULT '',
                cvss_score REAL DEFAULT 0.0,
                tool_version TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                data_json TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS plans (
                plan_id TEXT PRIMARY KEY,
                goal TEXT NOT NULL,
                mode TEXT DEFAULT 'registry',
                status TEXT DEFAULT 'completed',
                step_count INTEGER DEFAULT 0,
                completed_steps INTEGER DEFAULT 0,
                failed_steps INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                completed_at TEXT,
                data_json TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(completed_at);
            CREATE INDEX IF NOT EXISTS idx_plans_created ON plans(created_at);
        """)
        self._migrate(conn)
        conn.commit()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        version = int(row["value"]) if row else 0
        if version < 2:
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT 0.0")
            except sqlite3.OperationalError as e:
                logger.debug("cvss_score column already exists: %s", e)
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN metadata TEXT DEFAULT '{}'")
            except sqlite3.OperationalError as e:
                logger.debug("metadata column already exists: %s", e)
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2')")
            logger.info("OfflineStore migrated to schema v2")
        if version < 3:
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN tool_version TEXT DEFAULT ''")
            except sqlite3.OperationalError as e:
                logger.debug("tool_version column already exists: %s", e)
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')")
            logger.info("OfflineStore migrated to schema v3")

    async def save_scan_async(
        self,
        target: str,
        findings: list[dict[str, Any]],
        mode: str = "registry",
        plan_id: str = "",
    ) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_async_executor(),
            self.save_scan,
            target,
            findings,
            mode,
            plan_id,
        )

    def save_scan(
        self,
        target: str,
        findings: list[dict[str, Any]],
        mode: str = "registry",
        plan_id: str = "",
    ) -> str:
        scan_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO scans (scan_id, target, mode, plan_id, started_at, completed_at, tool_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, target, mode, plan_id, now, now, len(findings)),
                )
                for f in findings:
                    conn.execute(
                        "INSERT INTO findings (scan_id, tool, tool_version, target, severity, title, description, evidence, port, service, technology, cvss_score, data_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            scan_id,
                            f.get("tool", "unknown"),
                            f.get("tool_version", ""),
                            f.get("target", target),
                            f.get("severity", "info"),
                            f.get("title", ""),
                            f.get("description", ""),
                            f.get("evidence", ""),
                            f.get("port", 0),
                            f.get("service", ""),
                            f.get("technology", ""),
                            f.get("cvss_score", 0.0),
                            json.dumps(f),
                        ),
                    )
        logger.info("Saved scan %s for target %s (%d findings)", scan_id, target, len(findings))
        return scan_id

    def save_raw_scan(
        self,
        target: str,
        tool: str,
        raw_output: str,
        mode: str = "offline",
        plan_id: str = "",
    ) -> str:
        """Parse raw tool output and save it as a structured scan.

        This wires the offline registry directly to the parser ecosystem.
        """
        from .parsers import ParserRegistry

        registry = ParserRegistry()
        registry.discover()
        findings = registry.parse(tool, raw_output)
        if not findings:
            logger.warning("Parser for %s produced no findings from the raw output.", tool)
        return self.save_scan(target, findings, mode=mode, plan_id=plan_id)

    def save_plan(
        self, plan_id: str, goal: str, steps: list[dict[str, Any]], mode: str = "registry"
    ) -> None:
        completed = sum(1 for s in steps if s.get("status") == "completed")
        failed = sum(1 for s in steps if s.get("status") == "failed")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO plans (plan_id, goal, mode, status, step_count, completed_steps, failed_steps, data_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        plan_id,
                        goal,
                        mode,
                        "completed",
                        len(steps),
                        completed,
                        failed,
                        json.dumps(steps),
                    ),
                )

    def _hash_finding(self, r: sqlite3.Row) -> str:
        """Create a reproducible hash for a finding to track changes across scans."""
        import hashlib

        core_data = f"{r['tool']}|{r['title']}|{r['port']}|{r['service']}".encode("utf-8")
        return hashlib.sha256(core_data).hexdigest()

    async def diff_scans_async(self, scan_a_id: str, scan_b_id: str) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_async_executor(), self.diff_scans, scan_a_id, scan_b_id
        )

    def diff_scans(self, scan_a_id: str, scan_b_id: str) -> dict[str, Any]:
        conn = self._conn()
        a = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_a_id,)).fetchone()
        b = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_b_id,)).fetchone()
        if not a or not b:
            missing = scan_a_id if not a else scan_b_id
            return {
                "error": f"Scan {missing!r} not found",
                "summary": {"new": 0, "resolved": 0, "changed": 0},
            }

        findings_a = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_a_id,)
        ).fetchall()
        findings_b = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_b_id,)
        ).fetchall()

        map_a = {self._hash_finding(r): r for r in findings_a}
        map_b = {self._hash_finding(r): r for r in findings_b}

        hashes_a = set(map_a.keys())
        hashes_b = set(map_b.keys())

        new_hashes = hashes_b - hashes_a
        resolved_hashes = hashes_a - hashes_b
        common_hashes = hashes_a & hashes_b

        changed = 0
        for h in common_hashes:
            if (
                map_a[h]["severity"] != map_b[h]["severity"]
                or map_a[h]["description"] != map_b[h]["description"]
                or map_a[h]["cvss_score"] != map_b[h]["cvss_score"]
            ):
                changed += 1

        return {
            "scan_a": {"target": a["target"], "total": len(findings_a), "scan_id": scan_a_id},
            "scan_b": {"target": b["target"], "total": len(findings_b), "scan_id": scan_b_id},
            "summary": {
                "new": len(new_hashes),
                "resolved": len(resolved_hashes),
                "changed": changed,
            },
            "new_findings": [map_b[h]["title"] for h in list(new_hashes)[:20]],
            "resolved_findings": [map_a[h]["title"] for h in list(resolved_hashes)[:20]],
        }

    def stats(self) -> dict[str, int]:
        conn = self._conn()
        scans = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()
        findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()
        return {"total_scans": scans["c"], "total_findings": findings["c"]}

    def get_latest_plan_id(self) -> str:
        conn = self._conn()
        row = conn.execute("SELECT plan_id FROM plans ORDER BY created_at DESC LIMIT 1").fetchone()
        return row["plan_id"] if row else ""

    async def search_findings_async(
        self, severity: str = "critical", limit: int = 50
    ) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_async_executor(), self.search_findings, severity, limit
        )

    def search_findings(self, severity: str = "critical", limit: int = 50) -> list[dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    async def search_findings_full_async(
        self,
        severity: str | None = None,
        tool: str | None = None,
        target: str | None = None,
        search_text: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _get_async_executor(),
            self.search_findings_full,
            severity,
            tool,
            target,
            search_text,
            limit,
        )

    def search_findings_full(
        self,
        severity: str | None = None,
        tool: str | None = None,
        target: str | None = None,
        search_text: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        conditions: list[str] = []
        params: list[Any] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        if search_text:
            conditions.append(
                "(title LIKE ? OR description LIKE ? OR evidence LIKE ? OR service LIKE ?)"
            )
            params.extend([f"%{search_text}%"] * 4)
        query = "SELECT * FROM findings"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT ?"
        rows = conn.execute(query, (*params, limit)).fetchall()
        return [dict(r) for r in rows]

    async def list_scans_async(self, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_get_async_executor(), self.list_scans, limit, offset)

    def list_scans(self, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.scan_id) as findings_count "
            "FROM scans s ORDER BY s.completed_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    async def get_scan_async(self, scan_id: str) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_get_async_executor(), self.get_scan, scan_id)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        conn = self._conn()
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["findings"] = [
            dict(f)
            for f in conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        ]
        return result

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock:
            with self._conn() as conn:
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        return True

    def export_scans(self, path: Path) -> int:
        conn = self._conn()
        scans = conn.execute("SELECT * FROM scans").fetchall()
        data = []
        for s in scans:
            scan_dict = dict(s)
            scan_dict["findings"] = [
                dict(f)
                for f in conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ?", (s["scan_id"],)
                ).fetchall()
            ]
            data.append(scan_dict)
        path.write_text(json.dumps(data, indent=2))
        return len(data)

    def import_scans(self, path: Path) -> int:
        if not path.exists():
            return 0
        data = json.loads(path.read_text())
        count = 0
        with self._lock:
            with self._conn() as conn:
                for scan in data:
                    scan_id = scan["scan_id"]
                    existing = conn.execute(
                        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
                    ).fetchone()
                    if not existing:
                        conn.execute(
                            "INSERT INTO scans (scan_id, target, mode, plan_id, started_at, completed_at, tool_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                scan_id,
                                scan.get("target", ""),
                                scan.get("mode", ""),
                                scan.get("plan_id", ""),
                                scan.get("started_at", ""),
                                scan.get("completed_at", ""),
                                scan.get("tool_count", 0),
                            ),
                        )
                        for f in scan.get("findings", []):
                            conn.execute(
                                "INSERT INTO findings (scan_id, tool, tool_version, target, severity, title, description, evidence, port, service, technology, cvss_score, data_json) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    scan_id,
                                    f.get("tool", ""),
                                    f.get("tool_version", ""),
                                    f.get("target", ""),
                                    f.get("severity", ""),
                                    f.get("title", ""),
                                    f.get("description", ""),
                                    f.get("evidence", ""),
                                    f.get("port", 0),
                                    f.get("service", ""),
                                    f.get("technology", ""),
                                    f.get("cvss_score", 0.0),
                                    f.get("data_json", "{}"),
                                ),
                            )
                        count += 1
        return count


__all__ = [
    "OfflineStore",
]
