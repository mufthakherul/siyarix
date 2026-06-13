from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)


class OfflineStore:
    _DB_PATH = get_config_dir() / "offline_store.db"

    def __init__(self, db_path: str | Path | None = None) -> None:
        path = Path(db_path) if db_path else self._DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(path)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
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
                scan_id TEXT NOT NULL REFERENCES scans(scan_id),
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
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_plans_created ON plans(created_at);
        """)
        conn.commit()

    def save_scan(
        self,
        target: str,
        findings: list[dict[str, Any]],
        mode: str = "registry",
        plan_id: str = "",
    ) -> str:
        import uuid

        scan_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        conn = self._conn()
        conn.execute(
            "INSERT INTO scans (scan_id, target, mode, plan_id, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, target, mode, plan_id, now, now),
        )
        for f in findings:
            conn.execute(
                "INSERT INTO findings (scan_id, tool, target, severity, title, description, evidence, port, service, technology, data_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    f.get("tool", "unknown"),
                    f.get("target", target),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("port", 0),
                    f.get("service", ""),
                    f.get("technology", ""),
                    json.dumps(f),
                ),
            )
        conn.commit()
        logger.info("Saved scan %s for target %s (%d findings)", scan_id, target, len(findings))
        return scan_id

    def save_plan(
        self, plan_id: str, goal: str, steps: list[dict[str, Any]], mode: str = "registry"
    ) -> None:
        conn = self._conn()
        completed = sum(1 for s in steps if s.get("status") == "completed")
        failed = sum(1 for s in steps if s.get("status") == "failed")
        conn.execute(
            "INSERT OR REPLACE INTO plans (plan_id, goal, mode, status, step_count, completed_steps, failed_steps, data_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plan_id, goal, mode, "completed", len(steps), completed, failed, json.dumps(steps)),
        )
        conn.commit()

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
        titles_a = {r["title"] for r in findings_a}
        titles_b = {r["title"] for r in findings_b}
        new_titles = titles_b - titles_a
        resolved_titles = titles_a - titles_b
        changed = 0
        for fb in findings_b:
            if fb["title"] in titles_a:
                fa = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? AND title = ?",
                    (scan_a_id, fb["title"]),
                ).fetchone()
                if fa and (
                    fa["severity"] != fb["severity"] or fa["description"] != fb["description"]
                ):
                    changed += 1
        return {
            "scan_a": {"target": a["target"], "total": len(findings_a), "scan_id": scan_a_id},
            "scan_b": {"target": b["target"], "total": len(findings_b), "scan_id": scan_b_id},
            "summary": {
                "new": len(new_titles),
                "resolved": len(resolved_titles),
                "changed": changed,
            },
            "new_findings": sorted(new_titles)[:20],
            "resolved_findings": sorted(resolved_titles)[:20],
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

    def search_findings(self, severity: str = "critical", limit: int = 50) -> list[dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY completed_at DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["findings_count"] = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE scan_id = ?", (r["scan_id"],)
            ).fetchone()["c"]
            results.append(d)
        return results

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

__all__ = [
    "OfflineStore",
]
