"""Offline SQLite store for scan results and findings when the agent is disconnected."""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import UTC
from pathlib import Path

_DB_DIR = Path.home() / ".siyarix"
_DB_PATH = _DB_DIR / "offline.db"

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    tool TEXT,
    target TEXT,
    timestamp TEXT,
    synced INTEGER NOT NULL DEFAULT 0
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_findings_synced ON findings(synced)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool)",
    "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool)",
]

class OfflineStore:
    """SQLite-backed store for offline scan data and findings.

    The database lives at ``~/.siyarix/offline.db``.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def init_db(self) -> None:
        """Create database tables if they do not exist."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(_CREATE_SCANS)
            conn.execute(_CREATE_FINDINGS)
            for statement in _CREATE_INDEXES:
                conn.execute(statement)
            conn.commit()

    def save_scan(self, scan_id: str, target: str, tool: str, status: str) -> None:
        """Persist a new scan record."""
        from datetime import datetime

        created_at = datetime.now(tz=UTC).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scans (id, target, tool, status, created_at) " "VALUES (?, ?, ?, ?, ?)",
                (scan_id, target, tool, status, created_at),
            )
            conn.commit()

    def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update the status of an existing scan."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status, scan_id),
            )
            conn.commit()

    def save_finding(self, finding: dict, scan_id: str) -> None:
        """Persist a finding associated with *scan_id*."""
        import uuid

        finding_id = finding.get("id") or str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (id, scan_id, title, severity, description, evidence, tool, target, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    scan_id,
                    finding.get("title", ""),
                    finding.get("severity", "info"),
                    finding.get("description", ""),
                    finding.get("evidence", ""),
                    finding.get("tool", ""),
                    finding.get("target", ""),
                    finding.get("timestamp", ""),
                ),
            )
            conn.commit()

    def get_unsynced_findings(self) -> list[dict]:
        """Return all findings that have not yet been synced to the server."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE synced = 0").fetchall()
        return [dict(row) for row in rows]

    def mark_synced(self, finding_ids: list[str]) -> None:
        """Mark the given finding IDs as synced."""
        if not finding_ids:
            return
        placeholders = ",".join("?" for _ in finding_ids)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE findings SET synced = 1 WHERE id IN ({placeholders})",
                finding_ids,
            )
            conn.commit()

    def export_json(self, output_path: str) -> None:
        """Export all findings to a JSON file at *output_path*."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings").fetchall()
        data = [dict(row) for row in rows]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def export_csv(self, output_path: str) -> None:
        """Export all findings to a CSV file at *output_path*."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings").fetchall()
        if not rows:
            with open(output_path, "w", newline="", encoding="utf-8") as fh:
                fh.write("")
            return
        fieldnames = list(dict(rows[0]).keys())
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))

    # ------------------------------------------------------------------
    # CA-2.3 — History & search extensions
    # ------------------------------------------------------------------

    def list_scans(
        self,
        limit: int = 20,
        since: str | None = None,
        tool: str | None = None,
        target: str | None = None,
    ) -> list[dict]:
        """Return paginated scan records with optional filters."""
        conditions: list[str] = []
        params: list = []
        if since:
            conditions.append("created_at >= ?")
            params.append(since)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM scans {where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            if not rows:
                return []
            scan_ids = [r["id"] for r in rows]
            placeholders = ",".join("?" for _ in scan_ids)
            counts_rows = conn.execute(
                (
                    "SELECT scan_id, severity, COUNT(*) AS cnt FROM findings "
                    f"WHERE scan_id IN ({placeholders}) GROUP BY scan_id, severity"
                ),
                scan_ids,
            ).fetchall()

        counts_by_scan: dict[str, dict[str, int]] = {}
        for r in counts_rows:
            scan_counts = counts_by_scan.setdefault(r["scan_id"], {})
            scan_counts[r["severity"]] = r["cnt"]

        result = []
        for row in rows:
            d = dict(row)
            d["finding_counts"] = counts_by_scan.get(d["id"], {})
            d["total_findings"] = sum(d["finding_counts"].values())
            result.append(d)
        return result

    def get_scan_with_findings(self, scan_id: str) -> dict | None:
        """Return full scan record plus all its findings."""
        with self._connect() as conn:
            scan_row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan_row:
            return None
        scan = dict(scan_row)
        with self._connect() as conn:
            finding_rows = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        scan["findings"] = [dict(r) for r in finding_rows]
        return scan

    def search_findings(
        self,
        severity: str | None = None,
        tool: str | None = None,
        search: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Full-text-style search across all findings."""
        conditions: list[str] = []
        params: list = []
        if severity:
            conditions.append("LOWER(severity) = LOWER(?)")
            params.append(severity)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if search:
            conditions.append("(title LIKE ? OR description LIKE ? OR evidence LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM findings {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def diff_scans(self, scan_id_a: str, scan_id_b: str) -> dict:
        """Compare two scans: new, resolved, and changed-severity findings."""
        a = self.get_scan_with_findings(scan_id_a)
        b = self.get_scan_with_findings(scan_id_b)
        if not a or not b:
            return {"error": "One or both scans not found"}
        a_titles = {f["title"]: f for f in a["findings"]}
        b_titles = {f["title"]: f for f in b["findings"]}
        new_findings = [f for title, f in b_titles.items() if title not in a_titles]
        resolved_findings = [f for title, f in a_titles.items() if title not in b_titles]
        changed: list[dict] = []
        for title in a_titles:
            if title in b_titles:
                old_sev = a_titles[title]["severity"]
                new_sev = b_titles[title]["severity"]
                if old_sev != new_sev:
                    changed.append(
                        {
                            "title": title,
                            "old_severity": old_sev,
                            "new_severity": new_sev,
                        }
                    )
        return {
            "scan_a": {"id": scan_id_a, "target": a.get("target"), "total": len(a["findings"])},
            "scan_b": {"id": scan_id_b, "target": b.get("target"), "total": len(b["findings"])},
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "changed_severity": changed,
            "summary": {
                "new": len(new_findings),
                "resolved": len(resolved_findings),
                "changed": len(changed),
            },
        }

    def stats(self) -> dict:
        """Return aggregate statistics."""
        with self._connect() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            sev_rows = conn.execute("SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity").fetchall()
            tool_rows = conn.execute(
                "SELECT tool, COUNT(*) AS cnt FROM scans GROUP BY tool ORDER BY cnt DESC LIMIT 5"
            ).fetchall()
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "findings_by_severity": {r["severity"]: r["cnt"] for r in sev_rows},
            "top_tools": [{"tool": r["tool"], "scans": r["cnt"]} for r in tool_rows],
        }

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all its findings. Returns True if found."""
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            conn.commit()
        return True

    def vacuum(self) -> None:
        """Run VACUUM to compact the local database."""
        with self._connect() as conn:
            conn.execute("VACUUM")

    def optimize(self) -> None:
        """Run SQLite optimizer and ANALYZE for better query plans."""
        with self._connect() as conn:
            conn.execute("PRAGMA optimize")
            conn.execute("ANALYZE")
            conn.commit()

    def db_stats(self) -> dict[str, int]:
        """Return lightweight local DB storage stats."""
        file_size = self._db_path.stat().st_size if self._db_path.exists() else 0
        with self._connect() as conn:
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        return {
            "file_size_bytes": file_size,
            "page_count": page_count,
            "freelist_count": freelist_count,
            "page_size": page_size,
        }

    def import_findings(self, findings: list[dict], scan_id: str) -> int:
        """Import external findings into local store under a synthetic scan id."""
        if not findings:
            return 0
        self.save_scan(scan_id=scan_id, target="imported", tool="external", status="complete")
        imported = 0
        for finding in findings:
            if isinstance(finding, dict):
                self.save_finding(finding, scan_id=scan_id)
                imported += 1
        return imported
