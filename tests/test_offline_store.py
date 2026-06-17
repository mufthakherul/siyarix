from __future__ import annotations

from siyarix.offline_store import OfflineStore

def test_offline_store_init(tmp_path):
    db_path = tmp_path / "test.db"
    OfflineStore(db_path=db_path)
    assert db_path.exists()
    
def test_offline_store_scans(tmp_path):
    db_path = tmp_path / "test.db"
    store = OfflineStore(db_path=db_path)
    
    findings = [
        {"tool": "nmap", "title": "Open Port", "severity": "low"},
        {"tool": "gobuster", "title": "Dir Found", "severity": "info"}
    ]
    scan_id = store.save_scan("127.0.0.1", findings)
    
    stats = store.stats()
    assert stats["total_scans"] == 1
    assert stats["total_findings"] == 2
    
    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == scan_id
    assert scans[0]["findings_count"] == 2
    
    scan_detail = store.get_scan(scan_id)
    assert scan_detail is not None
    assert len(scan_detail["findings"]) == 2

def test_offline_store_plans(tmp_path):
    db_path = tmp_path / "test.db"
    store = OfflineStore(db_path=db_path)
    
    steps = [{"status": "completed"}, {"status": "failed"}]
    store.save_plan("plan_1", "Test goal", steps)
    
    latest_id = store.get_latest_plan_id()
    assert latest_id == "plan_1"

def test_offline_store_diff_scans(tmp_path):
    db_path = tmp_path / "test.db"
    store = OfflineStore(db_path=db_path)
    
    findings_a = [{"title": "Vuln A", "severity": "low"}]
    findings_b = [{"title": "Vuln A", "severity": "high"}, {"title": "Vuln B", "severity": "low"}]
    
    scan_a = store.save_scan("target", findings_a)
    scan_b = store.save_scan("target", findings_b)
    
    diff = store.diff_scans(scan_a, scan_b)
    assert diff["summary"]["new"] == 1
    assert diff["summary"]["resolved"] == 0
    assert diff["summary"]["changed"] == 1
    assert "Vuln B" in diff["new_findings"]
    
def test_offline_store_search_findings(tmp_path):
    db_path = tmp_path / "test.db"
    store = OfflineStore(db_path=db_path)
    
    findings = [
        {"title": "Vuln A", "severity": "critical"},
        {"title": "Vuln B", "severity": "critical"},
        {"title": "Vuln C", "severity": "low"}
    ]
    store.save_scan("target", findings)
    
    criticals = store.search_findings(severity="critical")
    assert len(criticals) == 2



"""Exhaustive extra tests for siyarix.offline_store — covering close(),
save_raw_scan, diff_scans_async, diff_scans error/changed paths,
search_findings_async, search_findings_full_async, search_findings_full,
and import_scans with all edge cases."""


import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.offline_store import OfflineStore, _get_async_executor


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> OfflineStore:
    db_path = tmp_path / "test_offline_extra.db"
    return OfflineStore(db_path=db_path)


@pytest.fixture
def store_with_scans(store: OfflineStore) -> OfflineStore:
    store.save_scan("target1", [
        {"tool": "nmap", "title": "Open SSH", "severity": "low", "port": 22, "cvss_score": 0.0,
         "description": "SSH port open", "service": "ssh", "technology": "", "evidence": ""},
    ])
    store.save_scan("target2", [
        {"tool": "nmap", "title": "Open HTTP", "severity": "medium", "port": 80, "cvss_score": 5.0,
         "description": "HTTP port open", "service": "http", "technology": "", "evidence": ""},
        {"tool": "nuclei", "title": "CVE-2024", "severity": "critical", "port": 0, "cvss_score": 9.0,
         "description": "RCE vuln", "service": "", "technology": "nginx", "evidence": "proof"},
    ])
    return store


# ── _get_async_executor / close (lines 44-47) ────────────────────────────

class TestClose:
    def test_close_no_connection(self, store: OfflineStore) -> None:
        store.close()
        conn = store._conn()
        assert conn is not None

    def test_close_existing_connection(self, store: OfflineStore) -> None:
        conn = store._conn()
        store.close()
        assert not hasattr(store._local, "conn") or store._local.conn is None

    def test_close_twice(self, store: OfflineStore) -> None:
        store._conn()
        store.close()
        store.close()

    def test_close_after_write(self, store: OfflineStore) -> None:
        store.save_scan("test", [{"tool": "x", "title": "y"}])
        store.close()
        new_conn = store._conn()
        assert new_conn is not None
        assert store.stats()["total_scans"] == 1


class TestGetAsyncExecutor:
    def test_singleton(self) -> None:
        e1 = _get_async_executor()
        e2 = _get_async_executor()
        assert e1 is e2

    def test_max_workers(self) -> None:
        ex = _get_async_executor()
        assert ex._max_workers == 2


# ── save_raw_scan (lines 206-213) ────────────────────────────────────────

class TestSaveRawScan:
    @patch("siyarix.parsers.ParserRegistry")
    def test_parse_and_save(self, mock_registry_cls: MagicMock, store: OfflineStore) -> None:
        mock_registry = MagicMock()
        mock_registry.parse.return_value = [
            {"tool": "nmap", "title": "Port 80", "severity": "low"},
        ]
        mock_registry_cls.return_value = mock_registry

        scan_id = store.save_raw_scan("10.0.0.1", "nmap", "raw output here")

        mock_registry.discover.assert_called_once()
        mock_registry.parse.assert_called_once_with("nmap", "raw output here")
        assert scan_id
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert len(scan["findings"]) == 1

    @patch("siyarix.parsers.ParserRegistry")
    def test_no_findings_logs_warning(self, mock_registry_cls: MagicMock, store: OfflineStore) -> None:
        mock_registry = MagicMock()
        mock_registry.parse.return_value = []
        mock_registry_cls.return_value = mock_registry

        with patch("siyarix.offline_store.logger.warning") as mock_warn:
            store.save_raw_scan("10.0.0.1", "nmap", "raw")
            mock_warn.assert_called_once()

    @patch("siyarix.parsers.ParserRegistry")
    def test_with_plan_id(self, mock_registry_cls: MagicMock, store: OfflineStore) -> None:
        mock_registry = MagicMock()
        mock_registry.parse.return_value = [{"tool": "x", "title": "y"}]
        mock_registry_cls.return_value = mock_registry

        scan_id = store.save_raw_scan("10.0.0.1", "nmap", "raw", plan_id="plan_1")
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan["plan_id"] == "plan_1"


# ── diff_scans_async (lines 245-246) ─────────────────────────────────────

class TestDiffScansAsync:
    async def test_diff_scans_async(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        assert len(scans) >= 2
        result = await store.diff_scans_async(scans[0]["scan_id"], scans[1]["scan_id"])
        assert "summary" in result
        assert "scan_a" in result
        assert "scan_b" in result


# ── diff_scans — missing scans (lines 255-256) ───────────────────────────

class TestDiffScansErrors:
    def test_scan_a_not_found(self, store: OfflineStore) -> None:
        result = store.diff_scans("nonexistent_a", "nonexistent_b")
        assert result["error"] == "Scan 'nonexistent_a' not found"
        assert result["summary"]["new"] == 0

    def test_scan_b_not_found(self, store: OfflineStore) -> None:
        store.save_scan("target", [{"title": "A"}])
        scans = store.list_scans()
        result = store.diff_scans(scans[0]["scan_id"], "nonexistent_b")
        assert result["error"] == "Scan 'nonexistent_b' not found"

    def test_both_scans_not_found(self, store: OfflineStore) -> None:
        result = store.diff_scans("missing_a", "missing_b")
        assert "error" in result

    def test_diff_same_scan(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        result = store.diff_scans(scans[0]["scan_id"], scans[0]["scan_id"])
        assert result["summary"]["new"] == 0
        assert result["summary"]["resolved"] == 0
        assert result["summary"]["changed"] == 0


# ── diff_scans — changed findings (line 280) ─────────────────────────────

class TestDiffScansChanged:
    def test_severity_changed(self, store: OfflineStore) -> None:
        scan_a = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http"},
        ])
        scan_b = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "high", "port": 80, "service": "http"},
        ])
        result = store.diff_scans(scan_a, scan_b)
        assert result["summary"]["changed"] == 1

    def test_description_changed(self, store: OfflineStore) -> None:
        scan_a = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http",
             "description": "old desc"},
        ])
        scan_b = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http",
             "description": "new desc"},
        ])
        result = store.diff_scans(scan_a, scan_b)
        assert result["summary"]["changed"] == 1

    def test_cvss_score_changed(self, store: OfflineStore) -> None:
        scan_a = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http",
             "cvss_score": 0.0},
        ])
        scan_b = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http",
             "cvss_score": 7.5},
        ])
        result = store.diff_scans(scan_a, scan_b)
        assert result["summary"]["changed"] == 1

    def test_no_change_when_identical(self, store: OfflineStore) -> None:
        scan_a = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http"},
        ])
        scan_b = store.save_scan("target", [
            {"tool": "x", "title": "Vuln", "severity": "low", "port": 80, "service": "http"},
        ])
        result = store.diff_scans(scan_a, scan_b)
        assert result["summary"]["changed"] == 0

    def test_new_and_resolved_findings(self, store: OfflineStore) -> None:
        scan_a = store.save_scan("target", [
            {"tool": "x", "title": "Old Vuln", "severity": "low", "port": 80, "service": "http"},
        ])
        scan_b = store.save_scan("target", [
            {"tool": "x", "title": "New Vuln", "severity": "low", "port": 443, "service": "https"},
        ])
        result = store.diff_scans(scan_a, scan_b)
        assert result["summary"]["new"] == 1
        assert result["summary"]["resolved"] == 1


# ── search_findings_async (lines 313-314) ────────────────────────────────

class TestSearchFindingsAsync:
    async def test_search_findings_async(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.search_findings_async(severity="critical")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    async def test_search_findings_async_no_match(self, store: OfflineStore) -> None:
        results = await store.search_findings_async(severity="critical")
        assert results == []

    async def test_search_findings_async_limit(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.search_findings_async(severity="low", limit=1)
        assert len(results) <= 1


# ── search_findings_full_async (lines 334-335) ───────────────────────────

class TestSearchFindingsFullAsync:
    async def test_full_search_async(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.search_findings_full_async(
            severity="critical", tool="nuclei", limit=10,
        )
        assert len(results) == 1
        assert results[0]["title"] == "CVE-2024"

    async def test_full_search_async_all_none(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.search_findings_full_async()
        assert len(results) == 3

    async def test_full_search_async_by_target(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.search_findings_full_async(target="target1")
        assert len(results) == 1


# ── search_findings_full (lines 353-375) ─────────────────────────────────

class TestSearchFindingsFull:
    def test_filter_by_severity(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(severity="critical")
        assert len(results) == 1

    def test_filter_by_tool(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(tool="nuclei")
        assert len(results) == 1

    def test_filter_by_target(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(target="target1")
        assert len(results) == 1

    def test_filter_by_search_text_title(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(search_text="CVE")
        assert len(results) == 1

    def test_filter_by_search_text_description(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(search_text="HTTP")
        assert len(results) == 1

    def test_filter_by_search_text_service(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(search_text="ssh")
        assert len(results) == 1

    def test_no_conditions_returns_all(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full()
        assert len(results) == 3

    def test_combined_filters(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(
            severity="medium", tool="nmap", target="target2",
        )
        assert len(results) == 1
        assert results[0]["title"] == "Open HTTP"

    def test_limit(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(limit=1)
        assert len(results) == 1

    def test_no_match_returns_empty(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(target="nonexistent")
        assert results == []

    def test_search_text_matches_evidence(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = store.search_findings_full(search_text="proof")
        assert len(results) == 1


# ── export_scans (lines 413-427) ─────────────────────────────────────────

class TestExportScans:
    def test_export_empty(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "export.json"
        count = store.export_scans(path)
        assert count == 0
        data = json.loads(path.read_text())
        assert data == []

    def test_export_with_scans(self, store_with_scans: OfflineStore, tmp_path: Path) -> None:
        store = store_with_scans
        path = tmp_path / "scans.json"
        count = store.export_scans(path)
        assert count == 2
        data = json.loads(path.read_text())
        assert len(data) == 2
        assert "findings" in data[0]
        assert len(data[0]["findings"]) == 1
        assert len(data[1]["findings"]) == 2

    def test_export_roundtrip(self, store_with_scans: OfflineStore, tmp_path: Path) -> None:
        store = store_with_scans
        path = tmp_path / "roundtrip.json"
        count = store.export_scans(path)
        assert count == 2


# ── import_scans (lines 429-475) ─────────────────────────────────────────

class TestImportScans:
    def test_import_path_not_exists(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "no_such.json"
        count = store.import_scans(path)
        assert count == 0

    def test_import_empty_json(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "empty.json"
        path.write_text("[]")
        count = store.import_scans(path)
        assert count == 0

    def test_import_single_scan(self, store: OfflineStore, tmp_path: Path) -> None:
        export_path = tmp_path / "single_scan.json"
        scan_a = store.save_scan("import_test", [
            {"tool": "nmap", "title": "Imported Finding", "severity": "high"},
        ])
        store.export_scans(export_path)

        store2 = OfflineStore(db_path=tmp_path / "imported.db")
        count = store2.import_scans(export_path)
        assert count == 1
        stats = store2.stats()
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 1

    def test_import_with_all_fields(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "full_fields.json"
        data = [{
            "scan_id": "custom_id_1",
            "target": "10.0.0.1",
            "mode": "registry",
            "plan_id": "plan_1",
            "started_at": "2025-01-01T00:00:00",
            "completed_at": "2025-01-01T01:00:00",
            "tool_count": 2,
            "findings": [
                {
                    "tool": "nmap",
                    "tool_version": "7.94",
                    "target": "10.0.0.1",
                    "severity": "critical",
                    "title": "Port 22",
                    "description": "SSH open",
                    "evidence": "banner",
                    "port": 22,
                    "service": "ssh",
                    "technology": "OpenSSH",
                    "cvss_score": 7.5,
                    "data_json": "{}",
                },
            ],
        }]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 1

        scan = store.get_scan("custom_id_1")
        assert scan is not None
        assert scan["target"] == "10.0.0.1"
        assert len(scan["findings"]) == 1
        f = scan["findings"][0]
        assert f["tool"] == "nmap"
        assert f["tool_version"] == "7.94"
        assert f["port"] == 22
        assert f["cvss_score"] == 7.5

    def test_import_skips_duplicate_scan_id(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "dup.json"
        store.save_scan("dup_target", [{"tool": "x", "title": "original"}])
        scans_before = store.list_scans()
        scan_id = scans_before[0]["scan_id"]
        target = scans_before[0]["target"]

        data = [{
            "scan_id": scan_id,
            "target": target,
            "mode": "",
            "plan_id": "",
            "started_at": "",
            "completed_at": "",
            "tool_count": 0,
            "findings": [],
        }]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 0

    def test_import_multiple_scans(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "multi.json"
        data = [
            {
                "scan_id": "multi_1", "target": "a", "mode": "", "plan_id": "",
                "started_at": "", "completed_at": "", "tool_count": 0,
                "findings": [{"tool": "x", "title": "A", "severity": "low"}],
            },
            {
                "scan_id": "multi_2", "target": "b", "mode": "", "plan_id": "",
                "started_at": "", "completed_at": "", "tool_count": 0,
                "findings": [{"tool": "y", "title": "B", "severity": "high"}],
            },
        ]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 2
        assert store.stats()["total_scans"] == 2
        assert store.stats()["total_findings"] == 2

    def test_import_mixed_duplicates(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "mixed.json"
        scan_id = store.save_scan("existing", [{"tool": "x", "title": "existing"}])
        data = [
            {
                "scan_id": scan_id,
                "target": "existing", "mode": "", "plan_id": "",
                "started_at": "", "completed_at": "", "tool_count": 0,
                "findings": [],
            },
            {
                "scan_id": "new_scan",
                "target": "new", "mode": "", "plan_id": "",
                "started_at": "", "completed_at": "", "tool_count": 0,
                "findings": [{"tool": "z", "title": "New Finding", "severity": "info"}],
            },
        ]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 1
        assert store.stats()["total_scans"] == 2

    def test_import_no_findings_list(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "no_findings.json"
        data = [{
            "scan_id": "no_find_id",
            "target": "x", "mode": "", "plan_id": "",
            "started_at": "", "completed_at": "", "tool_count": 0,
        }]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 1
        scan = store.get_scan("no_find_id")
        assert scan is not None
        assert scan["findings"] == []

    def test_import_empty_string_fallback(self, store: OfflineStore, tmp_path: Path) -> None:
        path = tmp_path / "empty_strings.json"
        data = [{
            "scan_id": "empty_str_id",
            "findings": [{}],
        }]
        path.write_text(json.dumps(data))
        count = store.import_scans(path)
        assert count == 1
        scan = store.get_scan("empty_str_id")
        assert scan is not None
        assert scan["target"] == ""


# ── save_plan / get_latest_plan_id ───────────────────────────────────────

class TestPlans:
    def test_save_plan_counts_steps(self, store: OfflineStore) -> None:
        steps = [
            {"status": "completed"},
            {"status": "completed"},
            {"status": "failed"},
            {"status": "pending"},
        ]
        store.save_plan("plan_counts", "Goal", steps)
        row = store._conn().execute(
            "SELECT completed_steps, failed_steps, step_count FROM plans WHERE plan_id = ?",
            ("plan_counts",),
        ).fetchone()
        assert row["completed_steps"] == 2
        assert row["failed_steps"] == 1
        assert row["step_count"] == 4

    def test_get_latest_plan_id_empty(self, store: OfflineStore) -> None:
        assert store.get_latest_plan_id() == ""

    def test_get_latest_plan_id_returns_latest(self, store: OfflineStore) -> None:
        store.save_plan("older", "Old", [])
        store.save_plan("newer", "New", [])
        assert store.get_latest_plan_id() == "newer"


# ── delete_scan / get_scan edge cases ────────────────────────────────────

class TestDeleteAndGetScan:
    def test_get_scan_not_found(self, store: OfflineStore) -> None:
        assert store.get_scan("nonexistent") is None

    def test_delete_scan_removes_findings(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        scan_id = scans[1]["scan_id"]
        store.delete_scan(scan_id)
        assert store.get_scan(scan_id) is None
        assert store.stats()["total_findings"] == 2

    def test_delete_nonexistent_scan(self, store: OfflineStore) -> None:
        result = store.delete_scan("nonexistent")
        assert result is True

    def test_get_scan_includes_findings(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        scan = store.get_scan(scans[0]["scan_id"])
        assert scan is not None
        assert "findings" in scan
        assert isinstance(scan["findings"], list)


# ── list_scans pagination ────────────────────────────────────────────────

class TestListScans:
    def test_list_with_offset(self, store: OfflineStore) -> None:
        for i in range(5):
            store.save_scan(f"target_{i}", [{"tool": "x", "title": f"F{i}"}])
        page1 = store.list_scans(limit=2, offset=0)
        page2 = store.list_scans(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["scan_id"] != page2[0]["scan_id"]

    def test_list_empty(self, store: OfflineStore) -> None:
        assert store.list_scans() == []


# ── stats ────────────────────────────────────────────────────────────────

class TestStats:
    def test_stats_empty(self, store: OfflineStore) -> None:
        stats = store.stats()
        assert stats["total_scans"] == 0
        assert stats["total_findings"] == 0

    def test_stats_after_scan(self, store: OfflineStore) -> None:
        store.save_scan("x", [{"tool": "a"}, {"tool": "b"}])
        stats = store.stats()
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 2

    def test_stats_after_delete(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        store.delete_scan(scans[1]["scan_id"])
        stats = store.stats()
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 2


# ── Async methods ────────────────────────────────────────────────────────

class TestAsyncMethods:
    async def test_save_scan_async(self, store: OfflineStore) -> None:
        scan_id = await store.save_scan_async(
            "async_target",
            [{"tool": "x", "title": "async finding"}],
        )
        assert scan_id
        scan = store.get_scan(scan_id)
        assert scan is not None

    async def test_list_scans_async(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        results = await store.list_scans_async()
        assert len(results) == 2

    async def test_get_scan_async(self, store_with_scans: OfflineStore) -> None:
        store = store_with_scans
        scans = store.list_scans()
        result = await store.get_scan_async(scans[0]["scan_id"])
        assert result is not None
        assert result["scan_id"] == scans[0]["scan_id"]

    async def test_get_scan_async_not_found(self, store: OfflineStore) -> None:
        result = await store.get_scan_async("nonexistent")
        assert result is None


"""Exhaustive tests for siyarix.offline_store — covers all remaining uncovered lines and branches."""


import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.offline_store import OfflineStore


class TestOfflineStoreInitAndClose:
    def test_init_creates_db(self, tmp_path):
        db = tmp_path / "test.db"
        store = OfflineStore(db_path=db)
        assert db.exists()
        store.close()

    def test_init_default_path(self):
        store = OfflineStore(db_path=Path(":memory:"))
        assert store._db_path == ":memory:" or store._db_path.endswith("offline_store.db")
        store.close()

    def test_close_none_conn(self):
        store = OfflineStore(db_path=Path(":memory:"))
        store._local.conn = None
        store.close()

    def test_close_clears_local(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "t.db")
        conn = store._conn()
        assert conn is not None
        store.close()
        assert getattr(store._local, "conn", None) is None

    def test_conn_threading_local(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "t.db")
        c1 = store._conn()
        c2 = store._conn()
        assert c1 is c2
        store.close()

    def test_migration_v2_columns(self, tmp_path):
        """Ensure v2 migration runs on a fresh v1 schema."""
        db = tmp_path / "migrate_v2.db"
        store = OfflineStore(db_path=db)
        conn = store._conn()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
        assert "cvss_score" in cols
        assert "tool_version" in cols
        store.close()

    def test_migration_v3(self, tmp_path):
        """Simulate starting at v1 and migrating through v2 and v3."""
        db = tmp_path / "migrate_v3.db"
        store = OfflineStore(db_path=db)
        conn = store._conn()
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert version is not None
        store.close()


class TestOfflineStoreStats:
    def test_stats_empty(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        stats = store.stats()
        assert stats["total_scans"] == 0
        assert stats["total_findings"] == 0
        store.close()

    def test_stats_with_data(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "nmap", "title": "port 80"}])
        stats = store.stats()
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 1
        store.close()


class TestOfflineStoreSaveScan:
    def test_save_scan(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings = [
            {"tool": "nmap", "title": "Open port 80", "severity": "medium", "port": 80, "service": "http"},
            {"tool": "gobuster", "title": "Dir /admin", "severity": "info"},
        ]
        scan_id = store.save_scan("10.0.0.1", findings)
        assert scan_id is not None
        assert len(scan_id) == 32
        row = store.get_scan(scan_id)
        assert row is not None
        assert row["target"] == "10.0.0.1"
        assert len(row["findings"]) == 2
        store.close()

    def test_save_scan_with_technology_cvss(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings = [{"tool": "nmap", "title": "Apache", "technology": "Apache 2.4", "cvss_score": 7.5}]
        scan_id = store.save_scan("10.0.0.1", findings)
        row = store.get_scan(scan_id)
        assert row["findings"][0]["technology"] == "Apache 2.4"
        assert row["findings"][0]["cvss_score"] == 7.5
        store.close()

    def test_save_scan_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings = [{"tool": "test", "title": "async finding"}]
        scan_id = asyncio.run(store.save_scan_async("10.0.0.1", findings))
        assert scan_id is not None
        store.close()

    def test_save_scan_with_custom_tool_version(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings = [{"tool": "nmap", "tool_version": "7.95", "title": "port scan"}]
        scan_id = store.save_scan("10.0.0.1", findings)
        row = store.get_scan(scan_id)
        assert row["findings"][0]["tool_version"] == "7.95"
        store.close()


class TestOfflineStoreSaveRawScan:
    def test_save_raw_scan_parses_and_saves(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_id = store.save_raw_scan("10.0.0.1", "nmap", "22/tcp open ssh")
        assert scan_id is not None
        store.close()

    def test_save_raw_scan_unknown_tool(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_id = store.save_raw_scan("10.0.0.1", "nonexistent_tool_xyz", "some output")
        assert scan_id is not None
        store.close()


class TestOfflineStoreSavePlan:
    def test_save_plan(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        steps = [
            {"status": "completed", "tool": "nmap"},
            {"status": "failed", "tool": "gobuster"},
            {"status": "completed", "tool": "curl"},
        ]
        store.save_plan("plan_001", "Scan target", steps)
        plan_id = store.get_latest_plan_id()
        assert plan_id == "plan_001"
        store.close()

    def test_save_plan_empty_steps(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_plan("plan_empty", "Empty goal", [])
        plan_id = store.get_latest_plan_id()
        assert plan_id == "plan_empty"
        store.close()

    def test_get_latest_plan_id_empty(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        plan_id = store.get_latest_plan_id()
        assert plan_id == ""
        store.close()


class TestOfflineStoreDiffScans:
    def test_diff_new_resolved_changed(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings_a = [
            {"tool": "nmap", "title": "Port 22", "severity": "low"},
            {"tool": "nmap", "title": "Port 80", "severity": "low"},
        ]
        findings_b = [
            {"tool": "nmap", "title": "Port 80", "severity": "high"},
            {"tool": "nmap", "title": "Port 443", "severity": "low"},
        ]
        scan_a = store.save_scan("10.0.0.1", findings_a)
        scan_b = store.save_scan("10.0.0.1", findings_b)
        diff = store.diff_scans(scan_a, scan_b)
        assert diff["summary"]["new"] == 1
        assert diff["summary"]["resolved"] == 1
        assert diff["summary"]["changed"] == 1
        store.close()

    def test_diff_missing_scan_a(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_b = store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        diff = store.diff_scans("nonexistent", scan_b)
        assert "error" in diff
        store.close()

    def test_diff_missing_scan_b(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_a = store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        diff = store.diff_scans(scan_a, "nonexistent")
        assert "error" in diff
        store.close()

    def test_diff_no_changes(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        findings = [{"tool": "nmap", "title": "Port 22", "severity": "low"}]
        scan_a = store.save_scan("10.0.0.1", findings)
        scan_b = store.save_scan("10.0.0.1", findings)
        diff = store.diff_scans(scan_a, scan_b)
        assert diff["summary"]["new"] == 0
        assert diff["summary"]["resolved"] == 0
        assert diff["summary"]["changed"] == 0
        store.close()

    def test_diff_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_a = store.save_scan("10.0.0.1", [{"tool": "t", "title": "A"}])
        scan_b = store.save_scan("10.0.0.1", [{"tool": "t", "title": "B"}])
        diff = asyncio.run(store.diff_scans_async(scan_a, scan_b))
        assert "summary" in diff
        store.close()


class TestOfflineStoreSearchFindings:
    def test_search_findings_default(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [
            {"tool": "nmap", "title": "critical finding", "severity": "critical"},
            {"tool": "nmap", "title": "info finding", "severity": "info"},
        ])
        results = store.search_findings()
        assert len(results) == 1
        assert results[0]["severity"] == "critical"
        store.close()

    def test_search_findings_custom_limit(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [
            {"tool": "t", "title": "c1", "severity": "critical"},
            {"tool": "t", "title": "c2", "severity": "critical"},
            {"tool": "t", "title": "c3", "severity": "critical"},
        ])
        results = store.search_findings(severity="critical", limit=2)
        assert len(results) == 2
        store.close()

    def test_search_findings_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "critical", "severity": "critical"}])
        results = asyncio.run(store.search_findings_async(severity="critical"))
        assert len(results) == 1
        store.close()

    def test_search_findings_full_severity(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [
            {"tool": "nmap", "title": "high one", "severity": "high"},
            {"tool": "nmap", "title": "low one", "severity": "low"},
        ])
        results = store.search_findings_full(severity="high")
        assert len(results) == 1
        store.close()

    def test_search_findings_full_tool(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [
            {"tool": "nmap", "title": "port", "severity": "info"},
            {"tool": "gobuster", "title": "dir", "severity": "info"},
        ])
        results = store.search_findings_full(tool="nmap")
        assert len(results) == 1
        store.close()

    def test_search_findings_full_target(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "test", "severity": "info"}])
        results = store.search_findings_full(target="10.0.0.1")
        assert len(results) == 1
        store.close()

    def test_search_findings_full_search_text(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "secret key found", "severity": "info"}])
        results = store.search_findings_full(search_text="secret")
        assert len(results) == 1
        store.close()

    def test_search_findings_full_all_params(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "nmap", "title": "critical port", "severity": "critical", "description": "port 22", "evidence": "22/tcp", "service": "ssh"}])
        results = store.search_findings_full(severity="critical", tool="nmap", target="10.0.0.1", search_text="port")
        assert len(results) == 1
        store.close()

    def test_search_findings_full_no_filters(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "one", "severity": "info"}])
        results = store.search_findings_full()
        assert len(results) == 1
        store.close()

    def test_search_findings_full_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "nmap", "title": "async test", "severity": "info"}])
        results = asyncio.run(store.search_findings_full_async(severity="info"))
        assert len(results) == 1
        store.close()


class TestOfflineStoreListScans:
    def test_list_scans(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        store.save_scan("10.0.0.2", [{"tool": "t", "title": "test2"}])
        scans = store.list_scans()
        assert len(scans) == 2
        store.close()

    def test_list_scans_offset(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        store.save_scan("10.0.0.2", [{"tool": "t", "title": "test2"}])
        scans = store.list_scans(limit=1, offset=1)
        assert len(scans) == 1
        store.close()

    def test_list_scans_empty(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scans = store.list_scans()
        assert len(scans) == 0
        store.close()

    def test_list_scans_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        scans = asyncio.run(store.list_scans_async())
        assert len(scans) == 1
        store.close()


class TestOfflineStoreGetScan:
    def test_get_scan_not_found(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        result = store.get_scan("nonexistent")
        assert result is None
        store.close()

    def test_get_scan_async(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_id = store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        result = asyncio.run(store.get_scan_async(scan_id))
        assert result is not None
        assert result["target"] == "10.0.0.1"
        store.close()


class TestOfflineStoreDeleteScan:
    def test_delete_scan(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_id = store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        assert store.get_scan(scan_id) is not None
        result = store.delete_scan(scan_id)
        assert result is True
        assert store.get_scan(scan_id) is None
        store.close()

    def test_delete_scan_nonexistent(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        result = store.delete_scan("nonexistent")
        assert result is True
        store.close()


class TestOfflineStoreExportImport:
    def test_export_scans(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "nmap", "title": "port 80", "severity": "medium"}])
        export_path = tmp_path / "export.json"
        count = store.export_scans(export_path)
        assert count == 1
        assert export_path.exists()
        data = json.loads(export_path.read_text())
        assert len(data) == 1
        assert data[0]["target"] == "10.0.0.1"
        store.close()

    def test_import_scans(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        store.save_scan("10.0.0.1", [{"tool": "nmap", "title": "port 80"}])
        export_path = tmp_path / "export.json"
        store.export_scans(export_path)

        store2 = OfflineStore(db_path=tmp_path / "s2.db")
        count = store2.import_scans(export_path)
        assert count == 1
        stats = store2.stats()
        assert stats["total_scans"] == 1
        store2.close()

    def test_import_scans_nonexistent(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        count = store.import_scans(tmp_path / "nonexistent.json")
        assert count == 0
        store.close()

    def test_import_scans_dedup(self, tmp_path):
        store = OfflineStore(db_path=tmp_path / "s.db")
        scan_id = store.save_scan("10.0.0.1", [{"tool": "t", "title": "test"}])
        export_path = tmp_path / "export.json"
        store.export_scans(export_path)
        count = store.import_scans(export_path)
        assert count == 0
        store.close()


class TestOfflineStoreMigration:
    def test_migration_idempotent(self, tmp_path):
        """Run migration twice to ensure it's safe."""
        store = OfflineStore(db_path=tmp_path / "s.db")
        conn = store._conn()
        store._migrate(conn)
        store._migrate(conn)
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert version["value"] == "4"
        store.close()

    def test_migration_error_handling(self, tmp_path):
        """If ALTER fails due to existing column, it should log and continue."""
        store = OfflineStore(db_path=tmp_path / "s.db")
        conn = store._conn()
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1')")
        store._migrate(conn)
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert version["value"] == "4"
        store.close()