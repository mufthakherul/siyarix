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
