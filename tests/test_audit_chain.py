from phalanx.audit_log import AuditLogger, AuditSeverity, AuditEventType


def test_audit_chain_tamper_detection(tmp_path, monkeypatch):
    # Ensure AuditLogger uses a temporary config dir to avoid touching user's files
    monkeypatch.setattr(AuditLogger, "_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(AuditLogger, "_AUDIT_DB", tmp_path / "audit.json")
    monkeypatch.setattr(AuditLogger, "_AUDIT_LOG", tmp_path / "audit.log")

    logger = AuditLogger(log_startup=False)

    # Log a few events
    logger.log(
        event_type=AuditEventType.SYSTEM_START,
        severity=AuditSeverity.INFO,
        user="sys",
        action="start",
        result="ok",
    )
    logger.log(
        event_type=AuditEventType.SCAN_START,
        severity=AuditSeverity.INFO,
        user="alice",
        action="scan",
        result="started",
    )
    logger.log(
        event_type=AuditEventType.SCAN_COMPLETE,
        severity=AuditSeverity.INFO,
        user="alice",
        action="scan_complete",
        result="success",
    )

    # At this point the chain should be valid
    res = logger.verify_chain()
    assert res["valid"] is True

    # Tamper with the second event's previous hash to simulate corruption
    if len(logger._events) >= 2:
        logger._events[1].hash_prev = "deadbeef"

    res2 = logger.verify_chain()
    assert res2["valid"] is False
    assert res2["broken_at"] is not None
