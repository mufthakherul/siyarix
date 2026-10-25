# SPDX-License-Identifier: AGPL-3.0-or-later
"""SX-009: redact/canonicalize once before hashing so reload still verifies."""

from __future__ import annotations

import json

import pytest

from siyarix.audit_log import AuditEventType, AuditLogger, AuditSeverity


@pytest.fixture
def audit_logger(tmp_path, monkeypatch):
    monkeypatch.setattr("siyarix.config.get_config_dir", lambda: tmp_path)
    # Avoid SYSTEM_START noise for chain assertions where needed
    logger = AuditLogger(log_startup=False)
    yield logger
    with logger._lock:
        if logger._dirty:
            logger._save_events()


class TestSX009AuditCanonicalHash:
    def test_chain_verifies_after_reload(self, tmp_path, monkeypatch):
        monkeypatch.setattr("siyarix.config.get_config_dir", lambda: tmp_path)
        logger = AuditLogger(log_startup=False)
        logger.log(
            event_type=AuditEventType.CONFIG_CHANGE,
            severity=AuditSeverity.INFO,
            user="alice",
            action="update_setting",
            result="success",
            details={"setting": "theme", "value": "dark"},
        )
        logger.log(
            event_type=AuditEventType.API_KEY_CREATE,
            severity=AuditSeverity.MEDIUM,
            user="alice",
            action="create_key",
            result="success",
            details={"api_key": "sk-test-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "ci"},
        )
        before = logger.verify_chain()
        assert before["valid"] is True
        logger._save_events()

        # Reload from disk
        logger2 = AuditLogger(log_startup=False)
        after = logger2.verify_chain()
        assert after["valid"] is True, after.get("errors")
        assert after["total_events"] >= 2

    def test_hash_matches_persisted_representation(self, audit_logger, tmp_path):
        event = audit_logger.log(
            event_type=AuditEventType.AUTH_LOGIN,
            severity=AuditSeverity.INFO,
            user="bob",
            action="login",
            result="success",
            details={"password": "hunter2", "note": "ok"},
        )
        # Sensitive detail redacted once into the stored event
        assert event.details.get("password") == "[REDACTED]"
        assert event.hash_current == event.compute_hash(event.hash_prev)

        audit_logger._save_events()
        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        persisted = json.loads(lines[-1])
        assert persisted["details"]["password"] == "[REDACTED]"
        assert persisted["hash_current"] == event.hash_current

    def test_sensitive_user_redacted_before_hash(self, audit_logger):
        event = audit_logger.log(
            event_type=AuditEventType.AUTH_FAILED,
            severity=AuditSeverity.HIGH,
            user="token=AKIAIOSFODNN7EXAMPLE",
            action="login",
            result="failure",
            details={},
        )
        # User field hashed in its redacted form
        assert "[REDACTED]" in event.user or event.user != "token=AKIAIOSFODNN7EXAMPLE"
        assert event.hash_current == event.compute_hash(event.hash_prev)
