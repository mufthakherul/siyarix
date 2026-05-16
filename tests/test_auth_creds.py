"""Tests for authentication, credential management, and audit logging."""

from __future__ import annotations

import json
from pathlib import Path

from siyarix.audit_log import AuditLogger
from siyarix.auth import AuthManager
from siyarix.credential_store import CredentialStore
from siyarix.profiles import ProfileStore


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


def test_credential_store_migration_and_roundtrip(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SIYARIX_MASTER_PASSWORD", "test-password")
    store = CredentialStore()

    legacy = tmp_path / "config.json"
    legacy.write_text(
        json.dumps(
            {
                "server_url": "http://localhost:8000",
                "api_key": "secret-key",
            }
        ),
        encoding="utf-8",
    )

    assert store.migrate_legacy_config(legacy) is True
    assert (tmp_path / "config.json.bak").exists()
    assert store.retrieve("default", "api_key") == "secret-key"
    assert store.retrieve("default", "server_url") == "http://localhost:8000"


def test_auth_profile_and_audit_flow(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SIYARIX_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SIYARIX_MASTER_PASSWORD", "test-password")

    def fake_get(url: str, headers: dict | None = None, timeout: float | None = None) -> _Resp:
        if url.endswith("/api/auth/me"):
            return _Resp(200, {"email": "agent@siyarix.dev", "org": "demo"})
        return _Resp(200, {"ok": True})

    monkeypatch.setattr("httpx.get", fake_get)

    auth = AuthManager()
    result = auth.login(
        profile="staging",
        server_url="http://localhost:8000",
        api_key="api-123",
        org_id="org-demo",
    )

    assert result["health"]["ok"] is True

    status = auth.status("staging")
    assert status["logged_in"] is True
    assert status["token_type"] == "api_key"

    profile = ProfileStore().get_profile("staging")
    assert profile is not None
    assert profile["org_id"] == "org-demo"

    audit = AuditLogger()
    audit.log(
        event_type="login",
        severity="info",
        user="agent@siyarix.dev",
        action="login",
        result="success",
        details={"profile": "staging"},
    )
    rows = audit.get_events(limit=5)
    assert rows
    assert any(r["action"] == "login" for r in rows)

    auth.logout("staging")
    assert CredentialStore().retrieve("staging", "api_key") is None
