"""Tests for CanaryTokenManager."""

from __future__ import annotations

from pathlib import Path

import pytest

from phalanx.canary import (CanaryDeployment, CanaryToken, CanaryTokenManager,
                            CanaryTokenType)

pytestmark = pytest.mark.canary


class TestCanaryTokenManager:
    @pytest.fixture
    def manager(self, tmp_path: Path):
        return CanaryTokenManager(storage_dir=tmp_path)

    def test_create_web_token(self, manager):
        token = manager.create_token(CanaryTokenType.WEB)
        assert token.token_id
        assert token.token_type == CanaryTokenType.WEB
        assert not token.triggered

    def test_create_dns_token(self, manager):
        token = manager.create_token(CanaryTokenType.DNS, location="test.example.com")
        assert token.location == "test.example.com"
        assert ".phalanx-alert.local" not in token.value

    def test_create_credential_token(self, manager):
        token = manager.create_token(
            CanaryTokenType.CREDENTIAL, description="SSH honeypot"
        )
        assert token.description == "SSH honeypot"
        assert ":" in token.value

    def test_get_token(self, manager):
        created = manager.create_token(CanaryTokenType.WEB)
        retrieved = manager.get_token(created.token_id)
        assert retrieved is not None
        assert retrieved.token_id == created.token_id

    def test_get_nonexistent_token(self, manager):
        assert manager.get_token("nonexistent") is None

    def test_trigger_token(self, manager):
        token = manager.create_token(CanaryTokenType.WEB)
        triggered = manager.trigger_token(token.token_id, source="192.168.1.100")
        assert triggered is not None
        assert triggered.triggered is True
        assert triggered.triggered_by == "192.168.1.100"

    def test_trigger_unknown_token(self, manager):
        assert manager.trigger_token("unknown") is None

    def test_list_tokens(self, manager):
        manager.create_token(CanaryTokenType.WEB)
        manager.create_token(CanaryTokenType.DNS)
        tokens = manager.list_tokens()
        assert len(tokens) == 2

    def test_list_triggered(self, manager):
        t1 = manager.create_token(CanaryTokenType.WEB)
        manager.create_token(CanaryTokenType.DNS)
        manager.trigger_token(t1.token_id)
        triggered = manager.list_triggered()
        assert len(triggered) == 1

    def test_delete_token(self, manager):
        token = manager.create_token(CanaryTokenType.WEB)
        assert manager.delete_token(token.token_id) is True
        assert manager.get_token(token.token_id) is None

    def test_delete_nonexistent(self, manager):
        assert manager.delete_token("nonexistent") is False

    def test_deploy_to_target(self, manager):
        deployment = manager.deploy_to_target("example.com")
        assert isinstance(deployment, CanaryDeployment)
        assert deployment.target == "example.com"
        assert len(deployment.tokens) > 0

    def test_alert_handler(self, manager):
        alerts = []

        def handler(token):
            alerts.append(token.token_id)

        manager.register_alert_handler(handler)
        token = manager.create_token(CanaryTokenType.WEB)
        manager.trigger_token(token.token_id)
        assert len(alerts) == 1

    def test_summary(self, manager):
        manager.create_token(CanaryTokenType.WEB)
        manager.create_token(CanaryTokenType.DNS)
        summary = manager.summary()
        assert summary["total_tokens"] == 2
        assert summary["active_tokens"] == 2

    def test_canary_token_dataclass(self):
        token = CanaryToken(
            token_id="test-123", token_type=CanaryTokenType.WEB, value="secret"
        )
        assert token.token_id == "test-123"
        assert not token.triggered

    def test_canary_deployment_dataclass(self):
        deployment = CanaryDeployment(target="example.com")
        assert len(deployment.tokens) == 0
        assert deployment.deployment_id
