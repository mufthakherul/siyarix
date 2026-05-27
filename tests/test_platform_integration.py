from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.platform_integration import (
    BOUNTY_PLATFORMS,
    COMMS_PLATFORMS,
    SIEM_PLATFORMS,
    PlatformIntegrationService,
    platform_integration,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    PlatformIntegrationService._instance = None  # type: ignore
    yield


@pytest.fixture
def service(tmp_path):
    s = PlatformIntegrationService()
    s._dir = tmp_path
    s._dir.mkdir(parents=True, exist_ok=True)
    s._bounty_connections = {}
    s._siem_connections = {}
    s._notification_channels = []
    return s


class TestPlatformIntegrationService:
    def test_init_creates_dir(self, tmp_path):
        s = PlatformIntegrationService()
        assert s._dir.exists()

    def test_connect_bounty_unsupported(self, service):
        conn = service.connect_bounty("unknown", api_key="key")
        assert conn.connected is False
        assert "Unsupported" in conn.error

    def test_connect_bounty_supported(self, service):
        conn = service.connect_bounty("hackerone", api_key="key", username="testuser")
        assert conn.connected is True
        assert conn.username == "testuser"
        assert "hackerone" in service._bounty_connections

    def test_connect_bounty_default_username(self, service):
        conn = service.connect_bounty("bugcrowd", api_key="key")
        assert conn.username == "anonymous"

    def test_submit_finding_not_connected(self, service):
        result = service.submit_finding("hackerone", "some-program", {"vuln": "xss"})
        assert result.success is False
        assert "Not connected" in result.error

    def test_submit_finding_connected(self, service):
        service.connect_bounty("hackerone", api_key="key")
        result = service.submit_finding("hackerone", "test-program", {"vuln": "xss"})
        assert result.success is True
        assert result.external_id.startswith("HA-")
        assert result.status == "Triaged"

    def test_connect_siem_unsupported(self, service):
        conn = service.connect_siem("unknown", url="http://siem")
        assert conn.connected is False
        assert "Unsupported" in conn.error

    def test_connect_siem_supported(self, service):
        conn = service.connect_siem("splunk", url="http://splunk:8088", token="tok")
        assert conn.connected is True
        assert conn.username == "http://splunk:8088"

    def test_forward_finding_to_siem_no_connections(self, service):
        assert service.forward_finding_to_siem({"description": "test"}) is False

    def test_forward_finding_to_siem_connected(self, service):
        service.connect_siem("splunk", url="http://splunk")
        assert service.forward_finding_to_siem({"description": "test"}) is True

    def test_add_notification_channel(self, service):
        channel = service.add_notification_channel("slack", webhook_url="https://hooks.slack.com/abc")
        assert channel.platform == "slack"
        assert channel.enabled is True
        assert len(service._notification_channels) == 1

    def test_remove_notification_channel_existing(self, service):
        service.add_notification_channel("slack", webhook_url="url")
        result = service.remove_notification_channel("slack")
        assert result is True
        assert len(service._notification_channels) == 0

    def test_remove_notification_channel_not_found(self, service):
        assert service.remove_notification_channel("nonexistent") is False

    def test_remove_notification_channel_case_insensitive(self, service):
        service.add_notification_channel("Slack", webhook_url="url")
        assert service.remove_notification_channel("SLACK") is True

    def test_list_notification_channels(self, service):
        service.add_notification_channel("slack")
        service.add_notification_channel("discord")
        channels = service.list_notification_channels()
        assert len(channels) == 2

    def test_send_notification_no_channels(self, service):
        assert service.send_notification("test message") == 0

    def test_send_notification_with_channels(self, service):
        service.add_notification_channel("slack", webhook_url="url")
        service.add_notification_channel("teams", webhook_url="url2")
        sent = service.send_notification("important message", severity="high")
        assert sent == 2

    def test_send_notification_disabled_channel(self, service):
        channel = service.add_notification_channel("slack", webhook_url="url")
        channel.enabled = False
        sent = service.send_notification("message")
        assert sent == 0

    def test_summary(self, service):
        service.connect_bounty("hackerone", api_key="key")
        service.connect_siem("splunk", url="http://splunk")
        service.add_notification_channel("slack", webhook_url="url")
        summary = service.summary()
        assert summary["bounty_connections"] == 1
        assert summary["siem_connections"] == 1
        assert "slack" in summary["notification_channels"]

    def test_save_and_load_persistence(self, tmp_path):
        s1 = PlatformIntegrationService()
        s1._dir = tmp_path
        s1.connect_bounty("hackerone", api_key="key", username="user1")
        s2 = PlatformIntegrationService()
        s2._dir = tmp_path
        s2._load()
        assert "hackerone" in s2._bounty_connections
        assert s2._bounty_connections["hackerone"].username == "user1"

    def test_load_corrupt_file(self, tmp_path):
        f = tmp_path / "integrations.json"
        f.write_text("corrupt json", encoding="utf-8")
        s = PlatformIntegrationService()
        s._dir = tmp_path
        s._load()

    def test_save_failure_logged(self, service):
        with patch.object(Path, "write_text", side_effect=PermissionError("denied")):
            service.connect_bounty("hackerone", api_key="key")

    def test_add_notification_channel_with_config(self, service):
        channel = service.add_notification_channel("discord", webhook_url="url", config={"channel": "#alerts"})
        assert channel.config["channel"] == "#alerts"

    def test_random_id(self):
        from siyarix.platform_integration import random_id
        rid = random_id(8)
        assert len(rid) == 8
        assert rid.isalnum()

    def test_module_level_singleton(self):
        assert platform_integration is not None

    def test_platform_lists(self):
        assert "hackerone" in BOUNTY_PLATFORMS
        assert "splunk" in SIEM_PLATFORMS
        assert "slack" in COMMS_PLATFORMS
