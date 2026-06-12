# SPDX-License-Identifier: AGPL-3.0-or-later

from siyarix.platform_integration import PlatformIntegrationService, random_id
import pytest

def test_random_id():
    rid = random_id(8)
    assert len(rid) == 8
    assert rid.isalnum()

def test_platform_integration_bounty(tmp_path, monkeypatch):
    monkeypatch.setattr("siyarix.platform_integration.INTEGRATIONS_DIR", tmp_path)
    pi = PlatformIntegrationService()
    
    # Test valid bounty
    conn = pi.connect_bounty("hackerone", "key", "user1")
    assert conn.connected is True
    assert conn.platform == "hackerone"
    
    # Test invalid bounty
    conn2 = pi.connect_bounty("invalid_bounty")
    assert conn2.connected is False
    assert "Unsupported" in conn2.error
    
    # Test submission
    res = pi.submit_finding("hackerone", "prog1")
    assert res.success is True
    assert "HA" in res.external_id
    
    res2 = pi.submit_finding("bugcrowd", "prog1")
    assert res2.success is False
    assert "Not connected" in res2.error

def test_platform_integration_siem(tmp_path, monkeypatch):
    monkeypatch.setattr("siyarix.platform_integration.INTEGRATIONS_DIR", tmp_path)
    pi = PlatformIntegrationService()
    
    conn = pi.connect_siem("splunk", "http://splunk", "token")
    assert conn.connected is True
    assert conn.platform == "splunk"
    
    conn2 = pi.connect_siem("invalid_siem")
    assert conn2.connected is False
    
    fwd = pi.forward_finding_to_siem({"description": "test"})
    assert fwd is True

def test_platform_integration_notifications(tmp_path, monkeypatch):
    monkeypatch.setattr("siyarix.platform_integration.INTEGRATIONS_DIR", tmp_path)
    pi = PlatformIntegrationService()
    
    pi.add_notification_channel("slack", "http://slack")
    channels = pi.list_notification_channels()
    assert len(channels) == 1
    assert channels[0].platform == "slack"
    
    sent = pi.send_notification("test message")
    assert sent == 1
    
    removed = pi.remove_notification_channel("slack")
    assert removed is True
    assert len(pi.list_notification_channels()) == 0

def test_platform_integration_summary(tmp_path, monkeypatch):
    monkeypatch.setattr("siyarix.platform_integration.INTEGRATIONS_DIR", tmp_path)
    pi = PlatformIntegrationService()
    
    pi.connect_bounty("hackerone", "key", "user")
    pi.connect_siem("splunk", "url")
    pi.add_notification_channel("slack")
    
    s = pi.summary()
    assert s["bounty_connections"] == 1
    assert s["siem_connections"] == 1
    assert "slack" in s["notification_channels"]
