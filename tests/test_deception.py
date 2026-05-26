"""Tests for deception tactics module."""

import pytest

from siyarix.deception import (DeceptionType, FakeBannerGenerator,
                               HoneypotDetector, TrapdoorCredentialManager)

pytestmark = pytest.mark.deception


class TestHoneypotDetector:
    def test_detect_cowrie_ssh(self):
        detector = HoneypotDetector()
        output = "SSH-2.0-cowrie SSH server"
        findings = detector.analyze_scan_output(output, "nmap", "10.0.0.1")
        assert len(findings) > 0
        assert findings[0].deception_type == DeceptionType.HONEYPOT_DETECTION

    def test_detect_canary_token(self):
        detector = HoneypotDetector()
        output = "Found canarytoken at canarytokens.com/traffic"
        findings = detector.analyze_scan_output(output, "nuclei", "example.com")
        assert len(findings) > 0
        assert findings[0].deception_type == DeceptionType.CANARY_TOKEN_DETECTION

    def test_clean_output_no_false_positive(self):
        detector = HoneypotDetector()
        output = "Nmap scan report for 10.0.0.1\n22/tcp open ssh\n80/tcp open http"
        findings = detector.analyze_scan_output(output, "nmap", "10.0.0.1")
        honeypot_findings = [
            f for f in findings if f.deception_type == DeceptionType.HONEYPOT_DETECTION
        ]
        assert len(honeypot_findings) == 0


class TestFakeBannerGenerator:
    def test_generate_ssh_banner(self):
        banner = FakeBannerGenerator.generate_banner("ssh")
        assert "SSH-" in banner

    def test_generate_http_banner(self):
        banner = FakeBannerGenerator.generate_banner("http")
        assert any(s in banner for s in ["Apache", "nginx", "Microsoft-IIS"])

    def test_generate_banner_with_os_match(self):
        banner = FakeBannerGenerator.generate_banner("ssh", os_type="Ubuntu")
        assert "Ubuntu" in banner

    def test_generate_banner_unknown_service(self):
        banner = FakeBannerGenerator.generate_banner("unknownsvc")
        assert "service ready" in banner

    def test_response_delay(self):
        delay = FakeBannerGenerator.generate_response_delay("ssh")
        assert 0.0 < delay < 1.0


class TestTrapdoorCredentialManager:
    def test_add_and_check_trapdoor(self):
        manager = TrapdoorCredentialManager()
        manager.add_trapdoor(
            "admin", "trapdoor_pass_123", "ssh", alert_message="Intruder detected!"
        )
        assert manager.check_credential("admin", "trapdoor_pass_123", "ssh") is True

    def test_trapdoor_not_triggered_by_wrong_password(self):
        manager = TrapdoorCredentialManager()
        manager.add_trapdoor("admin", "correct_pass", "ssh")
        assert manager.check_credential("admin", "wrong_pass", "ssh") is False

    def test_trapdoor_single_use(self):
        manager = TrapdoorCredentialManager()
        manager.add_trapdoor("root", "secret", "mysql")
        assert manager.check_credential("root", "secret", "mysql") is True
        assert manager.check_credential("root", "secret", "mysql") is False

    def test_alert_callback(self):
        manager = TrapdoorCredentialManager()
        triggered = []

        def on_alert(cred):
            triggered.append(cred)

        manager.on_alert(on_alert)
        manager.add_trapdoor("user", "pass", "ftp")
        manager.check_credential("user", "pass", "ftp")
        assert len(triggered) == 1

    def test_list_trapdoors(self):
        manager = TrapdoorCredentialManager()
        manager.add_trapdoor("admin", "pass1", "ssh")
        manager.add_trapdoor("root", "pass2", "mysql")
        creds = manager.list_trapdoors()
        assert len(creds) == 2

    def test_list_trapdoors_excludes_used(self):
        manager = TrapdoorCredentialManager()
        manager.add_trapdoor("admin", "pass", "ssh")
        manager.check_credential("admin", "pass", "ssh")
        creds = manager.list_trapdoors(include_used=False)
        assert len(creds) == 0
