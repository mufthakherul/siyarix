"""Tests for StealthEngine."""

from __future__ import annotations

import pytest

from phalanx.stealth import StealthConfig, StealthEngine

pytestmark = pytest.mark.stealth


class TestStealthEngine:
    @pytest.fixture
    def engine(self):
        return StealthEngine()

    def test_initial_disabled(self, engine):
        assert engine.config.enabled is False
        assert engine.config.evasion_level == "none"

    def test_enable_medium(self, engine):
        engine.enable("medium")
        assert engine.config.enabled is True
        assert engine.config.rotate_user_agents is True
        assert engine.config.use_proxy_chain is True

    def test_enable_paranoid(self, engine):
        engine.enable("paranoid")
        assert engine.config.jitter_percentage == 80
        assert engine.config.use_decoy_traffic is True

    def test_disable(self, engine):
        engine.enable("heavy")
        engine.disable()
        assert engine.config.enabled is False

    def test_get_user_agent_no_rotation(self, engine):
        ua = engine.get_current_user_agent()
        assert isinstance(ua, str) and len(ua) > 0

    def test_get_user_agent_with_rotation(self, engine):
        engine.enable("light")
        ua = engine.get_current_user_agent()
        assert isinstance(ua, str) and len(ua) >= 10

    def test_randomized_delay_no_jitter(self, engine):
        delay = engine.get_randomized_delay(100.0)
        assert delay == 100.0

    def test_randomized_delay_with_jitter(self, engine):
        engine.enable("medium")
        delays = [engine.get_randomized_delay(100.0) for _ in range(10)]
        assert any(d != 100.0 for d in delays)

    def test_get_proxy_disabled(self, engine):
        assert engine.get_current_proxy() is None

    def test_get_proxy_enabled(self, engine):
        engine.enable("medium")
        proxy = engine.get_current_proxy()
        assert proxy is not None
        assert proxy.startswith(("socks5://", "socks4://", "http://"))

    def test_decoy_requests_disabled(self, engine):
        assert engine.get_decoy_requests("http://example.com") == []

    def test_decoy_requests_enabled(self, engine):
        engine.enable("heavy")
        decoys = engine.get_decoy_requests("http://example.com")
        assert len(decoys) > 0
        for d in decoys:
            assert "url" in d
            assert "method" in d

    def test_stealth_score(self, engine):
        engine.enable("paranoid")
        score = engine.config.score()
        assert 0.0 <= score <= 10.0

    def test_summary(self, engine):
        engine.enable("medium")
        summary = engine.summary()
        assert summary["enabled"] is True
        assert summary["level"] == "medium"
        assert "stealth_score" in summary

    def test_stealth_config_apply_level(self):
        config = StealthConfig()
        config.apply_level("heavy")
        assert config.jitter_percentage == 50
        assert config.use_decoy_traffic is True
