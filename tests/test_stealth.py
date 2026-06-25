from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for StealthEngine."""


import pytest

from siyarix.stealth import StealthConfig, StealthEngine

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


"""Extra tests for stealth targeting uncovered lines."""


import pytest


class TestStealthConfigScore:
    def test_score_light_jitter(self) -> None:
        config = StealthConfig()
        config.apply_level("light")
        score = config.score()
        # jitter=10 → 1.5, rotate=True → 2.0, total = 3.5
        assert score == 3.5

    def test_score_no_jitter_but_rotate(self) -> None:
        config = StealthConfig()
        config.jitter_percentage = 0
        config.rotate_user_agents = True
        config.use_proxy_chain = False
        config.use_decoy_traffic = False
        config.evasion_level = "custom"
        score = config.score()
        assert score == 2.0

    def test_score_paranoid_bonus_clamped(self) -> None:
        config = StealthConfig()
        config.apply_level("paranoid")
        config.jitter_percentage = 80
        config.rotate_user_agents = True
        config.use_proxy_chain = True
        config.use_decoy_traffic = True
        score = config.score()
        # 3.0 + 2.0 + 2.5 + 1.5 + 1.0 = 10.0
        assert score == 10.0

    def test_score_all_features_enabled(self) -> None:
        config = StealthConfig()
        config.jitter_percentage = 50
        config.rotate_user_agents = True
        config.use_proxy_chain = True
        config.use_decoy_traffic = True
        config.evasion_level = "heavy"
        score = config.score()
        # 3.0 + 2.0 + 2.5 + 1.5 = 9.0
        assert score == 9.0


class TestStealthEngineProxyRotation:
    def test_get_proxy_empty_list(self) -> None:
        engine = StealthEngine()
        engine.config.use_proxy_chain = True
        engine.config.proxy_list = []
        proxy = engine.get_current_proxy()
        assert proxy is None

    def test_proxy_rotation_triggers(self) -> None:
        engine = StealthEngine()
        engine.config.use_proxy_chain = True
        engine.config.proxy_rotation_interval = 0  # rotate on every call
        engine._last_proxy_rotation = -1.0  # force immediate rotation
        proxy = engine.get_current_proxy()
        # Rotation should have happened
        assert engine._last_proxy_rotation > 0
        assert engine._proxy_index >= 0
        assert proxy is not None

    def test_get_config_returns_config(self) -> None:
        engine = StealthEngine()
        cfg = engine.get_config()
        assert cfg is engine._config

    def test_set_config_updates_attributes(self) -> None:
        engine = StealthEngine()
        engine.set_config(jitter_percentage=42, rotate_user_agents=True)
        assert engine._config.jitter_percentage == 42
        assert engine._config.rotate_user_agents is True

    def test_set_config_enabled_flag(self) -> None:
        engine = StealthEngine()
        engine.set_config(evasion_level="medium")
        assert engine._config.enabled is True

    def test_set_config_disabled_flag(self) -> None:
        engine = StealthEngine()
        engine._config.evasion_level = "light"
        engine._config.enabled = True
        engine.set_config(evasion_level="none")
        assert engine._config.enabled is False

    def test_set_config_ignores_unknown_keys(self) -> None:
        engine = StealthEngine()
        engine.set_config(nonexistent_attr=123)
        assert not hasattr(engine._config, "nonexistent_attr")

    def test_set_level(self) -> None:
        engine = StealthEngine()
        engine.set_level("heavy")
        assert engine._config.evasion_level == "heavy"
        assert engine._config.jitter_percentage == 50
        assert engine._config.enabled is True

    def test_set_level_none(self) -> None:
        engine = StealthEngine()
        engine._config.enabled = True
        engine.set_level("none")
        assert engine._config.enabled is False

    def test_summary_proxy_count_zero_when_disabled(self) -> None:
        engine = StealthEngine()
        summary = engine.summary()
        assert summary["proxy_count"] == 0

    def test_summary_user_agents_pool_zero_when_no_rotation(self) -> None:
        engine = StealthEngine()
        summary = engine.summary()
        assert summary["user_agents_pool"] == 0

    def test_get_decoy_requests_respects_max_concurrent(self) -> None:
        config = StealthConfig(
            evasion_level="heavy",
            enabled=True,
            use_decoy_traffic=True,
            max_concurrent_decoy_requests=2,
        )
        engine = StealthEngine(config)
        decoys = engine.get_decoy_requests("http://target.com")
        assert len(decoys) <= 2

    def test_get_decoy_requests_url_format(self) -> None:
        config = StealthConfig(
            evasion_level="heavy",
            enabled=True,
            use_decoy_traffic=True,
            max_concurrent_decoy_requests=1,
        )
        engine = StealthEngine(config)
        decoys = engine.get_decoy_requests("http://target.com/")
        assert decoys[0]["url"].startswith("http://target.com/")

    def test_proxy_index_increments_circular(self) -> None:
        engine = StealthEngine()
        engine.config.use_proxy_chain = True
        engine.config.proxy_list = ["p1", "p2"]
        engine._proxy_index = -1  # will become 0 after first increment
        p1 = engine.get_current_proxy()
        p2 = engine.get_current_proxy()
        p3 = engine.get_current_proxy()
        assert p1 != p2 or p2 != p3  # circular
        assert p1 in ("p1", "p2")
