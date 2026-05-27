from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from siyarix.ux.config_panel import ConfigPanel


@pytest.fixture
def panel() -> ConfigPanel:
    return ConfigPanel()


class TestConfigPanel:
    def test_run_quit(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="q"),
            patch("siyarix.ux.config_panel.console") as mock_console,
        ):
            panel.run()
            mock_console.print.assert_called_once()

    def test_run_with_dispatch(self, panel: ConfigPanel) -> None:
        with (
            patch.object(panel, "_section_cache") as mock_cache,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["7", "q"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            panel.run()
            mock_cache.assert_called_once()

    def test_dispatch_valid_choices(self, panel: ConfigPanel) -> None:
        dispatch_map = {
            "1": "_section_tool_acl",
            "2": "_section_masking",
            "3": "_section_stealth",
            "4": "_section_provider",
            "5": "_section_theme",
            "6": "_section_performance",
            "7": "_section_cache",
            "8": "_section_learning",
            "9": "_section_keys",
        }
        for choice, method_name in dispatch_map.items():
            with (
                patch.object(panel, method_name) as mock_method,
                patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["q"]),
                patch("siyarix.ux.config_panel.console"),
            ):
                panel._dispatch(choice)
                mock_method.assert_called_once()

    def test_dispatch_invalid_choice(self, panel: ConfigPanel) -> None:
        with patch("siyarix.ux.config_panel.console") as mock_console:
            panel._dispatch("99")
            mock_console.print.assert_called_once()

    def test_section_tool_acl_no_persona(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.persona_engine.PersonaEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value=""),
            patch("siyarix.ux.config_panel.console") as mock_console,
        ):
            engine = MagicMock()
            engine.active_persona = None
            mock_engine_cls.return_value = engine
            panel._section_tool_acl()
            mock_console.print.assert_called()

    def test_section_tool_acl_with_persona(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.persona_engine.PersonaEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value=""),
            patch("siyarix.ux.config_panel.console") as mock_console,
        ):
            engine = MagicMock()
            persona = MagicMock()
            persona.name = "bug_hunter"
            acl = MagicMock()
            acl.allowed = ["*"]
            acl.forbidden = []
            acl.permission_required = ["nuclei"]
            acl.review_required = []
            acl.auto_approve_seconds = 30
            persona.tool_acl = acl
            engine.active_persona = persona
            mock_engine_cls.return_value = engine
            panel._section_tool_acl()
            assert mock_console.print.call_count >= 1

    def test_section_masking_add_rule(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.masking.MaskingEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["a", "test-rule", r"\d+", "XXX", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            engine._rules = []
            mock_engine_cls.return_value = engine
            panel._section_masking()
            engine.add_rule.assert_called_once_with("test-rule", r"\d+", "XXX")

    def test_section_masking_remove_rule(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.masking.MaskingEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["r", "1", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            rule = MagicMock()
            rule.name = "old-rule"
            rule.pattern = MagicMock()
            rule.pattern.pattern = r"\d+"
            engine._rules = [rule]
            mock_engine_cls.return_value = engine
            panel._section_masking()
            assert len(engine._rules) == 0

    def test_section_masking_remove_invalid_index(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.masking.MaskingEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["r", "999", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            engine._rules = []
            mock_engine_cls.return_value = engine
            panel._section_masking()

    def test_section_masking_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.masking.MaskingEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            engine._rules = []
            mock_engine_cls.return_value = engine
            panel._section_masking()

    def test_section_stealth_on_off_level_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.stealth.StealthEngine") as mock_stealth_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["on", "off", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            config = MagicMock()
            config.enabled = True
            config.evasion_level = "low"
            config.jitter_percentage = 20
            config.rotate_user_agents = True
            config.use_proxy_chain = False
            config.use_decoy_traffic = False
            engine.get_config.return_value = config
            mock_stealth_cls.return_value = engine
            panel._section_stealth()
            engine.enable.assert_called_once()
            engine.disable.assert_called_once()

    def test_section_stealth_set_level(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.stealth.StealthEngine") as mock_stealth_cls,
            patch("siyarix.stealth.EVASION_LEVELS", {"low": {}, "medium": {}, "high": {}}),
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["l", "medium", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            config = MagicMock()
            config.evasion_level = "low"
            config.jitter_percentage = 20
            config.rotate_user_agents = True
            config.use_proxy_chain = False
            config.use_decoy_traffic = False
            engine.get_config.return_value = config
            mock_stealth_cls.return_value = engine
            panel._section_stealth()
            engine.set_level.assert_called_once_with("medium")

    def test_section_stealth_invalid_level(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.stealth.StealthEngine") as mock_stealth_cls,
            patch("siyarix.stealth.EVASION_LEVELS", {"low": {}, "high": {}}),
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["l", "invalid", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            config = MagicMock()
            config.evasion_level = "low"
            config.jitter_percentage = 20
            config.rotate_user_agents = True
            config.use_proxy_chain = False
            config.use_decoy_traffic = False
            engine.get_config.return_value = config
            mock_stealth_cls.return_value = engine
            panel._section_stealth()

    def test_section_provider_valid(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["ollama", ""]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.get.return_value = "auto"
            mock_store_cls.return_value = store
            panel._section_provider()
            store.set.assert_any_call("model_provider", "ollama")

    def test_section_provider_invalid(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["invalid_provider", ""]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.get.return_value = "auto"
            mock_store_cls.return_value = store
            panel._section_provider()

    def test_section_provider_with_model(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["ollama", "llama3"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.get.return_value = "auto"
            mock_store_cls.return_value = store
            panel._section_provider()
            store.set.assert_any_call("model_name", "llama3")

    def test_section_theme(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.branding.available_themes", return_value=["noir", "matrix"]),
            patch("siyarix.branding.resolve_theme", return_value="noir"),
            patch("siyarix.branding.print_theme_preview"),
            patch("siyarix.config.SettingsStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["noir", ""]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.get.return_value = "cyber-noir"
            mock_store_cls.return_value = store
            panel._section_theme()
            store.set.assert_called_with("color_theme", "noir")

    def test_section_theme_invalid(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.branding.available_themes", return_value=["noir", "matrix"]),
            patch("siyarix.branding.resolve_theme", return_value=None),
            patch("siyarix.config.SettingsStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["bad", ""]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.get.return_value = "cyber-noir"
            mock_store_cls.return_value = store
            panel._section_theme()

    def test_section_performance_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.performance.performance_optimizer") as mock_opt,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            config = MagicMock()
            config.max_concurrent_agents = 5
            config.memory_limit_per_agent_mb = 512
            config.log_level = "INFO"
            config.enable_caching = True
            mock_opt.config = config
            panel._section_performance()

    def test_section_performance_tune(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.performance.performance_optimizer") as mock_opt,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["t", "10", "1024"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            config = MagicMock()
            config.max_concurrent_agents = 5
            config.memory_limit_per_agent_mb = 512
            config.log_level = "INFO"
            config.enable_caching = True
            mock_opt.config = config
            panel._section_performance()
            mock_opt.configure.assert_called_with(max_concurrent_agents=10, memory_limit_per_agent_mb=1024)

    def test_section_performance_tune_invalid(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.performance.performance_optimizer") as mock_opt,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["t", "not_a_number", "1024"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            config = MagicMock()
            config.max_concurrent_agents = 5
            config.memory_limit_per_agent_mb = 512
            config.log_level = "INFO"
            config.enable_caching = True
            mock_opt.config = config
            panel._section_performance()

    def test_section_cache_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.cache_manager.cache_manager") as mock_cache,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            mock_cache.stats.return_value = {"entries": 10, "hits": 50, "misses": 5}
            panel._section_cache()

    def test_section_cache_clear(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.cache_manager.cache_manager") as mock_cache,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["c", "y"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            mock_cache.stats.return_value = {"entries": 10, "hits": 50, "misses": 5}
            panel._section_cache()
            mock_cache.clear.assert_called_once()

    def test_section_cache_clear_cancel(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.cache_manager.cache_manager") as mock_cache,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["c", "n"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            mock_cache.stats.return_value = {"entries": 10, "hits": 50, "misses": 5}
            panel._section_cache()
            mock_cache.clear.assert_not_called()

    def test_section_learning_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.user_learning.UserLearning") as mock_ul_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            ul = MagicMock()
            profile = MagicMock()
            profile.experience = "intermediate"
            profile.session_count = 10
            profile.unique_tools = 5
            ul.profile = profile
            mock_ul_cls.return_value = ul
            panel._section_learning()

    def test_section_learning_set_level(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.user_learning.UserLearning") as mock_ul_cls,
            patch("siyarix.user_learning.ExperienceLevel") as mock_exp_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["s", "expert"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            ul = MagicMock()
            profile = MagicMock()
            profile.experience = "beginner"
            profile.session_count = 0
            profile.unique_tools = 0
            ul.profile = profile
            mock_ul_cls.return_value = ul
            mock_exp_cls.all.return_value = ["beginner", "intermediate", "expert"]
            panel._section_learning()
            assert ul.experience == "expert"

    def test_section_learning_invalid_level(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.user_learning.UserLearning") as mock_ul_cls,
            patch("siyarix.user_learning.ExperienceLevel") as mock_exp_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["s", "invalid"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            ul = MagicMock()
            profile = MagicMock()
            profile.experience = "beginner"
            profile.session_count = 0
            profile.unique_tools = 0
            ul.profile = profile
            mock_ul_cls.return_value = ul
            mock_exp_cls.all.return_value = ["beginner", "intermediate", "expert"]
            panel._section_learning()

    def test_section_keys_back(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.credential_store.CredentialStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.list_credentials.return_value = [{"name": "openai"}]
            mock_store_cls.return_value = store
            panel._section_keys()

    def test_section_keys_set_key(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.credential_store.CredentialStore") as mock_store_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["s", "gemini", "sk-abc123"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            store = MagicMock()
            store.list_credentials.return_value = []
            mock_store_cls.return_value = store
            panel._section_keys()
            store.store.assert_called_once_with(name="gemini", value="sk-abc123")

    def test_section_learning_no_profile(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.user_learning.UserLearning") as mock_ul_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value="b"),
            patch("siyarix.ux.config_panel.console"),
        ):
            ul = MagicMock()
            ul.profile = None
            mock_ul_cls.return_value = ul
            panel._section_learning()

    def test_section_tool_acl_allowed_star(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.persona_engine.PersonaEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", return_value=""),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            persona = MagicMock()
            persona.name = "admin"
            acl = MagicMock()
            acl.allowed = ["*"]
            acl.forbidden = []
            acl.permission_required = []
            acl.review_required = []
            acl.auto_approve_seconds = 0
            persona.tool_acl = acl
            engine.active_persona = persona
            mock_engine_cls.return_value = engine
            panel._section_tool_acl()

    def test_section_masking_default_replacement(self, panel: ConfigPanel) -> None:
        with (
            patch("siyarix.masking.MaskingEngine") as mock_engine_cls,
            patch("siyarix.ux.config_panel.Prompt.ask", side_effect=["a", "ip-rule", r"\d+\.\d+\.\d+\.\d+", "", "b"]),
            patch("siyarix.ux.config_panel.console"),
        ):
            engine = MagicMock()
            engine._rules = []
            mock_engine_cls.return_value = engine
            panel._section_masking()
            engine.add_rule.assert_called_once_with("ip-rule", r"\d+\.\d+\.\d+\.\d+", None)
