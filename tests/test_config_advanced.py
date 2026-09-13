# SPDX-License-Identifier: AGPL-3.0-or-later

"""Advanced unit tests for Siyarix Configuration Management Suite."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from siyarix.config import (
    DEFAULTS,
    SettingsStore,
    canonicalize_key,
    is_sensitive_key,
    mask_value,
)
from siyarix.cli import app

runner = CliRunner()


@pytest.fixture
def custom_store(tmp_path: Path) -> SettingsStore:
    cfg = tmp_path / "settings.toml"
    return SettingsStore(path=cfg)


class TestKeyResolutionAndCanonicalization:
    def test_flat_keys_remain_unchanged(self) -> None:
        assert canonicalize_key("color_theme") == "color_theme"
        assert canonicalize_key("scan_timeout") == "scan_timeout"
        assert canonicalize_key("model_provider") == "model_provider"

    def test_special_dot_mappings(self) -> None:
        assert canonicalize_key("providers.gemini.model") == "gemini_model"
        assert canonicalize_key("providers.openai.model") == "openai_model"
        assert canonicalize_key("providers.anthropic.model") == "anthropic_model"
        assert canonicalize_key("providers.ollama.url") == "ollama_url"
        assert canonicalize_key("providers.vllm.model") == "vllm_model"

    def test_prefixed_dot_mappings(self) -> None:
        assert canonicalize_key("appearance.color_theme") == "color_theme"
        assert canonicalize_key("ui.syntax_theme") == "syntax_theme"
        assert canonicalize_key("security.stealth_mode") == "stealth_mode"
        assert canonicalize_key("general.scan_timeout") == "scan_timeout"
        assert canonicalize_key("agent.default_mode") == "default_mode"

    def test_custom_dot_keys_preserved(self) -> None:
        assert canonicalize_key("custom.plugin.api_endpoint") == "custom.plugin.api_endpoint"
        assert canonicalize_key("webhook.url") == "webhook.url"


class TestSecretMasking:
    def test_sensitive_key_detection(self) -> None:
        assert is_sensitive_key("api_key") is True
        assert is_sensitive_key("gemini_api_key") is True
        assert is_sensitive_key("auth_token") is True
        assert is_sensitive_key("slack_webhook") is True
        assert is_sensitive_key("db_password") is True

    def test_non_sensitive_exceptions(self) -> None:
        assert is_sensitive_key("token_saver") is False
        assert is_sensitive_key("max_tokens") is False
        assert is_sensitive_key("keyboard") is False
        assert is_sensitive_key("color_theme") is False

    def test_mask_value_behavior(self) -> None:
        # Sensitive masked
        assert mask_value("api_key", "secret123456789") == "sec***...***789"
        # Short sensitive
        assert mask_value("api_key", "12345") == "******"
        # Reveal flag
        assert mask_value("api_key", "secret123456789", reveal=True) == "secret123456789"
        # Non-sensitive preserved with native type
        assert mask_value("token_saver", False) is False
        assert mask_value("scan_timeout", 300) == 300


class TestCustomKeyLifecycle:
    def test_add_and_get_custom_key(self, custom_store: SettingsStore) -> None:
        custom_store.add("custom.webhook", "https://hooks.site/test", description="My webhook")
        assert custom_store.get("custom.webhook") == "https://hooks.site/test"
        assert custom_store.has("custom.webhook") is True

    def test_unset_custom_key(self, custom_store: SettingsStore) -> None:
        custom_store.add("custom.endpoint", "https://api.test")
        assert custom_store.has("custom.endpoint") is True
        assert custom_store.unset("custom.endpoint") is True
        assert custom_store.has("custom.endpoint") is False
        with pytest.raises(KeyError):
            custom_store.get("custom.endpoint")

    def test_unset_default_key_reverts_to_factory(self, custom_store: SettingsStore) -> None:
        custom_store.set("scan_timeout", 999)
        assert custom_store.get("scan_timeout") == 999
        custom_store.unset("scan_timeout")
        assert custom_store.get("scan_timeout") == DEFAULTS["scan_timeout"]

    def test_custom_key_types_coercion(self, custom_store: SettingsStore) -> None:
        # JSON list
        custom_store.add("custom.ports", "[80, 443, 8080]", value_type="list")
        assert custom_store.get("custom.ports") == [80, 443, 8080]

        # Comma list
        custom_store.add("custom.tags", "recon, web, ctf", value_type="list")
        assert custom_store.get("custom.tags") == ["recon", "web", "ctf"]

        # Boolean
        custom_store.add("custom.flag", "true", value_type="bool")
        assert custom_store.get("custom.flag") is True

        # Int & float
        custom_store.add("custom.retries", "5", value_type="int")
        assert custom_store.get("custom.retries") == 5

        custom_store.add("custom.ratio", "0.75", value_type="float")
        assert custom_store.get("custom.ratio") == 0.75


class TestValidationEngine:
    def test_default_config_is_valid(self, custom_store: SettingsStore) -> None:
        issues = custom_store.validate()
        errors = [i for i in issues if i.severity == "error"]
        assert len(errors) == 0

    def test_invalid_log_level_rejected(self, custom_store: SettingsStore) -> None:
        with pytest.raises(ValueError, match="Invalid log_level"):
            custom_store.set("log_level", "super_verbose")

    def test_invalid_output_format_rejected(self, custom_store: SettingsStore) -> None:
        with pytest.raises(ValueError, match="Invalid output format"):
            custom_store.set("default_output_format", "exe")

    def test_invalid_timeouts_rejected(self, custom_store: SettingsStore) -> None:
        with pytest.raises(ValueError, match="must be a positive integer"):
            custom_store.set("scan_timeout", -10)

    def test_invalid_parallel_rejected(self, custom_store: SettingsStore) -> None:
        with pytest.raises(ValueError, match="must be a positive integer"):
            custom_store.set("default_parallel", -5)
        with pytest.raises(ValueError, match="must be a positive integer"):
            custom_store.set("default_parallel", 0)
        # Positive parallel is accepted
        assert custom_store.set("default_parallel", 99) == 99

    def test_invalid_url_rejected(self, custom_store: SettingsStore) -> None:
        with pytest.raises(ValueError, match="must be a valid HTTP or HTTPS URL"):
            custom_store.set("ollama_url", "ftp://invalid-url")

    def test_heuristic_warnings(self, custom_store: SettingsStore) -> None:
        custom_store.set("tls_verify", False)
        custom_store.set("scan_timeout", 5)
        custom_store.set("default_parallel", 128)
        issues = custom_store.validate()
        warnings = [i for i in issues if i.severity == "warning"]
        keys = [w.key for w in warnings]
        assert "tls_verify" in keys
        assert "scan_timeout" in keys
        assert "default_parallel" in keys


class TestDiffEngine:
    def test_diff_against_defaults(self, custom_store: SettingsStore) -> None:
        custom_store.set("scan_timeout", 999)
        custom_store.add("custom.setting", "val")
        diffs = custom_store.diff("defaults")
        diff_map = {d.key: d for d in diffs}

        assert "scan_timeout" in diff_map
        assert diff_map["scan_timeout"].status == "modified"
        assert diff_map["scan_timeout"].current_value == 999

        assert "custom.setting" in diff_map
        assert diff_map["custom.setting"].status == "added"


class TestExportAndImport:
    def test_export_toml_and_json(self, custom_store: SettingsStore) -> None:
        custom_store.set("scan_timeout", 450)
        custom_store.add("api_key", "secret-token-12345")

        toml_exp = custom_store.export_config("toml", reveal_secrets=False)
        assert "scan_timeout = 450" in toml_exp
        assert "sec***...***345" in toml_exp

        json_exp = custom_store.export_config("json", reveal_secrets=True)
        data = json.loads(json_exp)
        assert data["scan_timeout"] == 450
        assert data["api_key"] == "secret-token-12345"

    def test_import_config_merge_and_replace(self, custom_store: SettingsStore) -> None:
        payload = json.dumps({"scan_timeout": 600, "color_theme": "neon"})
        count = custom_store.import_config(payload, merge=True)
        assert count == 2
        assert custom_store.get("scan_timeout") == 600
        assert custom_store.get("color_theme") == "neon"


class TestProfileManagement:
    def test_list_profiles_includes_presets(self, custom_store: SettingsStore) -> None:
        with patch.object(
            custom_store, "_get_profiles_dir", return_value=custom_store._path.parent / "profiles"
        ):
            profs = custom_store.list_profiles()
            names = [p.name for p in profs]
            assert "default" in names
            assert "ctf" in names
            assert "stealth" in names
            assert "offline" in names

    def test_create_switch_delete_profile(
        self, custom_store: SettingsStore, tmp_path: Path
    ) -> None:
        prof_dir = tmp_path / "profiles"
        prof_dir.mkdir(parents=True, exist_ok=True)
        with patch("siyarix.config.get_config_dir", return_value=tmp_path):
            assert custom_store.create_profile("test_ctf", from_profile="ctf") is True
            assert custom_store.switch_profile("test_ctf") is True
            assert custom_store.get_active_profile() == "test_ctf"
            assert custom_store.get("scan_timeout") == 60

            # Cannot delete active profile
            with pytest.raises(ValueError, match="Cannot delete active"):
                custom_store.delete_profile("test_ctf")

            # Switch back and delete
            assert custom_store.switch_profile("default") is True
            assert custom_store.delete_profile("test_ctf") is True


class TestBackupManagement:
    def test_backup_and_restore(self, custom_store: SettingsStore) -> None:
        custom_store.set("scan_timeout", 500)
        bk = custom_store.backup()
        assert bk is not None
        assert bk.exists()

        backups = custom_store.list_backups()
        assert len(backups) >= 1

        custom_store.set("scan_timeout", 100)
        assert custom_store.get("scan_timeout") == 100

        restored = custom_store.restore_backup(0)
        assert restored is not None
        assert custom_store.get("scan_timeout") == 500


class TestCliCommands:
    def test_cli_config_list(self) -> None:
        result = runner.invoke(app, ["config", "list"])
        assert result.exit_code == 0
        assert "Siyarix Configuration" in result.output

    def test_cli_config_path(self) -> None:
        result = runner.invoke(app, ["config", "path"])
        assert result.exit_code == 0
        assert "Configuration Paths" in result.output

    def test_cli_config_validate(self) -> None:
        result = runner.invoke(app, ["config", "validate"])
        assert result.exit_code == 0
        assert "Configuration is healthy" in result.output

    def test_cli_config_profile_list(self) -> None:
        result = runner.invoke(app, ["config", "profile", "list"])
        assert result.exit_code == 0
        assert "Configuration Profiles" in result.output

    def test_cli_config_diff(self) -> None:
        result = runner.invoke(app, ["config", "diff"])
        assert result.exit_code == 0

    def test_cli_config_add_and_unset(self) -> None:
        add_res = runner.invoke(app, ["config", "add", "temp_custom_setting", "testing123"])
        assert add_res.exit_code == 0
        assert "temp_custom_setting = testing123" in add_res.output

        get_res = runner.invoke(app, ["config", "get", "temp_custom_setting"])
        assert get_res.exit_code == 0
        assert "testing123" in get_res.output

        # Test secret masking and reveal
        add_sec = runner.invoke(app, ["config", "add", "temp_api_token", "secret123456"])
        assert add_sec.exit_code == 0

        get_masked = runner.invoke(app, ["config", "get", "temp_api_token"])
        assert "sec***...***456" in get_masked.output

        get_revealed = runner.invoke(app, ["config", "get", "temp_api_token", "--reveal"])
        assert "secret123456" in get_revealed.output

        # Clean up
        runner.invoke(app, ["config", "unset", "temp_custom_setting"])
        runner.invoke(app, ["config", "unset", "temp_api_token"])


class TestChatConfigIntegration:
    @pytest.mark.asyncio
    async def test_chat_cmd_config(self) -> None:
        from siyarix.chat.repl import SiyarixChat

        chat = SiyarixChat()

        # /config show
        await chat._cmd_config("")
        await chat._cmd_config("show")

        # /config diff
        await chat._cmd_config("diff")

        # /config validate
        await chat._cmd_config("validate")

        # /config profile list
        await chat._cmd_config("profile list")

        # /config set and unset
        await chat._cmd_config("add custom_chat_key hello_world")
        await chat._cmd_config("get custom_chat_key")
        await chat._cmd_config("unset custom_chat_key")
