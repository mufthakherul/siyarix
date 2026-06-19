"""Tests for tool availability evaluation — 100% coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from siyarix.tool_availability import (
    _eval_always,
    _eval_all_of,
    _eval_any_of,
    _eval_auth,
    _eval_config,
    _eval_env,
    _eval_installed,
    _SIGNAL_HANDLERS,
    check_tool_available,
    evaluate_availability,
    register_signal,
    ToolAvailabilityContext,
    ToolAvailabilityDiagnostic,
    ToolAvailabilityResult,
    __all__,
)


class TestExports:
    def test_all_contains_expected_names(self):
        expected = {
            "ToolAvailabilityContext",
            "ToolAvailabilityDiagnostic",
            "ToolAvailabilityResult",
            "register_signal",
            "evaluate_availability",
            "check_tool_available",
        }
        assert expected.issubset(__all__)


class TestToolAvailabilityContext:
    def test_default_factory_env(self):
        ctx = ToolAvailabilityContext()
        assert "PATH" in ctx.env or "Path" in ctx.env

    def test_default_factory_config(self):
        assert ToolAvailabilityContext().config == {}

    def test_default_factory_installed_tools(self):
        assert ToolAvailabilityContext().installed_tools == {}

    def test_default_factory_provider_auth(self):
        assert ToolAvailabilityContext().provider_auth == {}

    def test_custom_values(self):
        ctx = ToolAvailabilityContext(
            env={"CUSTOM": "val"},
            config={"key": "value"},
            installed_tools={"nmap": "/bin/nmap"},
            provider_auth={"openai": True},
        )
        assert ctx.env == {"CUSTOM": "val"}
        assert ctx.config == {"key": "value"}
        assert ctx.installed_tools == {"nmap": "/bin/nmap"}
        assert ctx.provider_auth == {"openai": True}


class TestToolAvailabilityDiagnostic:
    def test_default_detail(self):
        d = ToolAvailabilityDiagnostic(signal="sig", passed=True)
        assert d.signal == "sig"
        assert d.passed is True
        assert d.detail == ""

    def test_all_fields(self):
        d = ToolAvailabilityDiagnostic(signal="auth", passed=False, detail="nope")
        assert d.signal == "auth"
        assert d.passed is False
        assert d.detail == "nope"


class TestToolAvailabilityResult:
    def test_default_diagnostics(self):
        r = ToolAvailabilityResult(available=True)
        assert r.available is True
        assert r.diagnostics == []

    def test_with_diagnostics(self):
        diag = ToolAvailabilityDiagnostic("x", True)
        r = ToolAvailabilityResult(available=False, diagnostics=[diag])
        assert r.available is False
        assert r.diagnostics == [diag]


class TestEvalAlways:
    def test_always_returns_passed_true(self):
        ctx = ToolAvailabilityContext()
        diag = _eval_always({}, ctx)
        assert diag.signal == "always"
        assert diag.passed is True
        assert diag.detail == "always available"


class TestEvalAuth:
    def test_provider_authenticated(self):
        ctx = ToolAvailabilityContext(provider_auth={"openai": True})
        diag = _eval_auth({"provider": "openai"}, ctx)
        assert diag.signal == "auth"
        assert diag.passed is True
        assert "is authenticated" in diag.detail

    def test_provider_not_authenticated(self):
        ctx = ToolAvailabilityContext(provider_auth={"openai": False})
        diag = _eval_auth({"provider": "openai"}, ctx)
        assert diag.signal == "auth"
        assert diag.passed is False
        assert "is not authenticated" in diag.detail

    def test_empty_provider_string(self):
        ctx = ToolAvailabilityContext()
        diag = _eval_auth({"provider": ""}, ctx)
        assert diag.signal == "auth"
        assert diag.passed is False
        assert diag.detail == "no provider specified"

    def test_missing_provider_key(self):
        ctx = ToolAvailabilityContext()
        diag = _eval_auth({}, ctx)
        assert diag.passed is False
        assert diag.detail == "no provider specified"

    def test_provider_not_in_auth_dict(self):
        ctx = ToolAvailabilityContext(provider_auth={"other": True})
        diag = _eval_auth({"provider": "openai"}, ctx)
        assert diag.passed is False
        assert "is not authenticated" in diag.detail


class TestEvalConfig:
    def test_match_expected_value(self):
        ctx = ToolAvailabilityContext(config={"feature": "enabled"})
        diag = _eval_config({"key": "feature", "value": "enabled"}, ctx)
        assert diag.signal == "config"
        assert diag.passed is True
        assert "expected 'enabled'" in diag.detail

    def test_no_match_expected_value(self):
        ctx = ToolAvailabilityContext(config={"feature": "disabled"})
        diag = _eval_config({"key": "feature", "value": "enabled"}, ctx)
        assert diag.passed is False

    def test_key_present(self):
        ctx = ToolAvailabilityContext(config={"mykey": "val"})
        diag = _eval_config({"key": "mykey"}, ctx)
        assert diag.passed is True
        assert "is set" in diag.detail

    def test_key_absent(self):
        ctx = ToolAvailabilityContext(config={})
        diag = _eval_config({"key": "missing"}, ctx)
        assert diag.passed is False
        assert "is not set" in diag.detail

    def test_key_present_but_empty_string(self):
        ctx = ToolAvailabilityContext(config={"mykey": ""})
        diag = _eval_config({"key": "mykey"}, ctx)
        assert diag.passed is False
        assert "is not set" in diag.detail


class TestEvalEnv:
    def test_match_expected_value(self):
        ctx = ToolAvailabilityContext(env={"API_KEY": "sec"})
        diag = _eval_env({"var": "API_KEY", "value": "sec"}, ctx)
        assert diag.signal == "env"
        assert diag.passed is True
        assert "expected 'sec'" in diag.detail

    def test_no_match_expected_value(self):
        ctx = ToolAvailabilityContext(env={"API_KEY": "wrong"})
        diag = _eval_env({"var": "API_KEY", "value": "correct"}, ctx)
        assert diag.passed is False

    def test_var_set(self):
        ctx = ToolAvailabilityContext(env={"HOME": "/root"})
        diag = _eval_env({"var": "HOME"}, ctx)
        assert diag.passed is True
        assert "is set" in diag.detail

    def test_var_not_set(self):
        ctx = ToolAvailabilityContext(env={})
        diag = _eval_env({"var": "NONEXISTENT"}, ctx)
        assert diag.passed is False
        assert "is not set" in diag.detail

    def test_var_set_but_empty(self):
        ctx = ToolAvailabilityContext(env={"EMPTY": ""})
        diag = _eval_env({"var": "EMPTY"}, ctx)
        assert diag.passed is False
        assert "is not set" in diag.detail


class TestEvalInstalled:
    def test_in_installed_tools_dict(self):
        ctx = ToolAvailabilityContext(installed_tools={"nmap": "/bin/nmap"})
        diag = _eval_installed({"name": "nmap"}, ctx)
        assert diag.signal == "installed"
        assert diag.passed is True
        assert "is installed" in diag.detail

    @patch("siyarix.tool_availability.shutil.which")
    def test_found_via_shutil_which(self, mock_which: MagicMock):
        mock_which.return_value = "/usr/local/bin/nmap"
        ctx = ToolAvailabilityContext(installed_tools={})
        diag = _eval_installed({"name": "nmap"}, ctx)
        assert diag.passed is True
        mock_which.assert_called_once_with("nmap")

    @patch("siyarix.tool_availability.shutil.which")
    def test_not_found(self, mock_which: MagicMock):
        mock_which.return_value = None
        ctx = ToolAvailabilityContext(installed_tools={})
        diag = _eval_installed({"name": "nonexistent"}, ctx)
        assert diag.passed is False
        assert "is not installed" in diag.detail

    def test_empty_name(self):
        ctx = ToolAvailabilityContext()
        diag = _eval_installed({"name": ""}, ctx)
        assert diag.passed is False
        assert diag.detail == "no tool name specified"

    def test_missing_name_key(self):
        ctx = ToolAvailabilityContext()
        diag = _eval_installed({}, ctx)
        assert diag.passed is False
        assert diag.detail == "no tool name specified"


class TestEvalAllOf:
    def test_all_pass(self):
        ctx = ToolAvailabilityContext()
        result = _eval_all_of([True, {"always": True}], ctx)
        assert result.available is True
        assert len(result.diagnostics) == 1

    def test_one_fails(self):
        ctx = ToolAvailabilityContext()
        result = _eval_all_of([True, False], ctx)
        assert result.available is False
        assert result.diagnostics == []


class TestEvalAnyOf:
    def test_all_fail(self):
        ctx = ToolAvailabilityContext()
        result = _eval_any_of([False, False], ctx)
        assert result.available is False

    def test_one_passes(self):
        ctx = ToolAvailabilityContext()
        result = _eval_any_of([False, True], ctx)
        assert result.available is True


class TestEvaluateAvailability:
    @patch("siyarix.tool_availability.shutil.which")
    def test_bool_true(self, mock_which: MagicMock):
        result = evaluate_availability(True)
        assert result.available is True
        assert result.diagnostics == []

    @patch("siyarix.tool_availability.shutil.which")
    def test_bool_false(self, mock_which: MagicMock):
        result = evaluate_availability(False)
        assert result.available is False
        assert result.diagnostics == []

    @patch("siyarix.tool_availability.shutil.which")
    def test_str_delegates_to_installed(self, mock_which: MagicMock):
        mock_which.return_value = "/bin/nmap"
        result = evaluate_availability("nmap")
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_non_dict_non_bool_non_str_int(self, mock_which: MagicMock):
        result = evaluate_availability(42)
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_non_dict_non_bool_non_str_list(self, mock_which: MagicMock):
        result = evaluate_availability([1, 2])
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_allOf_list(self, mock_which: MagicMock):
        result = evaluate_availability({"allOf": [True, True]})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_allOf_non_list_single_item(self, mock_which: MagicMock):
        result = evaluate_availability({"allOf": True})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_anyOf_list(self, mock_which: MagicMock):
        result = evaluate_availability({"anyOf": [False, True]})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_anyOf_non_list_single_item(self, mock_which: MagicMock):
        result = evaluate_availability({"anyOf": False})
        assert result.available is False

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_bool_true(self, mock_which: MagicMock):
        result = evaluate_availability({"always": True})
        assert result.available is True
        assert result.diagnostics[0].signal == "always"
        assert result.diagnostics[0].passed is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_bool_false(self, mock_which: MagicMock):
        result = evaluate_availability({"always": False})
        assert result.available is False
        assert result.diagnostics[0].passed is False

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_value_not_bool_not_dict(self, mock_which: MagicMock):
        """Signal value is a string — falls through to next signal then returns True."""
        result = evaluate_availability({"installed": "some_tool"})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_dict_auth(self, mock_which: MagicMock):
        ctx = ToolAvailabilityContext(provider_auth={"openai": True})
        result = evaluate_availability({"auth": {"provider": "openai"}}, ctx)
        assert result.available is True
        assert result.diagnostics[0].signal == "auth"

    @patch("siyarix.tool_availability.shutil.which")
    def test_unknown_dict_keys_returns_true(self, mock_which: MagicMock):
        result = evaluate_availability({"unknown": "value"})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_none_context_creates_default(self, mock_which: MagicMock):
        result = evaluate_availability(True, None)
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_nested_allOf_containing_anyOf(self, mock_which: MagicMock):
        result = evaluate_availability({"allOf": [{"anyOf": [False, True]}, True]})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_nested_anyOf_containing_allOf(self, mock_which: MagicMock):
        result = evaluate_availability({"anyOf": [{"allOf": [True, False]}, True]})
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_config_dict(self, mock_which: MagicMock):
        ctx = ToolAvailabilityContext(config={"key": "val"})
        result = evaluate_availability({"config": {"key": "key", "value": "val"}}, ctx)
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_env_dict(self, mock_which: MagicMock):
        ctx = ToolAvailabilityContext(env={"VAR": "val"})
        result = evaluate_availability({"env": {"var": "VAR", "value": "val"}}, ctx)
        assert result.available is True

    @patch("siyarix.tool_availability.shutil.which")
    def test_signal_installed_dict(self, mock_which: MagicMock):
        ctx = ToolAvailabilityContext(installed_tools={"tool": "/bin/tool"})
        result = evaluate_availability({"installed": {"name": "tool"}}, ctx)
        assert result.available is True


class TestCheckToolAvailable:
    @patch("siyarix.tool_availability.shutil.which")
    def test_available(self, mock_which: MagicMock):
        mock_which.return_value = "/bin/tool"
        available, diagnostics = check_tool_available("tool")
        assert available is True
        assert len(diagnostics) == 1

    @patch("siyarix.tool_availability.shutil.which")
    def test_not_available(self, mock_which: MagicMock):
        mock_which.return_value = None
        available, diagnostics = check_tool_available("nonexistent")
        assert available is False
        assert len(diagnostics) == 1

    @patch("siyarix.tool_availability.shutil.which")
    def test_with_context(self, mock_which: MagicMock):
        mock_which.return_value = None
        ctx = ToolAvailabilityContext(installed_tools={"mytool": "/bin/mytool"})
        available, diagnostics = check_tool_available("mytool", ctx)
        assert available is True


class TestRegisterSignal:
    def test_register_and_evaluate_custom_signal(self):
        def custom_handler(
            expr: dict, ctx: ToolAvailabilityContext
        ) -> ToolAvailabilityDiagnostic:
            check = expr.get("enabled", False)
            return ToolAvailabilityDiagnostic(
                signal="custom", passed=check, detail=f"custom={check}"
            )

        register_signal("custom_sig", custom_handler)
        try:
            result = evaluate_availability({"custom_sig": {"enabled": True}})
            assert result.available is True
            assert result.diagnostics[0].signal == "custom"

            result = evaluate_availability({"custom_sig": {"enabled": False}})
            assert result.available is False
        finally:
            _SIGNAL_HANDLERS.pop("custom_sig", None)
