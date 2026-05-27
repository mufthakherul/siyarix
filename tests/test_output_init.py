"""Tests for output/__init__.py — OutputEngine / OutputFormatter (281 stmts, ~51%)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch


from siyarix.output import (
    OutputEngine,
    OutputFormat,
    OutputFormatter,
    OutputTheme,
    THEMES,
    YAML_AVAILABLE,
    get_formatter,
    set_formatter,
    _formatter_args,
)


# ---------------------------------------------------------------------------
# OutputEngine — initialization & theme
# ---------------------------------------------------------------------------

class TestEngineInit:
    def test_default_theme(self):
        engine = OutputEngine()
        assert engine.theme == THEMES[OutputTheme.CYBER_NOIR]
        assert engine.format == OutputFormat.TABLE

    def test_invalid_theme_falls_back(self):
        engine = OutputEngine(theme="nonexistent")
        assert engine.theme == THEMES[OutputTheme.CYBER_NOIR]

    def test_custom_format(self):
        engine = OutputEngine(output_format="json")
        assert engine.format == OutputFormat.JSON


# ---------------------------------------------------------------------------
# OutputEngine — print methods
# ---------------------------------------------------------------------------

class TestEnginePrint:
    def test_print_banner_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.print") as mock_print:
            engine.print_banner("Title", subtitle="Sub")
            mock_print.assert_called()

    def test_print_banner_with_rich(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_banner("Title", "Sub")
        engine.console.print.assert_called()

    def test_print_table_empty(self):
        engine = OutputEngine()
        with patch.object(engine, "print_warning") as mock_warn:
            engine.print_table([], title="test")
            mock_warn.assert_called_with("No data to display")

    def test_print_table_rich(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.format = OutputFormat.TABLE
        engine.print_table([{"a": "1", "b": "2"}], title="T")
        engine.console.print.assert_called()

    def test_print_table_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        engine.print_table([{"a": "1"}], title="T")

    def test_print_json_rich(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.format = OutputFormat.JSON
        engine.print_json({"key": "value"})
        engine.console.print.assert_called()

    def test_print_json_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.print") as mp:
            engine.print_json({"k": "v"})
            mp.assert_called()

    def test_print_yaml_not_available(self):
        engine = OutputEngine()
        with patch("siyarix.output.YAML_AVAILABLE", False):
            with patch.object(engine, "print_error") as mock_err:
                engine.print_yaml({"k": "v"})
                mock_err.assert_called()

    def test_print_yaml_available(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        if YAML_AVAILABLE:
            engine.print_yaml({"k": "v"})
            engine.console.print.assert_called()

    def test_print_yaml_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        if YAML_AVAILABLE:
            engine.print_yaml({"k": "v"})

    def test_print_csv_empty(self):
        engine = OutputEngine()
        engine.print_csv([])

    def test_print_csv_rich(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_csv([{"a": "1"}])
        engine.console.print.assert_called()

    def test_print_csv_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        engine.print_csv([{"a": "1"}])

    def test_print_success(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_success("done")
        engine.console.print.assert_called()

    def test_print_error(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_error("fail")
        engine.console.print.assert_called()

    def test_print_warning(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_warning("warn")
        engine.console.print.assert_called()

    def test_print_info(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.print_info("info")
        engine.console.print.assert_called()

    def test_print_progress(self):
        engine = OutputEngine()
        items = [1, 2, 3]
        fn = MagicMock()

        # With rich
        engine.console = MagicMock()
        with patch("siyarix.output.Progress"):
            engine.print_progress(items, fn, "test")
            assert fn.call_count == 3

    def test_print_progress_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        items = [1]
        fn = MagicMock()
        engine.print_progress(items, fn, "test")
        fn.assert_called_once()


# ---------------------------------------------------------------------------
# OutputEngine — prompts
# ---------------------------------------------------------------------------

class TestEnginePrompts:
    def test_prompt_confirm_rich(self):
        engine = OutputEngine()
        with patch("siyarix.output.Confirm.ask", return_value=True):
            assert engine.prompt_confirm("ask?") is True

    def test_prompt_confirm_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.input", return_value="y"):
            assert engine.prompt_confirm("ask?") is True

    def test_prompt_confirm_default(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.input", return_value=""):
            assert engine.prompt_confirm("ask?", default=True) is True
            assert engine.prompt_confirm("ask?", default=False) is False

    def test_prompt_input_rich(self):
        engine = OutputEngine()
        with patch("siyarix.output.Prompt.ask", return_value="response"):
            assert engine.prompt_input("ask?") == "response"

    def test_prompt_input_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.input", return_value="response"):
            assert engine.prompt_input("ask?") == "response"

    def test_prompt_input_password(self):
        engine = OutputEngine()
        engine.console = None
        with patch("getpass.getpass", return_value="secret"):
            assert engine.prompt_input("pw?", password=True) == "secret"

    def test_prompt_input_default(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.input", return_value=""):
            assert engine.prompt_input("ask?", default="def") == "def"


# ---------------------------------------------------------------------------
# OutputEngine — export methods
# ---------------------------------------------------------------------------

class TestEngineExport:
    def test_export_html(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine._export_html([{"a": "1", "b": "2"}])
        engine.console.print.assert_called()

    def test_export_html_empty(self):
        engine = OutputEngine()
        engine._export_html([])

    def test_export_xml(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine._export_xml([{"a": "1"}])
        engine.console.print.assert_called()

    def test_export_xml_no_rich(self):
        engine = OutputEngine()
        engine.console = None
        engine._export_xml([{"a": "1"}])

    def test_export_to_file_json(self, tmp_path):
        engine = OutputEngine()
        fp = tmp_path / "out.json"
        engine.export_to_file({"k": "v"}, str(fp))
        assert json.loads(fp.read_text()) == {"k": "v"}

    def test_export_to_file_csv(self, tmp_path):
        engine = OutputEngine()
        fp = tmp_path / "out.csv"
        engine.export_to_file([{"a": "1", "b": "2"}], str(fp))
        content = fp.read_text()
        assert "a" in content

    def test_export_to_file_yaml(self, tmp_path):
        engine = OutputEngine()
        fp = tmp_path / "out.yaml"
        if YAML_AVAILABLE:
            engine.export_to_file({"k": "v"}, str(fp))
            assert fp.exists()

    def test_export_to_file_other(self, tmp_path):
        engine = OutputEngine()
        fp = tmp_path / "out.txt"
        engine.export_to_file("raw data", str(fp))
        assert fp.read_text() == "raw data"

    def test_export_data_json(self):
        engine = OutputEngine()
        engine.format = OutputFormat.JSON
        engine.console = MagicMock()
        engine._export_data([{"a": "1"}])
        engine.console.print.assert_called()

    def test_export_data_yaml(self):
        engine = OutputEngine()
        engine.format = OutputFormat.YAML
        engine.console = MagicMock()
        if YAML_AVAILABLE:
            engine._export_data([{"a": "1"}])
            engine.console.print.assert_called()

    def test_export_data_csv(self):
        engine = OutputEngine()
        engine.format = OutputFormat.CSV
        engine.console = MagicMock()
        engine._export_data([{"a": "1"}])
        engine.console.print.assert_called()

    def test_export_data_html(self):
        engine = OutputEngine()
        engine.format = OutputFormat.HTML
        engine.console = MagicMock()
        engine._export_data([{"a": "1"}])
        engine.console.print.assert_called()

    def test_export_data_xml(self):
        engine = OutputEngine()
        engine.format = OutputFormat.XML
        engine.console = MagicMock()
        engine._export_data([{"a": "1"}])
        engine.console.print.assert_called()

    def test_export_data_fallback(self):
        engine = OutputEngine()
        engine.format = "some_format_that_does_not_match"
        engine.console = MagicMock()
        engine._export_data([{"a": "1"}])
        engine.console.print.assert_called()


class TestRawPrint:
    def test_raw_print_with_console(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine._raw_print("hello")
        engine.console.print.assert_called_with("hello")

    def test_raw_print_console_fallback(self):
        engine = OutputEngine()
        engine.console = MagicMock()
        engine.console.print.side_effect = Exception("fail")
        with patch("builtins.print") as mp:
            engine._raw_print("fallback")
            mp.assert_called_with("fallback")

    def test_raw_print_no_console(self):
        engine = OutputEngine()
        engine.console = None
        with patch("builtins.print") as mp:
            engine._raw_print("direct")
            mp.assert_called_with("direct")


# ---------------------------------------------------------------------------
# OutputFormatter
# ---------------------------------------------------------------------------

class TestOutputFormatter:
    def test_init(self):
        f = OutputFormatter(fmt="json", no_color=True, verbose=2)
        assert f.fmt == "json"
        assert f.no_color is True
        assert f.verbose == 2

    def test_json(self):
        f = OutputFormatter(fmt="json")
        f.engine.console = MagicMock()
        f.json({"k": "v"})
        f.engine.console.print.assert_called()

    def test_csv(self):
        f = OutputFormatter(fmt="csv")
        f.engine.console = MagicMock()
        f.csv([{"a": "1"}])
        f.engine.console.print.assert_called()

    def test_yaml(self):
        f = OutputFormatter(fmt="yaml")
        if YAML_AVAILABLE:
            f.engine.console = MagicMock()
            f.yaml({"k": "v"})
            f.engine.console.print.assert_called()

    def test_quiet(self):
        f = OutputFormatter(fmt="quiet")
        f.engine.console = MagicMock()
        f.quiet({"key": "value"}, key="key")
        f.engine.console.print.assert_called_with("value")

    def test_quiet_no_key(self):
        f = OutputFormatter(fmt="quiet")
        f.quiet({"key": "value"})

    def test_quiet_no_console(self):
        f = OutputFormatter(fmt="quiet")
        f.engine.console = None
        with patch("builtins.print") as mp:
            f.quiet({"key": "value"}, key="key")
            mp.assert_called_with("value")

    def test_raw_print(self):
        f = OutputFormatter()
        f.engine.console = MagicMock()
        f._raw_print("msg")
        f.engine.console.print.assert_called()

    def test_raw_print_no_console(self):
        f = OutputFormatter()
        f.engine.console = None
        with patch("builtins.print") as mp:
            f._raw_print("msg")
            mp.assert_called_with("msg")


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

class TestModuleFunctions:
    def test_get_formatter(self):
        f = get_formatter("json")
        assert isinstance(f, OutputFormatter)
        assert f.fmt == "json"

    def test_set_formatter_string(self):
        import sys
        _out_mod = sys.modules['siyarix.output']
        set_formatter("json", no_color=True, verbose=1)
        assert _out_mod.output.format == OutputFormat.JSON

    def test_set_formatter_object(self):
        import sys
        _out_mod = sys.modules['siyarix.output']
        f = OutputFormatter(fmt="yaml")
        set_formatter(f, no_color=True)
        assert _out_mod.output.format == OutputFormat.YAML

    def test_formatter_args_defaults(self):
        assert "no_color" in _formatter_args
