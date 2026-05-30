# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for OutputFormatter, SettingsStore, and OfflineStore history extensions."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# OutputFormatter tests
# ---------------------------------------------------------------------------


class TestOutputFormatter:
    def test_formatter_json(self, capsys):
        from siyarix.output import OutputFormatter

        fmt = OutputFormatter(fmt="json")
        fmt.json({"key": "value"})
        out = capsys.readouterr().out
        assert "key" in out
        assert "value" in out

    def test_formatter_csv(self, capsys):
        from siyarix.output import OutputFormatter

        fmt = OutputFormatter(fmt="csv")
        fmt.csv([{"a": 1, "b": 2}, {"a": 3, "b": 4}])
        out = capsys.readouterr().out
        assert "a" in out
        assert "1" in out

    def test_formatter_quiet(self, capsys):
        from siyarix.output import OutputFormatter

        fmt = OutputFormatter(fmt="quiet")
        fmt.quiet({"status": "ok"}, key="status")
        out = capsys.readouterr().out
        assert "ok" in out

    def test_formatter_yaml_fallback(self, capsys):
        """If pyyaml is not installed, should fall back to JSON without crashing."""
        import unittest.mock as mock

        from siyarix.output import OutputFormatter

        fmt = OutputFormatter(fmt="yaml")
        with mock.patch.dict("sys.modules", {"yaml": None}):
            # Re-import to get fresh module state
            fmt.yaml({"x": 1})  # Should not raise

    def test_set_formatter(self):
        from siyarix.output import get_formatter, set_formatter

        set_formatter("json")
        f = get_formatter("json")
        assert f.fmt == "json"

    def test_set_formatter_tracks_no_color_and_verbose(self):
        from siyarix.output import get_formatter, set_formatter

        set_formatter("yaml", no_color=True, verbose=2)
        f = get_formatter("yaml")
        assert f.fmt == "yaml"
        assert f.no_color is True
        assert f.verbose == 2

    def test_exit_codes_exported(self):
        from siyarix.output import EXIT_AUTH_ERROR, EXIT_ERROR, EXIT_OK

        assert EXIT_OK == 0
        assert EXIT_ERROR == 1
        assert EXIT_AUTH_ERROR == 2


# ---------------------------------------------------------------------------
# SettingsStore tests
# ---------------------------------------------------------------------------


class TestSettingsStore:
    def _make_store(self, tmp_path: Path):
        from siyarix.config import SettingsStore

        return SettingsStore(path=tmp_path / "settings.toml")

    def test_defaults(self, tmp_path):
        store = self._make_store(tmp_path)
        assert store.get("default_output_format") == "table"
        assert store.get("default_parallel") == 3
        assert store.get("auto_sync") is True

    def test_set_and_get(self, tmp_path):
        store = self._make_store(tmp_path)
        coerced = store.set("default_output_format", "json")
        assert coerced == "json"
        assert store.get("default_output_format") == "json"

    def test_set_bool(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set("auto_sync", "false")
        assert store.get("auto_sync") is False

    def test_set_int(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set("default_parallel", "5")
        assert store.get("default_parallel") == 5

    def test_invalid_key_raises(self, tmp_path):
        store = self._make_store(tmp_path)
        with pytest.raises(KeyError):
            store.get("nonexistent_key")

    def test_invalid_int_raises(self, tmp_path):
        store = self._make_store(tmp_path)
        with pytest.raises(ValueError):
            store.set("default_parallel", "not_a_number")

    def test_reset_single(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set("default_parallel", "99")
        store.reset("default_parallel")
        assert store.get("default_parallel") == 3

    def test_reset_all(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set("default_parallel", "99")
        store.set("auto_sync", "false")
        store.reset()
        assert store.get("default_parallel") == 3
        assert store.get("auto_sync") is True

    def test_list_all(self, tmp_path):
        store = self._make_store(tmp_path)
        rows = store.list_all()
        assert len(rows) >= 10
        keys = {r["key"] for r in rows}
        assert "default_output_format" in keys

    def test_persistence(self, tmp_path):
        """Changes survive creating a new SettingsStore instance."""
        path = tmp_path / "settings.toml"
        from siyarix.config import SettingsStore

        s1 = SettingsStore(path=path)
        s1.set("default_parallel", "7")
        s2 = SettingsStore(path=path)
        assert s2.get("default_parallel") == 7


class TestProgressRunner:
    @pytest.mark.skip(reason="progress module removed for v1.0")
    def test_run_tools_with_progress_returns_per_tool_results(self, monkeypatch):
        from siyarix import progress as p

        class DummyDisplay:
            def __init__(self, state):
                self.state = state

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def tool_started(self, tool_name: str):
                return None

            def tool_done(self, tool_name: str, finding_count: int):
                self.state.tools_done += 1

            def tool_error(self, tool_name: str, error: str):
                self.state.tools_done += 1

            def refresh(self):
                return None

            def print_summary(self, target: str):
                return None

        class DummyToken:
            cancel_all = False

            def install(self):
                return None

            def uninstall(self):
                return None

        async def fake_run_tool_complete(path: str, args: list[str]):
            if "fail" in path:
                return SimpleNamespace(exit_code=2, stdout="", stderr="boom")
            return SimpleNamespace(exit_code=0, stdout="ok", stderr="")

        monkeypatch.setattr(p, "ScanProgressDisplay", DummyDisplay)
        monkeypatch.setattr(p, "CancellationToken", DummyToken)
        monkeypatch.setattr(
            "siyarix.executor.run_tool_complete", fake_run_tool_complete
        )

        results, state = asyncio.run(
            p.run_tools_with_progress(
                [
                    {"name": "custom-ok", "path": "/bin/ok", "args": []},
                    {"name": "custom-fail", "path": "/bin/fail", "args": []},
                ],
                target="127.0.0.1",
                max_parallel=2,
            )
        )

        assert len(results) == 2
        assert {r["name"] for r in results} == {"custom-ok", "custom-fail"}
        assert any(r["exit_code"] == 2 for r in results)
        assert state.tools_total == 2
