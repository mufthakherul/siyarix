# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exhaustive tests for plugins/loader.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from siyarix.plugins.loader import PluginLoader


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def registry():
    return MagicMock()


@pytest.fixture
def provider_manager():
    return MagicMock()


@pytest.fixture
def loader(registry, provider_manager, tmp_path):
    with patch("siyarix.plugins.loader.get_config_dir", return_value=tmp_path):
        loader = PluginLoader(registry, provider_manager)
        yield loader


def _write_plugin(dir_path: Path, name: str, content: str) -> Path:
    p = dir_path / f"{name}.py"
    p.write_text(content)
    return p


# ── Initialization ───────────────────────────────────────────────────────


class TestInit:
    def test_plugins_dir_created(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        assert not plugins_dir.exists()
        with patch("siyarix.plugins.loader.get_config_dir", return_value=tmp_path):
            unused_loader = PluginLoader(MagicMock(), MagicMock())
        assert plugins_dir.exists()

    def test_plugins_dir_already_exists(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir(parents=True)
        with patch("siyarix.plugins.loader.get_config_dir", return_value=tmp_path):
            unused_loader = PluginLoader(MagicMock(), MagicMock())
        assert plugins_dir.exists()


# ── load_all ─────────────────────────────────────────────────────────────


class TestLoadAll:
    def test_no_plugins_dir(self, loader):
        loader.plugins_dir = Path("/nonexistent/path/that/does/not/exist")
        loader.load_all()

    def test_empty_plugins_dir(self, loader):
        loader.load_all()

    def test_skips_underscore_prefix(self, loader):
        _write_plugin(loader.plugins_dir, "_internal", "x = 1")
        _write_plugin(loader.plugins_dir, "valid_plugin", "x = 1")
        with patch.object(loader, "_load_plugin") as mock_load:
            loader.load_all()
        mock_load.assert_called_once()
        assert "_internal" not in str(mock_load.call_args[0][0])

    def test_loads_multiple_plugins(self, loader):
        _write_plugin(loader.plugins_dir, "plugin_a", "x = 1")
        _write_plugin(loader.plugins_dir, "plugin_b", "x = 1")
        with patch.object(loader, "_load_plugin") as mock_load:
            loader.load_all()
        assert mock_load.call_count == 2

    def test_error_during_load_logged(self, loader):
        _write_plugin(loader.plugins_dir, "bad_plugin", "x = 1")
        with patch.object(loader, "_load_plugin", side_effect=ValueError("bad plugin")):
            with patch("siyarix.plugins.loader.logger") as mock_log:
                loader.load_all()
        args, _ = mock_log.error.call_args
        assert args[0] == "Failed to load plugin %s: %s"
        assert args[1] == "bad_plugin.py"
        assert isinstance(args[2], ValueError)
        assert str(args[2]) == "bad plugin"

    def test_handles_non_py_files(self, loader):
        (loader.plugins_dir / "readme.txt").write_text("hello")
        (loader.plugins_dir / "plugin.py").write_text("x = 1")
        with patch.object(loader, "_load_plugin") as mock_load:
            loader.load_all()
        mock_load.assert_called_once()


# ── _load_plugin ─────────────────────────────────────────────────────────


class TestLoadPlugin:
    def test_no_spec_raises_importerror(self, loader):
        with patch("importlib.util.spec_from_file_location", return_value=None):
            with pytest.raises(ImportError, match="Could not load spec"):
                loader._load_plugin(Path("/fake/plugin.py"))

    def test_no_loader_raises_importerror(self, loader):
        spec = MagicMock()
        spec.loader = None
        with patch("importlib.util.spec_from_file_location", return_value=spec):
            with pytest.raises(ImportError, match="Could not load spec"):
                loader._load_plugin(Path("/fake/plugin.py"))

    def test_loads_module_and_stores_in_sys_modules(self, loader):
        plugin_path = _write_plugin(loader.plugins_dir, "simple_plugin", "x = 42")
        module_name = "siyarix_plugin_simple_plugin"
        loader._load_plugin(plugin_path)
        assert module_name in sys.modules
        assert sys.modules[module_name].x == 42
        # Cleanup
        del sys.modules[module_name]

    def test_register_tools_hook_called(self, loader):
        plugin_path = _write_plugin(
            loader.plugins_dir,
            "tool_plugin",
            "def register_tools(registry):\n    registry.register_tool('test')\n",
        )
        loader._load_plugin(plugin_path)
        loader.registry.register_tool.assert_called_once_with("test")

    def test_register_providers_hook_called(self, loader):
        plugin_path = _write_plugin(
            loader.plugins_dir,
            "prov_plugin",
            "def register_providers(pm):\n    pm.add_provider('custom')\n",
        )
        loader._load_plugin(plugin_path)
        loader.provider_manager.add_provider.assert_called_once_with("custom")

    def test_both_hooks_called(self, loader):
        plugin_path = _write_plugin(
            loader.plugins_dir,
            "full_plugin",
            (
                "def register_tools(registry):\n"
                "    registry.register_tool('tool_a')\n"
                "def register_providers(pm):\n"
                "    pm.add_provider('prov_a')\n"
            ),
        )
        loader._load_plugin(plugin_path)
        loader.registry.register_tool.assert_called_once_with("tool_a")
        loader.provider_manager.add_provider.assert_called_once_with("prov_a")

    def test_module_has_neither_hook(self, loader):
        plugin_path = _write_plugin(loader.plugins_dir, "neutral", "x = 1")
        loader._load_plugin(plugin_path)
        loader.registry.register_tool.assert_not_called()
        loader.provider_manager.add_provider.assert_not_called()

    def test_exception_during_hook_execution(self, loader):
        plugin_path = _write_plugin(
            loader.plugins_dir,
            "broken_hook",
            "def register_tools(registry):\n    raise RuntimeError('hook failed')\n",
        )
        with pytest.raises(RuntimeError, match="hook failed"):
            loader._load_plugin(plugin_path)

    def test_invalid_syntax_plugin(self, loader):
        plugin_path = _write_plugin(loader.plugins_dir, "syntax_error", "def foo( ")
        with pytest.raises(SyntaxError):
            loader._load_plugin(plugin_path)

    def test_module_name_isolation(self, loader):
        plugin_path = _write_plugin(loader.plugins_dir, "isolated", "x = 99")
        module_name = "siyarix_plugin_isolated"
        assert module_name not in sys.modules
        loader._load_plugin(plugin_path)
        assert sys.modules[module_name].x == 99
        del sys.modules[module_name]


# ── Integration: load_all with real plugins ──────────────────────────────


class TestLoadAllIntegration:
    def test_full_workflow(self, registry, provider_manager, tmp_path):
        with patch("siyarix.plugins.loader.get_config_dir", return_value=tmp_path):
            loader = PluginLoader(registry, provider_manager)
            _write_plugin(
                loader.plugins_dir,
                "alpha",
                "def register_tools(r): r.register_tool('alpha')\n"
                "def register_providers(p): p.add_provider('alpha')\n",
            )
            _write_plugin(
                loader.plugins_dir,
                "beta",
                "def register_tools(r): r.register_tool('beta')\n",
            )
            _write_plugin(
                loader.plugins_dir,
                "_hidden",
                "def register_tools(r): r.register_tool('hidden')\n",
            )
            loader.load_all()
        assert registry.register_tool.call_count == 2
        provider_manager.add_provider.assert_called_once_with("alpha")

    def test_load_all_with_broken_plugin_continues(self, registry, provider_manager, tmp_path):
        with patch("siyarix.plugins.loader.get_config_dir", return_value=tmp_path):
            loader = PluginLoader(registry, provider_manager)
            _write_plugin(loader.plugins_dir, "broken", "this is not valid python @@@")
            _write_plugin(
                loader.plugins_dir,
                "good",
                "def register_tools(r): r.register_tool('good')\n",
            )
            loader.load_all()
        registry.register_tool.assert_called_once_with("good")
