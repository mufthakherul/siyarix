# SPDX-License-Identifier: AGPL-3.0-or-later
"""SIYARIX_TRUST_PLUGINS must gate in-process plugin execution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from siyarix.plugins.loader import PluginLoader
from siyarix.plugins.manager import PluginManager
from siyarix.plugins.models import (
    PluginManifest,
    PluginMetadata,
    PluginStatus,
    PluginType,
)


def test_manager_refuses_load_without_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is False
    assert mgr._installed_plugins["demo"].status == PluginStatus.DISABLED
    assert "SIYARIX_TRUST_PLUGINS" in (mgr._installed_plugins["demo"].error_message or "")


def test_legacy_loader_refuses_without_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")
    loader = PluginLoader(MagicMock(), MagicMock(), plugins_dir=plugins)
    with pytest.raises(PermissionError, match="SIYARIX_TRUST_PLUGINS"):
        loader._load_plugin(entry)


def test_production_requires_force_not_lab_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SX-A01: SIYARIX_TRUST_PLUGINS=1 is insufficient under production flags."""
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "1")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is False
    err = mgr._installed_plugins["demo"].error_message or ""
    assert "force" in err
    assert mgr._installed_plugins["demo"].status == PluginStatus.DISABLED


def test_production_allows_force_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "1")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "demo.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(_graph=MagicMock(_nodes={})),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    # registry._graph._nodes needs to support .keys() for tool snapshot
    mgr.registry._graph._nodes = {}
    mgr._installed_plugins["demo"] = PluginMetadata(
        manifest=PluginManifest(name="demo", version="0.0.1", entrypoint="demo.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("demo") is True
    assert mgr._installed_plugins["demo"].status == PluginStatus.ACTIVE


def test_preflight_rejects_syntax_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "1")
    monkeypatch.delenv("SIYARIX_PRODUCTION", raising=False)
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")  # host AST still runs
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "bad.py"
    entry.write_text("def broken(\n", encoding="utf-8")

    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["bad"] = PluginMetadata(
        manifest=PluginManifest(name="bad", version="0.0.1", entrypoint="bad.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("bad") is False
    assert "syntax" in (mgr._installed_plugins["bad"].error_message or "").lower()


def test_preflight_blocks_ctypes_under_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_TRUST_PLUGINS", "force")
    monkeypatch.setenv("SIYARIX_PRODUCTION", "1")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "0")
    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "0")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    entry = plugins / "risky.py"
    entry.write_text(
        "import ctypes\n\ndef register_tools(reg):\n    pass\n",
        encoding="utf-8",
    )
    mgr = PluginManager(
        registry=MagicMock(),
        provider_manager=MagicMock(),
        plugins_dir=plugins,
        config_dir=tmp_path,
    )
    mgr._installed_plugins["risky"] = PluginMetadata(
        manifest=PluginManifest(name="risky", version="0.0.1", entrypoint="risky.py"),
        path=entry,
        plugin_type=PluginType.SINGLE_FILE,
        status=PluginStatus.ACTIVE,
    )
    mgr._config_data = {"disabled": []}
    assert mgr.load_plugin("risky") is False
    assert "ctypes" in (mgr._installed_plugins["risky"].error_message or "")


def test_os_isolate_force_requires_bwrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from siyarix.plugins import isolation as iso

    monkeypatch.setenv("SIYARIX_PLUGIN_OS_ISOLATE", "force")
    monkeypatch.setenv("SIYARIX_PLUGIN_PREFLIGHT", "1")
    monkeypatch.setattr(iso.shutil, "which", lambda _name: None)
    entry = tmp_path / "ok.py"
    entry.write_text("def register_tools(reg):\n    pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bubblewrap"):
        iso.preflight_plugin_entrypoint(entry)


def test_plugin_manager_singleton_lock_exists() -> None:
    assert hasattr(PluginManager, "_instance_lock")
