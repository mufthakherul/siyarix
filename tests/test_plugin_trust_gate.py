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
