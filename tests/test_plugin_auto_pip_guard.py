# SPDX-License-Identifier: AGPL-3.0-or-later
"""SIYARIX_PLUGIN_AUTO_PIP requirements abuse guards (SX-A02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from siyarix.plugins.manager import PluginManager, _assert_safe_requirement_line


@pytest.mark.parametrize(
    "line",
    [
        "requests>=2.28.0",
        "PyYAML==6.0.1",
        "package[extra]==1.0",
        "# comment only",
        "",
    ],
)
def test_safe_requirement_lines_ok(line: str) -> None:
    _assert_safe_requirement_line(line, plugin="demo")


@pytest.mark.parametrize(
    "line",
    [
        "-r other.txt",
        "--index-url https://evil.example/simple",
        "git+https://evil.example/pkg.git",
        "requests @ https://evil.example/requests.whl",
        "./local_pkg",
        "/tmp/evil",
        "file:///tmp/evil",
        "pkg @ file:///tmp/x",
        "..\\evil",
    ],
)
def test_unsafe_requirement_lines_rejected(line: str) -> None:
    with pytest.raises(RuntimeError, match="Refusing"):
        _assert_safe_requirement_line(line, plugin="demo")


def test_install_dependencies_rejects_path_req(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_PLUGIN_AUTO_PIP", "1")
    plugin = tmp_path / "evilplug"
    plugin.mkdir()
    (plugin / "requirements.txt").write_text("./malicious_pkg\n", encoding="utf-8")
    mgr = PluginManager(plugins_dir=tmp_path, config_dir=tmp_path)
    with pytest.raises(RuntimeError, match="path/URL|Refusing"):
        mgr._install_dependencies(plugin)


def test_install_dependencies_skips_when_auto_pip_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SIYARIX_PLUGIN_AUTO_PIP", "0")
    plugin = tmp_path / "safeplug"
    plugin.mkdir()
    (plugin / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    mgr = PluginManager(plugins_dir=tmp_path, config_dir=tmp_path)
    mgr._install_dependencies(plugin)  # no raise
