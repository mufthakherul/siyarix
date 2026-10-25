# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for remaining hunt findings."""

from __future__ import annotations

import pytest

from siyarix.exceptions import PermissionDeniedError
from siyarix.executor import BaseExecutor
from siyarix.plugins.manager import _assert_under_dir, _safe_plugin_name


class _Exec(BaseExecutor):
    async def execute_plan(self, plan, **kwargs):  # type: ignore[no-untyped-def]
        return plan


def test_check_destructive_blocks_rm_fr_system_paths() -> None:
    ex = _Exec()
    with pytest.raises(PermissionDeniedError):
        ex.check_destructive("rm -fr /")
    with pytest.raises(PermissionDeniedError):
        ex.check_destructive("sudo rm --recursive --force /var")
    with pytest.raises(PermissionDeniedError):
        ex.check_destructive("rm -Rf /etc")


def test_safe_plugin_name_rejects_traversal() -> None:
    with pytest.raises(ValueError):
        _safe_plugin_name("../../escape_plugin")
    with pytest.raises(ValueError):
        _safe_plugin_name("a/b")
    assert _safe_plugin_name("legit-plugin") == "legit-plugin"


def test_assert_under_dir_rejects_escape(tmp_path) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    with pytest.raises(ValueError):
        _assert_under_dir(tmp_path / "outside", root, what="dest")


def test_plugin_fetch_url_rejects_ssrf_and_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    from siyarix.plugins.manager import _validate_git_clone_url, _validate_plugin_fetch_url

    with pytest.raises(ValueError):
        _validate_plugin_fetch_url("http://example.com/index.json")
    with pytest.raises(ValueError):
        _validate_plugin_fetch_url("https://127.0.0.1/index.json")
    with pytest.raises(ValueError):
        _validate_plugin_fetch_url("https://localhost/index.json")
    with pytest.raises(ValueError):
        _validate_git_clone_url("git@github.com:org/repo.git")

    import socket

    def _public_dns(host: str, _port: object) -> list[tuple]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    assert _validate_plugin_fetch_url("https://example.com/index.json").startswith("https://")
