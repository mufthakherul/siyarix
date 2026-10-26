# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for remaining hunt findings."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from siyarix.exceptions import PermissionDeniedError
from siyarix.executor import BaseExecutor
from siyarix.executor_registry import RegistryExecutor
from siyarix.models import ExecutionPlan, PlanStep, PlanType, StepStatus
from siyarix.plugins.manager import _assert_under_dir, _safe_plugin_name
from siyarix.webhooks import _is_blocked_ip, _validate_url


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


def test_check_destructive_blocks_dual_of_dd_and_mkfs() -> None:
    ex = _Exec()
    with pytest.raises(PermissionDeniedError, match="block devices"):
        ex.check_destructive("dd of=/dev/null of=/dev/sda if=/dev/urandom")
    with pytest.raises(PermissionDeniedError, match="Formatting"):
        ex.check_destructive("mkfs.ext4 /dev/sda1")
    with pytest.raises(PermissionDeniedError, match="Formatting"):
        ex.check_destructive("fdisk /dev/sda")
    # Harmless sinks remain allowed
    ex.check_destructive("dd if=/dev/zero of=/dev/null bs=1M count=1")


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
    with pytest.raises(ValueError, match="credentials"):
        _validate_git_clone_url("https://user:token@github.com/org/repo.git")

    import socket

    def _public_dns(host: str, _port: object) -> list[tuple]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    assert _validate_plugin_fetch_url("https://example.com/index.json").startswith("https://")


def test_validate_url_rejects_userinfo_and_cgnat(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="credentials"):
        _validate_url("https://user:secret@example.com/hook")

    import ipaddress

    assert _is_blocked_ip(ipaddress.ip_address("100.64.0.1")) is True
    assert _is_blocked_ip(ipaddress.ip_address("198.18.0.1")) is True

    import socket

    def _cgnat_dns(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.1.2", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _cgnat_dns)
    with pytest.raises(ValueError, match="blocked IP"):
        _validate_url("https://evil.internal/hook")


@pytest.mark.asyncio
async def test_registry_executor_resolves_dependency_cycles() -> None:
    a = PlanStep(id="a", tool="nmap", command="nmap a", dependencies=["b"])
    b = PlanStep(id="b", tool="nmap", command="nmap b", dependencies=["a"])
    plan = ExecutionPlan(plan_type=PlanType.DAG, steps=[a, b])
    ex = RegistryExecutor(registry=MagicMock())
    result = await asyncio.wait_for(ex.execute_plan(plan), timeout=2.0)
    assert all(s.status == StepStatus.SKIPPED for s in result.steps)


@pytest.mark.asyncio
async def test_workflow_resolves_dependency_cycles() -> None:
    from siyarix.workflow import WorkflowEngine, WorkflowStepStatus

    eng = WorkflowEngine()

    async def _noop(ctx: dict) -> dict:
        return {"status": "success"}

    eng.register_step("noop", _noop)
    wf = eng.create_workflow(
        name="cycle",
        description="cycle",
        nodes=[
            {"id": "a", "name": "a", "step_fn": "noop", "args": {}},
            {"id": "b", "name": "b", "step_fn": "noop", "args": {}},
        ],
        edges=[
            {"source": "a", "target": "b"},
            {"source": "b", "target": "a"},
        ],
    )
    # Mutual edges with no ready start → both stay pending until deadlock skip.
    # Break the bootstrap by clearing edges that would make one ready... both have
    # incoming edges so neither is ready.
    out = await asyncio.wait_for(eng.run_workflow(wf), timeout=2.0)
    assert all(n.status == WorkflowStepStatus.SKIPPED for n in out.nodes)


def test_https_post_json_pinned_connects_to_resolved_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    from siyarix.webhooks import _https_post_json_pinned

    monkeypatch.setattr(
        "siyarix.webhooks._resolve_public_ips",
        lambda host, port=443: ["93.184.216.34"],
    )
    monkeypatch.setattr("siyarix.webhooks._validate_url", lambda url, allow_ip=False: None)

    created: dict[str, object] = {}

    class _FakeResp:
        status = 200

        def read(self) -> bytes:
            return b"ok"

    class _FakeConn:
        def __init__(self, host: str, port: int = 443, timeout: float = 5.0, context=None):
            created["host"] = host
            created["port"] = port
            self.sock = None
            self.connect = lambda: None

        def request(self, method: str, path: str, body=None, headers=None) -> None:
            if self.sock is None:
                self.connect()
            created["method"] = method
            created["path"] = path
            created["headers"] = headers

        def getresponse(self) -> _FakeResp:
            return _FakeResp()

        def close(self) -> None:
            created["closed"] = True

    monkeypatch.setattr("http.client.HTTPSConnection", _FakeConn)

    def _fake_create_connection(address, timeout=None):
        created["connect_addr"] = address
        return MagicMock()

    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: MagicMock(wrap_socket=lambda sock, server_hostname=None: sock),
    )

    _https_post_json_pinned("https://example.com/hook", {"ok": True}, timeout=2.0)
    assert created["connect_addr"][0] == "93.184.216.34"
    assert created["host"] == "example.com"
    assert created["headers"]["Host"] == "example.com"


def test_cache_data_path_hashes_and_uses_wall_clock(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from siyarix import cache_manager as cm

    monkeypatch.setattr(cm, "CACHE_DIR", tmp_path)
    mgr = cm.CacheManager()
    path = mgr._data_path("../escape")
    assert path.parent == tmp_path.resolve()
    assert ".." not in path.name
    mgr.set("k", "v", domain="tool_output")
    entry = mgr._entries["k"]
    assert entry.created_at > 1_000_000_000  # wall-clock epoch, not near-zero monotonic
