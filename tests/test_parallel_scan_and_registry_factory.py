# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-target parallel scan merge + production registry factory."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from siyarix.compat import EngineResult
from siyarix.registry_factory import make_tool_registry, permission_gate_enabled


def test_permission_gate_enabled_defaults_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIYARIX_SAFE_MODE", raising=False)
    assert permission_gate_enabled() is True


def test_permission_gate_enabled_can_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIYARIX_SAFE_MODE", "0")
    assert permission_gate_enabled() is False


def test_make_tool_registry_attaches_gate_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIYARIX_SAFE_MODE", raising=False)
    reg = make_tool_registry()
    assert reg._permission_gate is not None


def test_make_tool_registry_respects_explicit_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIYARIX_SAFE_MODE", raising=False)
    reg = make_tool_registry(permission_gate=None)
    assert reg._permission_gate is None


@pytest.mark.asyncio
async def test_execute_targets_parallel_merges_findings() -> None:
    from siyarix.cli import _execute_targets_parallel

    results = {
        "10.0.0.1": EngineResult(
            success=True,
            summary="host1 ok",
            all_findings=[{"host": "10.0.0.1", "port": 22}],
            step_results=["s1"],
            duration_ms=10.0,
        ),
        "10.0.0.2": EngineResult(
            success=False,
            summary="host2 fail",
            all_findings=[{"host": "10.0.0.2", "port": 80}],
            step_results=["s2"],
            duration_ms=20.0,
            error_message="timeout",
        ),
    }

    class _FakeEngine:
        async def execute(self, instruction: str, **kwargs: Any) -> EngineResult:
            for host, res in results.items():
                if host in instruction:
                    return res
            return EngineResult(success=False, summary="missing")

    with patch("siyarix.cli._get_engine", return_value=_FakeEngine()):
        merged = await _execute_targets_parallel(
            ["10.0.0.1", "10.0.0.2"],
            mode="registry",
            parallel=2,
        )

    assert merged.success is False
    assert len(merged.all_findings) == 2
    assert len(merged.step_results) == 2
    assert merged.duration_ms == 30.0
    assert "timeout" in merged.error_message
    assert "Parallel scan of 2 targets" in merged.summary
    assert "1 ok / 1 fail" in merged.summary
    assert "2 findings" in merged.summary
    assert merged.all_findings[0].get("scan_target") == "10.0.0.1"
    assert merged.all_findings[1].get("scan_target") == "10.0.0.2"


@pytest.mark.asyncio
async def test_execute_targets_parallel_bounds_concurrency() -> None:
    from siyarix.cli import _execute_targets_parallel

    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    class _SlowEngine:
        async def execute(self, instruction: str, **kwargs: Any) -> EngineResult:
            nonlocal in_flight, max_in_flight
            async with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.05)
            async with lock:
                in_flight -= 1
            return EngineResult(success=True, summary=instruction, all_findings=[])

    with patch("siyarix.cli._get_engine", return_value=_SlowEngine()):
        merged = await _execute_targets_parallel(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            mode="registry",
            parallel=2,
        )

    assert merged.success is True
    assert max_in_flight <= 2
    assert max_in_flight >= 1
