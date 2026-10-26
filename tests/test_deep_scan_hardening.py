"""Deep-scan executor injection and alternative-tool permission recheck."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

import siyarix.planner_registry as pr
from siyarix.deep_scan import DeepScanEngine
from siyarix.exceptions import PermissionDeniedError
from siyarix.models import PlanStep


class _DenyAltExecutor:
    """Minimal executor that denies permissions for alternate tools only."""

    def __init__(self) -> None:
        self.checked: list[str] = []

    async def _check_permissions(self, step: PlanStep) -> None:
        self.checked.append(step.tool)
        if step.tool != "primary_missing":
            raise PermissionDeniedError(f"blocked alt {step.tool}")


@pytest.mark.asyncio
async def test_try_alternatives_rechecks_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = MagicMock()
    registry.execute = AsyncMock(return_value={"status": "ok"})
    monkeypatch.setitem(pr.TOOL_ALTERNATIVES, "primary_missing", ["alt_tool"])

    gate = _DenyAltExecutor()
    engine = DeepScanEngine(registry=registry, executor=gate)  # type: ignore[arg-type]
    step = PlanStep(tool="primary_missing", args={"target": "example.com"})
    result = await engine._try_alternatives(step)

    assert result["status"] == "error"
    assert gate.checked == ["alt_tool"]
    registry.execute.assert_not_called()


@pytest.mark.asyncio
async def test_try_alternatives_allows_when_gate_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = MagicMock()
    registry.execute = AsyncMock(return_value={"status": "ok", "stdout": ""})

    import siyarix.planner_registry as pr

    monkeypatch.setitem(pr.TOOL_ALTERNATIVES, "primary_missing", ["alt_tool"])

    gate = MagicMock()
    gate._check_permissions = AsyncMock()
    engine = DeepScanEngine(registry=registry, executor=gate)  # type: ignore[arg-type]
    step = PlanStep(tool="primary_missing", args={"target": "example.com"})
    result = await engine._try_alternatives(step)

    assert result["status"] == "completed"
    gate._check_permissions.assert_awaited()
    registry.execute.assert_awaited_once_with("alt_tool", target="example.com")


@pytest.mark.asyncio
async def test_execute_tool_runs_executor_before_registry() -> None:
    registry = MagicMock()
    registry.execute = AsyncMock(return_value={"status": "ok", "summary": "done"})
    gate = MagicMock()
    gate._check_permissions = AsyncMock()

    engine = DeepScanEngine(registry=registry, executor=gate)  # type: ignore[arg-type]
    step = PlanStep(tool="nmap", args={"target": "10.0.0.1", "flags": "-sn"})
    result = await engine._execute_tool(step, "discovery")

    gate._check_permissions.assert_awaited_once()
    registry.execute.assert_awaited_once_with("nmap", target="10.0.0.1", flags="-sn")
    assert result["status"] == "completed"
