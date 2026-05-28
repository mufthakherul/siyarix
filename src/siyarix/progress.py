# SPDX-License-Identifier: AGPL-3.0-or-later

"""Progress helpers for running multiple tools with live state updates."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from . import executor


@dataclass
class ScanProgressState:
    """Mutable progress state shared with the display layer."""

    target: str
    tools_total: int
    tools_done: int = 0
    tools_started: int = 0
    errors: list[str] = field(default_factory=list)


class CancellationToken:
    """Simple cancellation token used by progress runners."""

    def __init__(self) -> None:
        self.cancel_all = False

    def install(self) -> None:
        return None

    def uninstall(self) -> None:
        return None


class ScanProgressDisplay:
    """No-op compatible display implementation for scan progress."""

    def __init__(self, state: ScanProgressState) -> None:
        self.state = state

    def __enter__(self) -> ScanProgressDisplay:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def tool_started(self, tool_name: str) -> None:
        self.state.tools_started += 1

    def tool_done(self, tool_name: str, finding_count: int) -> None:
        self.state.tools_done += 1

    def tool_error(self, tool_name: str, error: str) -> None:
        self.state.tools_done += 1
        self.state.errors.append(f"{tool_name}: {error}")

    def refresh(self) -> None:
        return None

    def print_summary(self, target: str) -> None:
        return None


async def run_tools_with_progress(
    tools: list[dict[str, Any]],
    target: str,
    max_parallel: int = 4,
    timeout: int = 300,
) -> tuple[list[dict[str, Any]], ScanProgressState]:
    """Run tools concurrently while updating shared progress state."""

    state = ScanProgressState(target=target, tools_total=len(tools))
    cancellation = CancellationToken()
    semaphore = asyncio.Semaphore(max_parallel if max_parallel > 0 else 1)
    results: list[dict[str, Any]] = []

    async def _run_one(tool: dict[str, Any], display: ScanProgressDisplay) -> None:
        name = str(tool.get("name") or tool.get("path") or "tool")
        path = str(tool.get("path") or "")
        args = list(tool.get("args") or [])

        display.tool_started(name)
        async with semaphore:
            try:
                execution = await executor.run_tool_complete(path, args, timeout=timeout)
                result = {
                    "name": name,
                    "path": path,
                    "args": args,
                    "exit_code": execution.exit_code,
                    "stdout": execution.stdout,
                    "stderr": execution.stderr,
                    "duration_ms": execution.duration_ms,
                }
                results.append(result)
                if execution.exit_code == 0:
                    display.tool_done(name, finding_count=0)
                else:
                    display.tool_error(name, execution.stderr or "tool failed")
            except Exception as exc:
                results.append(
                    {
                        "name": name,
                        "path": path,
                        "args": args,
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": str(exc),
                        "duration_ms": 0.0,
                    }
                )
                display.tool_error(name, str(exc))
            finally:
                display.refresh()

    cancellation.install()
    try:
        with ScanProgressDisplay(state) as display:
            await asyncio.gather(*(_run_one(tool, display) for tool in tools))
            display.print_summary(target)
    finally:
        cancellation.uninstall()

    return results, state
