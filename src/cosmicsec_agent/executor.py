"""Async executor for running security tools as subprocesses."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass

@dataclass
class ExecutionResult:
    """Result of a completed tool execution."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float

async def run_tool(
    tool_path: str,
    args: list[str],
    timeout: int = 300,
) -> AsyncGenerator[str, None]:
    """Run *tool_path* with *args*, yielding stdout lines as they arrive.

    Handles timeout gracefully by terminating the subprocess.
    """
    proc = await asyncio.create_subprocess_exec(
        tool_path,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    assert proc.stdout is not None  # guaranteed by PIPE

    deadline = time.monotonic() + timeout

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                await proc.wait()
                return
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return
            if not line:
                break
            yield line.decode(errors="replace").rstrip("\n")
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()

async def run_tool_complete(
    tool_path: str,
    args: list[str],
    timeout: int = 300,
) -> ExecutionResult:
    """Run *tool_path* with *args* to completion and return an :class:`ExecutionResult`.

    Kills the process and returns a partial result on timeout.
    """
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        tool_path,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else 0
    except TimeoutError:
        proc.kill()
        stdout_bytes, stderr_bytes = await proc.communicate()
        exit_code = -1

    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        duration_ms=duration_ms,
    )
