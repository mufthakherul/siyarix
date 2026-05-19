"""Async executor for running security tools as subprocesses."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
import logging
import subprocess


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

    if proc.stdout is None:  # guaranteed by PIPE, but guard for type safety
        raise RuntimeError("subprocess stdout is None despite PIPE — this should never happen")

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


logger = logging.getLogger(__name__)


def _validate_cmd_list(cmd: list[str]) -> None:
    """Validate a command list to avoid shell-injection patterns.

    This enforces a few simple rules: it must be a non-empty list of strings
    and no argument may contain characters that indicate shell metacharacters
    such as ; | & ` > < $( ) unless they are obviously intended (best-effort).
    """
    if not isinstance(cmd, list) or not cmd:
        raise ValueError("cmd must be a non-empty list of strings")
    for part in cmd:
        if not isinstance(part, str):
            raise ValueError("all command parts must be strings")
        # Reject obvious shell metacharacters
        if any(ch in part for ch in [";", "|", "&", "`", "$", ">", "<"]):
            raise ValueError(f"command part contains suspicious character: {part!r}")


def safe_run_sync(
    cmd: list[str], timeout: int = 10, capture_output: bool = True, text: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess safely (sync).

    Validates the command list and runs subprocess.run. Returns CompletedProcess.
    """
    _validate_cmd_list(cmd)
    try:
        return subprocess.run(cmd, capture_output=capture_output, text=text, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.debug("safe_run_sync timeout for cmd=%s", cmd)
        raise
    except Exception as exc:
        logger.exception("safe_run_sync failed for cmd=%s: %s", cmd, exc)
        raise


async def safe_run_async(cmd: list[str], timeout: int = 10) -> ExecutionResult:
    """Run a subprocess safely (async) and return ExecutionResult."""
    _validate_cmd_list(cmd)
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
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
