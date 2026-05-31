# SPDX-License-Identifier: AGPL-3.0-or-later

"""Async executor for running security tools as subprocesses."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import subprocess  # nosec B404
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


async def _apply_stealth_modifications(
    tool_path: str, args: list[str]
) -> tuple[str, list[str]]:
    """Rewrite tool arguments and add delay jitter when stealth mode is enabled."""
    from siyarix.config import SettingsStore

    try:
        config = SettingsStore()
        if not config.get("stealth_mode"):
            return tool_path, args
    except Exception:
        return tool_path, args

    import random

    # Timing Jitter: sleep between 100ms and 500ms to mimic human typing / evade threshold detection
    delay = random.uniform(0.1, 0.5)
    await asyncio.sleep(delay)

    name = os.path.basename(tool_path).lower()
    new_args = list(args)

    # 1. Evasive rewriting for nmap
    if "nmap" in name:
        # Inject stealth scan -sS and polite speed T2 if not specified, randomize hosts
        if not any(arg.startswith("-T") for arg in new_args):
            new_args.append("-T2")
        if not any(arg.startswith("-s") for arg in new_args):
            new_args.append("-sS")
        if "-f" not in new_args:
            new_args.append("-f")  # Fragment packets

    # 2. Evasive rewriting for ffuf
    elif "ffuf" in name:
        # Rate limit to 50 requests/sec
        if "-rate" not in new_args:
            new_args.extend(["-rate", "50"])
        # Rotate user agent
        if "-H" not in new_args:
            new_args.extend(
                [
                    "-H",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ]
            )

    # 3. Evasive rewriting for nuclei
    elif "nuclei" in name:
        if "-rate-limit" not in new_args:
            new_args.extend(["-rate-limit", "10"])
        if "-H" not in new_args:
            new_args.extend(
                ["-H", "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]
            )

    return tool_path, new_args


async def run_tool(
    tool_path: str,
    args: list[str],
    timeout: int = 300,
) -> AsyncGenerator[str, None]:
    """Run *tool_path* with *args*, yielding stdout lines as they arrive.

    Handles timeout gracefully by terminating the subprocess.
    """
    tool_path, args = await _apply_stealth_modifications(tool_path, args)
    _validate_cmd_list([tool_path, *args])
    proc = await asyncio.create_subprocess_exec(
        tool_path,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )  # nosec B603

    if proc.stdout is None:  # guaranteed by PIPE, but guard for type safety
        raise RuntimeError(
            "subprocess stdout is None despite PIPE — this should never happen"
        )

    deadline = time.monotonic() + timeout

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await _kill_process(proc)
                await proc.wait()
                return
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except TimeoutError:
                await _kill_process(proc)
                await proc.wait()
                return
            if not line:
                break
            yield line.decode(errors="replace").rstrip("\n")
    finally:
        if proc.returncode is None:
            await _kill_process(proc)
            await proc.wait()


async def run_tool_complete(
    tool_path: str,
    args: list[str],
    timeout: int = 300,
) -> ExecutionResult:
    """Run *tool_path* with *args* to completion and return an :class:`ExecutionResult`.

    Kills the process and returns a partial result on timeout.
    """
    tool_path, args = await _apply_stealth_modifications(tool_path, args)
    _validate_cmd_list([tool_path, *args])
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        tool_path,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )  # nosec B603

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        exit_code = proc.returncode if proc.returncode is not None else 0
    except TimeoutError:
        await _kill_process(proc)
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


async def _kill_process(proc: asyncio.subprocess.Process) -> None:
    """Terminate a process, supporting both sync and async mock implementations."""
    result = proc.kill()  # type: ignore[func-returns-value]
    if inspect.isawaitable(result):
        await result


def _validate_cmd_list(cmd: list[str]) -> None:
    """Validate a command list to avoid shell-injection patterns.

    This enforces a few simple rules: it must be a non-empty list of strings
    and no argument may contain characters that indicate shell metacharacters
    such as ; | & ` > < $( ) or injection vectors like newlines and null bytes.
    """
    if not isinstance(cmd, list) or not cmd:
        raise ValueError("cmd must be a non-empty list of strings")
    for part in cmd:
        if not isinstance(part, str):
            raise ValueError("all command parts must be strings")
        # Reject obvious shell metacharacters and injection vectors
        cleaned = part.replace(">=", "").replace("<=", "").replace("==", "")
        if any(ch in cleaned for ch in [";", "|", "&", "`", "$", ">", "<"]):
            raise ValueError(f"command part contains suspicious character: {part!r}")
        # Block newline and null byte injection
        if "\n" in part or "\r" in part or "\x00" in part:
            raise ValueError(f"command part contains injection character: {part!r}")


def safe_run_sync(
    cmd: list[str], timeout: int = 10, capture_output: bool = True, text: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess safely (sync).

    Validates the command list and runs subprocess.run. Returns CompletedProcess.
    """
    _validate_cmd_list(cmd)
    try:
        return subprocess.run(
            cmd, capture_output=capture_output, text=text, timeout=timeout
        )  # nosec B603
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
    )  # nosec B603
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        await _kill_process(proc)
        stdout_bytes, stderr_bytes = await proc.communicate()
        exit_code = -1

    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        duration_ms=duration_ms,
    )
