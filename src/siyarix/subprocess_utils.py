# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safe subprocess execution utilities."""

from __future__ import annotations

import asyncio
import inspect
import logging
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0


async def _kill_process(proc: asyncio.subprocess.Process) -> None:
    result = proc.kill()
    if inspect.isawaitable(result):
        await result


def _validate_cmd_list(cmd: list[str]) -> None:
    if not isinstance(cmd, list) or not cmd:
        raise ValueError("cmd must be a non-empty list of strings")
    for part in cmd:
        if not isinstance(part, str):
            raise ValueError("all command parts must be strings")
        cleaned = part.replace(">=", "").replace("<=", "").replace("==", "")
        if any(ch in cleaned for ch in [";", "|", "&", "`", "$", ">", "<"]):
            raise ValueError(f"command part contains suspicious character: {part!r}")
        if "\n" in part or "\r" in part or "\x00" in part:
            raise ValueError(f"command part contains injection character: {part!r}")


def safe_run_sync(
    cmd: list[str], timeout: int = 10, capture_output: bool = True, text: bool = True
) -> subprocess.CompletedProcess:
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


async def safe_run_async(cmd: list[str], timeout: int = 10, validate: bool = True) -> ExecutionResult:
    if validate:
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


async def safe_run_async_stream(
    cmd: list[str],
    timeout: int = 10,
    validate: bool = True,
    on_stdout: Callable[[str], None] | None = None,
    on_stderr: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """Run a command and stream output line-by-line via callbacks."""
    if validate:
        _validate_cmd_list(cmd)
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )  # nosec B603

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _read_stream(
        stream: asyncio.StreamReader,
        lines: list[str],
        callback: Callable[[str], None] | None,
    ) -> None:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            line = raw.decode(errors="replace").rstrip("\n")
            lines.append(line)
            if callback:
                callback(line)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                _read_stream(proc.stdout, stdout_lines, on_stdout),
                _read_stream(proc.stderr, stderr_lines, on_stderr),
            ),
            timeout=timeout,
        )
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        await _kill_process(proc)
        # Read remaining buffer
        async def _drain(s: asyncio.StreamReader | None, cb: Callable[[str], None] | None) -> list[str]:
            if not s:
                return []
            out: list[str] = []
            while True:
                raw = await s.readline()
                if not raw:
                    break
                line = raw.decode(errors="replace").rstrip("\n")
                out.append(line)
                if cb:
                    cb(line)
            return out
        stdout_lines += await _drain(proc.stdout, on_stdout)
        stderr_lines += await _drain(proc.stderr, on_stderr)
        exit_code = -1

    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        duration_ms=duration_ms,
    )
