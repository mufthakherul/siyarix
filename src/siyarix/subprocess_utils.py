# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safe subprocess execution utilities.

Supports sync and async subprocess execution with:
- Input validation against shell injection
- Timeout enforcement with forced process termination
- Streaming output via callbacks
- Cross-platform process cleanup (or child process tracking)
"""

from __future__ import annotations

import asyncio
import atexit as _atexit
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Track orphan child processes for cleanup on parent crash
_ORPHAN_TRACKER: set[int] = set()


@_atexit.register
def _cleanup_orphans_atexit() -> None:
    """Clean up orphaned child processes on interpreter exit."""
    _cleanup_orphans()


@dataclass
class ExecutionResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0


def _cleanup_orphans() -> None:
    """Attempt to kill orphaned child processes."""
    for pid in list(_ORPHAN_TRACKER):
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=5
                )
            else:
                os.kill(pid, signal.SIGTERM)
        except (OSError, PermissionError, subprocess.SubprocessError):
            logger.debug("Failed to kill orphan PID %d (already exited)", pid)
        _ORPHAN_TRACKER.discard(pid)


async def _kill_process(proc: asyncio.subprocess.Process) -> None:
    """Force-kill a subprocess and all children."""
    try:
        if sys.platform == "win32":
            proc.kill()
        else:
            pgid = None
            try:
                pgid = os.getpgid(proc.pid)
            except (OSError, ProcessLookupError):
                logger.debug("Could not get pgid for PID %s (may have exited)", proc.pid)
            if pgid and pgid > 1:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
    except ProcessLookupError:
        logger.debug("Process PID %s already exited during kill", proc.pid)
    except Exception:
        proc.kill()


def get_platform_shell_cmd(command: str) -> list[str]:
    """Return a platform-appropriate shell command list for *command*.

    - Windows: ``["cmd", "/c", command]``
    - Unix:    ``["sh",  "-c", command]``
    """
    if sys.platform == "win32":
        return ["cmd", "/c", command]
    return ["sh", "-c", command]


def _validate_cmd_list(cmd: list[str]) -> None:
    if not isinstance(cmd, list) or not cmd:
        raise ValueError("cmd must be a non-empty list of strings")
    for i, part in enumerate(cmd):
        if not isinstance(part, str):
            raise ValueError(
                f"all command parts must be strings, got {type(part).__name__} at index {i}"
            )
        if not part:
            raise ValueError(f"command part at index {i} is empty")
        cleaned = part.replace(">=", "").replace("<=", "").replace("==", "")
        for ch in [";", "|", "&", "`", "$", ">", "<"]:
            if ch in cleaned:
                raise ValueError(
                    f"command part at index {i} contains suspicious character {ch!r}: {part!r}"
                )
        for ch in ["\n", "\r", "\x00", "\x1b"]:
            if ch in part:
                raise ValueError(
                    f"command part at index {i} contains injection character {ch!r}: {part!r}"
                )


def safe_run_sync(
    cmd: list[str], timeout: int = 10, capture_output: bool = True, text: bool = True
) -> subprocess.CompletedProcess:
    _validate_cmd_list(cmd)
    _cleanup_orphans()
    try:
        return subprocess.run(cmd, capture_output=capture_output, text=text, timeout=timeout)  # nosec B603
    except subprocess.TimeoutExpired:
        logger.debug("safe_run_sync timeout for cmd=%s", cmd)
        raise
    except Exception as exc:
        logger.exception("safe_run_sync failed for cmd=%s: %s", cmd, exc)
        raise


async def safe_run_async(
    cmd: list[str], timeout: int = 10, validate: bool = True
) -> ExecutionResult:
    if validate:
        _validate_cmd_list(cmd)
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )  # nosec B603
    if proc.pid is not None:
        _ORPHAN_TRACKER.add(proc.pid)
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        await _kill_process(proc)
        stdout_bytes, stderr_bytes = await proc.communicate()
        exit_code = -1
    finally:
        if proc.pid:
            _ORPHAN_TRACKER.discard(proc.pid)
    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
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
    if proc.pid is not None:
        _ORPHAN_TRACKER.add(proc.pid)

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

    async def _safe_read(
        s: asyncio.StreamReader | None, lines: list[str], cb: Callable[[str], None] | None
    ) -> None:
        if s is not None:
            await _read_stream(s, lines, cb)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                _safe_read(proc.stdout, stdout_lines, on_stdout),
                _safe_read(proc.stderr, stderr_lines, on_stderr),
            ),
            timeout=timeout,
        )
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        await _kill_process(proc)

        async def _drain(
            s: asyncio.StreamReader | None, cb: Callable[[str], None] | None
        ) -> list[str]:
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
    finally:
        if proc.pid:
            _ORPHAN_TRACKER.discard(proc.pid)

    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        duration_ms=duration_ms,
    )
