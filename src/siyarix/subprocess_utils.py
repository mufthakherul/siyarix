# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safe subprocess execution utilities.

Supports sync and async subprocess execution with:

- Input validation against shell injection
- Timeout enforcement with forced process termination
- Streaming output via callbacks
- Cross-platform process cleanup (orphan child-process tracking)

Note on URL-encoded inputs
    Shell-metacharacter detection operates on raw string values.
    Command parts are **not** expected to be URL-encoded; passing
    percent-encoded payloads is the caller's responsibility to avoid.
    This is by design — decoding would open an injection vector.
"""

from __future__ import annotations

import asyncio
import atexit as _atexit
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

logger = logging.getLogger(__name__)

__all__ = [
    "ExecutionResult",
    "detect_package_manager",
    "get_platform_shell_cmd",
    "safe_run_async",
    "safe_run_async_stream",
    "safe_run_sync",
    "safe_run_sandboxed",
]

# Track orphan child processes for cleanup on parent crash.
# All mutations must be guarded by ``_ORPHAN_LOCK``.
_ORPHAN_TRACKER: set[int] = set()
_ORPHAN_LOCK = threading.Lock()

# Shell metacharacters to detect injection attempts
# Shell metacharacters to detect injection attempts.
# ``\r`` is included to block carriage-return injection (CRLF smuggling).
_SHELL_METACHARS = frozenset({";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\x00", "\x1b"})

# Pre-compiled pattern for version-comparison operators adjacent to digits
# (e.g. ``>=3.9``, ``<=2.0``, ``==1.5``).  Only these are stripped before
# metachar scanning so that bare ``>`` / ``<`` / ``=`` are still caught.
_VERSION_CMP_RE = re.compile(r"(?<=\d)(?:>=|<=|==)|(?:>=|<=|==)(?=\d)")


@_atexit.register
def _cleanup_orphans_atexit() -> None:
    """Clean up orphaned child processes on interpreter exit.

    Runs during interpreter shutdown where modules may already be
    partially torn down, so we catch *everything* to avoid noisy
    tracebacks on exit.
    """
    try:
        _cleanup_orphans(is_exit=True)
    except Exception:  # noqa: BLE001 – shutdown resilience
        pass


@dataclass
class ExecutionResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0


def _cleanup_orphans(is_exit: bool = False) -> None:
    """Attempt to kill all tracked orphan child processes.

    Thread-safe: acquires ``_ORPHAN_LOCK`` while iterating/mutating
    the tracker set.
    """
    with _ORPHAN_LOCK:
        pids = list(_ORPHAN_TRACKER)
    for pid in pids:
        try:
            if sys.platform == "win32":
                if is_exit:
                    import signal
                    os.kill(pid, signal.SIGTERM)
                else:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        timeout=5,
                    )
            else:
                os.kill(pid, signal.SIGTERM)
        except (OSError, PermissionError, subprocess.SubprocessError):
            logger.debug("Failed to kill orphan PID %d (already exited)", pid)
        with _ORPHAN_LOCK:
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


def detect_package_manager() -> str:
    """Detect the available system package manager."""
    is_win = os.name == "nt"
    checks: list[tuple[str, str]] = []
    if is_win:
        checks += [("winget", "winget"), ("choco", "choco")]
    else:
        checks += [("apt-get", "apt"), ("apt", "apt")]
    checks += [
        ("brew", "brew"), ("pkg", "pkg"), ("pacman", "pacman"),
        ("dnf", "dnf"), ("apk", "apk"),
    ]
    for binary, name in checks:
        if shutil.which(binary):
            return name
    return "pip"


def get_platform_shell_cmd(command: str) -> list[str]:
    """Return a platform-appropriate shell command list for *command*.

    - Windows: ``["cmd", "/c", command]``
    - Unix:    ``["sh",  "-c", command]``
    """
    if sys.platform == "win32":
        return ["cmd", "/c", command]
    return ["sh", "-c", command]


def _validate_cmd_list(cmd: list[str]) -> None:
    """Validate that *cmd* is a well-formed command list free of shell metacharacters.

    Version-comparison operators (``>=``, ``<=``, ``==``) are only
    stripped when they appear adjacent to a digit (e.g. ``>=3.9``)
    and ONLY if we are not running a shell, so that bare ``>``/``<``/``=``
    characters are still caught.

    Raises:
        ValueError: If any element fails validation.
    """
    import urllib.parse

    if not isinstance(cmd, list) or not cmd:
        raise ValueError("cmd must be a non-empty list of strings")
        
    is_shell = bool(cmd and os.path.basename(cmd[0]).lower() in ("sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"))
    
    for i, part in enumerate(cmd):
        if not isinstance(part, str):
            raise ValueError(
                f"all command parts must be strings, got {type(part).__name__} at index {i}"
            )
        if not part:
            raise ValueError(f"command part at index {i} is empty")
        
        # H-06: Decode URL-encoded inputs to prevent bypasses
        decoded = urllib.parse.unquote(part)
        
        # M-14: Strip version-comparison operators only when adjacent to digits,
        # AND only if not running a shell (where it could hide redirections).
        cleaned = decoded
        if not is_shell:
            cleaned = _VERSION_CMP_RE.sub("", decoded)
            
        for ch in _SHELL_METACHARS:
            if ch in cleaned:
                raise ValueError(
                    f"command part at index {i} contains suspicious character {ch!r}: {part!r}"
                )


def safe_run_sync(
    cmd: list[str],
    timeout: int = 10,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run *cmd* synchronously with validation and timeout.

    Returns:
        The completed process result.

    Raises:
        ValueError: If *cmd* fails validation.
        subprocess.TimeoutExpired: If the process exceeds *timeout*.
    """
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


def _use_thread_fallback() -> bool:
    """Return True when asyncio subprocess is unavailable (Windows SelectorEventLoop)."""
    if os.name != "nt":
        return False
    loop = asyncio.get_running_loop()
    return isinstance(loop, asyncio.SelectorEventLoop)


async def safe_run_async(
    cmd: list[str], timeout: int = 10, validate: bool = True
) -> ExecutionResult:
    if validate:
        _validate_cmd_list(cmd)
    start = time.monotonic()
    if _use_thread_fallback():
        loop = asyncio.get_running_loop()
        try:
            cp = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                ),
                timeout=timeout + 5,
            )
        except asyncio.TimeoutError:
            logger.debug("safe_run_async (thread) executor timeout for cmd=%s", cmd)
            return ExecutionResult(exit_code=-1, stderr="Command timed out", duration_ms=(time.monotonic() - start) * 1000)
        except subprocess.TimeoutExpired:
            logger.debug("safe_run_async (thread) subprocess timeout for cmd=%s", cmd)
            return ExecutionResult(exit_code=-1, duration_ms=(time.monotonic() - start) * 1000)
        except FileNotFoundError:
            logger.debug("safe_run_async (thread) binary not found: %s", cmd[0] if cmd else "?")
            return ExecutionResult(
                exit_code=-1, stderr=f"Binary not found: {cmd[0] if cmd else '?'}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        return ExecutionResult(
            exit_code=cp.returncode,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            duration_ms=(time.monotonic() - start) * 1000,
        )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )  # nosec B603
    except FileNotFoundError:
        logger.debug("safe_run_async binary not found: %s", cmd[0] if cmd else "?")
        return ExecutionResult(
            exit_code=-1, stderr=f"Binary not found: {cmd[0] if cmd else '?'}",
            duration_ms=(time.monotonic() - start) * 1000,
        )
    if proc.pid is not None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(proc.pid)
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else -1
    except asyncio.TimeoutError:
        await _kill_process(proc)
        stdout_bytes, stderr_bytes = await proc.communicate()
        exit_code = -1
    finally:
        if proc.pid:
            with _ORPHAN_LOCK:
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
    on_stdout: Callable[[str], Any] | None = None,
    on_stderr: Callable[[str], Any] | None = None,
    max_output_bytes: int | None = None,
) -> ExecutionResult:
    """Run a command and stream output line-by-line via callbacks."""
    if validate:
        _validate_cmd_list(cmd)
    start = time.monotonic()
    
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    bytes_read = [0]

    if _use_thread_fallback():
        loop = asyncio.get_running_loop()
        try:
            sync_proc = await loop.run_in_executor(
                None, lambda: subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    errors="replace",  # Handle encoding issues gracefully
                )
            )
        except FileNotFoundError:
            logger.debug("safe_run_async_stream (thread) binary not found: %s", cmd[0] if cmd else "?")
            return ExecutionResult(
                exit_code=-1, stderr=f"Binary not found: {cmd[0] if cmd else '?'}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

        def _pipe_reader(
            pipe: IO[str], lines: list[str], callback: Callable[[str], Any] | None,
        ) -> None:
            try:
                for raw_line in iter(pipe.readline, ""):
                    bytes_read[0] += len(raw_line.encode("utf-8", errors="replace"))
                    if max_output_bytes and bytes_read[0] > max_output_bytes:
                        continue
                    line = raw_line.rstrip("\n")
                    lines.append(line)
                    if callback:
                        callback(line)
            finally:
                pipe.close()

        readers = []
        if sync_proc.stdout:
            t = threading.Thread(
                target=_pipe_reader, args=(sync_proc.stdout, stdout_lines, on_stdout), daemon=True,
            )
            t.start()
            readers.append(t)
        if sync_proc.stderr:
            t = threading.Thread(
                target=_pipe_reader, args=(sync_proc.stderr, stderr_lines, on_stderr), daemon=True,
            )
            t.start()
            readers.append(t)

        try:
            logger.debug("Waiting for process exit: %s", cmd)
            exit_code = await asyncio.wait_for(
                loop.run_in_executor(None, sync_proc.wait),
                timeout=timeout,
            )
            logger.debug("Process exited with code %d: %s", exit_code, cmd)
        except asyncio.TimeoutError:
            logger.warning("safe_run_async_stream (thread) timeout for cmd=%s", cmd)
            try:
                sync_proc.kill()
            except Exception:
                pass
            exit_code = -1

        for t in readers:
            t.join(timeout=2)

        return ExecutionResult(
            exit_code=exit_code,
            stdout="\n".join(stdout_lines),
            stderr="\n".join(stderr_lines),
            duration_ms=(time.monotonic() - start) * 1000,
        )

    try:
        async_proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )  # nosec B603
    except FileNotFoundError:
        logger.debug("safe_run_async_stream binary not found: %s", cmd[0] if cmd else "?")
        return ExecutionResult(
            exit_code=-1, stderr=f"Binary not found: {cmd[0] if cmd else '?'}",
            duration_ms=(time.monotonic() - start) * 1000,
        )
    if async_proc.pid is not None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(async_proc.pid)

    async def _read_stream(
        stream: asyncio.StreamReader,
        lines: list[str],
        callback: Callable[[str], Any] | None,
    ) -> None:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            bytes_read[0] += len(raw)
            if max_output_bytes and bytes_read[0] > max_output_bytes:
                continue
            line = raw.decode(errors="replace").rstrip("\n")
            lines.append(line)
            if callback:
                callback(line)

    async def _safe_read(
        s: asyncio.StreamReader | None, lines: list[str], cb: Callable[[str], Any] | None
    ) -> None:
        if s is not None:
            await _read_stream(s, lines, cb)

    try:
        # H-22: Gather reader tasks and ALSO wait for the process to exit
        # to ensure returncode is populated.
        await asyncio.wait_for(
            asyncio.gather(
                _safe_read(async_proc.stdout, stdout_lines, on_stdout),
                _safe_read(async_proc.stderr, stderr_lines, on_stderr),
                async_proc.wait(),
            ),
            timeout=timeout,
        )
        exit_code = async_proc.returncode if async_proc.returncode is not None else -1
    except asyncio.TimeoutError:
        await _kill_process(async_proc)

        async def _drain(
            s: asyncio.StreamReader | None, cb: Callable[[str], Any] | None
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

        stdout_lines += await _drain(async_proc.stdout, on_stdout)
        stderr_lines += await _drain(async_proc.stderr, on_stderr)
        exit_code = -1
    finally:
        if async_proc.pid:
            with _ORPHAN_LOCK:
                _ORPHAN_TRACKER.discard(async_proc.pid)

    duration_ms = (time.monotonic() - start) * 1000
    return ExecutionResult(
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        duration_ms=duration_ms,
    )

def safe_run_sandboxed(
    command: list[str],
    timeout: float = 60.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    allow_network: bool = False,
) -> ExecutionResult:
    """Run a command inside a sandbox if available, otherwise fallback to restricted env.
    
    Attempts to use `bwrap` (Bubblewrap) on Linux or Docker. If neither are available,
    runs the command normally but with a restricted PATH and sanitized environment.
    """
    sandbox_cmd = []
    
    if sys.platform == "linux" and shutil.which("bwrap"):
        sandbox_cmd = [
            "bwrap", "--ro-bind", "/", "/", "--dev", "/dev",
            "--proc", "/proc", "--unshare-all"
        ]
        if allow_network:
            sandbox_cmd.remove("--unshare-all")
            sandbox_cmd.extend(["--unshare-pid", "--unshare-user", "--unshare-cgroup", "--unshare-ipc"])
        
        if cwd:
            sandbox_cmd.extend(["--bind", cwd, cwd])
        sandbox_cmd.extend(["--"])
        sandbox_cmd.extend(command)
    elif shutil.which("docker"):
        # basic docker fallback
        img = "alpine:latest" if not allow_network else "ubuntu:latest"
        sandbox_cmd = ["docker", "run", "--rm", "--network", "host" if allow_network else "none"]
        if cwd:
            sandbox_cmd.extend(["-v", f"{Path(cwd).resolve()}:/workspace", "-w", "/workspace"])
        sandbox_cmd.append(img)
        sandbox_cmd.extend(command)
    else:
        # Fallback to restricted environment
        sandbox_cmd = command
        restricted_env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}
        if env:
            restricted_env.update(env)
        env = restricted_env

    return safe_run_sync(sandbox_cmd, timeout=timeout, cwd=cwd, env=env)

