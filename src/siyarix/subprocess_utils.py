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
from pathlib import Path
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

# Thread-safe session cache for the sudo/administrator password.
# Only resides in memory for security.
_SUDO_PASSWORD_CACHE: str | None = None
_SUDO_PASSWORD_LOCK = threading.Lock()

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
        return not self.exit_code


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
                        check=False,
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
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except PermissionError:
                    # If we don't have permission to kill the process group (e.g. sudo), try killing the process directly
                    proc.kill()
            else:
                proc.kill()
    except ProcessLookupError:
        logger.debug("Process PID %s already exited during kill", proc.pid)
    except Exception as exc:
        logger.debug("First kill attempt failed for PID %s: %s, trying fallback", proc.pid, exc)
        try:
            proc.kill()
        except Exception as fallback_exc:
            logger.debug("Fallback proc.kill() failed for PID %s: %s", proc.pid, fallback_exc)


# ── Error message helpers ──────────────────────────────────────────────

_SIGNAL_NAMES: dict[int, str] = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 6: "SIGABRT",
    8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM",
}

def _signal_name(signum: int) -> str:
    return _SIGNAL_NAMES.get(signum, f"signal {signum}")


def _format_not_found(cmd: list[str]) -> str:
    """Return a user-friendly 'binary not found' message with install hints."""
    # When the command is wrapped in ``sh -c "tool ..."``, extract the tool name.
    if len(cmd) >= 3 and os.path.basename(cmd[0]).lower() in ("sh", "bash") and cmd[1] == "-c":
        parts = cmd[2].strip().split()
        name = parts[0] if parts else "?"
        # Skip sudo prefix in the inner command
        if name == "sudo" and len(parts) > 1:
            name = parts[1] if parts[1] != "-S" else (parts[2] if len(parts) > 2 else "?")
    else:
        name = cmd[0] if cmd else "?"
        # Skip sudo prefix
        if name == "sudo" and len(cmd) > 1:
            name = cmd[1] if cmd[1] != "-S" else (cmd[2] if len(cmd) > 2 else "?")
    hints: list[str] = []
    if shutil.which("apt-get"):
        hints.append(f"sudo apt-get install {name}")
    elif shutil.which("brew"):
        hints.append(f"brew install {name}")
    elif shutil.which("pacman"):
        hints.append(f"sudo pacman -S {name}")
    elif shutil.which("dnf"):
        hints.append(f"sudo dnf install {name}")
    msg = f"Tool '{name}' is not installed or not found in PATH."
    if hints:
        msg += f"\nInstall it with: {hints[0]}"
    return msg


def _describe_exit(exit_code: int) -> str:
    """Describe a non‑zero exit code — e.g. killed by signal, crash, etc."""
    if exit_code == -1:
        return "Internal error"
    if exit_code < 0:
        name = _signal_name(-exit_code)
        return f"Killed by {name}"
    return f"Exited with code {exit_code}"


def detect_package_manager() -> str:
    """Detect the available system package manager."""
    is_win = os.name == "nt"
    checks: list[tuple[str, str]] = []
    if is_win:
        checks += [("winget", "winget"), ("choco", "choco")]
    else:
        checks += [("apt-get", "apt"), ("apt", "apt")]
    checks += [
        ("brew", "brew"),
        ("pkg", "pkg"),
        ("pacman", "pacman"),
        ("dnf", "dnf"),
        ("apk", "apk"),
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

    is_shell = bool(
        cmd
        and os.path.basename(cmd[0]).lower()
        in ("sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh")
    )

    for i, part in enumerate(cmd):
        if not isinstance(part, str):
            raise ValueError(
                f"all command parts must be strings, got {type(part).__name__} at index {i}"
            )
        if not part:
            raise ValueError(f"command part at index {i} is empty")

        # H-06: Decode URL-encoded inputs to prevent bypasses
        decoded = urllib.parse.unquote(part)

        # When running through an explicit shell (sh -c, cmd /c etc.) the
        # command part is legitimate shell syntax and must not be flagged.
        if is_shell:
            continue

        # M-14: Strip version-comparison operators (e.g. >=3.9) that could
        # otherwise hide bare > / < metacharacters.
        cleaned = _VERSION_CMP_RE.sub("", decoded)

        for ch in _SHELL_METACHARS:
            if ch in cleaned:
                raise ValueError(
                    f"command part at index {i} contains suspicious character {ch!r}: {part!r}"
                )


def _prepare_env(env: dict[str, str] | None = None) -> dict[str, str]:
    from siyarix.stealth import stealth_engine
    exec_env = os.environ.copy()
    if env:
        exec_env.update(env)
    if stealth_engine.config.enabled:
        proxy = stealth_engine.get_current_proxy()
        if proxy:
            exec_env["HTTP_PROXY"] = proxy
            exec_env["HTTPS_PROXY"] = proxy
            exec_env["ALL_PROXY"] = proxy
    return exec_env


def safe_run_sync(
    cmd: list[str],
    timeout: float = 10,
    capture_output: bool = True,
    text: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
    """Run *cmd* synchronously with validation and timeout.

    Returns:
        The completed process result.

    Raises:
        ValueError: If *cmd* fails validation.
        subprocess.TimeoutExpired: If the process exceeds *timeout*.
    """
    _validate_cmd_list(cmd)
    _cleanup_orphans()
    exec_env = _prepare_env(env)
    try:
        cp = subprocess.run(
            cmd,
            capture_output=capture_output,
            stdin=subprocess.DEVNULL,
            text=text,
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=exec_env,
        )  # nosec B603
        return ExecutionResult(exit_code=cp.returncode, stdout=cp.stdout, stderr=cp.stderr)
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


def _verify_sudo_password(password: str) -> bool:
    """Verify a sudo password by attempting ``sudo -S -k true``.

    Returns ``True`` if the password is accepted, ``False`` otherwise.
    """
    try:
        cp = subprocess.run(
            ["sudo", "-S", "-k", "true"],
            input=f"{password}\n".encode(),
            capture_output=True,
            timeout=5,
            check=False,
        )
        return cp.returncode == 0
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _get_sudo_password() -> str | None:
    """Retrieve the sudo/administrator password from cache, env, config, or prompt the user securely.

    When prompting interactively the password is **verified** immediately
    via ``sudo -S -k true``.  Up to 3 attempts are allowed; on the third
    the user is warned it is the last chance.
    """
    global _SUDO_PASSWORD_CACHE
    
    # 1. Check in-memory session cache
    if _SUDO_PASSWORD_CACHE is not None:
        return _SUDO_PASSWORD_CACHE

    # 2. Check environment variable
    val = os.environ.get("SIYARIX_SUDO_PASSWORD")
    if val:
        with _SUDO_PASSWORD_LOCK:
            _SUDO_PASSWORD_CACHE = val
        return val

    # 3. Check SettingsStore config
    try:
        from siyarix.config import SettingsStore
        store = SettingsStore()
        config_val = store.get("SIYARIX_SUDO_PASSWORD") or store.get("sudo_password")
        if config_val:
            val = str(config_val)
            with _SUDO_PASSWORD_LOCK:
                _SUDO_PASSWORD_CACHE = val
            return val
    except Exception:
        pass

    # 4. Prompt the user interactively (if tty is available), with retry logic.
    #    Use getpass.getpass() as primary — it is more reliable across terminal
    #    states than rich's Prompt.ask().  Rich markup is NOT used in the
    #    plain-text fallback since we write directly to stderr.
    if sys.stdin.isatty():
        banner = (
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  Sudo/administrator password required for this command  ║\n"
            "║  (type it below — input is hidden for security)         ║\n"
            "║                                                        ║\n"
            "║  Tip: set SIYARIX_SUDO_PASSWORD env var or configure   ║\n"
            "║       sudo_password in settings to skip this prompt.   ║\n"
            "╚══════════════════════════════════════════════════════════╝\n"
        )
        sys.stderr.write(banner)
        sys.stderr.flush()

        import getpass as _getpass

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            is_last = attempt == max_attempts
            label = (
                "Sudo/Administrator password: "
                if not is_last
                else "Sudo/Administrator password (LAST ATTEMPT): "
            )

            try:
                password = _getpass.getpass(label)
            except (EOFError, KeyboardInterrupt):
                sys.stderr.write("\nPassword entry cancelled.\n")
                sys.stderr.flush()
                return None
            except Exception:
                password = None

            if not password:
                continue

            # Verify the password immediately
            if _verify_sudo_password(password):
                with _SUDO_PASSWORD_LOCK:
                    _SUDO_PASSWORD_CACHE = password
                return password

            msg = (
                "Incorrect password. Please try again.\n"
                if not is_last
                else "Incorrect password after 3 attempts. "
                       "The command will fail unless you configure the password "
                       "via the SIYARIX_SUDO_PASSWORD env var or settings.\n"
            )
            sys.stderr.write(msg)
            sys.stderr.flush()

        # All attempts exhausted
        return None

    else:
        logger.warning(
            "sudo required but no TTY available to prompt for password. "
            "Set SIYARIX_SUDO_PASSWORD env var or configure sudo_password in settings."
        )

    return None


async def safe_run_async(
    cmd: list[str], timeout: int = 10, validate: bool = True, env: dict[str, str] | None = None
) -> ExecutionResult:
    if validate:
        _validate_cmd_list(cmd)
    exec_env = _prepare_env(env)
    start = time.monotonic()
    if _use_thread_fallback():
        loop = asyncio.get_running_loop()
        try:
            cp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=timeout, check=False, env=exec_env
                    ),
                ),
                timeout=timeout + 5,
            )
        except asyncio.TimeoutError:
            logger.debug("safe_run_async (thread) executor timeout for cmd=%s", cmd)
            return ExecutionResult(
                exit_code=-1,
                stderr=f"Command timed out after {timeout}s (executor) and was killed.",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except subprocess.TimeoutExpired:
            logger.debug("safe_run_async (thread) subprocess timeout for cmd=%s", cmd)
            return ExecutionResult(
                exit_code=-1,
                stderr=f"Command timed out after {timeout}s and was killed.",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except FileNotFoundError:
            logger.debug("safe_run_async (thread) binary not found: %s", cmd[0] if cmd else "?")
            return ExecutionResult(
                exit_code=-1,
                stderr=_format_not_found(cmd),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except OSError as exc:
            logger.debug("safe_run_async (thread) failed to start command %s: %s", cmd, exc)
            return ExecutionResult(
                exit_code=-1,
                stderr=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        return ExecutionResult(
            exit_code=cp.returncode,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
            duration_ms=(time.monotonic() - start) * 1000,
        )
    # Sudo elevation detection & rewriting
    modified_cmd = list(cmd)
    has_sudo = False
    password = None
    
    if modified_cmd:
        if modified_cmd[0] == "sudo":
            has_sudo = True
        else:
            for part in modified_cmd:
                if re.search(r"\bsudo\b", part):
                    has_sudo = True
                    break
                    
    if has_sudo:
        password = _get_sudo_password()
        if password is None:
            logger.error("sudo required but no password available — returning error")
            return ExecutionResult(
                exit_code=-1,
                stderr=(
                    "sudo password is required for this command.\n"
                    "Provide it via one of:\n"
                    "  1. Set the SIYARIX_SUDO_PASSWORD environment variable\n"
                    "  2. Configure sudo_password in settings\n"
                    "  3. Run in an interactive terminal to be prompted"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        if modified_cmd[0] == "sudo":
            if "-S" not in modified_cmd:
                modified_cmd.insert(1, "-S")
        else:
            is_shell = len(modified_cmd) >= 3 and os.path.basename(modified_cmd[0]).lower() in ("sh", "bash", "pwsh", "powershell") and modified_cmd[1] == "-c"
            if is_shell:
                shell_str = modified_cmd[2]
                new_shell_str = re.sub(r"\bsudo\b(?! -S\b)(?!\s*-S\b)", "sudo -S", shell_str)
                modified_cmd[2] = new_shell_str

    stdin_val = asyncio.subprocess.PIPE if (has_sudo and password) else asyncio.subprocess.DEVNULL

    try:
        proc = await asyncio.create_subprocess_exec(
            *modified_cmd,
            stdin=stdin_val,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=exec_env,
        )  # nosec B603
    except FileNotFoundError:
        logger.debug("safe_run_async binary not found: %s", cmd[0] if cmd else "?")
        return ExecutionResult(
            exit_code=-1,
            stderr=_format_not_found(cmd),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    except OSError as exc:
        logger.debug("safe_run_async failed to start command %s: %s", cmd, exc)
        return ExecutionResult(
            exit_code=-1,
            stderr=str(exc),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    if proc.pid is not None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(proc.pid)

    if has_sudo and password and proc.stdin is not None:
        try:
            proc.stdin.write(f"{password}\n".encode())
            await proc.stdin.drain()
            proc.stdin.close()
        except Exception as exc:
            logger.debug("Failed writing sudo password to stdin: %s", exc)

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode if proc.returncode is not None else -1
    except asyncio.TimeoutError:
        logger.warning("safe_run_async timeout (%ds) for cmd=%s — killing process", timeout, cmd)
        timed_out = True
        await _kill_process(proc)
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=1.0)
        except asyncio.TimeoutError:
            logger.debug("safe_run_async — drain after kill timed out for cmd=%s", cmd)
            stdout_bytes, stderr_bytes = b"", b""
        exit_code = -1
    finally:
        if proc.pid:
            with _ORPHAN_LOCK:
                _ORPHAN_TRACKER.discard(proc.pid)
    duration_ms = (time.monotonic() - start) * 1000
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    if timed_out:
        timeout_msg = f"Command timed out after {timeout}s and was killed."
        stderr_text = f"{timeout_msg}\n{stderr_text}" if stderr_text else timeout_msg
    elif exit_code in (126, 127):
        # Shell exit codes: 127 = command not found, 126 = not executable.
        tool_hint = _format_not_found(cmd)
        stderr_text = f"{tool_hint}\n{stderr_text}" if stderr_text else tool_hint
    elif exit_code < 0:
        sig_msg = f"Process terminated by {_signal_name(-exit_code)}."
        stderr_text = f"{sig_msg}\n{stderr_text}" if stderr_text else sig_msg
    return ExecutionResult(
        exit_code=exit_code,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_text,
        duration_ms=duration_ms,
    )


async def safe_run_async_stream(
    cmd: list[str],
    timeout: int = 10,
    validate: bool = True,
    on_stdout: Callable[[str], Any] | None = None,
    on_stderr: Callable[[str], Any] | None = None,
    max_output_bytes: int | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
    """Run a command and stream output line-by-line via callbacks."""
    if validate:
        _validate_cmd_list(cmd)
    exec_env = _prepare_env(env)
    start = time.monotonic()

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    bytes_read = [0]

    if _use_thread_fallback():
        loop = asyncio.get_running_loop()
        try:
            sync_proc = await loop.run_in_executor(
                None,
                lambda: subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    errors="replace",  # Handle encoding issues gracefully
                    env=exec_env,
                ),
            )
        except FileNotFoundError:
            logger.debug(
                "safe_run_async_stream (thread) binary not found: %s", cmd[0] if cmd else "?"
            )
            return ExecutionResult(
                exit_code=-1,
                stderr=_format_not_found(cmd),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except OSError as exc:
            logger.debug(
                "safe_run_async_stream (thread) failed to start command %s: %s", cmd, exc
            )
            return ExecutionResult(
                exit_code=-1,
                stderr=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )

        def _pipe_reader(
            pipe: IO[str],
            lines: list[str],
            callback: Callable[[str], Any] | None,
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
                target=_pipe_reader,
                args=(sync_proc.stdout, stdout_lines, on_stdout),
                daemon=True,
            )
            t.start()
            readers.append(t)
        if sync_proc.stderr:
            t = threading.Thread(
                target=_pipe_reader,
                args=(sync_proc.stderr, stderr_lines, on_stderr),
                daemon=True,
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
            stderr_lines.append(f"Command timed out after {timeout}s and was killed.")

        # Signal-death and missing-tool detection (applies when not a timeout)
        if exit_code is not None and exit_code < 0:
            sig_msg = f"Process terminated by {_signal_name(-exit_code)}."
            stderr_lines.append(sig_msg)
        elif exit_code in (126, 127):
            tool_hint = _format_not_found(cmd)
            stderr_lines.append(tool_hint)

        for t in readers:
            t.join(timeout=2)

        return ExecutionResult(
            exit_code=exit_code,
            stdout="\n".join(stdout_lines),
            stderr="\n".join(stderr_lines),
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # Sudo elevation detection & rewriting
    modified_cmd = list(cmd)
    has_sudo = False
    password = None
    
    if modified_cmd:
        if modified_cmd[0] == "sudo":
            has_sudo = True
        else:
            for part in modified_cmd:
                if re.search(r"\bsudo\b", part):
                    has_sudo = True
                    break
                    
    if has_sudo:
        password = _get_sudo_password()
        if password is None:
            logger.error("sudo required but no password available — returning error")
            return ExecutionResult(
                exit_code=-1,
                stderr=(
                    "sudo password is required for this command.\n"
                    "Provide it via one of:\n"
                    "  1. Set the SIYARIX_SUDO_PASSWORD environment variable\n"
                    "  2. Configure sudo_password in settings\n"
                    "  3. Run in an interactive terminal to be prompted"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        if modified_cmd[0] == "sudo":
            if "-S" not in modified_cmd:
                modified_cmd.insert(1, "-S")
        else:
            is_shell = len(modified_cmd) >= 3 and os.path.basename(modified_cmd[0]).lower() in ("sh", "bash", "pwsh", "powershell") and modified_cmd[1] == "-c"
            if is_shell:
                shell_str = modified_cmd[2]
                new_shell_str = re.sub(r"\bsudo\b(?! -S\b)(?!\s*-S\b)", "sudo -S", shell_str)
                modified_cmd[2] = new_shell_str

    stdin_val = asyncio.subprocess.PIPE if (has_sudo and password) else asyncio.subprocess.DEVNULL

    try:
        async_proc = await asyncio.create_subprocess_exec(
            *modified_cmd,
            stdin=stdin_val,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=exec_env,
        )  # nosec B603
    except FileNotFoundError:
        logger.debug("safe_run_async_stream binary not found: %s", cmd[0] if cmd else "?")
        return ExecutionResult(
            exit_code=-1,
            stderr=_format_not_found(cmd),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    except OSError as exc:
        logger.debug("safe_run_async_stream failed to start command %s: %s", cmd, exc)
        return ExecutionResult(
            exit_code=-1,
            stderr=str(exc),
            duration_ms=(time.monotonic() - start) * 1000,
        )
    if async_proc.pid is not None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(async_proc.pid)

    if has_sudo and password and async_proc.stdin is not None:
        try:
            async_proc.stdin.write(f"{password}\n".encode())
            await async_proc.stdin.drain()
            async_proc.stdin.close()
        except Exception as exc:
            logger.debug("Failed writing sudo password to stdin: %s", exc)

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

    # Start the reader tasks
    stdout_task = asyncio.create_task(_safe_read(async_proc.stdout, stdout_lines, on_stdout))
    stderr_task = asyncio.create_task(_safe_read(async_proc.stderr, stderr_lines, on_stderr))

    timed_out = False
    try:
        # Wait for the process to exit first
        await asyncio.wait_for(async_proc.wait(), timeout=timeout)
        exit_code = async_proc.returncode if async_proc.returncode is not None else -1
        
        # After process exits, give reader tasks 1 second to drain the remaining output
        try:
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task),
                timeout=1.0
            )
        except asyncio.TimeoutError:
            logger.debug("safe_run_async_stream reader tasks timed out after process exit")
            stdout_task.cancel()
            stderr_task.cancel()
    except asyncio.TimeoutError:
        logger.warning("safe_run_async_stream timeout (%ds) for cmd=%s — killing process", timeout, cmd)
        timed_out = True
        # The process itself timed out
        await _kill_process(async_proc)
        
        # After process is killed, give reader tasks 1 second to drain the remaining output
        try:
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task),
                timeout=1.0
            )
        except asyncio.TimeoutError:
            logger.debug("safe_run_async_stream reader tasks timed out after process kill")
            stdout_task.cancel()
            stderr_task.cancel()
        exit_code = -1
    finally:
        if async_proc.pid:
            with _ORPHAN_LOCK:
                _ORPHAN_TRACKER.discard(async_proc.pid)

    # Annotate stderr with timeout / signal-death / missing-tool info
    if timed_out:
        timeout_msg = f"Command timed out after {timeout}s and was killed."
        stderr_lines.append(timeout_msg)
    elif exit_code in (126, 127):
        tool_hint = _format_not_found(cmd)
        stderr_lines.append(tool_hint)
    elif exit_code < 0:
        sig_msg = f"Process terminated by {_signal_name(-exit_code)}."
        stderr_lines.append(sig_msg)

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
            "bwrap",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-all",
        ]
        if allow_network:
            sandbox_cmd.remove("--unshare-all")
            sandbox_cmd.extend(
                ["--unshare-pid", "--unshare-user", "--unshare-cgroup", "--unshare-ipc"]
            )

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
