# SPDX-License-Identifier: AGPL-3.0-or-later
"""Safe subprocess execution utilities.

Supports sync and async subprocess execution with:

- Input validation against shell injection
- Timeout enforcement with forced process termination
- Streaming output via callbacks
- Cross-platform process cleanup (orphan child-process tracking)
- Path traversal protection
- Resource usage limits per tool
- Seccomp/sandboxing integration
"""

from __future__ import annotations

import asyncio
import atexit as _atexit
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from ._platform import (
    get_platform_id,
    set_event_loop_policy,
)
from ._platform import (
    get_platform_shell_cmd as _get_platform_shell_cmd,
)
from ._platform import (
    get_termux_prefix as _get_termux_prefix,
)
from ._platform import (
    has_signal as _has_signal,
)
from ._platform import (
    is_linux as _is_linux,
)
from ._platform import (
    is_mobile as _is_mobile,
)
from ._platform import (
    is_windows as _is_windows,
)

_console: Console | None = None
try:
    from rich.console import Console

    _console = Console()
except ImportError:
    # rich console is optional; fallback to None
    pass

if _has_signal():
    import signal as _signal
else:
    _signal = None  # type: ignore

logger = logging.getLogger(__name__)

__all__ = [
    "ExecutionResult",
    "detect_package_manager",
    "get_platform_shell_cmd",
    "safe_run_async",
    "safe_run_async_stream",
    "safe_run_sandboxed",
    "safe_run_sync",
]

_ORPHAN_TRACKER: set[int] = set()
_ORPHAN_LOCK = threading.Lock()


class _SudoCache:
    password: str | None = None


_SUDO_PASSWORD_LOCK = threading.Lock()


_PATH_TRAVERSAL_RE = re.compile(r"(?:\.\.[\\/]|%2e%2e[\\/%])", re.IGNORECASE)


@_atexit.register
def _cleanup_orphans_atexit() -> None:
    try:
        _cleanup_orphans(is_exit=True)
    except Exception:
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
    with _ORPHAN_LOCK:
        pids = list(_ORPHAN_TRACKER)
    for pid in pids:
        try:
            if _is_windows():
                if is_exit:
                    if _signal:
                        os.kill(pid, _signal.SIGTERM)
                else:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
            else:
                if _signal:
                    os.kill(pid, _signal.SIGTERM)
        except (OSError, PermissionError, subprocess.SubprocessError):
            logger.debug("Failed to kill orphan PID %d (already exited)", pid)
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.discard(pid)


async def _kill_process(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        logger.debug("Process PID %s already exited during kill", proc.pid)
    except Exception as exc:
        logger.debug("Failed to kill process PID %s: %s", proc.pid, exc)


_SIGNAL_NAMES: dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    6: "SIGABRT",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    15: "SIGTERM",
}


def _signal_name(signum: int) -> str:
    return _SIGNAL_NAMES.get(signum, f"signal {signum}")


def _check_path_traversal(cmd: list[str]) -> None:
    """Check for path traversal patterns in command arguments."""
    for i, part in enumerate(cmd):
        if _PATH_TRAVERSAL_RE.search(part):
            raise ValueError(f"command part at index {i} contains path traversal pattern: {part!r}")


def _format_not_found(cmd: list[str]) -> str:
    if len(cmd) >= 3 and Path(cmd[0]).name.lower() in ("sh", "bash") and cmd[1] == "-c":
        parts = cmd[2].strip().split()
        name = parts[0] if parts else "?"
        if name == "sudo" and len(parts) > 1:
            name = parts[1] if parts[1] != "-S" else (parts[2] if len(parts) > 2 else "?")
    else:
        name = cmd[0] if cmd else "?"
        if name == "sudo" and len(cmd) > 1:
            name = cmd[1] if cmd[1] != "-S" else (cmd[2] if len(cmd) > 2 else "?")
    hints: list[str] = []
    pid = get_platform_id()
    if pid == "android":
        hints.append(f"pkg install {name}")
    elif pid == "ios":
        hints.append(f"apk add {name}")
    elif pid == "harmonyos":
        hints.append(f"ohpm install {name}")
    elif pid == "windows":
        hints.append(f"winget install {name}")
        hints.append(f"choco install {name}")
    elif pid == "macos":
        if shutil.which("brew"):
            hints.append(f"brew install {name}")
    else:
        if shutil.which("apt-get"):
            hints.append(f"sudo apt-get install {name}")
        elif shutil.which("brew"):
            hints.append(f"brew install {name}")
        elif shutil.which("pacman"):
            hints.append(f"sudo pacman -S {name}")
        elif shutil.which("dnf"):
            hints.append(f"sudo dnf install {name}")
        elif shutil.which("apk"):
            hints.append(f"apk add {name}")
    msg = f"Binary not found: '{name}' is not installed or not found in PATH."
    if hints:
        msg += f"\nInstall it with: {hints[0]}"
    return msg


def _describe_exit(exit_code: int) -> str:
    if exit_code == -1:
        return "Internal error"
    if exit_code < 0:
        name = _signal_name(-exit_code)
        return f"Killed by {name}"
    return f"Exited with code {exit_code}"


def detect_package_manager() -> str:
    from ._platform import detect_package_manager_platform

    return detect_package_manager_platform()


def get_platform_shell_cmd(command: str) -> list[str]:
    return _get_platform_shell_cmd(command)


_DESTRUCTIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+(?:-rf\s+)?(?:--no-preserve-root\s+)?/(?:\.\s*)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bdd\s+if=/dev/zero\s+of=", re.IGNORECASE),
    re.compile(r"\bdd\b.*\bof=/dev/(?!null\b|zero\b)\S+", re.IGNORECASE),
    re.compile(r":\(\)\{\s*:\|:&\s*\};\s*:"),
    re.compile(r"\bmkfs\.", re.IGNORECASE),
    re.compile(
        r"\b(mkfs(?:\.\w+)?|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|mkswap|"
        r"ntfsformat|mkntfs|newfs(?:_\w+)?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bmkswap\b"),
    re.compile(
        r"\b(?:chmod|chown|chgrp)\b.*(?:-[a-zA-Z]*R[a-zA-Z]*\b|--recursive\b).*/", re.IGNORECASE
    ),
    re.compile(
        r"\b(?:curl|wget|fetch|aria2c|axel)\b.*"
        r"(?:-o|--output(?:-document)?|--out|--index-out|-O)"
        r"(?:=|\s*)(?:\d+=)?/dev/(?:sd|nvme|vd|xvd|disk/)",
        re.IGNORECASE,
    ),
    re.compile(r"\blwp-download\b.*/dev/(?:sd|nvme|vd|xvd|disk/)", re.IGNORECASE),
    re.compile(r"\bsocat\b.*(?:OPEN|CREATE):/dev/(?:sd|nvme|vd|disk/)", re.IGNORECASE),
    re.compile(r"\b(?:nwipe|scrub|sg_unmap|srm|wipe|bcwipe)\b", re.IGNORECASE),
    re.compile(r"(?:\\\\\.\\physicaldrive|\bformat\s+[a-z]\s*:)", re.IGNORECASE),
    re.compile(r"/dev/disk/", re.IGNORECASE),
    re.compile(r"\bln\b.*/dev/null.*/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
    re.compile(r"\bcp\b\s+(?:-[^\s]+\s+)*\S+\s+/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
    re.compile(r"(?:>{1,2}|\btee\b)\s*/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
    re.compile(r"\b(?:truncate|shred|install)\b.*/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
    re.compile(
        r"\bfind\b.*(?:-delete\b|-exec\s+(?:rm|shred|wipe|srm|dd|bcwipe)\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(wipefs|sgdisk|blkdiscard|truncate|shred|hdparm|nvme|cryptsetup|"
        r"sg_format|sg_sanitize|nwipe|scrub|sg_unmap)\b.*(/dev/)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:cp|tee|install|openssl|tar|dc3dd|badblocks|fio|rsync)\b"
        r".*/dev/(?:sd|nvme|vd|xvd)",
        re.IGNORECASE,
    ),
    re.compile(r"shutil\s*\.\s*rmtree\s*\(\s*['\"]/", re.IGNORECASE),
    re.compile(r"(?:FileUtils\s*\.\s*rm_rf|rmSync)\s*\(?\s*['\"]/", re.IGNORECASE),
    re.compile(
        r"(?:open|File\.write|IO\.write|writeFile(?:Sync)?|file_put_contents)\s*\(\s*"
        r"['\"]?/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/)",
        re.IGNORECASE,
    ),
    re.compile(
        r"Path\s*\(\s*['\"]?/dev/(?:sd|nvme|vd|xvd|hd|loop|dm-|mapper/).{0,80}"
        r"\.write_(?:bytes|text)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(r"\bqemu-img\b.*/dev/(?:sd|nvme|vd|xvd)", re.IGNORECASE),
    re.compile(r"\brsync\b.*--delete", re.IGNORECASE),
    re.compile(r"\bmv\b\s+(?:-[^\s]+\s+)*(?:/etc|/var|/usr|/boot|/root)\b", re.IGNORECASE),
    re.compile(r"\b(?:chmod|chown)\b\s+(?:-R\s+|--recursive\s+)\S+\s+/", re.IGNORECASE),
    re.compile(
        r"\b(?:zpool\s+destroy|zfs\s+destroy|lvremove|vgremove|pvremove|" r"dmsetup\s+remove)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bmdadm\b.*--zero-superblock\b", re.IGNORECASE),
    re.compile(r"\bbtrfs\s+(?:subvolume\s+delete|filesystem\s+resize)\b", re.IGNORECASE),
    re.compile(r"\bxfs_repair\b.*-L\b", re.IGNORECASE),
    re.compile(r"\bdebugfs\s+-w\b", re.IGNORECASE),
]


def _confirm_destructive(cmd: list[str]) -> None:
    full = " ".join(cmd)
    match_text = ""
    for pattern in _DESTRUCTIVE_PATTERNS:
        m = pattern.search(full)
        if m:
            match_text = m.group(0)
            break
    if _console:
        _console.print(f"[yellow]⚠ Destructive command detected: {match_text}[/yellow]")
        _console.print(f"[dim]Full: {full[:200]}[/dim]")
    else:
        print(f"WARNING: Destructive command detected: {match_text}")
        print(f"Full: {full[:200]}")
    from .tool_installer import tty_confirm

    if not tty_confirm("Run this command?", default=False):
        raise ValueError(f"destructive command cancelled by user: {full[:120]}")


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

    _check_path_traversal(cmd)

    full = " ".join(cmd)
    # Hard-block the same disk-wipe / partition class as BaseExecutor (no prompt).
    try:
        from siyarix.destructive import assert_command_not_destructive
        from siyarix.exceptions import PermissionDeniedError

        assert_command_not_destructive(full)
    except PermissionDeniedError as exc:
        raise ValueError(str(exc)) from exc

    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(full):
            _confirm_destructive(cmd)
            return


# Secrets / posture that must never ride into child tool processes (SX-A03 / SEC-07).
# Prefer shared names from dotenv_guard so planted-.env and child-env stay aligned.
from siyarix.dotenv_guard import API_KEY_PATTERNS as _DOTENV_API_KEY_PATTERNS
from siyarix.dotenv_guard import BLOCKED_EXACT as _DOTENV_BLOCKED_EXACT
from siyarix.dotenv_guard import BLOCKED_VARS as _DOTENV_BLOCKED_VARS

# Exact names dotenv already refuses (BLOCKED_EXACT / BLOCKED_VARS / API_KEY_PATTERNS).
_DOTENV_DENY_EXACT: frozenset[str] = (
    _DOTENV_BLOCKED_EXACT
    | _DOTENV_BLOCKED_VARS
    | frozenset(p for p in _DOTENV_API_KEY_PATTERNS if p.isidentifier() and p == p.upper())
)

# Session / TLS / cloud config pivots dotenv already refuses from cwd .env.
_SCRUB_DOTENV_SHARED_EXACT: frozenset[str] = frozenset(
    name
    for name in (
        "SSLKEYLOGFILE",
        "NETRC",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "KUBECONFIG",
        "KUBE_CONFIG",
        "KUBE_CONFIG_PATH",
        "PGPASSFILE",
        "DOCKER_CERT_PATH",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "CURL_HOME",
        "OPENSSL_CONF",
        "GNUPGHOME",
        "BOTO_CONFIG",
        "GOOGLE_APPLICATION_CREDENTIALS",
    )
    if name in _DOTENV_DENY_EXACT
)
# Always drop (profile / webhook / TLS & netrc pivots) even if dotenv lists drift.
_SCRUB_ENV_ALWAYS: frozenset[str] = frozenset(
    {
        "SSLKEYLOGFILE",
        "NETRC",
        "SIYARIX_WEBHOOK_URL",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
    }
)
# Infix from dotenv API_KEY_PATTERNS (covers DISCORD_WEBHOOK_URL, etc.).
_SCRUB_WEBHOOK_INFIX = "_WEBHOOK" if "_WEBHOOK" in _DOTENV_API_KEY_PATTERNS else "_WEBHOOK"
# Suffixes shared with dotenv credential fragments (suffix-only to avoid
# over-matching names like XDG_SESSION_TYPE).
_SCRUB_DOTENV_SUFFIXES: tuple[str, ...] = tuple(
    p for p in ("_COOKIE", "_SESSION", "_AUTH") if p in _DOTENV_API_KEY_PATTERNS
)

_SCRUB_ENV_EXACT: frozenset[str] = frozenset(
    {
        "SIYARIX_SUDO_PASSWORD",
        "SIYARIX_MASTER_PASSWORD",
        "SIYARIX_MASTER_KEY",
        "SIYARIX_VAULT_PASSWORD",
        "SIYARIX_PREAUTHORIZED",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",  # RH-31
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "PGPASSWORD",
        "MYSQL_PWD",
        "REDIS_PASSWORD",
        # Connection DSNs / URLs often embed credentials (RH-13).
        "DATABASE_URL",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URI",
        "CONNECTION_STRING",
        "DSN",
        "AMQP_URL",
        "BROKER_URL",
        "CELERY_BROKER_URL",
        # Provider short keys / framework secrets (RH-31).
        "OPENAI_KEY",
        "ANTHROPIC_KEY",
        "XAI_KEY",
        "GROQ_KEY",
        "DJANGO_SECRET_KEY",
        "FLASK_SECRET_KEY",
        "SECRET_KEY",
    }
) | _SCRUB_DOTENV_SHARED_EXACT | _SCRUB_ENV_ALWAYS
_SCRUB_ENV_SUFFIXES: tuple[str, ...] = (
    "_API_KEY",
    "_SECRET",
    "_SECRET_KEY",
    "_PASSWORD",
    "_TOKEN",
    "_PRIVATE_KEY",
    "_ACCESS_KEY",
    "_ACCESS_KEY_ID",
    "_MASTER_PASSWORD",
    "_MASTER_KEY",
    "_PASSPHRASE",
    "_BEARER",
    "_CONNECTION_STRING",
    "_DATABASE_URL",
    "_DSN",
    "_COOKIES",
) + _SCRUB_DOTENV_SUFFIXES
# Bare ``FOO_KEY`` provider shorthand (OPENAI_KEY, etc.).
_SCRUB_BARE_KEY_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*)_KEY$")


def _scrub_secret_env(exec_env: dict[str, str]) -> dict[str, str]:
    """Drop credential / vault secrets from the child process environment."""
    cleaned: dict[str, str] = {}
    for key, val in exec_env.items():
        upper = key.upper()
        if upper in _SCRUB_ENV_EXACT or key in _SCRUB_ENV_EXACT:
            continue
        # Common *_WEBHOOK* names (DISCORD_WEBHOOK_URL, …) — SEC-07.
        if _SCRUB_WEBHOOK_INFIX in upper:
            continue
        if any(upper.endswith(suf) for suf in _SCRUB_ENV_SUFFIXES):
            continue
        if upper.startswith("SIYARIX_") and upper.endswith("_KEY"):
            continue
        # Bare provider ``*_KEY`` (OPENAI_KEY) — RH-31.
        if _SCRUB_BARE_KEY_RE.match(upper):
            continue
        # Any *URL / *URI that looks like a DSN with userinfo (RH-13).
        if (upper.endswith("_URL") or upper.endswith("_URI")) and "://" in val:
            try:
                parsed = urllib.parse.urlparse(val)
                if parsed.username is not None or parsed.password is not None:
                    continue
            except Exception:
                continue
        cleaned[key] = val
    return cleaned


def _prepare_env(env: dict[str, str] | None = None) -> dict[str, str]:
    exec_env = _scrub_secret_env(dict(os.environ))
    if env:
        # Caller-supplied overrides are scrubbed too (no secret laundering).
        exec_env.update(_scrub_secret_env(dict(env)))
    try:
        from siyarix.stealth import stealth_engine

        if stealth_engine.config.enabled:
            proxy = stealth_engine.get_current_proxy()
            if proxy:
                exec_env["HTTP_PROXY"] = proxy
                exec_env["HTTPS_PROXY"] = proxy
                exec_env["ALL_PROXY"] = proxy
    except (ImportError, AttributeError):
        pass
    return exec_env


def safe_run_sync(
    cmd: list[str],
    timeout: float = 60,
    capture_output: bool = True,
    text: bool = True,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
    _validate_cmd_list(cmd)
    _cleanup_orphans()
    exec_env = _prepare_env(env)
    if cwd is not None and not isinstance(cwd, str):
        cwd = str(cwd)
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
        )
        return ExecutionResult(exit_code=cp.returncode, stdout=cp.stdout, stderr=cp.stderr)
    except subprocess.TimeoutExpired:
        logger.debug("safe_run_sync timeout for cmd=%s", cmd)
        raise
    except Exception as exc:
        logger.exception("safe_run_sync failed for cmd=%s: %s", cmd, exc)
        raise


def _use_thread_fallback() -> bool:
    if not _is_windows():
        return False
    try:
        loop = asyncio.get_running_loop()
        proactor = getattr(asyncio, "ProactorEventLoop", None)
        if proactor is not None and isinstance(loop, proactor):
            return True
        if isinstance(loop, asyncio.SelectorEventLoop):
            return True
        return False
    except RuntimeError:
        set_event_loop_policy()
        return True


def _verify_sudo_password(password: str) -> bool:
    if _is_windows() or not shutil.which("sudo"):
        return False
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
    if _SudoCache.password is not None:
        return _SudoCache.password

    val = os.environ.get("SIYARIX_SUDO_PASSWORD")
    if val:
        with _SUDO_PASSWORD_LOCK:
            _SudoCache.password = val
        return val

    # Intentionally do NOT read sudo passwords from settings.toml — plaintext
    # persistence there is a production secret leak. Use SIYARIX_SUDO_PASSWORD.

    if sys.stdin.isatty():
        banner = (
            "\n"
            "Sudo/administrator password required for this command\n"
            "(type it below -- input is hidden for security)\n"
            "\n"
            "Tip: set SIYARIX_SUDO_PASSWORD in the environment (not settings.toml)\n"
            "     to skip this prompt.\n"
            "\n"
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

            if _verify_sudo_password(password):
                with _SUDO_PASSWORD_LOCK:
                    _SudoCache.password = password
                return password

            msg = (
                "Incorrect password. Please try again.\n"
                if not is_last
                else "Incorrect password after 3 attempts. "
                "The command will fail unless you configure the password "
                "via the SIYARIX_SUDO_PASSWORD environment variable.\n"
            )
            sys.stderr.write(msg)
            sys.stderr.flush()

        return None

    else:
        logger.warning(
            "sudo required but no TTY available to prompt for password. "
            "Set SIYARIX_SUDO_PASSWORD in the environment (never in settings.toml)."
        )

    return None


async def safe_run_async(
    cmd: list[str], timeout: int = 60, validate: bool = True, env: dict[str, str] | None = None
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
                        cmd,
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        text=True,
                        timeout=timeout,
                        check=False,
                        env=exec_env,
                    ),
                ),
                timeout=timeout + 5,
            )
        except TimeoutError:
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
            logger.error("sudo required but no password available -- returning error")
            return ExecutionResult(
                exit_code=-1,
                stderr=(
                    "sudo password is required for this command.\n"
                    "Provide it via one of:\n"
                    "  1. Set the SIYARIX_SUDO_PASSWORD environment variable\n"
                    "  2. Export SIYARIX_SUDO_PASSWORD in your environment\n"
                    "  3. Run in an interactive terminal to be prompted"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        if modified_cmd[0] == "sudo":
            if "-S" not in modified_cmd:
                modified_cmd.insert(1, "-S")
        else:
            is_shell = (
                len(modified_cmd) >= 3
                and os.path.basename(modified_cmd[0]).lower()
                in ("sh", "bash", "pwsh", "powershell")
                and modified_cmd[1] == "-c"
            )
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
        )
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
    except TimeoutError:
        logger.warning("safe_run_async timeout (%ds) for cmd=%s -- killing process", timeout, cmd)
        timed_out = True
        await _kill_process(proc)
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=1.0)
        except TimeoutError:
            logger.debug("safe_run_async -- drain after kill timed out for cmd=%s", cmd)
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
    timeout: int = 60,
    validate: bool = True,
    on_stdout: Callable[[str], Any] | None = None,
    on_stderr: Callable[[str], Any] | None = None,
    max_output_bytes: int | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
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
                    bufsize=1,
                    errors="replace",
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
            logger.debug("safe_run_async_stream (thread) failed to start command %s: %s", cmd, exc)
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
            exit_code = await asyncio.wait_for(
                loop.run_in_executor(None, sync_proc.wait),
                timeout=timeout,
            )
        except TimeoutError:
            logger.warning("safe_run_async_stream (thread) timeout for cmd=%s", cmd)
            try:
                sync_proc.kill()
            except Exception:
                pass
            exit_code = -1
            stderr_lines.append(f"Command timed out after {timeout}s and was killed.")

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
            logger.error("sudo required but no password available -- returning error")
            return ExecutionResult(
                exit_code=-1,
                stderr=(
                    "sudo password is required for this command.\n"
                    "Provide it via one of:\n"
                    "  1. Set the SIYARIX_SUDO_PASSWORD environment variable\n"
                    "  2. Export SIYARIX_SUDO_PASSWORD in your environment\n"
                    "  3. Run in an interactive terminal to be prompted"
                ),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        if modified_cmd[0] == "sudo":
            if "-S" not in modified_cmd:
                modified_cmd.insert(1, "-S")
        else:
            is_shell = (
                len(modified_cmd) >= 3
                and Path(modified_cmd[0]).name.lower()
                in ("sh", "bash", "pwsh", "powershell", "dash")
                and modified_cmd[1] == "-c"
            )
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
        )
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

    stdout_task = asyncio.create_task(_safe_read(async_proc.stdout, stdout_lines, on_stdout))
    stderr_task = asyncio.create_task(_safe_read(async_proc.stderr, stderr_lines, on_stderr))

    timed_out = False
    try:
        await asyncio.wait_for(async_proc.wait(), timeout=timeout)
        exit_code = async_proc.returncode if async_proc.returncode is not None else -1

        try:
            await asyncio.wait_for(asyncio.gather(stdout_task, stderr_task), timeout=1.0)
        except TimeoutError:
            logger.debug("safe_run_async_stream reader tasks timed out after process exit")
            stdout_task.cancel()
            stderr_task.cancel()
    except TimeoutError:
        logger.warning(
            "safe_run_async_stream timeout (%ds) for cmd=%s -- killing process", timeout, cmd
        )
        timed_out = True
        await _kill_process(async_proc)

        try:
            await asyncio.wait_for(asyncio.gather(stdout_task, stderr_task), timeout=1.0)
        except TimeoutError:
            logger.debug("safe_run_async_stream reader tasks timed out after process kill")
            stdout_task.cancel()
            stderr_task.cancel()
        exit_code = -1
    finally:
        if async_proc.pid:
            with _ORPHAN_LOCK:
                _ORPHAN_TRACKER.discard(async_proc.pid)

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
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    allow_network: bool = False,
    use_seccomp: bool = True,
    seccomp_profile: str | None = None,
) -> ExecutionResult:
    """Run a command inside a sandbox if available, otherwise fallback to restricted env.

    Attempts to use `bwrap` (Bubblewrap) on Linux or Docker. If neither are available,
    runs the command normally but with a restricted PATH and sanitized environment.
    On Windows/mobile, directly falls back to restricted env.

    Args:
        command: The command to run.
        timeout: Timeout in seconds (default 60).
        cwd: Working directory.
        env: Additional environment variables.
        allow_network: If True, allow network access.
        use_seccomp: If True and using bwrap, apply a restrictive seccomp profile.
    """
    sandbox_cmd = []

    if not _is_windows() and not _is_mobile() and _is_linux() and shutil.which("bwrap"):
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
        if seccomp_profile and use_seccomp:
            sandbox_cmd.extend(["--seccomp", str(seccomp_profile)])
        if allow_network:
            sandbox_cmd.remove("--unshare-all")
            sandbox_cmd.extend(
                ["--unshare-pid", "--unshare-user", "--unshare-cgroup", "--unshare-ipc"]
            )

        if cwd:
            cwd_str = str(cwd)
            sandbox_cmd.extend(["--bind", cwd_str, cwd_str])
        sandbox_cmd.extend(["--"])
        sandbox_cmd.extend(command)
    elif shutil.which("docker") and not _is_mobile():
        img = "alpine:latest" if not allow_network else "ubuntu:latest"
        sandbox_cmd = ["docker", "run", "--rm", "--network", "host" if allow_network else "none"]
        if use_seccomp:
            from .security_hardening import SeccompProfile

            sandbox_cmd.extend(
                ["--security-opt", f"seccomp={SeccompProfile.generate_docker_seccomp()}"]
            )
        if cwd:
            cwd_str = str(Path(cwd).resolve())
            sandbox_cmd.extend(["-v", f"{cwd_str}:/workspace", "-w", "/workspace"])
        sandbox_cmd.append(img)
        sandbox_cmd.extend(command)
    else:
        sandbox_cmd = command
        pid_safe = get_platform_id()
        if pid_safe == "android":
            restricted_env = {"PATH": f"{_get_termux_prefix()}/bin:/system/bin"}
        elif pid_safe == "ios":
            restricted_env = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
        else:
            restricted_env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}
        if env:
            restricted_env.update(env)
        env = restricted_env

    return safe_run_sync(sandbox_cmd, timeout=timeout, cwd=cwd, env=env)
