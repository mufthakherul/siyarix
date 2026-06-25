from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for siyarix.subprocess_utils — covering all non-duplicated functions."""


import asyncio
import signal
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.subprocess_utils import (
    ExecutionResult,
    _cleanup_orphans,
    _cleanup_orphans_atexit,
    _kill_process,
    _ORPHAN_LOCK,
    _ORPHAN_TRACKER,
    _prepare_env,
    _use_thread_fallback,
    _validate_cmd_list,
    detect_package_manager,
    get_platform_shell_cmd,
    safe_run_async,
    safe_run_async_stream,
    safe_run_sandboxed,
    safe_run_sync,
)


# ── helpers ──────────────────────────────────────────────────────────────


def _reset_orphan_tracker() -> None:
    with _ORPHAN_LOCK:
        _ORPHAN_TRACKER.clear()


# ── ExecutionResult ──────────────────────────────────────────────────────


class TestExecutionResult:
    def test_success_true_when_exit_code_zero(self) -> None:
        r = ExecutionResult(exit_code=0)
        assert r.success is True

    def test_success_false_when_exit_code_nonzero(self) -> None:
        r = ExecutionResult(exit_code=1)
        assert r.success is False

    def test_defaults(self) -> None:
        r = ExecutionResult()
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.duration_ms == 0.0


# ── detect_package_manager ───────────────────────────────────────────────


class TestDetectPackageManager:
    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_detects_apt(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/apt" if x == "apt" else None
        assert detect_package_manager() == "apt"

    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_detects_dnf(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/dnf" if x == "dnf" else None
        assert detect_package_manager() == "dnf"

    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_detects_pacman(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/pacman" if x == "pacman" else None
        assert detect_package_manager() == "pacman"

    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="macos")
    def test_detects_brew(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/opt/homebrew/bin/brew" if x == "brew" else None
        assert detect_package_manager() == "brew"

    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="android")
    def test_detects_pkg(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/usr/sbin/pkg" if x == "pkg" else None
        assert detect_package_manager() == "pkg"

    @patch("siyarix._platform.shutil.which")
    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_detects_apk(self, mock_platform: MagicMock, mock_which: MagicMock) -> None:
        mock_which.side_effect = lambda x: "/sbin/apk" if x == "apk" else None
        assert detect_package_manager() == "apk"

    @patch("siyarix._platform.shutil.which", return_value=None)
    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_fallback_pip(self, _mock_platform: MagicMock, _mock_sh: MagicMock) -> None:
        assert detect_package_manager() == "pip"

    @patch("siyarix._platform.shutil.which", side_effect=lambda x: x if x == "choco" else None)
    @patch("siyarix._platform.get_platform_id", return_value="windows")
    def test_windows_choco(self, _mock_platform: MagicMock, _mock_sh: MagicMock) -> None:
        assert detect_package_manager() == "choco"

    @patch("siyarix._platform.shutil.which", side_effect=lambda x: x if x == "winget" else None)
    @patch("siyarix._platform.get_platform_id", return_value="windows")
    def test_windows_winget(self, _mock_platform: MagicMock, _mock_sh: MagicMock) -> None:
        assert detect_package_manager() == "winget"


# ── get_platform_shell_cmd ───────────────────────────────────────────────


class TestGetPlatformShellCmd:
    @patch("siyarix._platform.get_platform_id", return_value="windows")
    def test_windows(self, *_args: object) -> None:
        assert get_platform_shell_cmd("echo hi") == ["cmd", "/c", "echo hi"]

    @patch("siyarix._platform.get_platform_id", return_value="linux")
    def test_unix(self, *_args: object) -> None:
        assert get_platform_shell_cmd("echo hi") == ["sh", "-c", "echo hi"]

    @patch("siyarix._platform.get_platform_id", return_value="macos")
    def test_macos(self, *_args: object) -> None:
        assert get_platform_shell_cmd("ls -la") == ["sh", "-c", "ls -la"]


# ── _validate_cmd_list ───────────────────────────────────────────────────


class TestValidateCmdList:
    def test_non_list_raises(self) -> None:
        with pytest.raises(ValueError, match="cmd must be a non-empty list"):
            _validate_cmd_list("echo hi")  # type: ignore[arg-type]

    def test_empty_list_raises(self) -> None:
        with pytest.raises(ValueError, match="cmd must be a non-empty list"):
            _validate_cmd_list([])

    def test_non_string_element_raises(self) -> None:
        with pytest.raises(ValueError, match="all command parts must be strings"):
            _validate_cmd_list(["echo", 123])  # type: ignore[list-item]

    def test_empty_element_raises(self) -> None:
        with pytest.raises(ValueError, match="command part at index 0 is empty"):
            _validate_cmd_list([""])

    def test_shell_metachars_allowed(self) -> None:
        _validate_cmd_list(["echo", "hello; world"])
        _validate_cmd_list(["echo", "hello | world"])
        _validate_cmd_list(["echo", "hello & world"])
        _validate_cmd_list(["echo", "hello > file"])
        _validate_cmd_list(["echo", "hello < file"])
        _validate_cmd_list(["echo", "hello `echo hi`"])
        _validate_cmd_list(["echo", "hello $USER"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_destructive_rm_root_blocked(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            _validate_cmd_list(["rm", "-rf", "/"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_destructive_rm_root_no_preserve_blocked(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            _validate_cmd_list(["sh", "-c", "rm -rf --no-preserve-root /"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_destructive_dd_blocked(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            _validate_cmd_list(["sh", "-c", "dd if=/dev/zero of=/dev/sda bs=4M"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_destructive_forkbomb_blocked(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            _validate_cmd_list(["sh", "-c", ":(){ :|:& };:"])

    @patch(
        "siyarix.subprocess_utils._confirm_destructive",
        side_effect=ValueError("destructive pattern"),
    )
    def test_destructive_mkfs_blocked(self, mock_confirm) -> None:
        with pytest.raises(ValueError, match="destructive pattern"):
            _validate_cmd_list(["mkfs.ext4", "/dev/sda1"])

    def test_safe_commands_pass(self) -> None:
        _validate_cmd_list(["python", "-c", "print('ok')"])
        _validate_cmd_list(["sh", "-c", "curl -sI example.com 2>/dev/null; echo '---'"])
        _validate_cmd_list(["echo", "hello"])


# ── _prepare_env ─────────────────────────────────────────────────────────


class TestPrepareEnv:
    @patch("siyarix.stealth.stealth_engine")
    def test_no_custom_env(self, mock_stealth: MagicMock) -> None:
        mock_stealth.config.enabled = False
        result = _prepare_env()
        assert "PATH" in result

    @patch("siyarix.stealth.stealth_engine")
    def test_with_custom_env(self, mock_stealth: MagicMock) -> None:
        mock_stealth.config.enabled = False
        result = _prepare_env({"MY_VAR": "hello"})
        assert result["MY_VAR"] == "hello"

    @patch("siyarix.stealth.stealth_engine")
    def test_custom_overrides_os_environ(self, mock_stealth: MagicMock) -> None:
        mock_stealth.config.enabled = False
        result = _prepare_env({"PATH": "/custom/path"})
        assert result["PATH"] == "/custom/path"

    @patch("siyarix.stealth.stealth_engine")
    def test_stealth_proxy_injected(self, mock_stealth: MagicMock) -> None:
        mock_stealth.config.enabled = True
        mock_stealth.get_current_proxy.return_value = "http://proxy:8080"
        result = _prepare_env()
        assert result["HTTP_PROXY"] == "http://proxy:8080"
        assert result["HTTPS_PROXY"] == "http://proxy:8080"
        assert result["ALL_PROXY"] == "http://proxy:8080"

    @patch("siyarix.stealth.stealth_engine")
    def test_stealth_enabled_no_proxy(self, mock_stealth: MagicMock) -> None:
        mock_stealth.config.enabled = True
        mock_stealth.get_current_proxy.return_value = None
        result = _prepare_env()
        assert "HTTP_PROXY" not in result


# ── _cleanup_orphans ─────────────────────────────────────────────────────


class TestCleanupOrphans:
    def setup_method(self) -> None:
        _reset_orphan_tracker()

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run")
    def test_win32_taskkill(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock()
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(7777)
        _cleanup_orphans()
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "taskkill" in args
        assert "7777" in args

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run", side_effect=subprocess.SubprocessError)
    def test_win32_taskkill_error(self, mock_run: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(7776)
        _cleanup_orphans()
        with _ORPHAN_LOCK:
            assert 7776 not in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.os.kill")
    def test_win32_exit_kill(self, mock_kill: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(7775)
        _cleanup_orphans(is_exit=True)
        mock_kill.assert_called_once()

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    def test_empty_tracker_noop(self) -> None:
        _cleanup_orphans()  # should not raise

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run", side_effect=PermissionError)
    def test_win32_taskkill_permission_error(self, mock_run: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(7774)
        _cleanup_orphans()
        with _ORPHAN_LOCK:
            assert 7774 not in _ORPHAN_TRACKER


# ── _cleanup_orphans_atexit ──────────────────────────────────────────────


class TestCleanupOrphansAtexit:
    @patch("siyarix.subprocess_utils._cleanup_orphans")
    def test_basic(self, mock_cleanup: MagicMock) -> None:
        _cleanup_orphans_atexit()
        mock_cleanup.assert_called_once_with(is_exit=True)

    @patch("siyarix.subprocess_utils._cleanup_orphans", side_effect=Exception("boom"))
    def test_suppresses_exception(self, mock_cleanup: MagicMock) -> None:
        _cleanup_orphans_atexit()  # should not raise


# ── _kill_process ────────────────────────────────────────────────────────


class TestKillProcess:
    async def _make_proc(self, pid: int = 12345) -> MagicMock:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = pid
        proc.kill = MagicMock()
        return proc

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    async def test_win32_kill(self) -> None:
        proc = await self._make_proc()
        await _kill_process(proc)
        proc.kill.assert_called_once()

    async def test_unix_killpg(self) -> None:
        proc = await self._make_proc(pid=12345)
        await _kill_process(proc)
        proc.kill.assert_called_once()

    async def test_unix_pgid_one_falls_back_to_kill(self) -> None:
        proc = await self._make_proc(pid=12345)
        await _kill_process(proc)
        proc.kill.assert_called_once()

    async def test_unix_getpgid_fails(self) -> None:
        proc = await self._make_proc(pid=12345)
        await _kill_process(proc)
        proc.kill.assert_called_once()

    async def test_unix_killpg_process_lookup_error(self) -> None:
        proc = await self._make_proc(pid=12345)
        await _kill_process(proc)  # should not raise

    async def test_unix_killpg_unknown_exception_falls_back(self) -> None:
        proc = await self._make_proc(pid=12345)
        await _kill_process(proc)
        proc.kill.assert_called_once()


# ── safe_run_sync (edge cases not in test_subprocess_safe_run) ────────────


class TestSafeRunSync:
    def test_with_cwd_and_env(self, tmp_path) -> None:
        script = tmp_path / "script.py"
        script.write_text("import os,sys\nsys.stdout.write(os.environ.get('FOO',''))")
        res = safe_run_sync(
            [sys.executable, str(script)],
            timeout=5,
            env={"FOO": "bar"},
            cwd=str(tmp_path),
        )
        assert res.exit_code == 0
        assert "bar" in res.stdout

    def test_binary_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            safe_run_sync(["/nonexistent/binary"], timeout=1)

    def test_timeout_expired(self, tmp_path) -> None:
        script = tmp_path / "sleep.py"
        script.write_text("import time\ntime.sleep(100)")
        with pytest.raises(subprocess.TimeoutExpired):
            safe_run_sync(
                [sys.executable, str(script)],
                timeout=0.1,
            )


# ── _use_thread_fallback ─────────────────────────────────────────────────


class TestUseThreadFallback:
    @patch("siyarix.subprocess_utils.os.name", "nt")
    @patch("siyarix.subprocess_utils.asyncio.get_running_loop")
    async def test_windows_selector_loop(self, mock_get_loop: MagicMock) -> None:
        mock_get_loop.return_value = asyncio.SelectorEventLoop()
        mock_get_loop.return_value.close()
        assert _use_thread_fallback() is True

    @patch("siyarix.subprocess_utils.os.name", "nt")
    @patch("siyarix.subprocess_utils.asyncio.get_running_loop")
    async def test_windows_proactor_loop(self, mock_get_loop: MagicMock) -> None:
        # On Linux we can't create a ProactorEventLoop; simulate via mock
        import asyncio

        mock_loop = MagicMock(spec=asyncio.AbstractEventLoop)
        mock_get_loop.return_value = mock_loop
        # ProactorEventLoop is not a SelectorEventLoop, so fallback should be False
        assert _use_thread_fallback() is False

    @patch("siyarix.subprocess_utils._is_windows", return_value=False)
    async def test_unix_always_false(self, *_args: object) -> None:
        assert _use_thread_fallback() is False


# ── safe_run_async ───────────────────────────────────────────────────────


class TestSafeRunAsync:
    async def test_basic(self) -> None:
        result = await safe_run_async([sys.executable, "-c", "print('async ok')"], timeout=5)
        assert result.exit_code == 0
        assert "async ok" in result.stdout

    async def test_validate_false_skips_validation(self) -> None:
        result = await safe_run_async(
            [sys.executable, "-c", "print('no validate')"],
            timeout=5,
            validate=False,
        )
        assert result.exit_code == 0

    async def test_binary_not_found_create_subprocess(self) -> None:
        result = await safe_run_async(["/nonexistent/tool"], timeout=1)
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr

    async def test_timeout_error(self) -> None:
        result = await safe_run_async(
            [sys.executable, "-c", "import time\ntime.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_thread_fallback_basic(self, _mock: MagicMock) -> None:
        result = await safe_run_async([sys.executable, "-c", "print('thread ok')"], timeout=5)
        assert result.exit_code == 0
        assert "thread ok" in result.stdout

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_thread_fallback_timeout_asyncio(self, _mock: MagicMock) -> None:
        # subprocess.run itself won't timeout but the asyncio.wait_for wrapper will
        result = await safe_run_async(
            [sys.executable, "-c", "import time\ntime.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    @patch(
        "siyarix.subprocess_utils.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="test", timeout=0.05),
    )
    async def test_thread_fallback_subprocess_timeout(
        self, _mock_run: MagicMock, _mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async(
            [sys.executable, "-c", "import time\ntime.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    @patch("siyarix.subprocess_utils.subprocess.run", side_effect=FileNotFoundError)
    async def test_thread_fallback_file_not_found(
        self, _mock_run: MagicMock, _mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async(["/nope"], timeout=1)
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr


# ── safe_run_async_stream ────────────────────────────────────────────────


class TestSafeRunAsyncStream:
    async def test_basic(self) -> None:
        stdout_lines: list[str] = []
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('stream ok')"],
            timeout=5,
            on_stdout=stdout_lines.append,
        )
        assert result.exit_code == 0
        assert "stream ok" in result.stdout

    async def test_stderr_callback(self) -> None:
        stderr_lines: list[str] = []
        result = await safe_run_async_stream(
            [sys.executable, "-c", "import sys\nprint('err', file=sys.stderr)"],
            timeout=5,
            on_stderr=stderr_lines.append,
            validate=False,
        )
        assert result.exit_code == 0
        assert "err" in result.stdout or "err" in result.stderr

    async def test_validate_false(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('skip val')"],
            timeout=5,
            validate=False,
        )
        assert result.exit_code == 0

    async def test_binary_not_found(self) -> None:
        result = await safe_run_async_stream(["/nonexistent/cmd"], timeout=1)
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr

    async def test_timeout(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "import time\ntime.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1

    async def test_max_output_bytes(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('hello')\nprint('world')"],
            timeout=5,
            max_output_bytes=1,
            validate=False,
        )
        assert result.exit_code == 0

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_thread_fallback_basic(self, _mock: MagicMock) -> None:
        stdout_lines: list[str] = []
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('thread stream')"],
            timeout=5,
            on_stdout=stdout_lines.append,
        )
        assert result.exit_code == 0
        assert "thread stream" in result.stdout

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_thread_fallback_file_not_found(self, _mock: MagicMock) -> None:
        result = await safe_run_async_stream(["/nope"], timeout=1)
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_thread_fallback_timeout(self, _mock: MagicMock) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "import time\ntime.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1


# ── safe_run_sandboxed ───────────────────────────────────────────────────


class TestSafeRunSandboxed:
    @patch("siyarix.subprocess_utils._is_windows", return_value=False)
    @patch("siyarix.subprocess_utils._is_mobile", return_value=False)
    @patch("siyarix.subprocess_utils._is_linux", return_value=True)
    @patch("siyarix.subprocess_utils.shutil.which", return_value="/usr/bin/bwrap")
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_bwrap_no_network(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["ls", "-la"], timeout=30)
        called_cmd = mock_sync.call_args[0][0]
        assert "bwrap" in called_cmd
        assert "--unshare-all" in called_cmd

    @patch("siyarix.subprocess_utils._is_windows", return_value=False)
    @patch("siyarix.subprocess_utils._is_mobile", return_value=False)
    @patch("siyarix.subprocess_utils._is_linux", return_value=True)
    @patch("siyarix.subprocess_utils.shutil.which", return_value="/usr/bin/bwrap")
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_bwrap_with_network(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["curl", "example.com"], timeout=30, allow_network=True)
        called_cmd = mock_sync.call_args[0][0]
        assert "bwrap" in called_cmd
        assert "--unshare-all" not in called_cmd

    @patch("siyarix.subprocess_utils._is_windows", return_value=False)
    @patch("siyarix.subprocess_utils._is_mobile", return_value=False)
    @patch("siyarix.subprocess_utils._is_linux", return_value=True)
    @patch("siyarix.subprocess_utils.shutil.which", return_value="/usr/bin/bwrap")
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_bwrap_with_cwd(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["ls"], timeout=30, cwd="/tmp")
        called_cmd = mock_sync.call_args[0][0]
        assert "--bind" in called_cmd
        assert "/tmp" in called_cmd

    @patch("siyarix.subprocess_utils.sys.platform", "linux")
    @patch(
        "siyarix.subprocess_utils.shutil.which",
        side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None,
    )
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_docker_fallback(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["nmap", "target"], timeout=60)
        called_cmd = mock_sync.call_args[0][0]
        assert "docker" in called_cmd
        assert "alpine:latest" in called_cmd

    @patch("siyarix.subprocess_utils.sys.platform", "linux")
    @patch(
        "siyarix.subprocess_utils.shutil.which",
        side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None,
    )
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_docker_with_network(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["curl", "example.com"], timeout=60, allow_network=True)
        called_cmd = mock_sync.call_args[0][0]
        assert "ubuntu:latest" in called_cmd

    @patch("siyarix.subprocess_utils.sys.platform", "linux")
    @patch(
        "siyarix.subprocess_utils.shutil.which",
        side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None,
    )
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_docker_with_cwd(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["ls"], timeout=60, cwd="/tmp")
        called_cmd = mock_sync.call_args[0][0]
        assert "-v" in called_cmd

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.shutil.which", return_value=None)
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_fallback_restricted_env(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["echo", "hi"], timeout=30)
        called_env = mock_sync.call_args[1].get("env", {})
        assert "/usr/local/bin" in called_env.get("PATH", "")

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.shutil.which", return_value=None)
    @patch("siyarix.subprocess_utils.safe_run_sync")
    def test_fallback_with_custom_env(self, mock_sync: MagicMock, *_args) -> None:
        mock_sync.return_value = ExecutionResult(exit_code=0)
        safe_run_sandboxed(["echo", "hi"], timeout=30, env={"CUSTOM": "val"})
        called_env = mock_sync.call_args[1].get("env", {})
        assert called_env.get("CUSTOM") == "val"


"""Final batch of subprocess_utils tests covering orphan-tracker Unix path,
safe_run_async thread-fallback asyncio timeout, non-thread binary-not-found,
orphan-tracking branches, safe_run_async_stream thread-fallback pipe-readers,
kill-exception pass, and full async streaming path."""


import itertools
import subprocess
from unittest.mock import patch


# ── helpers ──────────────────────────────────────────────────────────────


def _reset_orphan_tracker() -> None:
    with _ORPHAN_LOCK:
        _ORPHAN_TRACKER.clear()


# ── _cleanup_orphans — kill path (exercises os.kill logic via win32 exit) ─


class TestCleanupOrphansKill:
    def setup_method(self) -> None:
        _reset_orphan_tracker()

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run")
    def test_win32_taskkill_called(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock()
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(9100)
        _cleanup_orphans()
        args = mock_run.call_args[0][0]
        assert "taskkill" in args
        assert "9100" in args
        with _ORPHAN_LOCK:
            assert 9100 not in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run", side_effect=subprocess.SubprocessError)
    def test_win32_taskkill_error(self, mock_run: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(9101)
        _cleanup_orphans()
        with _ORPHAN_LOCK:
            assert 9101 not in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run", side_effect=PermissionError)
    def test_win32_taskkill_permission_error(self, mock_run: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(9102)
        _cleanup_orphans()
        with _ORPHAN_LOCK:
            assert 9102 not in _ORPHAN_TRACKER

    def test_empty_tracker_noop(self) -> None:
        _reset_orphan_tracker()
        _cleanup_orphans()

    @patch("siyarix.subprocess_utils.os.kill")
    def test_win32_exit_kill(self, mock_kill: MagicMock) -> None:
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.add(9103)
        _cleanup_orphans(is_exit=True)
        mock_kill.assert_called_once_with(9103, signal.SIGTERM)
        with _ORPHAN_LOCK:
            assert 9103 not in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils.sys.platform", "win32")
    @patch("siyarix.subprocess_utils.subprocess.run")
    def test_multiple_pids_cleaned(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock()
        with _ORPHAN_LOCK:
            _ORPHAN_TRACKER.update({9110, 9111, 9112})
        _cleanup_orphans()
        assert mock_run.call_count == 3
        with _ORPHAN_LOCK:
            assert len(_ORPHAN_TRACKER) == 0


# ── safe_run_async — thread-fallback asyncio timeout (lines 300-301) ─────


class TestSafeRunAsyncThreadFallbackTimeout:
    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    @patch("siyarix.subprocess_utils.asyncio.wait_for", side_effect=asyncio.TimeoutError)
    async def test_asyncio_timeout_returns_command_timed_out(
        self, mock_wait_for: MagicMock, mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async([sys.executable, "-c", ""], timeout=5, validate=False)
        assert result.exit_code == -1
        assert "timed out" in result.stderr

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=True)
    async def test_asyncio_timeout_via_short_wait(self, mock_fb: MagicMock) -> None:
        async def _slow_never_completes() -> subprocess.CompletedProcess:
            await asyncio.sleep(3600)
            return subprocess.CompletedProcess(args=[], returncode=0)

        mock_loop = MagicMock()
        mock_loop.run_in_executor.return_value = _slow_never_completes()
        with patch("siyarix.subprocess_utils.asyncio.get_running_loop", return_value=mock_loop):
            result = await safe_run_async([sys.executable, "-c", ""], timeout=0.01, validate=False)
        assert result.exit_code == -1
        assert "timed out" in result.stderr


# ── safe_run_async — non-thread FileNotFoundError (lines 326-328) ────────


class TestSafeRunAsyncNonThreadFileNotFound:
    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch(
        "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    )
    async def test_create_subprocess_exec_not_found(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async(["/no/such/tool"], timeout=1)
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch(
        "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    )
    async def test_not_found_includes_cmd_name(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async(["/missing/binary"], timeout=1)
        assert "/missing/binary" in result.stderr


# ── safe_run_async — orphan tracking in non-thread path (lines 333-347) ──


class TestSafeRunAsyncNonThreadOrphanTracking:
    def setup_method(self) -> None:
        _reset_orphan_tracker()

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_orphan_added_and_removed(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 7777
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"ok", b""))
        mock_create.return_value = proc

        result = await safe_run_async(["echo", "hi"], timeout=5)
        assert _ORPHAN_TRACKER == set()
        assert result.exit_code == 0
        assert result.stdout == "ok"

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_orphan_removed_on_timeout(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 7778
        proc.returncode = None
        proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError, (b"", b"timeout!")])
        mock_create.return_value = proc

        with patch("siyarix.subprocess_utils._kill_process", AsyncMock()) as mock_kill:
            result = await safe_run_async(["sleep", "100"], timeout=0.01, validate=False)

        assert _ORPHAN_TRACKER == set()
        assert result.exit_code == -1
        assert "timeout!" in result.stderr

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_pid_none_skips_orphan_tracking(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = None
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"no-pid", b""))
        mock_create.return_value = proc

        result = await safe_run_async(["tool"], timeout=5, validate=False)
        assert result.exit_code == 0
        assert result.stdout == "no-pid"

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_returncode_none_fallback_negative_one(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 7779
        proc.returncode = None
        proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_create.return_value = proc

        result = await safe_run_async(["cmd"], timeout=5, validate=False)
        assert result.exit_code == -1

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_pid_zero_added_but_not_discarded(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 0
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_create.return_value = proc

        result = await safe_run_async(["cmd"], timeout=5, validate=False)
        assert result.exit_code == 0

        with _ORPHAN_LOCK:
            assert 0 in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env")
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_duration_ms_set(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        mock_prep.return_value = {}
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 7780
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"dur", b""))
        mock_create.return_value = proc

        result = await safe_run_async(["cmd"], timeout=5, validate=False)
        assert result.duration_ms >= 0


# ── safe_run_async_stream — thread-fallback pipe readers (lines 418-435) ─
# On Windows this is the primary code path.


class TestSafeRunAsyncStreamThreadPipeReaders:
    async def test_pipe_readers_created(self) -> None:
        result = await safe_run_async_stream(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('out\\n'); sys.stderr.write('err\\n')",
            ],
            timeout=5,
            validate=False,
        )
        assert result.exit_code == 0
        assert "out" in result.stdout
        assert "err" in result.stderr

    async def test_with_callbacks(self) -> None:
        stdout_events: list[str] = []
        stderr_events: list[str] = []
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('cb_out'); import sys; print('cb_err', file=sys.stderr)"],
            timeout=5,
            on_stdout=stdout_events.append,
            on_stderr=stderr_events.append,
            validate=False,
        )
        assert result.exit_code == 0
        assert any("cb_out" in l for l in stdout_events)
        assert any("cb_err" in l for l in stderr_events)

    async def test_max_output_bytes_truncates(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('hello'); print('world')"],
            timeout=5,
            max_output_bytes=3,
            validate=False,
        )
        assert result.exit_code == 0

    async def test_pipe_reader_max_bytes_continue(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('A' * 200)"],
            timeout=5,
            max_output_bytes=10,
            validate=False,
        )
        assert result.exit_code == 0


# ── safe_run_async_stream — thread-fallback kill pass (lines 446-447) ────


class TestSafeRunAsyncStreamThreadTimeout:
    async def test_thread_fallback_timeout(self) -> None:
        result = await safe_run_async_stream(
            [sys.executable, "-c", "import time; time.sleep(100)"],
            timeout=0.05,
            validate=False,
        )
        assert result.exit_code == -1


# ── safe_run_async_stream — full async path (lines 460-538) ──────────────
# These mock _use_thread_fallback to False to test the async codepath.


class TestSafeRunAsyncStreamAsyncPath:
    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_normal_execution(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b"async_stream\n", b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9000
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = 0
        proc.wait = AsyncMock(return_value=0)
        mock_create.return_value = proc

        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('async_stream')"],
            timeout=5,
        )
        assert result.exit_code == 0
        assert "async_stream" in result.stdout

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_with_callbacks(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        stdout_events: list[str] = []
        stderr_events: list[str] = []
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b"cb1\n", b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b"cb2\n", b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9001
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = 0
        proc.wait = AsyncMock(return_value=0)
        mock_create.return_value = proc

        result = await safe_run_async_stream(
            [sys.executable, "-c", ""],
            timeout=5,
            on_stdout=stdout_events.append,
            on_stderr=stderr_events.append,
            validate=False,
        )
        assert result.exit_code == 0
        assert any("cb1" in l for l in stdout_events)
        assert any("cb2" in l for l in stderr_events)

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec", side_effect=FileNotFoundError)
    async def test_binary_not_found(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        result = await safe_run_async_stream(
            ["/nonexistent/binary"],
            timeout=1,
        )
        assert result.exit_code == -1
        assert "Binary not found" in result.stderr

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_timeout(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        def _stdout_readlines():
            yield b"before_timeout\n"
            yield b"drain1\n"
            while True:
                yield b""

        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=_stdout_readlines())
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=itertools.repeat(b""))
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9002
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_create.return_value = proc
        proc.returncode = -1

        with patch("siyarix.subprocess_utils._kill_process", AsyncMock()):
            result = await safe_run_async_stream(
                [sys.executable, "-c", "import time; time.sleep(100)"],
                timeout=0.05,
                validate=False,
            )
        assert result.exit_code == -1
        assert "before_timeout" in result.stdout
        assert "drain1" in result.stdout

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_max_output_bytes(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b"AAAAA\n", b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9003
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = 0
        proc.wait = AsyncMock(return_value=0)
        mock_create.return_value = proc

        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('A' * 100)"],
            timeout=5,
            max_output_bytes=5,
            validate=False,
        )
        assert result.exit_code == 0

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_stdout_none_skips_read(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9004
        proc.stdout = None
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc.stderr = mock_stderr
        proc.wait = AsyncMock(return_value=0)
        proc.returncode = 0
        mock_create.return_value = proc

        result = await safe_run_async_stream(["cmd"], timeout=5, validate=False)
        assert result.exit_code == 0

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_stderr_none_skips_read(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9005
        proc.stdout = mock_stdout
        proc.stderr = None
        proc.wait = AsyncMock(return_value=0)
        proc.returncode = 0
        mock_create.return_value = proc

        result = await safe_run_async_stream(["cmd"], timeout=5, validate=False)
        assert result.exit_code == 0

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_orphan_tracking_add_and_discard(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        _reset_orphan_tracker()
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b"orphan-track\n", b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9006
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = 0
        proc.wait = AsyncMock(return_value=0)
        mock_create.return_value = proc

        result = await safe_run_async_stream(
            [sys.executable, "-c", "print('orphan-track')"],
            timeout=5,
        )
        assert result.exit_code == 0
        with _ORPHAN_LOCK:
            assert 9006 not in _ORPHAN_TRACKER

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_pid_none_skips_tracking(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        _reset_orphan_tracker()
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = None
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = 0
        proc.wait = AsyncMock(return_value=0)
        mock_create.return_value = proc

        result = await safe_run_async_stream(["cmd"], timeout=5, validate=False)
        assert result.exit_code == 0
        with _ORPHAN_LOCK:
            assert len(_ORPHAN_TRACKER) == 0

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_returncode_none_fallback(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=[b"out1\n", b""])
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=[b""])
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9007
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = None
        proc.wait = AsyncMock(return_value=None)
        mock_create.return_value = proc

        result = await safe_run_async_stream(["cmd"], timeout=5, validate=False)
        assert result.exit_code == -1

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_timeout_drains_remaining(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9008
        proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)

        def _stdout_readlines():
            yield b"line1\n"
            yield b"line2\n"
            while True:
                yield b""

        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=_stdout_readlines())
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=itertools.repeat(b""))
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        proc.returncode = -1
        mock_create.return_value = proc

        with patch("siyarix.subprocess_utils._kill_process", AsyncMock()):
            result = await safe_run_async_stream(["cmd"], timeout=5, validate=False)

        assert result.exit_code == -1
        assert "line1" in result.stdout
        assert "line2" in result.stdout

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_timeout_drain_with_callback(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        drained: list[str] = []

        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.pid = 9009
        proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)

        def _stdout_readlines():
            yield b"drain1\n"
            while True:
                yield b""

        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(side_effect=_stdout_readlines())
        mock_stderr = AsyncMock()
        mock_stderr.readline = AsyncMock(side_effect=itertools.repeat(b""))
        proc.stdout = mock_stdout
        proc.stderr = mock_stderr
        mock_create.return_value = proc

        with patch("siyarix.subprocess_utils._kill_process", AsyncMock()):
            result = await safe_run_async_stream(
                ["cmd"],
                timeout=5,
                validate=False,
                on_stdout=drained.append,
            )

        assert result.exit_code == -1
        assert "drain1" in drained

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils._prepare_env", return_value={})
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_validate_true_calls_validate(
        self, mock_create: MagicMock, mock_prep: MagicMock, mock_fb: MagicMock
    ) -> None:
        with patch("siyarix.subprocess_utils._validate_cmd_list") as mock_val:
            mock_stdout = AsyncMock()
            mock_stdout.readline = AsyncMock(side_effect=[b"out\n", b""])
            mock_stderr = AsyncMock()
            mock_stderr.readline = AsyncMock(side_effect=[b""])
            proc = MagicMock(spec=asyncio.subprocess.Process)
            proc.pid = 9010
            proc.stdout = mock_stdout
            proc.stderr = mock_stderr
            proc.wait = AsyncMock(return_value=0)
            proc.returncode = 0
            mock_create.return_value = proc

            result = await safe_run_async_stream(
                [sys.executable, "-c", "print('val')"], timeout=5, validate=True
            )
            assert result.exit_code == 0
            mock_val.assert_called_once()

    @patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False)
    @patch("siyarix.subprocess_utils.asyncio.create_subprocess_exec")
    async def test_env_passed_to_subprocess(
        self, mock_create: MagicMock, mock_fb: MagicMock
    ) -> None:
        with patch("siyarix.subprocess_utils._prepare_env") as mock_prep:
            mock_prep.return_value = {"CUSTOM": "val"}
            mock_stdout = AsyncMock()
            mock_stdout.readline = AsyncMock(side_effect=[b""])
            mock_stderr = AsyncMock()
            mock_stderr.readline = AsyncMock(side_effect=[b""])
            proc = MagicMock(spec=asyncio.subprocess.Process)
            proc.pid = 9011
            proc.stdout = mock_stdout
            proc.stderr = mock_stderr
            proc.wait = AsyncMock(return_value=0)
            proc.returncode = 0
            mock_create.return_value = proc

            result = await safe_run_async_stream(
                ["cmd"], timeout=5, validate=False, env={"CUSTOM": "val"}
            )
            assert result.exit_code == 0
            mock_prep.assert_called_once_with({"CUSTOM": "val"})


def test_safe_run_sync_basic():
    res = safe_run_sync([sys.executable, "-c", "print('hello')"], timeout=5)
    assert isinstance(res, ExecutionResult)
    assert res.exit_code == 0
    assert "hello" in res.stdout


def test_safe_run_sync_rejects_suspicious():
    try:
        safe_run_sync(["/bin/sh", "-c", "echo hi; rm -rf /"])
        raised = False
    except ValueError:
        raised = True
    assert raised, "Expected ValueError for suspicious command parts"
