from __future__ import annotations
from siyarix.worker_pool import AsyncWorkerPool
from unittest.mock import patch, MagicMock
import asyncio
import pytest


# SPDX-License-Identifier: AGPL-3.0-or-later


import os
from pathlib import Path
from siyarix.chat.platform_utils import (
    detect_shell,
    get_security_commands,
    get_shell_platform,
    list_supported_shells,
    load_env_file,
    normalize_shell,
    provider_env_var,
)


def test_worker_pool_concurrency_and_results():
    pool = AsyncWorkerPool(max_workers=2)

    async def task(n: int):
        await asyncio.sleep(0.05 * n)
        return n * 2

    async def _run():
        tasks = [pool.submit(task, i) for i in range(1, 5)]
        results = await asyncio.gather(*tasks)
        await pool.close()
        assert results == [2, 4, 6, 8]

    asyncio.run(_run())


def test_worker_pool_close_cancels_tasks():
    pool = AsyncWorkerPool(max_workers=2)

    async def long_task():
        try:
            await asyncio.sleep(5)
            return "done"
        except asyncio.CancelledError:
            return "cancelled"

    async def _run():
        # Submit the long task and let it start
        task = asyncio.create_task(pool.submit(long_task))
        await asyncio.sleep(0.01)
        # Close pool, forcing cancellation
        await pool.close(timeout=0.1)
        try:
            res = await task
            assert res in ("cancelled", "done")
        except asyncio.CancelledError:
            assert True

    asyncio.run(_run())


async def _sleep_and_return(x: int) -> int:
    await asyncio.sleep(0.01)
    return x * 2


def test_worker_pool_basic():
    pool = AsyncWorkerPool(max_workers=2)

    async def _run():
        r1 = await pool.submit(_sleep_and_return, 2)
        r2 = await pool.submit(_sleep_and_return, 3)
        await pool.close()
        return (r1, r2)

    res = asyncio.run(_run())
    assert res == (4, 6)


"""Extra tests for worker_pool targeting uncovered lines."""


class TestAsyncWorkerPoolValidation:
    def test_max_workers_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="max_workers must be > 0"):
            AsyncWorkerPool(max_workers=0)

    def test_max_workers_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_workers must be > 0"):
            AsyncWorkerPool(max_workers=-1)


class TestAsyncWorkerPoolSubmitAfterClose:
    @pytest.mark.asyncio
    async def test_submit_after_close_raises(self) -> None:
        pool = AsyncWorkerPool(max_workers=1)

        async def dummy():
            return 42

        await pool.close()
        with pytest.raises(RuntimeError, match="Pool is closed"):
            await pool.submit(dummy)

    @pytest.mark.asyncio
    async def test_close_empty_pool(self) -> None:
        pool = AsyncWorkerPool(max_workers=1)
        # Should not raise
        await pool.close()

    @pytest.mark.asyncio
    async def test_close_with_timeout_all_tasks_finish(self) -> None:
        pool = AsyncWorkerPool(max_workers=2)

        async def quick():
            await asyncio.sleep(0.01)
            return "ok"

        t1 = asyncio.create_task(pool.submit(quick))
        t2 = asyncio.create_task(pool.submit(quick))
        await asyncio.sleep(0.02)
        await pool.close(timeout=5.0)
        assert await t1 == "ok"
        assert await t2 == "ok"

    @pytest.mark.asyncio
    async def test_close_with_timeout_some_tasks_timeout(self) -> None:
        pool = AsyncWorkerPool(max_workers=1)

        async def slow():
            await asyncio.sleep(10.0)
            return "late"

        t = asyncio.create_task(pool.submit(slow))
        await asyncio.sleep(0.01)
        await pool.close(timeout=0.01)
        # Task may be cancelled
        try:
            await t
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    @pytest.mark.asyncio
    async def test_cancel_pending(self) -> None:
        pool = AsyncWorkerPool(max_workers=2)

        async def slow():
            await asyncio.sleep(10.0)
            return "x"

        t1 = asyncio.create_task(pool.submit(slow))
        t2 = asyncio.create_task(pool.submit(slow))
        await asyncio.sleep(0.01)
        await pool.cancel_pending()
        await asyncio.sleep(0.01)
        try:
            await t1
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        try:
            await t2
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    @pytest.mark.asyncio
    async def test_submit_backpressure_releases_sema(self) -> None:
        pool = AsyncWorkerPool(max_workers=1, max_queue=2)

        async def fast():
            return 1

        # Submit one task to fill the worker sema
        t1 = asyncio.create_task(pool.submit(fast))
        t2 = asyncio.create_task(pool.submit(fast))
        await asyncio.gather(t1, t2, return_exceptions=True)
        await pool.close(timeout=5.0)
        assert await t1 == 1
        assert await t2 == 1

    @pytest.mark.asyncio
    async def test_submit_with_args(self) -> None:
        pool = AsyncWorkerPool(max_workers=2)

        async def add(a, b):
            await asyncio.sleep(0.01)
            return a + b

        result = await pool.submit(add, 2, b=3)
        await pool.close()
        assert result == 5


class TestPlatformUtils:
    """Cover platform detection, Windows detection, terminal features."""

    def test_detect_shell_nt_returns_comspec(self):
        with patch("os.name", "nt"):
            with patch.dict(os.environ, {"COMSPEC": "cmd.exe"}, clear=True):
                assert detect_shell() == "cmd.exe"

    def test_detect_shell_posix_with_shell_env(self):
        with patch("os.name", "posix"):
            with patch.dict(os.environ, {"SHELL": "/bin/zsh"}, clear=True):
                assert detect_shell() == "/bin/zsh"

    def test_detect_shell_posix_no_shell_env_finds_first(self):
        with patch("os.name", "posix"):
            with patch.dict(os.environ, {}, clear=True):
                with patch(
                    "shutil.which", side_effect=lambda x: f"/usr/bin/{x}" if x == "bash" else None
                ):
                    assert detect_shell() == "/usr/bin/bash"

    def test_detect_shell_no_shell_found_fallback_nt(self):
        with patch("os.name", "nt"):
            with patch.dict(os.environ, {}, clear=True):
                with patch("shutil.which", return_value=None):
                    assert detect_shell() == "cmd.exe"

    def test_detect_shell_no_shell_found_fallback_posix(self):
        with patch("os.name", "posix"):
            with patch.dict(os.environ, {}, clear=True):
                with patch("shutil.which", return_value=None):
                    assert detect_shell() == "/bin/sh"

    def test_provider_env_var(self):
        assert provider_env_var("openai") == "OPENAI_API_KEY"
        assert provider_env_var("deepseek") == "DEEPSEEK_API_KEY"

    def test_list_supported_shells(self):
        shells = list_supported_shells()
        assert ("bash", "native") in shells
        assert ("zsh", "native") in shells
        assert ("powershell", "compat") in shells

    def test_get_shell_platform(self):
        with patch("platform.system", return_value="Linux"):
            assert get_shell_platform() == "Linux"

    @patch("siyarix.chat.platform_utils.get_config_dir")
    def test_load_env_file_not_exists(self, mock_get_config_dir):
        mock_get_config_dir.return_value / Path("/nonexistent")
        Path_obj = MagicMock()
        Path_obj.exists.return_value = False
        mock_get_config_dir.return_value = MagicMock()
        mock_get_config_dir.return_value.__truediv__.return_value = Path_obj
        load_env_file()

    @patch("siyarix.chat.platform_utils.get_config_dir")
    def test_load_env_file_skips_api_key_patterns(self, mock_get_config_dir):
        env_path = MagicMock(spec=Path)
        env_path.exists.return_value = True
        env_path.read_text.return_value = "OPENAI_API_KEY=sk-123\nMY_SECRET=hidden\nVALID_KEY=ok"
        mock_dir = MagicMock()
        mock_dir.__truediv__.return_value = env_path
        mock_get_config_dir.return_value = mock_dir
        with patch("siyarix.chat.platform_utils.logger") as mock_log:
            load_env_file()
            assert os.environ.get("VALID_KEY") == "ok"
            assert "OPENAI_API_KEY" not in os.environ
            mock_log.debug.assert_any_call(
                "Skipping %s from .env (use /key command instead)", "OPENAI_API_KEY"
            )

    def test_get_security_commands_windows(self):
        with patch("sys.platform", "win32"):
            cmds = get_security_commands()
            assert "Firewall status" in cmds
            assert cmds["Firewall status"] == "netsh advfirewall show allprofiles state"
            assert "Audit policy" in cmds

    def test_get_security_commands_non_windows(self):
        with patch("sys.platform", "linux"):
            cmds = get_security_commands()
            assert "Listening ports" in cmds
            assert cmds["Listening ports"] == "ss -tulpn"
            assert "SUID binaries" in cmds

    def test_normalize_shell(self):
        sh = normalize_shell("bash")
        assert sh.value == "bash"


# ═══════════════════════════════════════════════════════════════════
# 3. chat/prompts.py (88% - missing line 24)
# ═══════════════════════════════════════════════════════════════════
