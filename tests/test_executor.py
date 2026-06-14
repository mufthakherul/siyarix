# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.subprocess_utils import (
    ExecutionResult,
    _validate_cmd_list,
    safe_run_async,
    safe_run_sync,
)


class TestValidateCmdList:
    def test_valid_command(self) -> None:
        _validate_cmd_list(["nmap", "-sV", "127.0.0.1"])

    def test_empty_list(self) -> None:
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_cmd_list([])

    def test_not_a_list(self) -> None:
        with pytest.raises(ValueError, match="non-empty list"):
            _validate_cmd_list("nmap")  # type: ignore[arg-type]

    def test_non_string_element(self) -> None:
        with pytest.raises(ValueError, match="must be strings"):
            _validate_cmd_list(["nmap", 123])  # type: ignore[list-item]

    @pytest.mark.parametrize("bad_char", [";", "|", "&", "`", "$", ">", "<"])
    def test_shell_metacharacters(self, bad_char: str) -> None:
        with pytest.raises(ValueError, match="suspicious character"):
            _validate_cmd_list(["nmap", f"target{bad_char}cmd"])

    def test_multiple_args_valid(self) -> None:
        _validate_cmd_list(["tool", "-a", "-b", "--long", "value"])


class TestExecutionResult:
    def test_success_property(self) -> None:
        r = ExecutionResult(exit_code=0, stdout="ok", stderr="", duration_ms=100)
        assert r.success is True

    def test_failure_property(self) -> None:
        r = ExecutionResult(exit_code=1, stdout="", stderr="error", duration_ms=50)
        assert r.success is False

    def test_defaults(self) -> None:
        r = ExecutionResult()
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.duration_ms == 0.0


class TestSafeRunSync:
    def test_success(self) -> None:
        with patch("siyarix.subprocess_utils.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            result = safe_run_sync(["echo", "hi"])
            assert result.exit_code == 0

    def test_timeout_raises(self) -> None:
        with patch(
            "siyarix.subprocess_utils.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="sleep 10", timeout=0.001),
        ):
            with pytest.raises(subprocess.TimeoutExpired):
                safe_run_sync(["sleep", "10"], timeout=0.001)

    def test_exception_raises(self) -> None:
        with patch(
            "siyarix.subprocess_utils.subprocess.run",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                safe_run_sync(["nonexistent_tool"])

    def test_validation_error(self) -> None:
        with pytest.raises(ValueError):
            safe_run_sync(["bad;command"])


class TestSafeRunAsync:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"out", b"err"))
        mock_proc.returncode = 0

        with (
            patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False),
            patch("siyarix.subprocess_utils._validate_cmd_list"),
            patch(
                "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await safe_run_async(["tool", "arg"])
            assert result.exit_code == 0
            assert result.stdout == "out"

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError(), (b"partial", b"")])
        mock_proc.kill = MagicMock()

        with (
            patch("siyarix.subprocess_utils._use_thread_fallback", return_value=False),
            patch("siyarix.subprocess_utils._validate_cmd_list"),
            patch(
                "siyarix.subprocess_utils.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await safe_run_async(["tool", "arg"], timeout=0.001)
            assert result.exit_code == -1
            mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_validation_error(self) -> None:
        with pytest.raises(ValueError):
            await safe_run_async([])
