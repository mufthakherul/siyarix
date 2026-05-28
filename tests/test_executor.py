# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.executor import (
    _apply_stealth_modifications,
    _validate_cmd_list,
    run_tool,
    run_tool_complete,
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


class TestApplyStealthModifications:
    @pytest.mark.asyncio
    async def test_stealth_disabled(self) -> None:
        with patch("siyarix.config.SettingsStore") as mock_settings:
            instance = MagicMock()
            instance.get.return_value = False
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/nmap", ["-sV"])
            assert args == ["-sV"]

    @pytest.mark.asyncio
    async def test_stealth_error_returns_original(self) -> None:
        with patch("siyarix.config.SettingsStore", side_effect=ImportError("no module")):
            tp, args = await _apply_stealth_modifications("/usr/bin/nmap", ["-sV"])
            assert args == ["-sV"]

    @pytest.mark.asyncio
    async def test_nmap_stealth_modifications(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/nmap", ["-sV", "target"])
            assert "-T2" in args
            assert "-f" in args

    @pytest.mark.asyncio
    async def test_nmap_stealth_no_s_flag(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/nmap", ["target"])
            assert "-T2" in args
            assert "-sS" in args
            assert "-f" in args

    @pytest.mark.asyncio
    async def test_nmap_stealth_preserves_existing_flags(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/nmap", ["-sS", "-T4"])
            assert "-T4" in args
            assert "-sS" in args
            assert "-f" in args

    @pytest.mark.asyncio
    async def test_ffuf_stealth_modifications(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/ffuf", ["-u", "target"])
            assert "-rate" in args
            assert "-H" in args

    @pytest.mark.asyncio
    async def test_nuclei_stealth_modifications(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/nuclei", ["-u", "target"])
            assert "-rate-limit" in args
            assert "-H" in args

    @pytest.mark.asyncio
    async def test_unknown_tool_no_modifications(self) -> None:
        with (
            patch("siyarix.config.SettingsStore") as mock_settings,
            patch("siyarix.executor.asyncio.sleep"),
            patch("random.uniform", return_value=0.2),
        ):
            instance = MagicMock()
            instance.get.return_value = True
            mock_settings.return_value = instance
            tp, args = await _apply_stealth_modifications("/usr/bin/unknown_tool", ["arg1"])
            assert args == ["arg1"]


class TestRunTool:
    @pytest.mark.asyncio
    async def test_yields_lines(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(side_effect=[b"line1\n", b"line2\n", b""])
        mock_proc.returncode = None

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            lines = [line async for line in run_tool("/bin/tool", ["arg"], timeout=30)]
            assert lines == ["line1", "line2"]

    @pytest.mark.asyncio
    async def test_remaining_expires(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(side_effect=[b"line1\n", b"line2\n", b""])
        mock_proc.returncode = None

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            lines = [line async for line in run_tool("/bin/tool", ["arg"], timeout=0)]
            assert lines == []

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(side_effect=[b"line\n", asyncio.TimeoutError()])
        mock_proc.returncode = None

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            lines = [line async for line in run_tool("/bin/tool", ["arg"], timeout=0.01)]
            assert lines == ["line"]

    @pytest.mark.asyncio
    async def test_stdout_none_raises_error(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.stdout = None

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            with pytest.raises(RuntimeError, match="stdout is None"):
                async for _ in run_tool("/bin/tool", ["arg"]):
                    pass


class TestRunToolComplete:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"stdout", b"stderr"))
        mock_proc.returncode = 0

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await run_tool_complete("/bin/tool", ["arg"])
            assert result.exit_code == 0
            assert result.stdout == "stdout"
            assert result.stderr == "stderr"
            assert result.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError(), (b"partial", b"err")])
        mock_proc.kill = MagicMock()

        with (
            patch("siyarix.executor._apply_stealth_modifications", return_value=("/bin/tool", ["arg"])),
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await run_tool_complete("/bin/tool", ["arg"], timeout=0.001)
            assert result.exit_code == -1
            mock_proc.kill.assert_called_once()


class TestSafeRunSync:
    def test_success(self) -> None:
        with patch("siyarix.executor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            result = safe_run_sync(["echo", "hi"])
            assert result.returncode == 0

    def test_timeout_raises(self) -> None:
        import subprocess
        with patch("siyarix.executor.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="sleep 10", timeout=0.001)):
            with pytest.raises(subprocess.TimeoutExpired):
                safe_run_sync(["sleep", "10"], timeout=0.001)

    def test_exception_raises(self) -> None:
        with patch("siyarix.executor.subprocess.run", side_effect=FileNotFoundError("not found")):
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
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
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
            patch("siyarix.executor._validate_cmd_list"),
            patch("siyarix.executor.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await safe_run_async(["tool", "arg"], timeout=0.001)
            assert result.exit_code == -1
            mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_validation_error(self) -> None:
        with pytest.raises(ValueError):
            await safe_run_async([])
