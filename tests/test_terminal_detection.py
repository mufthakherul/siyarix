# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for TerminalDetector."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from siyarix.terminal_detection import (ShellType, TerminalDetector,
                                        TerminalInfo, TerminalType)

pytestmark = pytest.mark.terminal


class TestTerminalDetector:
    @pytest.fixture
    def detector(self):
        return TerminalDetector()

    def test_detect_basic(self, detector):
        with patch("platform.system", return_value="Linux"):
            info = detector.detect()
            assert isinstance(info, TerminalInfo)
            assert info.os_name == "Linux"

    def test_detect_wsl(self, detector):
        with patch("platform.release", return_value="5.15.0-1042-azure Microsoft"):
            assert detector._is_wsl() is True

    def test_detect_not_wsl(self, detector):
        with patch("platform.release", return_value="5.15.0-1042-aws"):
            assert detector._is_wsl() is False

    def test_shell_detection_bash(self, detector):
        with patch.dict("os.environ", {"SHELL": "/bin/bash"}, clear=True):
            assert detector._detect_shell() == ShellType.BASH

    def test_shell_detection_zsh(self, detector):
        with patch.dict("os.environ", {"SHELL": "/bin/zsh"}, clear=True):
            assert detector._detect_shell() == ShellType.ZSH

    def test_translate_command(self, detector):
        translated = detector.translate_command("list_files /tmp")
        assert (
            "ls" in translated or "dir" in translated or "Get-ChildItem" in translated
        )

    def test_translate_command_custom_shell(self, detector):
        translated = detector.translate_command("list_files /tmp", ShellType.POWERSHELL)
        assert "Get-ChildItem" in translated

    def test_shell_translation_rules(self, detector):
        rules = detector.get_shell_translation_rules()
        assert "list_files" in rules
        assert "ping" in rules
        assert "grep" in rules

    def test_color_support(self, detector):
        with patch.dict("os.environ", {"TERM": "xterm-256color"}, clear=True):
            assert detector._supports_color() is True

    def test_terminal_info_defaults(self):
        info = TerminalInfo()
        assert info.shell == ShellType.GENERIC
        assert info.terminal == TerminalType.GENERIC
