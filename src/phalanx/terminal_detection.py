"""Terminal and shell detection logic.

Detects the current terminal emulator and shell for cross-platform
command adaptation as described in Chapter 13.2.
"""

from __future__ import annotations

import logging
import os
import platform
import re
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class ShellType(StrEnum):
    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"
    SH = "sh"
    NUSHELL = "nushell"
    XONSH = "xonsh"
    POWERSHELL = "powershell"
    PWSH = "pwsh"
    CMD = "cmd"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class TerminalType(Enum):
    GNOME_TERMINAL = "gnome-terminal"
    KONSOLE = "konsole"
    TERMINAL_APP = "Apple_Terminal"
    ITERM2 = "iTerm2"
    WINDOWS_TERMINAL = "Windows Terminal"
    CONEMU = "ConEmu"
    TMUX = "tmux"
    SCREEN = "screen"
    VSCODE = "vscode"
    WEB = "web"
    GENERIC = "generic"


@dataclass
class TerminalInfo:
    """Detected terminal and shell information."""

    shell: ShellType = ShellType.GENERIC
    terminal: TerminalType = TerminalType.GENERIC
    os_name: str = ""
    is_wsl: bool = False
    supports_color: bool = True
    supports_unicode: bool = True
    supports_hyperlinks: bool = False
    is_interactive: bool = False


class TerminalDetector:
    """Detects the current terminal and shell environment."""

    def detect(self) -> TerminalInfo:
        info = TerminalInfo(
            os_name=platform.system(),
            is_wsl=self._is_wsl(),
            is_interactive=(
                hasattr(__builtins__, "__IPYTHON__") or sys.stdin.isatty()
                if hasattr(sys, "stdin")
                else False
            ),
        )

        # Shell detection
        info.shell = self._detect_shell()

        # Terminal detection
        info.terminal = self._detect_terminal()

        # Capabilities
        info.supports_color = self._supports_color()
        info.supports_unicode = self._supports_unicode()
        info.supports_hyperlinks = self._supports_hyperlinks()

        return info

    def _is_wsl(self) -> bool:
        release = platform.release().lower()
        return "microsoft" in release or "wsl" in release

    def _detect_shell(self) -> ShellType:
        env_shell = os.environ.get("SHELL", "").lower()
        env_psmodule = os.environ.get("PSModulePath", "")

        if "zsh" in env_shell:
            return ShellType.ZSH
        if "bash" in env_shell:
            return ShellType.BASH
        if "fish" in env_shell:
            return ShellType.FISH
        if env_psmodule or os.environ.get("POWERSHELL_DISTRIBUTION_CHANNEL"):
            return ShellType.POWERSHELL
        if os.name == "nt":
            # Check for pwsh vs cmd
            if os.environ.get("TERM_PROGRAM") == "vscode" or "pwsh" in env_shell:
                return ShellType.PWSH
            return ShellType.CMD
        return ShellType.GENERIC

    def _detect_terminal(self) -> TerminalType:
        term_program = os.environ.get("TERM_PROGRAM", "")
        term = os.environ.get("TERM", "")

        if term_program == "iTerm.app":
            return TerminalType.ITERM2
        if term_program == "Apple_Terminal":
            return TerminalType.TERMINAL_APP
        if term_program == "vscode":
            return TerminalType.VSCODE
        if "gnome" in term or "vte" in term:
            return TerminalType.GNOME_TERMINAL
        if "konsole" in term:
            return TerminalType.KONSOLE
        if "tmux" in term:
            return TerminalType.TMUX
        if "screen" in term:
            return TerminalType.SCREEN
        if os.environ.get("VSCODE_INJECTION"):
            return TerminalType.VSCODE
        if os.environ.get("TERMINAL_EMULATOR") == "JetBrains-JediTerm":
            return TerminalType.GENERIC
        if os.name == "nt":
            if term_program == "WindowsTerminal":
                return TerminalType.WINDOWS_TERMINAL
            if os.environ.get("ConEmuANSI") == "ON":
                return TerminalType.CONEMU
        return TerminalType.GENERIC

    def _supports_color(self) -> bool:
        if os.name == "nt":
            # Windows 10+ supports color
            return True
        term = os.environ.get("TERM", "")
        return "color" in term or "256" in term or term.startswith("xterm")

    def _supports_unicode(self) -> bool:
        if os.name == "nt":
            return True
        lang = os.environ.get("LANG", "")
        return "UTF-8" in lang or "UTF-8" in os.environ.get("LC_ALL", "")

    def _supports_hyperlinks(self) -> bool:
        term_program = os.environ.get("TERM_PROGRAM", "")
        return term_program in ("iTerm.app", "vscode", "WindowsTerminal")

    def get_shell_translation_rules(self) -> dict[str, dict[str, str]]:
        """Return shell-specific command translations."""
        return {
            "list_files": {
                "bash": "ls -la {path}",
                "zsh": "ls -la {path}",
                "powershell": "Get-ChildItem -Path {path} -Force",
                "cmd": "dir {path}",
                "generic": "ls {path}",
            },
            "ping": {
                "bash": "ping -c 4 {target}",
                "zsh": "ping -c 4 {target}",
                "powershell": "Test-NetConnection -ComputerName {target} -Count 4",
                "cmd": "ping -n 4 {target}",
                "generic": "ping {target}",
            },
            "grep": {
                "bash": "grep {pattern} {file}",
                "zsh": "grep {pattern} {file}",
                "powershell": "Select-String -Path {file} -Pattern {pattern}",
                "cmd": "findstr {pattern} {file}",
                "generic": "grep {pattern} {file}",
            },
        }

    def translate_command(
        self, command: str, shell_type: ShellType | None = None
    ) -> str:
        """Translate a generic command for the target shell."""
        if shell_type is None:
            shell_type = self.detect().shell

        rules = self.get_shell_translation_rules()
        for cmd_name, translations in rules.items():
            if command.startswith(cmd_name):
                shell_key = shell_type.value
                if shell_key in translations:
                    return translations[shell_key]
                return translations.get("generic", command)

        return command


import sys  # noqa: E402 (needed for is_interactive detection)

__all__ = [
    "TerminalDetector",
    "TerminalInfo",
    "ShellType",
    "TerminalType",
]
