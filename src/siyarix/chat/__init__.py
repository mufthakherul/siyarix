# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Siyarix, similar to Claude CLI and
Gemini CLI, specialized for cybersecurity workflows.
"""

from .repl import SiyarixChat, start_chat
from .commands import CommandProfile, CommandProfileStore
from .platform_utils import CROSS_PLATFORM_COMMANDS, detect_shell, get_shell_platform, get_security_commands
from .ui import SmartAutocomplete, CommandPalette
from .session import ChatSession, ChatMessage

__all__ = [
    "start_chat",
    "SiyarixChat",
    "CommandProfile",
    "CommandProfileStore",
    "CROSS_PLATFORM_COMMANDS",
    "detect_shell",
    "get_shell_platform",
    "get_security_commands",
    "SmartAutocomplete",
    "CommandPalette",
    "ChatSession",
    "ChatMessage",
]
