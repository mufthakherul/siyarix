# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Siyarix, similar to leading enterprise terminal agents, specialized for cybersecurity workflows.
"""

from .repl import SiyarixChat, start_chat
from .console import console
from .commands import CommandProfile, CommandProfileStore
from .platform_utils import (
    CROSS_PLATFORM_COMMANDS,
    detect_shell,
    get_shell_platform,
    get_security_commands,
)
from .ui import SmartAutocomplete
from .session import ChatSession, ChatMessage

__all__ = [
    "start_chat",
    "SiyarixChat",
    "console",
    "CommandProfile",
    "CommandProfileStore",
    "CROSS_PLATFORM_COMMANDS",
    "detect_shell",
    "get_shell_platform",
    "get_security_commands",
    "SmartAutocomplete",
    "ChatSession",
    "ChatMessage",
]
