# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Siyarix, similar to leading enterprise
terminal agents, specialized for cybersecurity workflows.
"""

from .repl import SiyarixChat, start_chat
from .console import console
from .commands import (
    CommandProfile,
    CommandProfileStore,
    CommandRegistry,
    CommandCategory,
    CommandInfo,
    ArgInfo,
    CommandHistory,
    command_history,
    HELP_CATEGORIES,
    SLASH_HELP,
)
from .platform_utils import (
    CROSS_PLATFORM_COMMANDS,
    detect_shell,
    get_shell_platform,
    get_security_commands,
)
from .ui import SmartAutocomplete, render_welcome_banner, SplitPane, ConfigPanel
from .session import ChatSession, ChatMessage
from .prompts import (
    mode_color,
    make_prompt_top,
    make_prompt_bottom,
    make_prompt_bar,
    mode_prompt_hint,
)
from .console import (
    panel_response,
    mode_border,
    severity_style,
    print_severity,
    print_error,
    print_warning,
    print_info,
    print_success,
    table_from_dicts,
    tree_from_dict,
    status_spinner,
    progress_bar,
)

__all__ = [
    "start_chat",
    "SiyarixChat",
    "console",
    "CommandProfile",
    "CommandProfileStore",
    "CommandRegistry",
    "CommandCategory",
    "CommandInfo",
    "ArgInfo",
    "CommandHistory",
    "command_history",
    "HELP_CATEGORIES",
    "SLASH_HELP",
    "CROSS_PLATFORM_COMMANDS",
    "detect_shell",
    "get_shell_platform",
    "get_security_commands",
    "SmartAutocomplete",
    "ChatSession",
    "ChatMessage",
    "render_welcome_banner",
    "SplitPane",
    "ConfigPanel",
    "mode_color",
    "make_prompt_top",
    "make_prompt_bottom",
    "make_prompt_bar",
    "mode_prompt_hint",
    "panel_response",
    "mode_border",
    "severity_style",
    "print_severity",
    "print_error",
    "print_warning",
    "print_info",
    "print_success",
    "table_from_dicts",
    "tree_from_dict",
    "status_spinner",
    "progress_bar",
]
