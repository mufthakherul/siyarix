# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Siyarix, similar to leading enterprise
terminal agents, specialized for cybersecurity workflows.
"""

from .commands import (
    HELP_CATEGORIES,
    SLASH_HELP,
    ArgInfo,
    CommandCategory,
    CommandHistory,
    CommandInfo,
    CommandProfile,
    CommandProfileStore,
    CommandRegistry,
    command_history,
)
from .console import (
    console,
    mode_border,
    panel_response,
    print_error,
    print_info,
    print_severity,
    print_success,
    print_warning,
    progress_bar,
    severity_style,
    status_spinner,
    table_from_dicts,
    tree_from_dict,
)
from .platform_utils import (
    CROSS_PLATFORM_COMMANDS,
    detect_shell,
    get_security_commands,
    get_shell_platform,
)
from .prompts import (
    make_prompt_bar,
    make_prompt_bottom,
    make_prompt_top,
    mode_color,
    mode_prompt_hint,
)
from .repl import SiyarixChat, start_chat
from .session import ChatMessage, ChatSession
from .subagents import (
    SubagentManager,
    SubagentRecord,
    SubagentRole,
    SubagentStatus,
    SubagentTask,
)
from .ui import ConfigPanel, SmartAutocomplete, SplitPane, render_welcome_banner

__all__ = [
    "CROSS_PLATFORM_COMMANDS",
    "HELP_CATEGORIES",
    "SLASH_HELP",
    "ArgInfo",
    "ChatMessage",
    "ChatSession",
    "CommandCategory",
    "CommandHistory",
    "CommandInfo",
    "CommandProfile",
    "CommandProfileStore",
    "CommandRegistry",
    "ConfigPanel",
    "SiyarixChat",
    "SmartAutocomplete",
    "SplitPane",
    "SubagentManager",
    "SubagentRecord",
    "SubagentRole",
    "SubagentStatus",
    "SubagentTask",
    "command_history",
    "console",
    "detect_shell",
    "get_security_commands",
    "get_shell_platform",
    "make_prompt_bar",
    "make_prompt_bottom",
    "make_prompt_top",
    "mode_border",
    "mode_color",
    "mode_prompt_hint",
    "panel_response",
    "print_error",
    "print_info",
    "print_severity",
    "print_success",
    "print_warning",
    "progress_bar",
    "render_welcome_banner",
    "severity_style",
    "start_chat",
    "status_spinner",
    "table_from_dicts",
    "tree_from_dict",
]
