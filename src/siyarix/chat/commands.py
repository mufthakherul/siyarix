# SPDX-License-Identifier: AGPL-3.0-or-later

"""Slash command registry and profiles for Siyarix chat."""

from __future__ import annotations

from dataclasses import dataclass


# ── Help category definitions ─────────────────────────────────────────────
HELP_CATEGORIES = [
    ("Session & Navigation", {
        "/help": "Show available slash commands (alias: /?)",
        "/exit": "Exit chat mode (aliases: /quit, /bye)",
        "/clear": "Clear screen and conversation history (aliases: /clean, /cls)",
        "/new": "Start a fresh conversation",
        "/history [n]": "Show recent conversation history",
        "/search <text>": "Search chat history for a keyword",
        "/cancel": "Cancel current task without exiting (ESC key also works)",
    }),
    ("Configuration", {
        "/config": "Open the interactive configuration panel",
        "/config tools": "Manage discovered security tools",
        "/key": "Manage API keys for AI providers",
        "/mode <mode>": "Switch execution mode (autonomous|integrated|registry)",
        "/model [provider]": "Show or switch AI model provider",
        "/provider [name]": "Show detailed provider info and available models",
        "/theme mode|appearance": "Change UI theme or preview appearance",
        "/target <host>": "Set the current target",
    }),
    ("Information", {
        "/tools": "List discovered security tools",
        "/platform": "Show platform and shell information",
        "/status": "Show session and runtime status",
        "/session": "Show detailed session metadata",
        "/uptime": "Show chat session uptime",
        "/env": "Show terminal environment summary",
        "/context": "Show current session context",
        "/version": "Show Siyarix version",
        "/shells": "List supported shells",
    }),
    ("Execution", {
        "/run <command>": "Run a tool or shell command",
        "/security-cmds": "Show security commands for current platform",
        "/intents [filter]": "List cross-platform command intents",
        "/translate <intent>": "Translate a command intent to all shells",
        "/save": "Save current session",
    }),
    ("Session Management", {
        "/log list|show|export": "Manage session logs",
        "/diff <id_a> <id_b>": "Compare two sessions",
        "/reset": "Reset mode and target to defaults",
        "/examples": "Show practical prompt examples",
        "/palette": "Open interactive command palette",
    }),
]

# Flat lookup for command dispatch (includes all commands, including hidden ones)
SLASH_HELP = {}
for _cat_name, _cmds in HELP_CATEGORIES:
    SLASH_HELP.update(_cmds)


@dataclass
class CommandProfile:
    name: str
    command: str
    description: str | None = None
    created_at: str = ""


class CommandProfileStore:
    def save(self, profile: CommandProfile) -> None:
        pass

    def get(self, name: str) -> CommandProfile | None:
        return None

    def list_credentials(self) -> list[CommandProfile]:
        return []

    def delete(self, name: str) -> bool:
        return False

    def render(self, command: str, params: dict[str, str]) -> str:
        """Render a command template with key=value parameters."""
        rendered = command
        for k, v in params.items():
            rendered = rendered.replace(f"{{{k}}}", v).replace(f"${{{k}}}", v)
        return rendered
