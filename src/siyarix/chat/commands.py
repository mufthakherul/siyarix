# SPDX-License-Identifier: AGPL-3.0-or-later

"""Slash command registry and profiles for Siyarix chat."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from pathlib import Path
from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)

# ── Help category definitions ─────────────────────────────────────────────
HELP_CATEGORIES = [
    (
        "Session & Navigation",
        {
            "/help": "Show available slash commands (alias: /?)",
            "/exit": "Exit chat mode (aliases: /quit, /bye)",
            "/clear": "Clear screen and conversation history (aliases: /clean, /cls)",
            "/new": "Start a fresh conversation",
            "/history [n]": "Show recent conversation history",
            "/search <text>": "Search chat history for a keyword",
            "/cancel": "Cancel current task without exiting (ESC key also works)",
        },
    ),
    (
        "Configuration",
        {
            "/config": "Open the interactive configuration panel",
            "/config tools": "Manage discovered security tools",
            "/key": "Manage API keys for AI providers",
            "/mode <mode>": "Switch execution mode (autonomous|integrated|registry|offline)",
            "/model [provider]": "Show or switch AI model provider",
            "/provider [name]": "Show detailed provider info and available models",
            "/theme mode|appearance": "Change UI theme or preview appearance",
            "/target <host>": "Set the current target",
        },
    ),
    (
        "Information",
        {
            "/tools": "List discovered security tools",
            "/platform": "Show platform and shell information",
            "/status": "Show session and runtime status",
            "/session": "Show detailed session metadata",
            "/uptime": "Show chat session uptime",
            "/env": "Show terminal environment summary",
            "/context": "Show current session context",
            "/version": "Show Siyarix version",
            "/shells": "List supported shells",
        },
    ),
    (
        "Execution",
        {
            "/run <command>": "Run a tool or shell command",
            "/security-cmds": "Show security commands for current platform",
            "/intents [filter]": "List cross-platform command intents",
            "/translate <intent>": "Translate a command intent to all shells",
            "/save": "Save current session",
        },
    ),
    (
        "Session Management",
        {
            "/log list|show|export": "Manage session logs",
            "/diff <id_a> <id_b>": "Compare two sessions",
            "/reset": "Reset mode and target to defaults",
            "/examples": "Show practical prompt examples",

        },
    ),
    (
        "Advanced Operations",
        {
            "/report [format]": "Generate executive report (markdown|html)",
            "/split [type]": "Toggle split pane (timeline|metrics|cheatsheet|attack_map)",
            "/batch run <file>": "Execute batch command file",
            "/opsec isolate|burn|status": "Operational security",
            "/siem connect|status": "SIEM/SOAR integration",
            "/performance status|tune": "Resource optimization",
            "/cache status|clear": "Cache management",
            "/campaign list|create": "Multi-target campaigns",
            "/kb search|list": "Knowledge base operations",
            "/ticket create|list": "External ticket creation",
            "/retest schedule|status": "Verification scans",
            "/stealth status|on|off": "Evasion configuration",
            "/audit export|status|verify": "Compliance and legal export",
        },
    ),
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
    """Persistent storage for reusable command profiles."""

    def __init__(self) -> None:
        self._profiles_dir = get_config_dir() / "command_profiles"
        self._profiles_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        safe = name.replace("/", "_").replace("\\", "_")
        return self._profiles_dir / f"{safe}.json"

    def save(self, profile: CommandProfile) -> None:
        if not profile.created_at:
            profile.created_at = datetime.now(tz=UTC).isoformat()
        self._path(profile.name).write_text(
            json.dumps(asdict(profile), indent=2), encoding="utf-8"
        )

    def get(self, name: str) -> CommandProfile | None:
        path = self._path(name)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return CommandProfile(**data)

    def list_credentials(self) -> list[CommandProfile]:
        profiles: list[CommandProfile] = []
        for p in sorted(self._profiles_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                profiles.append(CommandProfile(**data))
            except Exception:
                continue
        return profiles

    def delete(self, name: str) -> bool:
        path = self._path(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def render(self, command: str, params: dict[str, str]) -> str:
        """Render a command template with key=value parameters."""
        rendered = command
        for k, v in params.items():
            rendered = rendered.replace(f"{{{k}}}", v).replace(f"${{{k}}}", v)
        return rendered
