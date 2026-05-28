# SPDX-License-Identifier: AGPL-3.0-or-later

"""Command Palette for Siyarix v0.1.3.

Provides a fuzzy-search interface to quickly search and select core commands,
predefined intent templates, saved profiles, and recent command history.
Uses prompt_toolkit when available, falling back gracefully to a beautiful
Rich terminal-based prompt overlay.
"""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from siyarix.command_profiles import CommandProfileStore
from siyarix.session_manager import command_history

WordCompleter: Any = None
ptk_prompt: Any = None

try:
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.shortcuts import prompt as ptk_prompt

    PTK_AVAILABLE = True
except ImportError:
    PTK_AVAILABLE = False

logger = logging.getLogger(__name__)


class CommandPalette:
    """Fuzzy-search command palette for rapid tool execution."""

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self._profile_store = CommandProfileStore()

        # Predefined operations that make sense to launch from the command palette
        self._core_actions = {
            "nmap scan full": "Scan all 65535 ports with service & OS detection",
            "nmap scan quick": "Perform standard fast port scan",
            "nuclei scan": "Scan target for CVE and critical vulnerabilities",
            "gobuster dir": "Discover hidden web directories and files",
            "sqlmap test": "Scan URL parameters for SQL injection vulnerabilities",
            "hydra ssh": "Brute-force SSH server login credentials",
            "subfinder recon": "Enumerate subdomains using passive OSINT services",
            "nikto web audit": "Audit web server software flags and SSL issues",
            "dashboard show": "Switch to real-time security dashboard TUI",
            "wizard launch": "Run onboarding configuration wizard",
        }

    def get_search_options(self) -> list[str]:
        """Compile a list of searchable command items."""
        options = []

        # Core actions
        for act, desc in self._core_actions.items():
            options.append(f"action: {act} | {desc}")

        # Command profiles
        profiles = self._profile_store.list_profiles()
        for p in profiles:
            options.append(
                f"profile: {p.name} | {p.command} ({p.description or 'No desc'})"
            )

        # Persistent history
        try:
            recent = command_history.recent(limit=15)
            for cmd_record in recent:
                cmd = cmd_record.get("command", "")
                if cmd and cmd not in self._core_actions:
                    options.append(f"history: {cmd}")
        except Exception as exc:
            logger.debug("Failed to read recent command history for palette: %s", exc)

        return options

    def show(self, console: Console) -> str | None:
        """Display the fuzzy command palette overlay.

        Returns the selected and parsed command string, or None if cancelled.
        """
        # Draw elegant cyberpunk header
        header_text = Text()
        header_text.append("⚡ COMMAND PALETTE ", style="bold cyan")
        header_text.append("[Ctrl+P / /palette]", style="dim")

        console.print(
            Panel(
                "[bold green]◈ CORE ACTIONS  ◈ SAVED PROFILES  ◈ RECENT HISTORY[/bold green]\n"
                "[dim]Enter keyword search term to filter choices. Leave blank to cancel.[/dim]",
                title=header_text,
                border_style="bright_blue",
                padding=(1, 2),
            )
        )

        options = self.get_search_options()
        query = ""

        try:
            if PTK_AVAILABLE:
                completer = WordCompleter(options, ignore_case=True)
                query = ptk_prompt("Search > ", completer=completer).strip()
            else:
                from rich.prompt import Prompt

                query = Prompt.ask("Search > ", default="").strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled Command Palette.[/yellow]")
            return None
        except Exception as exc:
            logger.exception("Failed to query command palette prompt: %s", exc)
            return None

        if not query:
            return None

        # Filter choices based on fuzzy overlap
        filtered = [o for o in options if query.lower() in o.lower()]
        if not filtered:
            console.print("[red]✗ No matching commands or profiles found.[/red]")
            return None

        # Render matches
        table = Table(
            title="🔍 Matching Actions",
            border_style="dim",
            header_style="bold bright_cyan",
            row_styles=["", "dim"],
        )
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Type", style="magenta", width=10)
        table.add_column("Command / Action Details", style="cyan")

        for idx, choice in enumerate(filtered[:10], 1):
            if " | " in choice:
                source_part, details = choice.split(" | ", 1)
            else:
                source_part, details = choice, ""

            if ":" in source_part:
                ctype, name = source_part.split(":", 1)
            else:
                ctype, name = "history", source_part

            cmd_display = (
                f"[bold]{name.strip()}[/bold] - {details.strip()}"
                if details
                else name.strip()
            )
            table.add_row(str(idx), ctype.strip().upper(), cmd_display)

        console.print(table)

        # Ask to execute or insert
        from rich.prompt import Prompt

        selection = Prompt.ask("Select command index to execute", default="").strip()
        if not selection:
            return None

        try:
            selected_idx = int(selection) - 1
            if 0 <= selected_idx < len(filtered):
                chosen = filtered[selected_idx]

                # Parse choice back to clean command
                if chosen.startswith("action:"):
                    act_name = chosen.split(":", 1)[1].split(" | ", 1)[0].strip()
                    # Map simple action back to an executable tool template
                    return self._map_action_to_cmd(act_name)
                elif chosen.startswith("profile:"):
                    prof_name = chosen.split(":", 1)[1].split(" | ", 1)[0].strip()
                    profile = self._profile_store.get(prof_name)
                    if profile:
                        # Handle placeholder substitution dynamically
                        return self._substitute_placeholders(console, profile.command)
                elif chosen.startswith("history:"):
                    return chosen.split(":", 1)[1].strip()
                else:
                    # Generic fallback
                    if " | " in chosen:
                        return chosen.split(" | ", 1)[0].split(":", 1)[-1].strip()
                    return chosen.split(":", 1)[-1].strip()
            else:
                console.print("[red]✗ Invalid selection index.[/red]")
        except ValueError:
            console.print("[red]✗ Selection must be an integer index.[/red]")
        except Exception as exc:
            logger.exception("Failed selection parse: %s", exc)

        return None

    def _map_action_to_cmd(self, action: str) -> str:
        """Resolve predefined operations to exact shell commands."""
        mappings = {
            "nmap scan full": "nmap -sV -sC -O -p 1-65535",
            "nmap scan quick": "nmap -F",
            "nuclei scan": "nuclei -severity critical,high",
            "gobuster dir": "gobuster dir -w common.txt",
            "sqlmap test": "sqlmap -u",
            "hydra ssh": "hydra -l admin -P passwords.txt ssh://",
            "subfinder recon": "subfinder -d",
            "nikto web audit": "nikto -h",
            "dashboard show": "dashboard",
            "wizard launch": "wizard",
        }
        return mappings.get(action, action)

    def _substitute_placeholders(self, console: Console, command: str) -> str:
        """Dynamically extract placeholders and prompt user for parameters."""
        placeholders = self._profile_store.extract_placeholders(command)
        if not placeholders:
            return command

        console.print(
            f"\n[cyan]◈ Profile contains {len(placeholders)} variable placeholders.[/cyan]"
        )
        params = {}
        from rich.prompt import Prompt

        for ph in placeholders:
            val = Prompt.ask(f"Value for '{ph}'").strip()
            params[ph] = val

        return self._profile_store.render(command, params)
