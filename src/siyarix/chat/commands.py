# SPDX-License-Identifier: AGPL-3.0-or-later

"""Slash command registry and profiles for Siyarix chat.

Provides a comprehensive CommandRegistry with categories, aliases,
argument metadata, and help system — powers autocomplete, help, and dispatch.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)


# ── Command Categories ────────────────────────────────────────────────────


class CommandCategory(str, Enum):
    NAVIGATION = "Navigation"
    SESSION = "Session"
    CONFIGURATION = "Configuration"
    TOOLS = "Tools"
    ANALYSIS = "Analysis"
    REPORT = "Report"
    SYSTEM = "System"
    MODE = "Mode"
    EXPORT = "Export"
    LEARNING = "Learning"
    TEAM = "Team"
    ADVANCED = "Advanced"
    HELP = "Help"

    def __str__(self) -> str:
        return self.value


# ── Command Info Dataclass ────────────────────────────────────────────────


@dataclass
class ArgInfo:
    name: str
    description: str = ""
    optional: bool = False
    choices: list[str] | None = None  # fixed set of valid values


@dataclass
class CommandInfo:
    """Metadata for a single slash command."""

    name: str
    category: CommandCategory
    description: str
    usage: str = ""
    aliases: list[str] = field(default_factory=list)
    args: list[ArgInfo] = field(default_factory=list)
    hidden: bool = False
    handler: str = ""
    mode_filter: list[str] | None = None
    examples: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def all_names(self) -> list[str]:
        return [self.name] + self.aliases

    def format_detailed(self) -> str:
        """Return a detailed help string for this command."""
        parts = [f"[bold cyan]{self.usage or self.name}[/bold cyan]"]
        parts.append(f"  [dim]{self.description}[/dim]")
        if self.aliases:
            parts.append(f"  [bold]Aliases:[/bold] {', '.join(self.aliases)}")
        if self.args:
            parts.append("  [bold]Arguments:[/bold]")
            for arg in self.args:
                opt = " [dim](optional)[/dim]" if arg.optional else ""
                choices = f" [yellow]{{{', '.join(arg.choices)}}}[/yellow]" if arg.choices else ""
                parts.append(f"    [cyan]{arg.name}[/cyan]: {arg.description}{opt}{choices}")
        if self.mode_filter:
            parts.append(f"  [bold]Available in modes:[/bold] {', '.join(self.mode_filter)}")
        if self.examples:
            parts.append("  [bold]Examples:[/bold]")
            for ex in self.examples:
                parts.append(f"    [green]{ex}[/green]")
        if self.notes:
            parts.append(f"  [dim]ℹ {self.notes}[/dim]")
        return "\n".join(parts)


# ── Command Registry ──────────────────────────────────────────────────────


class CommandRegistry:
    """Central registry of all slash commands with lookup and filtering."""

    _commands: dict[str, CommandInfo] = {}
    _by_category: dict[CommandCategory, list[CommandInfo]] = {}
    _initialized = False

    @classmethod
    def initialize(cls) -> None:
        if cls._initialized:
            return
        cls._initialized = True
        cls._commands.clear()
        cls._by_category.clear()
        for cat in CommandCategory:
            cls._by_category[cat] = []

        for info in _BUILTIN_COMMANDS:
            for name in info.all_names:
                cls._commands[name] = info
            cls._by_category.setdefault(info.category, []).append(info)

    @classmethod
    def get(cls, name: str) -> CommandInfo | None:
        cls.initialize()
        return cls._commands.get(name)

    @classmethod
    def all_commands(cls) -> list[CommandInfo]:
        cls.initialize()
        seen = set()
        result = []
        for info in _BUILTIN_COMMANDS:
            if info.name not in seen:
                seen.add(info.name)
                result.append(info)
        return result

    @classmethod
    def visible_commands(cls) -> list[CommandInfo]:
        return [c for c in cls.all_commands() if not c.hidden]

    @classmethod
    def visible_commands_for_mode(cls, mode: str) -> list[CommandInfo]:
        """Return commands visible for the given mode, with mode-relevant
        commands promoted to the top.

        Commands with a mode_filter that includes the current mode are
        boosted to the top of the list; all other visible commands follow.
        Commands with mode_filter that do NOT include the current mode
        are moved to the bottom (but not hidden — the user can still
        switch modes)."""
        seen = set()
        promoted = []
        normal = []
        demoted = []
        for c in cls.visible_commands():
            if c.name in seen:
                continue
            seen.add(c.name)
            if c.mode_filter is None:
                normal.append(c)
            elif mode in c.mode_filter:
                promoted.append(c)
            else:
                demoted.append(c)
        return promoted + normal + demoted

    @classmethod
    def categorized_for_mode(cls, mode: str) -> dict[CommandCategory, list[CommandInfo]]:
        """Return commands grouped by category, filtered/ordered by mode."""
        grouped: dict[CommandCategory, list[CommandInfo]] = {}
        for cmd in cls.visible_commands_for_mode(mode):
            grouped.setdefault(cmd.category, []).append(cmd)
        return grouped

    @classmethod
    def by_category(cls, cat: CommandCategory) -> list[CommandInfo]:
        cls.initialize()
        return cls._by_category.get(cat, [])

    @classmethod
    def search(cls, query: str) -> list[CommandInfo]:
        """Fuzzy search commands by name, alias, or description."""
        q = query.lower()
        results = []
        for info in cls.all_commands():
            if q in info.name.lower():
                results.append(info)
                continue
            if any(q in a.lower() for a in info.aliases):
                results.append(info)
                continue
            if q in info.description.lower():
                results.append(info)
                continue
            for arg in info.args:
                if q in arg.name.lower():
                    results.append(info)
                    break
        return results

    @classmethod
    def suggestions_for(cls, command_name: str) -> list[CommandInfo]:
        """Find commands similar to the given partial name."""
        cls.initialize()
        q = command_name.lstrip("/").lower()
        matches = []
        for info in cls.visible_commands():
            if q in info.name.lstrip("/").lower():
                matches.append(info)
        matches.sort(
            key=lambda c: (
                0 if c.name.lstrip("/").lower().startswith(q) else 1,
                c.name,
            )
        )
        return matches[:8]

    @classmethod
    def top_commands(cls, limit: int = 10) -> list[CommandInfo]:
        """Return the most commonly useful commands for the welcome screen."""
        return [c for c in cls.visible_commands() if not c.hidden][:limit]


# ── Built-in command definitions ──────────────────────────────────────────

_BUILTIN_COMMANDS: list[CommandInfo] = [
    # ── Help ──
    CommandInfo(
        name="/help",
        category=CommandCategory.HELP,
        description="Show contextual help system with categories",
        usage="/help [category|command]",
        aliases=["/?", "/h"],
        args=[
            ArgInfo("category", "Filter help by category name", optional=True),
        ],
        handler="_cmd_help",
        examples=["/help", "/help Navigation", "/help mode", "/help /scan"],
        notes="Use /help <category> to filter commands. Use /help <command> for detailed help.",
    ),
    # ── Navigation ──
    CommandInfo(
        name="/exit",
        category=CommandCategory.NAVIGATION,
        description="Exit chat mode",
        aliases=["/quit", "/bye"],
        handler="_cmd_exit",
        examples=["/exit", "/quit"],
        notes="Saves session before exiting.",
    ),
    CommandInfo(
        name="/clear",
        category=CommandCategory.NAVIGATION,
        description="Clear screen and conversation",
        usage="/clear",
        aliases=["/clean", "/cls"],
        handler="_cmd_clear",
        examples=["/clear", "/cls"],
        notes="Clears the terminal and resets conversation history.",
    ),
    CommandInfo(
        name="/new",
        category=CommandCategory.NAVIGATION,
        description="Start a fresh conversation",
        aliases=["/fresh"],
        handler="_cmd_new",
        examples=["/new", "/fresh"],
        notes="Clears all messages from current session context.",
    ),
    CommandInfo(
        name="/cancel",
        category=CommandCategory.NAVIGATION,
        description="Cancel current task without exiting",
        aliases=["/esc"],
        handler="_cmd_esc",
        examples=["/cancel", "/esc"],
        notes="Cancels any running operation without exiting the REPL.",
    ),
    CommandInfo(
        name="/history",
        category=CommandCategory.NAVIGATION,
        description="Browse conversation history with optional search",
        usage="/history [n] [filter]",
        args=[
            ArgInfo("n", "Number of messages to show (max 200)", optional=True),
            ArgInfo("filter", "Keyword to search for", optional=True),
        ],
        handler="_cmd_history",
        examples=["/history", "/history 50", "/history 20 scan"],
        notes="Shows last N messages. Provide a filter keyword to narrow results.",
    ),
    CommandInfo(
        name="/search",
        category=CommandCategory.NAVIGATION,
        description="Search chat history for a keyword",
        usage="/search <text>",
        args=[ArgInfo("text", "Keyword to search for")],
        handler="_cmd_search",
        examples=["/search nmap", "/search vulnerability"],
        notes="Finds all messages containing the keyword.",
    ),
    # ── Session ──
    CommandInfo(
        name="/session",
        category=CommandCategory.SESSION,
        description="Show detailed session metadata",
        aliases=["/info"],
        handler="_cmd_session",
        examples=["/session", "/info"],
        notes="Displays session ID, created/last active timestamps, mode, target, and context keys.",
    ),
    CommandInfo(
        name="/save",
        category=CommandCategory.SESSION,
        description="Save current session to disk",
        usage="/save [session_id]",
        args=[ArgInfo("session_id", "Optional custom session ID", optional=True)],
        handler="_cmd_save",
        examples=["/save", "/save my_engagement_001"],
        notes="Saves to ~/.config/siyarix/sessions/. Sessions auto-save on exit.",
    ),
    CommandInfo(
        name="/load",
        category=CommandCategory.SESSION,
        description="Load a saved session by ID",
        usage="/load <session_id>",
        args=[ArgInfo("session_id", "Session ID to load")],
        handler="_cmd_load",
        examples=["/load abc12345", "/load"],
        notes="Without arguments, lists all saved sessions for selection.",
    ),
    CommandInfo(
        name="/fork",
        category=CommandCategory.SESSION,
        description="Fork current session into a new branch",
        usage="/fork [message_index] [summary]",
        args=[
            ArgInfo("message_index", "Message index to fork at", optional=True),
            ArgInfo("summary", "Summary of the fork", optional=True),
        ],
        handler="_cmd_fork",
        examples=["/fork", "/fork 5 Exploration path B"],
        notes="Creates a snapshot of the session at the given message index.",
    ),
    CommandInfo(
        name="/diff",
        category=CommandCategory.SESSION,
        description="Diff between two sessions",
        usage="/diff <session_a> <session_b>",
        args=[
            ArgInfo("session_a", "First session ID"),
            ArgInfo("session_b", "Second session ID"),
        ],
        handler="_cmd_diff",
        examples=["/diff abc123 def456"],
        notes="Compares findings between two scan sessions.",
    ),
    CommandInfo(
        name="/log",
        category=CommandCategory.SESSION,
        description="Manage session logs",
        usage="/log list|show|export <session_id>",
        args=[
            ArgInfo("action", "list, show, or export"),
            ArgInfo("session_id", "Session ID (for show/export)", optional=True),
        ],
        handler="_cmd_log",
        examples=[
            "/log list",
            "/log show abc123",
            "/log export abc123 --format json --output log.json",
        ],
        notes="Formats: json, markdown, sarif. Use --output to save to file.",
    ),
    CommandInfo(
        name="/reset",
        category=CommandCategory.SESSION,
        description="Reset mode and target to defaults",
        handler="_cmd_reset",
        examples=["/reset"],
        notes="Resets mode to 'integrated' and clears target.",
    ),
    CommandInfo(
        name="/stats",
        category=CommandCategory.SESSION,
        description="Show usage statistics for current session",
        usage="/stats [detail]",
        args=[ArgInfo("detail", "Show detailed breakdown", optional=True)],
        handler="_cmd_stats",
        examples=["/stats", "/stats detail"],
        notes="With 'detail' shows command usage frequency breakdown.",
    ),
    # ── Configuration ──
    CommandInfo(
        name="/config",
        category=CommandCategory.CONFIGURATION,
        description="View/edit configuration settings",
        usage="/config [show|set|get|list|tools]",
        args=[
            ArgInfo("action", "show, set <key> <value>, get <key>, list, tools"),
        ],
        handler="_cmd_config",
        examples=[
            "/config",
            "/config set color_theme cyber-noir",
            "/config get model_provider",
            "/config list",
        ],
        notes="Modified values are highlighted in yellow in the table.",
    ),
    CommandInfo(
        name="/key",
        category=CommandCategory.CONFIGURATION,
        description="Manage API keys for AI providers",
        usage="/key [set|remove|list|rotate] <provider> <key>",
        args=[
            ArgInfo("action", "set, remove, list, or rotate"),
            ArgInfo("provider", "Provider name (e.g. gemini, openai)", optional=True),
            ArgInfo("key", "API key value", optional=True),
        ],
        handler="_cmd_key",
        examples=["/key list", "/key set gemini AIza...", "/key remove openai", "/key rotate"],
        notes="Keys can be stored in credential store (cryptography) or ephemeral env vars.",
    ),
    CommandInfo(
        name="/theme",
        category=CommandCategory.CONFIGURATION,
        description="Switch color themes",
        usage="/theme [list|preview|set] <theme> [syntax_theme]",
        args=[
            ArgInfo("action", "list, preview, set, or theme name", optional=True),
            ArgInfo("theme", "Theme name", optional=True),
        ],
        handler="_cmd_theme",
        examples=["/theme", "/theme list", "/theme cyber-noir dracula", "/theme preview"],
        notes="Syntax themes: monokai, dracula, nord, github-dark, etc.",
    ),
    CommandInfo(
        name="/alias",
        category=CommandCategory.CONFIGURATION,
        description="Create and manage command aliases",
        usage="/alias [list|set|remove] <name> <command>",
        args=[
            ArgInfo("action", "list, set, or remove"),
            ArgInfo("name", "Alias name", optional=True),
            ArgInfo("command", "Command to alias", optional=True),
        ],
        handler="_cmd_alias",
        examples=["/alias list", "/alias set sc /scan", "/alias remove sc"],
        notes="Aliases are persisted to ~/.config/siyarix/aliases.json.",
    ),
    CommandInfo(
        name="/language",
        category=CommandCategory.CONFIGURATION,
        description="Switch output language",
        usage="/language [list|<lang>]",
        args=[
            ArgInfo("lang", "Language code (en, fr, de, es, etc.)", optional=True),
        ],
        handler="_cmd_language",
        examples=["/language", "/language list", "/language fr"],
        notes="LLM response language depends on provider support.",
    ),
    CommandInfo(
        name="/savecmd",
        category=CommandCategory.CONFIGURATION,
        description="Save a command profile for reuse",
        usage="/savecmd <name> <command>",
        args=[
            ArgInfo("name", "Profile name"),
            ArgInfo("command", "Command to save"),
        ],
        handler="_cmd_savecmd",
        examples=["/savecmd my_scan scan 10.0.0.1"],
        notes="Saved profiles can be run with /cmd <name>.",
    ),
    CommandInfo(
        name="/cmds",
        category=CommandCategory.CONFIGURATION,
        description="List saved command profiles",
        handler="_cmd_cmds",
        examples=["/cmds"],
        notes="Shows name, command, and creation timestamp for each profile.",
    ),
    CommandInfo(
        name="/cmd",
        category=CommandCategory.CONFIGURATION,
        description="Run a saved command profile",
        usage="/cmd <profile_name>",
        args=[ArgInfo("profile_name", "Name of saved profile")],
        handler="_cmd_cmd",
        examples=["/cmd my_scan"],
        notes="Prompts for confirmation before executing.",
    ),
    # ── Mode ──
    CommandInfo(
        name="/mode",
        category=CommandCategory.MODE,
        description="Switch execution mode",
        usage="/mode <mode>",
        args=[
            ArgInfo(
                "mode",
                "Mode name",
                choices=[
                    "autonomous",
                    "integrated",
                    "offline",
                    "stealth",
                    "verbose",
                    "quiet",
                    "expert",
                    "beginner",
                    "interactive",
                    "batch",
                    "redteam",
                    "blueteam",
                    "compliance",
                    "audit",
                ],
            ),
        ],
        aliases=["/m"],
        handler="_cmd_mode",
        examples=["/mode", "/mode integrated", "/m stealth"],
        notes="Core modes: autonomous (LLM-driven), integrated (hybrid), offline (no LLM). Team modes: redteam, blueteam.",
    ),
    CommandInfo(
        name="/model",
        category=CommandCategory.CONFIGURATION,
        description="Switch AI model/provider on the fly",
        usage="/model <provider> [model_name]",
        args=[
            ArgInfo("provider", "Provider name (gemini, openai, anthropic, etc.)"),
            ArgInfo("model_name", "Specific model name (optional)", optional=True),
        ],
        handler="_cmd_model",
        examples=[
            "/model gemini",
            "/model openai gpt-4o",
            "/model anthropic claude-sonnet-4-20250514",
        ],
        notes="Validates the provider connection after switching.",
    ),
    CommandInfo(
        name="/provider",
        category=CommandCategory.CONFIGURATION,
        description="Show detailed provider info and models",
        usage="/provider [name]",
        aliases=["/providers"],
        args=[ArgInfo("name", "Provider name to inspect", optional=True)],
        handler="_cmd_provider",
        examples=["/provider", "/provider gemini", "/providers"],
        notes="Shows type, cost tier, capabilities, models, and configuration status.",
    ),
    CommandInfo(
        name="/persona",
        category=CommandCategory.CONFIGURATION,
        description="Switch mindset/persona",
        usage="/persona [list|<name>]",
        args=[ArgInfo("name", "Persona name", optional=True)],
        handler="_cmd_persona",
        examples=["/persona", "/persona list", "/persona pentester"],
        notes="Personas shape LLM behavior. 'auto' selects based on mode.",
    ),
    CommandInfo(
        name="/redteam",
        category=CommandCategory.TEAM,
        description="Switch to red team mode (offensive focus)",
        aliases=["/offensive"],
        handler="_cmd_redteam",
        examples=["/redteam", "/offensive"],
        mode_filter=[
            "blueteam",
            "integrated",
            "autonomous",
            "stealth",
            "verbose",
            "quiet",
            "expert",
            "beginner",
            "interactive",
            "batch",
            "compliance",
            "audit",
        ],
        notes="Sets persona to 'red-team' and activates offensive posture.",
    ),
    CommandInfo(
        name="/blueteam",
        category=CommandCategory.TEAM,
        description="Switch to blue team mode (defensive focus)",
        aliases=["/defensive"],
        handler="_cmd_blueteam",
        examples=["/blueteam", "/defensive"],
        mode_filter=[
            "redteam",
            "integrated",
            "autonomous",
            "stealth",
            "verbose",
            "quiet",
            "expert",
            "beginner",
            "interactive",
            "batch",
            "compliance",
            "audit",
        ],
        notes="Sets persona to 'blue-team' and activates defensive posture.",
    ),
    # ── Tools ──
    CommandInfo(
        name="/tools",
        category=CommandCategory.TOOLS,
        description="List discovered security tools with search/filter",
        usage="/tools [category]",
        args=[ArgInfo("category", "Tool category filter", optional=True)],
        handler="_cmd_tools",
        examples=["/tools", "/tools recon", "/tools exploitation"],
        notes="Tools are discovered from PATH at startup. Categories: recon, exploitation, web, etc.",
    ),
    CommandInfo(
        name="/run",
        category=CommandCategory.TOOLS,
        description="Run a tool or shell command",
        usage="/run <command>",
        args=[ArgInfo("command", "Command or tool to run")],
        handler="_cmd_run",
        examples=["/run nmap -sV 10.0.0.1", "/run gobuster dir -u https://example.com"],
        notes="Executes raw shell commands with output captured back into context.",
    ),
    CommandInfo(
        name="/scan",
        category=CommandCategory.TOOLS,
        description="Quick scan configuration on target",
        usage="/scan <target>",
        args=[ArgInfo("target", "Target IP/hostname/URL")],
        handler="_cmd_scan",
        examples=["/scan 10.0.0.1", "/scan example.com"],
        notes="Uses the current target if not specified. Runs full recon pipeline.",
    ),
    CommandInfo(
        name="/target",
        category=CommandCategory.CONFIGURATION,
        description="Set or show the current target",
        usage="/target [host]",
        args=[ArgInfo("host", "Target host/IP/URL", optional=True)],
        handler="_cmd_target",
        examples=["/target", "/target 10.0.0.5", "/target example.com"],
        notes="Affects all subsequent scan/recon commands as default target.",
    ),
    CommandInfo(
        name="/intents",
        category=CommandCategory.TOOLS,
        description="List cross-platform command intents",
        usage="/intents [filter]",
        args=[ArgInfo("filter", "Keyword to filter intents", optional=True)],
        handler="_cmd_intents",
        examples=["/intents", "/intents scan"],
        notes="Cross-platform command translations for Linux, macOS, and Windows.",
    ),
    CommandInfo(
        name="/translate",
        category=CommandCategory.TOOLS,
        description="Translate a command intent to all shells",
        usage="/translate <intent>",
        args=[ArgInfo("intent", "Command intent to translate")],
        handler="_cmd_translate",
        examples=["/translate port_scan"],
        notes="Shows the command for each shell variant (bash, powershell, cmd).",
    ),
    CommandInfo(
        name="/security-cmds",
        category=CommandCategory.TOOLS,
        description="Show security commands for current platform",
        handler="_cmd_security_cmds",
        examples=["/security-cmds"],
        notes="Lists platform-specific security commands with descriptions.",
    ),
    CommandInfo(
        name="/plugins",
        category=CommandCategory.TOOLS,
        description="List and manage Siyarix plugins",
        usage="/plugins [list|status]",
        args=[ArgInfo("action", "list or status", optional=True)],
        handler="_cmd_plugins",
        examples=["/plugins", "/plugins list", "/plugins status"],
        notes="Plugins directory: ~/.config/siyarix/plugins/. Supports .py and .yaml.",
    ),
    CommandInfo(
        name="/playbook",
        category=CommandCategory.TOOLS,
        description="Load and run playbooks",
        usage="/playbook [list|run|show] <path>",
        args=[
            ArgInfo("action", "list, run, or show"),
            ArgInfo("path", "Playbook file path", optional=True),
        ],
        handler="_cmd_playbook",
        examples=["/playbook list", "/playbook show my_scan", "/playbook run my_scan"],
        notes="Playbooks are YAML files in ~/.config/siyarix/playbooks/ with a 'steps' list.",
    ),
    # ── Analysis ──
    CommandInfo(
        name="/context",
        category=CommandCategory.ANALYSIS,
        description="Show current session context",
        handler="_cmd_context",
        examples=["/context"],
        notes="Displays recent conversation context summary.",
    ),
    CommandInfo(
        name="/examples",
        category=CommandCategory.ANALYSIS,
        description="Show practical prompt examples",
        handler="_cmd_examples",
        examples=["/examples"],
        notes="Useful prompt patterns for common security tasks.",
    ),
    CommandInfo(
        name="/review",
        category=CommandCategory.ANALYSIS,
        description="Toggle command review prompt before execution",
        usage="/review [on|off]",
        args=[ArgInfo("state", "on or off", optional=True)],
        handler="_cmd_review",
        examples=["/review", "/review on", "/review off"],
        notes="When on, every command is reviewed before execution.",
    ),
    CommandInfo(
        name="/intel",
        category=CommandCategory.ANALYSIS,
        description="Threat intelligence lookup",
        usage="/intel lookup|status [indicator]",
        args=[
            ArgInfo("action", "lookup or status"),
            ArgInfo("indicator", "CVE, IP, domain to look up", optional=True),
        ],
        handler="_cmd_intel",
        examples=["/intel lookup CVE-2023-1234", "/intel lookup 8.8.8.8", "/intel status"],
        notes="Uses AlienVault OTX for threat intelligence data.",
    ),
    CommandInfo(
        name="/kb",
        category=CommandCategory.ANALYSIS,
        description="Knowledge base operations",
        usage="/kb search|list <query>",
        args=[
            ArgInfo("action", "search or list"),
            ArgInfo("query", "Search query", optional=True),
        ],
        handler="_cmd_kb",
        examples=["/kb search sql injection", "/kb list"],
        notes="Searches the local knowledge graph.",
    ),
    # ── Report ──
    CommandInfo(
        name="/report",
        category=CommandCategory.REPORT,
        description="Generate executive report from current session",
        usage="/report [format]",
        args=[
            ArgInfo("format", "Output format (markdown, html, json)", optional=True),
        ],
        handler="_cmd_report",
        examples=["/report", "/report html"],
        notes="Generates from session findings. Output saved to sessions/reports/.",
    ),
    CommandInfo(
        name="/export",
        category=CommandCategory.EXPORT,
        description="Export conversation in various formats",
        usage="/export <format> [path]",
        args=[
            ArgInfo(
                "format", "Export format", choices=["json", "md", "markdown", "html", "pdf", "txt"]
            ),
            ArgInfo("path", "Output file path", optional=True),
        ],
        handler="_cmd_export",
        examples=["/export json", "/export md ./conversation.md", "/export html"],
        notes="PDF export requires pdfkit or weasyprint.",
    ),
    # ── System ──
    CommandInfo(
        name="/status",
        category=CommandCategory.SYSTEM,
        description="Show session and runtime status dashboard",
        handler="_cmd_status",
        examples=["/status"],
        notes="Shows mode, provider, target, messages, findings, uptime, shell info.",
    ),
    CommandInfo(
        name="/env",
        category=CommandCategory.SYSTEM,
        description="Show terminal environment summary",
        handler="_cmd_env",
        examples=["/env"],
        notes="Safe environment keys only (no secrets).",
    ),
    CommandInfo(
        name="/platform",
        category=CommandCategory.SYSTEM,
        description="Show platform and shell information",
        handler="_cmd_platform",
        examples=["/platform"],
        notes="Detailed OS, terminal, runtime, and flags information.",
    ),
    CommandInfo(
        name="/version",
        category=CommandCategory.SYSTEM,
        description="Show Siyarix version",
        handler="_cmd_version",
        examples=["/version"],
        notes="Shows the installed Siyarix package version.",
    ),
    CommandInfo(
        name="/uptime",
        category=CommandCategory.SYSTEM,
        description="Show chat session uptime",
        handler="_cmd_uptime",
        examples=["/uptime"],
        notes="Time elapsed since the current session was created.",
    ),
    CommandInfo(
        name="/shells",
        category=CommandCategory.SYSTEM,
        description="List supported shells",
        handler="_cmd_shells",
        examples=["/shells"],
        notes="Shows shell name and support tier (full/basic).",
    ),
    CommandInfo(
        name="/upgrade",
        category=CommandCategory.SYSTEM,
        description="Check for Siyarix updates",
        handler="_cmd_upgrade",
        examples=["/upgrade"],
        notes="Runs pip install --dry-run --upgrade siyarix to check.",
    ),
    CommandInfo(
        name="/docs",
        category=CommandCategory.SYSTEM,
        description="Open Siyarix documentation",
        usage="/docs [section]",
        args=[ArgInfo("section", "Documentation section", optional=True)],
        handler="_cmd_docs",
        examples=["/docs", "/docs commands", "/docs providers"],
        notes="Sections: getting-started, commands, configuration, providers, plugins, playbooks, api, troubleshooting.",
    ),
    CommandInfo(
        name="/bug",
        category=CommandCategory.SYSTEM,
        description="Report a bug (opens GitHub issues)",
        handler="_cmd_bug",
        examples=["/bug"],
        notes="Opens https://github.com/mufthakherul/siyarix/issues/new",
    ),
    CommandInfo(
        name="/suggest",
        category=CommandCategory.SYSTEM,
        description="Suggest a feature (opens GitHub discussions)",
        handler="_cmd_suggest",
        examples=["/suggest"],
        notes="Opens GitHub discussions for feature ideas.",
    ),
    CommandInfo(
        name="/tutorial",
        category=CommandCategory.SYSTEM,
        description="Launch interactive tutorial",
        usage="/tutorial [topic]",
        args=[ArgInfo("topic", "Tutorial topic", optional=True)],
        handler="_cmd_tutorial",
        examples=["/tutorial", "/tutorial scanning"],
        notes="Topics: basics, scanning, recon, exploitation, reporting, playbooks, aliases, learning.",
    ),
    CommandInfo(
        name="/benchmark",
        category=CommandCategory.SYSTEM,
        description="Run performance benchmark",
        usage="/benchmark [provider] [model]",
        args=[
            ArgInfo("provider", "Provider to benchmark", optional=True),
            ArgInfo("model", "Model to benchmark", optional=True),
        ],
        handler="_cmd_benchmark",
        examples=["/benchmark", "/benchmark gemini", "/benchmark openai gpt-4o"],
        notes="Tests short, medium, and long prompts. Reports time, characters, and chars/s.",
    ),
    # ── Learning ──
    CommandInfo(
        name="/learn",
        category=CommandCategory.LEARNING,
        description="Toggle Continuous Learning System",
        usage="/learn [on|off|status]",
        args=[ArgInfo("state", "on, off, or status", optional=True)],
        handler="_cmd_learn",
        examples=["/learn", "/learn on", "/learn off", "/learn status"],
        notes="CLS learns from repeated workflows and auto-suggests skills.",
    ),
    CommandInfo(
        name="/skills",
        category=CommandCategory.LEARNING,
        description="Manage learned skills",
        usage="/skills [stats|list|show|edit|remove|add|export]",
        handler="_cmd_skills",
        examples=[
            "/skills list",
            "/skills show 3",
            "/skills edit 4 notes",
            "/skills remove 2",
            "/skills add 1. ping {target}; ping -c 2 {target}.",
            "/skills export ~/skills.json",
        ],
        notes="Skills are learned patterns. Sl No comes from /skills list.",
    ),
    CommandInfo(
        name="/feedback",
        category=CommandCategory.LEARNING,
        description="Provide feedback on the last response",
        usage="/feedback <rating> [comment]",
        args=[
            ArgInfo("rating", "Rating: 1-5 or good/bad"),
            ArgInfo("comment", "Optional comment", optional=True),
        ],
        handler="_cmd_feedback",
        examples=["/feedback 5 Great analysis!", "/feedback bad"],
        notes="Saved to ~/.config/siyarix/feedback/ for model improvement.",
    ),
    # ── Advanced Operations ──
    CommandInfo(
        name="/split",
        category=CommandCategory.ADVANCED,
        description="Toggle split pane view",
        usage="/split [timeline|metrics|cheatsheet|attack_map|off]",
        handler="_cmd_split",
        examples=["/split", "/split timeline", "/split attack_map", "/split off"],
        notes="Displays side-by-side panels with contextual information.",
    ),
    CommandInfo(
        name="/batch",
        category=CommandCategory.ADVANCED,
        description="Execute batch command file",
        usage="/batch run <file>",
        args=[ArgInfo("file", "Batch script file path")],
        handler="_cmd_batch",
        examples=["/batch run targets.txt"],
        notes="Each line is executed sequentially. '#' lines are skipped as comments.",
    ),
    CommandInfo(
        name="/opsec",
        category=CommandCategory.ADVANCED,
        description="Operational security controls",
        usage="/opsec isolate|burn|status|disable",
        handler="_cmd_opsec",
        examples=["/opsec status", "/opsec isolate", "/opsec burn", "/opsec disable"],
        notes="Isolate: enables TOR + DoH. Burn: destroys session artifacts.",
    ),
    CommandInfo(
        name="/stealth",
        category=CommandCategory.ADVANCED,
        description="Evasion configuration",
        usage="/stealth status|on|off|level <level>",
        handler="_cmd_stealth",
        examples=["/stealth status", "/stealth on", "/stealth level heavy"],
        notes="Levels: none, light, medium, heavy, paranoid. Controls jitter, UA rotation, proxy chain.",
    ),
    CommandInfo(
        name="/audit",
        category=CommandCategory.ADVANCED,
        description="Compliance and legal export",
        usage="/audit export|status|verify",
        handler="_cmd_audit",
        examples=["/audit status", "/audit export", "/audit verify"],
        notes="Maintains a cryptographic chain of custody for all operations.",
    ),
    CommandInfo(
        name="/queue",
        category=CommandCategory.ADVANCED,
        description="Offline command queue management",
        usage="/queue status|list|retry|clear|flush",
        handler="_cmd_queue",
        examples=["/queue status", "/queue list", "/queue retry", "/queue flush"],
        notes="Queues commands for retry in offline mode. Flush executes pending now.",
    ),
    CommandInfo(
        name="/cache",
        category=CommandCategory.ADVANCED,
        description="Cache management",
        usage="/cache status|clear|invalidate [domain]",
        handler="_cmd_cache",
        examples=["/cache status", "/cache clear", "/cache invalidate example.com"],
        notes="Manages the DNS/HTTP response cache to reduce duplicate requests.",
    ),
    CommandInfo(
        name="/performance",
        category=CommandCategory.ADVANCED,
        description="Resource optimization",
        usage="/performance status|tune|configure",
        handler="_cmd_performance",
        examples=["/performance status", "/performance tune"],
        notes="Auto-tunes concurrent agent count and memory limits based on system resources.",
    ),
    CommandInfo(
        name="/campaign",
        category=CommandCategory.ADVANCED,
        description="Multi-target campaign management",
        usage="/campaign list|create|status",
        handler="_cmd_campaign",
        examples=["/campaign list", "/campaign create my_campaign"],
        notes="Manages multi-target security testing campaigns.",
    ),
    CommandInfo(
        name="/ticket",
        category=CommandCategory.ADVANCED,
        description="External ticket creation",
        usage="/ticket create|list",
        handler="_cmd_ticket",
        examples=["/ticket create SQL injection found on /login", "/ticket list"],
        notes="Creates internal tickets (Jira/GitHub integration not yet available).",
    ),
    CommandInfo(
        name="/retest",
        category=CommandCategory.ADVANCED,
        description="Verification scan scheduling",
        usage="/retest schedule|status",
        handler="_cmd_retest",
        examples=["/retest schedule", "/retest status"],
        notes="Schedules follow-up scans to verify fix efficacy.",
    ),
    CommandInfo(
        name="/agent",
        category=CommandCategory.ADVANCED,
        description="Sub-agent lifecycle management",
        usage="/agent run <goal>|status",
        handler="_cmd_agent",
        examples=["/agent run enumerate all open ports on 10.0.0.1", "/agent status"],
        notes="Spawns autonomous sub-agents for delegated tasks.",
    ),
    CommandInfo(
        name="/siem",
        category=CommandCategory.ADVANCED,
        description="SIEM/SOAR integration (legacy)",
        usage="/siem connect|status",
        handler="_cmd_siem",
        examples=["/siem status"],
        notes="SIEM integration has been migrated to a separate plugin.",
    ),
]

CommandRegistry.initialize()

# ── Backward compatibility: HELP_CATEGORIES and SLASH_HELP ────────────────

HELP_CATEGORIES: list[tuple[str, dict[str, str]]] = []
_cat_map: dict[CommandCategory, str] = {
    CommandCategory.NAVIGATION: "Navigation & Session",
    CommandCategory.SESSION: "Session Management",
    CommandCategory.CONFIGURATION: "Configuration",
    CommandCategory.MODE: "Mode Switching",
    CommandCategory.TOOLS: "Tools & Execution",
    CommandCategory.ANALYSIS: "Analysis & Intelligence",
    CommandCategory.REPORT: "Reporting",
    CommandCategory.EXPORT: "Export & Sharing",
    CommandCategory.SYSTEM: "System Information",
    CommandCategory.LEARNING: "Learning & Feedback",
    CommandCategory.TEAM: "Team Operations",
    CommandCategory.HELP: "Help & Support",
    CommandCategory.ADVANCED: "Advanced Operations",
}

for cat in CommandCategory:
    cmds_in_cat = CommandRegistry.by_category(cat)
    if cmds_in_cat:
        entries: dict[str, str] = {}
        for ci in cmds_in_cat:
            if not ci.hidden:
                key = ci.usage if ci.usage else ci.name
                desc = ci.description
                if ci.aliases:
                    desc += f" (aliases: {', '.join(ci.aliases)})"
                entries[key] = desc
        if entries:
            label = _cat_map.get(cat, cat.value)
            HELP_CATEGORIES.append((label, entries))

SLASH_HELP: dict[str, str] = {}
for _label, _entries in HELP_CATEGORIES:
    for k, v in _entries.items():
        primary = k.split()[0]
        SLASH_HELP[primary] = v


# ── Command Profile (unchanged) ───────────────────────────────────────────


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
        self._path(profile.name).write_text(json.dumps(asdict(profile), indent=2), encoding="utf-8")

    def get(self, name: str) -> CommandProfile | None:
        path = self._path(name)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return CommandProfile(**data)

    def list_profiles(self) -> list[CommandProfile]:
        profiles: list[CommandProfile] = []
        for p in sorted(self._profiles_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                profiles.append(CommandProfile(**data))
            except Exception:
                continue
        return profiles

    list_credentials = list_profiles

    def delete(self, name: str) -> bool:
        path = self._path(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def render(self, command: str, params: dict[str, str]) -> str:
        rendered = command
        for k, v in params.items():
            rendered = rendered.replace(f"{{{k}}}", v).replace(f"${{{k}}}", v)
        return rendered


# ── Command History (for autocomplete ranking) ────────────────────────────


class CommandHistory:
    """Tracks recently used commands for smarter autocomplete ranking."""

    def __init__(self, maxlen: int = 100) -> None:
        self._history: list[str] = []
        self._maxlen = maxlen

    def record(self, command: str) -> None:
        cmd = command.split()[0].lower()
        # Move to front
        if cmd in self._history:
            self._history.remove(cmd)
        self._history.insert(0, cmd)
        if len(self._history) > self._maxlen:
            self._history.pop()

    def recent(self, limit: int = 10) -> list[str]:
        return self._history[:limit]

    def frequency_score(self, command: str) -> float:
        """Score a command by recency. 1.0 = most recent, 0.0 = not used."""
        cmd = command.split()[0].lower()
        try:
            idx = self._history.index(cmd)
            return max(0.0, 1.0 - (idx / max(len(self._history), 1)))
        except ValueError:
            return 0.0


# Global instances
command_history = CommandHistory()

__all__ = [
    "CommandCategory",
    "CommandInfo",
    "ArgInfo",
    "CommandRegistry",
    "CommandProfile",
    "CommandProfileStore",
    "CommandHistory",
    "command_history",
    "HELP_CATEGORIES",
    "SLASH_HELP",
    "_BUILTIN_COMMANDS",
]
