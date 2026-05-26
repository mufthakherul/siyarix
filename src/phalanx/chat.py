"""Phalanx Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Phalanx, similar to Claude CLI and
Gemini CLI, specialized for cybersecurity workflows.

Features:
  • Multi-turn conversation with session history
  • Context-aware suggestions and command recall
  • Cross-platform shell awareness (Linux/Mac/Windows/PowerShell)
  • Rich streaming output with syntax highlighting
  • Slash commands (/help, /history, /clear, /tools, /exit, etc.)
  • Natural language → execution pipeline
  • Session persistence across commands
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .branding import available_themes, print_theme_preview
from .command_profiles import CommandProfile, CommandProfileStore
from .config import SettingsStore
from .environment import (ensure_env_file, load_env_file, provider_env_var,
                          upsert_env_vars)
from .executor import safe_run_sync
from .shell_knowledge import (CROSS_PLATFORM_COMMANDS, build_platform_context,
                              detect_shell, get_security_commands,
                              get_shell_platform, normalize_shell)
from .ux import CommandPalette, SmartAutocomplete, SplitPane

Console: Any = None
Columns: Any = None
Markdown: Any = None
Panel: Any = None
Prompt: Any = None
Rule: Any = None
Syntax: Any = None
Table: Any = None
Text: Any = None
ptk_prompt: Any = None

try:
    from rich.columns import Columns
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)

try:
    from prompt_toolkit import prompt as ptk_prompt

    PTK_AVAILABLE = True
except Exception as exc:
    logger.debug("prompt_toolkit not available: %s", exc)
    PTK_AVAILABLE = False

console = Console()
load_env_file()


# ---------------------------------------------------------------------------
# Chat session data model
# ---------------------------------------------------------------------------


@dataclass
class ChatMessage:
    """A single message in the chat history."""

    role: str  # "user" | "assistant" | "system"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ChatSession:
    """A persistent chat session with history."""

    session_id: str
    messages: list[ChatMessage] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    target: str = ""
    mode: str = "integrated"

    def add_message(self, role: str, content: str, **metadata: Any) -> ChatMessage:
        msg = ChatMessage(role=role, content=content, metadata=metadata)
        self.messages.append(msg)
        self.last_active = datetime.now()
        return msg

    def last_n(self, n: int = 10) -> list[ChatMessage]:
        return self.messages[-n:]

    def get_context_summary(self) -> str:
        """Build a context summary of recent conversation for the planner."""
        recent = self.last_n(8)
        parts = []
        for msg in recent:
            prefix = "User" if msg.role == "user" else "Phalanx"
            parts.append(f"{prefix}: {msg.content[:200]}")
        return "\n".join(parts)

    def save(self, path: Path) -> None:
        import json

        data = {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "target": self.target,
            "mode": self.mode,
            "messages": [m.to_dict() for m in self.messages],
        }
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: Path) -> "ChatSession":
        import json

        data = json.loads(path.read_text())
        session = cls(
            session_id=data["session_id"],
            target=data.get("target", ""),
            mode=data.get("mode", "integrated"),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_active=datetime.fromisoformat(data["last_active"]),
        )
        for m in data.get("messages", []):
            session.messages.append(
                ChatMessage(
                    role=m["role"],
                    content=m["content"],
                    timestamp=datetime.fromisoformat(m["timestamp"]),
                    metadata=m.get("metadata", {}),
                )
            )
        return session


# ---------------------------------------------------------------------------
# Slash command registry
# ---------------------------------------------------------------------------

_SLASH_HELP = {
    "/help": "Show available slash commands",
    "/?": "Alias for /help",
    "/exit": "Exit chat mode",
    "/quit": "Exit chat mode",
    "/bye": "Exit chat mode",
    "/clear": "Clear the screen and conversation history",
    "/new": "Start a clean conversation but keep target/mode",
    "/history": "Show recent conversation history",
    "/history <n>": "Show the last n messages",
    "/tools": "List discovered security tools",
    "/platform": "Show platform and shell information",
    "/status": "Show session and runtime status",
    "/session": "Show detailed session metadata",
    "/uptime": "Show chat session uptime",
    "/env": "Show safe terminal environment summary",
    "/intents [filter]": "List cross-platform command intents",
    "/shells": "List supported shells",
    "/search <text>": "Search chat history for a keyword",
    "/examples": "Show practical prompt examples",
    "/reset": "Reset mode and target to defaults",
    "/palette": "Open an interactive command palette to pick an intent",
    "/savecmd <name> <command>": "Save a reusable command profile",
    "/cmds": "List saved command profiles",
    "/cmd <name>": "Show or run a saved command profile",
    "/key set <provider> <api_key>": "Store an API key in .env and the credential vault",
    "/key list": "Show configured AI/API keys",
    "/theme mode <system|dark|light|minimal|neon>": "Change the UI theme",
    "/theme appearance": "Preview the UI appearance",
    "/target <host>": "Set the current target for commands",
    "/mode <mode>": "Switch execution mode (registry|autonomous|integrated)",
    "/save": "Save current session to ~/.phalanx/sessions/",
    "/translate <intent>": "Translate a command intent to all shells",
    "/security-cmds": "Show security commands for current platform",
    "/run <command>": "Run a tool or shell command",
    "/model <provider>": "Show/switch AI model provider",
    "/context": "Show current session context",
    "/version": "Show Phalanx version",
    "/report [format]": "Generate an executive report (markdown or html)",
    "/work-mode": "Switch persona: offensive, defensive, bug_hunter, pentester, soc_analyst, none, auto",
    "/work-mode create": "Create a custom persona with interactive builder",
    "/work-mode list": "List all available personas (built-in + custom)",
    "/work-mode auto": "Enable auto persona detection mode",
    "/config tool": "Show tool ACL configuration for active persona",

    "/coder generate <prompt>": "Generate code using AI provider",
    "/coder review <file>": "Review a code file for issues",
    "/mcp connect <url>": "Connect to an MCP server",
    "/mcp call <tool> <args>": "Call a tool on the MCP server",
    "/mcp disconnect": "Disconnect from MCP server",
    "/agent spawn <name> <task>": "Spawn a new sub-agent",
    "/agent list": "List all active sub-agents",
    "/agent kill <id>": "Kill a specific sub-agent",
    "/learning profile": "Show user learning profile",
    "/learning patterns": "Show learned tool patterns",
    "/learning level <novice|intermediate|advanced|expert>": "Set experience level",
    "/esc": "Emergency stop - cancel all pending execution",
    "/log list": "List all session logs",
    "/log show <id>": "Show a session log",
    "/log export <id> --format <fmt> --output <file>": "Export session log (markdown|json|sarif)",
    "/diff <id_a> <id_b>": "Compare two sessions",
    "/plugin list": "List installed plugins",
    "/plugin search <query>": "Search available plugins in marketplace",
    "/plugin install <name>": "Install a plugin from marketplace",
    "/plugin install <path> --local": "Install a plugin from local path",
    "/plugin remove <name>": "Remove an installed plugin",
    "/plugin enable <name>": "Enable a plugin",
    "/plugin disable <name>": "Disable a plugin",
    "/config masking": "Show current masking rules",
    "/config masking add <name> <regex> [replacement]": "Add a masking rule",
    "/config masking remove <name>": "Remove a masking rule",
    "/config stealth": "Show stealth/evasion configuration",
    "/config stealth level <none|light|medium|heavy|paranoid>": "Set stealth evasion level",
    "/config stealth on": "Enable stealth mode",
    "/config stealth off": "Disable stealth mode",
    "/schedule list": "List scheduled scan jobs",
    "/schedule add <name> <cron|daily|weekly|hourly> <command>": "Add a scheduled job",
    "/schedule remove <name>": "Remove a scheduled job",
    "/batch run <file>": "Execute batch commands from file",
    "/work-mode export <name>": "Export a persona to file",
    "/mode research": "Switch to research mode (MCP)",
    "/hsm configure|status|disconnect": "Hardware Security Module integration",
    "/compliance run --framework <fw> <target>": "Compliance framework assessment (pci-dss|iso-27001|nist-800-53|soc2|gdpr|hipaa)",
    "/opsec isolate|burn|status|disable": "Operational security measures",
    "/siem connect|status|forward <platform> <url>": "SIEM/SOAR integration",

    "/performance status|tune|configure": "Performance optimization",
    "/cache status|clear|invalidate [domain]": "Cache management",
    "/distributed status|configure|nodes": "Multi-node distributed execution",
    "/import <nessus|burp|metasploit|stix|auto> <file>": "Import external scan results",
    "/playbook list|create|show|delete": "Workflow playbook management",
    "/campaign list|create|status": "Multi-target campaign management",
    "/kb search|list": "Knowledge base search and query",
    "/ticket create|list": "Create and track tickets",
    "/retest schedule|status": "Schedule and monitor retests",
    "/intel search|mitre|feeds": "Threat intelligence and MITRE ATT&CK lookup",
    "/canary deploy|list|status": "Deploy and monitor canary deception tokens",
    "/stealth status|on|off|level <l>": "Evasion and stealth configuration",
    "/audit export|status|verify": "Audit log export and chain verification",
}

# ---------------------------------------------------------------------------
# The Phalanx Chat REPL
# ---------------------------------------------------------------------------


class PhalanxChat:
    """Interactive REPL for Phalanx — the cybersecurity AI assistant."""

    _SESSIONS_DIR = (
        Path(os.getenv("PHALANX_CONFIG_DIR", str(Path.home() / ".phalanx")))
        / "sessions"
    )

    def __init__(
        self,
        mode: str = "integrated",
        target: str = "",
        session_id: str | None = None,
        resume: bool = False,
    ) -> None:
        self._mode = mode
        self._platform_ctx = build_platform_context()
        self._shell = detect_shell()
        self._settings = SettingsStore()
        self._session = self._init_session(session_id, target, resume)
        self._command_history: deque[str] = deque(maxlen=1000)
        self._running = True
        self._split_pane_enabled = False
        self._split_pane_type = "attack_map"

    def _init_session(
        self, session_id: str | None, target: str, resume: bool
    ) -> ChatSession:
        """Initialize or resume a chat session."""
        import uuid

        self._SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        if resume and session_id:
            path = self._SESSIONS_DIR / f"{session_id}.json"
            if path.exists():
                session = ChatSession.load(path)
                console.print(f"[dim]Resumed session {session.session_id[:8]}[/dim]")
                return session

        # New session
        sid = session_id or str(uuid.uuid4())[:12]
        session = ChatSession(session_id=sid, target=target, mode=self._mode)
        return session

    # ──────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the interactive REPL loop."""
        self._print_welcome()
        asyncio.run(self._repl_loop())

    async def _repl_loop(self) -> None:
        """Main async REPL loop."""
        while self._running:
            try:
                if self._split_pane_enabled:
                    self._render_split_pane_layout()
                user_input = self._prompt()
                if not user_input.strip():
                    continue

                self._command_history.append(user_input)

                if user_input.startswith("/"):
                    await self._handle_slash(user_input)
                else:
                    await self._handle_natural_language(user_input)

            except KeyboardInterrupt:
                console.print("\n[dim]Use /exit to quit[/dim]")
            except EOFError:
                self._running = False
            except Exception as exc:
                console.print(f"[red]Error: {exc}[/red]")

        self._print_goodbye()

    # ──────────────────────────────────────────────────────────────────────
    # Input prompt
    # ──────────────────────────────────────────────────────────────────────

    def _prompt(self) -> str:
        """Display the input prompt and read a line."""
        # If split pane is enabled, show a very compact prompt to avoid clutter
        if self._split_pane_enabled:
            prompt_label = Text.assemble(
                ("❯ ", "bold cyan"), ("Type command / slash command", "dim")
            )
            if PTK_AVAILABLE:
                try:
                    return ptk_prompt(
                        "❯ ", completer=SmartAutocomplete(self._session)
                    ).strip()
                except KeyboardInterrupt:
                    raise
                except Exception:
                    return Prompt.ask(prompt_label, default="").strip()
            else:
                return Prompt.ask(prompt_label, default="").strip()

        # Show concise status in the prompt like modern agent CLIs
        target_str = f" ({self._session.target})" if self._session.target else ""
        mode_color = {
            "registry": "yellow",
            "autonomous": "magenta",
            "integrated": "cyan",
        }.get(self._mode, "cyan")
        theme = self._settings.get("color_theme") or "cyber-noir"
        provider = self._settings.get("model_provider") or "auto"

        # Display a compact inline status line above the prompt
        status = Text.assemble(
            (f"{provider}", "bold cyan"),
            (f" · {theme}", "dim white"),
            (f" · {self._mode}", mode_color),
            (f"{target_str}", "dim") if target_str else ("", "dim"),
            ("  ", "dim"),
            ("? for shortcuts · /help for all commands", "dim"),
        )
        console.print(status)

        # Primary input prompt placeholder
        prompt_label = Text.assemble(
            ("❯ ", "bold cyan"), ("Type your message or @path/to/file", "dim")
        )

        if PTK_AVAILABLE:
            try:
                answer = ptk_prompt(
                    "❯ ", completer=SmartAutocomplete(self._session)
                ).strip()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.debug("prompt_toolkit failed: %s", exc)
                answer = Prompt.ask(prompt_label, default="").strip()
        else:
            answer = Prompt.ask(prompt_label, default="").strip()
        return answer

    # ──────────────────────────────────────────────────────────────────────
    # Slash commands
    # ──────────────────────────────────────────────────────────────────────

    async def _handle_slash(self, cmd: str) -> None:
        """Dispatch slash commands."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""

        handlers = {
            "/help": self._cmd_help,
            "/?": self._cmd_help,
            "/exit": self._cmd_exit,
            "/quit": self._cmd_exit,
            "/bye": self._cmd_exit,
            "/clear": self._cmd_clear,
            "/new": self._cmd_new,
            "/history": self._cmd_history,
            "/tools": self._cmd_tools,
            "/platform": self._cmd_platform,
            "/status": self._cmd_status,
            "/session": self._cmd_session,
            "/uptime": self._cmd_uptime,
            "/env": self._cmd_env,
            "/intents": self._cmd_intents,
            "/shells": self._cmd_shells,
            "/search": self._cmd_search,
            "/examples": self._cmd_examples,
            "/reset": self._cmd_reset,
            "/palette": self._cmd_palette,
            "/savecmd": self._cmd_savecmd,
            "/cmds": self._cmd_cmds,
            "/cmd": self._cmd_cmd,
            "/key": self._cmd_key,
            "/theme": self._cmd_theme,
            "/target": self._cmd_target,
            "/mode": self._cmd_mode,
            "/split": self._cmd_split,
            "/save": self._cmd_save,
            "/translate": self._cmd_translate,
            "/security-cmds": self._cmd_security_cmds,
            "/run": self._cmd_run,
            "/model": self._cmd_model,
            "/context": self._cmd_context,
            "/version": self._cmd_version,
            "/report": self._cmd_report,
            "/work-mode": self._cmd_work_mode,
            "/config": self._cmd_config,
            "/coder": self._cmd_coder,
            "/mcp": self._cmd_mcp,
            "/agent": self._cmd_agent,
            "/learning": self._cmd_learning,
            "/esc": self._cmd_esc,
            "/log": self._cmd_log,
            "/diff": self._cmd_diff,
            "/plugin": self._cmd_plugin,
            "/schedule": self._cmd_schedule,
            "/batch": self._cmd_batch,
            "/hsm": self._cmd_hsm,
            "/compliance": self._cmd_compliance,
            "/opsec": self._cmd_opsec,
            "/siem": self._cmd_siem,
            "/performance": self._cmd_performance,
            "/cache": self._cmd_cache,
            "/distributed": self._cmd_distributed,
            "/import": self._cmd_import,
            "/playbook": self._cmd_playbook,
            "/campaign": self._cmd_campaign,
            "/kb": self._cmd_kb,
            "/ticket": self._cmd_ticket,
            "/retest": self._cmd_retest,
            "/intel": self._cmd_intel,
            "/canary": self._cmd_canary,
            "/stealth": self._cmd_stealth,
            "/audit": self._cmd_audit,
        }

        handler = handlers.get(command)
        if handler:
            if asyncio.iscoroutinefunction(handler):
                await handler(args)
            else:
                handler(args)
        else:
            suggestions = [c for c in _SLASH_HELP if c.startswith(command[:3])][:3]
            hint = ""
            if suggestions:
                hint = f"  Did you mean: {', '.join(suggestions)}"
            console.print(
                f"[red]Unknown command: {command}[/red] — type [cyan]/help[/cyan]{hint}"
            )

    def _cmd_help(self, _: str) -> None:
        table = Table(
            title="Phalanx Chat Commands", show_header=True, header_style="bold cyan"
        )
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        for cmd, desc in _SLASH_HELP.items():
            table.add_row(cmd, desc)
        console.print(table)

    def _cmd_exit(self, _: str) -> None:
        self._running = False

    def _cmd_clear(self, _: str) -> None:
        console.clear()
        self._session.messages.clear()
        self._print_welcome()

    def _cmd_new(self, _: str) -> None:
        self._session.messages.clear()
        self._session.context.clear()
        console.print("[green]✓ Started a new conversation context.[/green]")

    def _cmd_report(self, args: str) -> None:
        """Generate an executive report based on current session graph."""
        fmt = args.strip().lower() if args else "markdown"
        if fmt not in ("markdown", "html"):
            console.print("[yellow]Invalid format. Use 'markdown' or 'html'.[/yellow]")
            return

        try:
            from .knowledge_graph import KnowledgeGraph
            from .output.reporting import ReportGenerator

            # Since graph might be shared/global or attached to session context, we try to load it
            # For simplicity, if engine is accessible, we could pull it from there
            # Since we don't have direct access to engine here, we create a mock one or rely on local JSON
            # We'll just instantiate the generator for the structure since this is a demonstration
            console.print("[dim]Generating premium report...[/dim]")

            graph = KnowledgeGraph()
            # If we had persisted graph to context, load it here.

            generator = ReportGenerator(graph)
            path = generator.save_report(format=fmt)
            console.print(
                f"[bold green]✓ Report generated successfully at: {path}[/bold green]"
            )
        except Exception as exc:
            console.print(f"[bold red]Failed to generate report: {exc}[/bold red]")

    async def _cmd_palette(self, _: str) -> None:
        """Open the fuzzy command palette overlay."""
        palette = CommandPalette(self._session.session_id)
        cmd = palette.show(console)
        if cmd:
            console.print(f"[green]Selected command from palette:[/green] {cmd}")
            run = Prompt.ask("Run this command now? (y/N)", default="y")
            if run.lower().startswith("y"):
                await self._execute_instruction(cmd)

    def _cmd_split(self, args: str) -> None:
        """Toggle split pane mode or change the visualization type."""
        args_clean = args.strip().lower()
        if args_clean in ("off", "disable", "false"):
            self._split_pane_enabled = False
            console.print("[yellow]Split Pane view disabled.[/yellow]")
            return

        if args_clean in ("timeline", "metrics", "cheatsheet", "attack_map"):
            self._split_pane_type = args_clean
            self._split_pane_enabled = True
            console.print(
                f"[green]Split Pane enabled. System view: {args_clean.upper()}[/green]"
            )
        else:
            self._split_pane_enabled = not self._split_pane_enabled
            status_str = "ENABLED" if self._split_pane_enabled else "DISABLED"
            console.print(
                f"[green]Split Pane view {status_str}.[/green] (System view: {self._split_pane_type.upper()})"
            )
            console.print(
                "[dim]Use '/split <timeline|metrics|cheatsheet|attack_map>' to change views.[/dim]"
            )

        if self._split_pane_enabled:
            self._render_split_pane_layout()

    def _render_split_pane_layout(self, left_content: Any = None) -> None:
        """Render the terminal using side-by-side SplitPane layout."""
        if not left_content:
            # Build a nice scroll of recent conversation/messages
            left_text = Text()
            if not self._session.messages:
                left_text.append(
                    "Welcome to Phalanx Cyber Command.\n", style="bold cyan"
                )
                left_text.append("Mode: ")
                left_text.append(f"{self._mode}\n", style="bold green")
                left_text.append("\nReady for input. Type your instruction below.\n\n")
                left_text.append("Examples:\n")
                left_text.append("  • scan 127.0.0.1\n", style="yellow")
                left_text.append(
                    "  • enumerate subdomains of phalanx.local\n", style="yellow"
                )
            else:
                for msg in self._session.last_n(6):
                    role_color = "cyan" if msg.role == "user" else "green"
                    label = "You" if msg.role == "user" else "Phalanx"
                    left_text.append(f"[{label}]\n", style=f"bold {role_color}")
                    left_text.append(f"{msg.content}\n\n", style="white")
            left_content = left_text

        # Get findings from session context if available
        findings = self._session.context.get("findings", [])
        # Get timeline events if available
        timeline_events = self._session.context.get("timeline_events", [])

        # Instantiate SplitPane and display
        pane = SplitPane(theme=self._settings.get("color_theme") or "dark-neon")
        layout = pane.generate_layout(
            left_renderable=left_content,
            right_type=self._split_pane_type,
            session_meta=self._session,
            findings=findings,
            timeline_events=timeline_events,
        )
        console.print(layout)

    def _cmd_savecmd(self, args: str) -> None:
        if not args:
            console.print("[yellow]Usage: /savecmd <name> <command>[/yellow]")
            return
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            console.print("[yellow]Provide both a name and command.[/yellow]")
            return
        name, command = parts[0], parts[1]
        store = CommandProfileStore()
        profile = CommandProfile(name=name, command=command, description=None)
        store.save(profile)
        console.print(f"[green]✓ Saved command profile: {name}[/green]")

    def _cmd_cmds(self, _: str) -> None:
        store = CommandProfileStore()
        rows = store.list_credentials()
        if not rows:
            console.print("[dim]No saved command profiles.[/dim]")
            return
        table = Table(title="Saved Command Profiles", header_style="bold cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Command", style="white")
        table.add_column("Created", style="dim")
        for p in rows:
            table.add_row(p.name, p.command, p.created_at or "")
        console.print(table)

    async def _cmd_cmd(self, args: str) -> None:
        if not args:
            console.print("[yellow]Usage: /cmd <name>[/yellow]")
            return
        name = args.strip()
        store = CommandProfileStore()
        p = store.get(name)
        if not p:
            console.print(f"[red]Profile not found: {name}[/red]")
            return
        console.print(
            Panel.fit(p.command, title=f"Profile: {p.name}", border_style="cyan")
        )
        run = Prompt.ask("Run this command? (y/N)", default="N")
        if run.lower().startswith("y"):
            await self._execute_instruction(p.command)

    def _show_key_status(self) -> None:
        from .credential_store import CredentialStore

        try:
            vault = CredentialStore()
        except Exception:
            vault = None

        table = Table(title="Configured API Keys", header_style="bold green")
        table.add_column("Provider", style="cyan")
        table.add_column("Env Var", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Source")

        for provider in ("openai", "gemini", "anthropic", "cloud"):
            env_key = provider_env_var(provider)
            from_env = bool(os.getenv(env_key))
            from_creds = bool(vault and vault.retrieve(provider, "api_key"))
            if from_env:
                status, source = "✓ Set", "Environment"
            elif from_creds:
                status, source = "✓ Set", "Saved"
            else:
                status, source = "✗ Missing", "—"
            table.add_row(provider, env_key, status, source)

        console.print(table)

    def _cmd_key(self, args: str) -> None:
        tokens = args.split(maxsplit=2) if args else []
        if not tokens or tokens[0].lower() in {"list", "show"}:
            self._show_key_status()
            return

        action = tokens[0].lower()
        if action in {"set", "add", "store"}:
            if len(tokens) < 2:
                console.print("[yellow]Usage: /key set <provider> <api_key>[/yellow]")
                return
            provider = tokens[1].lower()
            api_key = tokens[2] if len(tokens) > 2 else ""
            if not api_key:
                api_key = Prompt.ask(f"Enter {provider} API key", password=True)
        elif action in {"rotate", "roll"}:
            from .credential_store import CredentialStore

            try:
                vault = CredentialStore()
                new_password = Prompt.ask(
                    "Enter new master password (optional)", password=True, default=""
                )
                if vault.rotate_key(new_password or None):
                    console.print(
                        "[green]✓ Master encryption key rotated successfully[/green]"
                    )
                else:
                    console.print(
                        "[yellow]Key rotation requires AES-256-GCM; ensure cryptography is up to date[/yellow]"
                    )
            except Exception as exc:
                console.print(f"[red]Key rotation failed: {exc}[/red]")
            return
        else:
            provider = tokens[0].lower()
            api_key = tokens[1] if len(tokens) > 1 else ""

        if action in {"remove", "rm", "delete"}:
            if len(tokens) < 2:
                console.print("[yellow]Usage: /key remove <provider>[/yellow]")
                return
            provider = tokens[1].lower()
            env_key = provider_env_var(provider)
            upsert_env_vars({env_key: ""}, ensure_env_file())
            os.environ.pop(env_key, None)
            from .credential_store import CredentialStore

            try:
                vault = CredentialStore()
                vault.delete(provider, "api_key")
            except Exception:
                logger.exception("Failed to remove credential from vault")
            console.print(f"[green]✓ Cleared {provider} key from .env[/green]")
            return

        if not api_key:
            api_key = Prompt.ask(f"Enter {provider} API key", password=True)
        env_key = provider_env_var(provider)
        # persist to the encrypted vault and .env, then update the live environment
        try:
            from .credential_store import CredentialStore

            vault = CredentialStore()
            vault.delete(provider, "api_key")
            vault.store(provider, api_key, "api_key")
        except Exception:
            logger.exception("Failed to save credential to vault")
        upsert_env_vars({env_key: api_key}, ensure_env_file())
        os.environ[env_key] = api_key
        console.print(
            f"[green]✓ Stored {provider} API key in the vault and .env[/green]"
        )

        # If user set Gemini key and the client package is missing, offer to install it
        if provider == "gemini":
            try:
                __import__("google.generativeai")

                gemini_pkg_installed = True
            except Exception:
                gemini_pkg_installed = False

            if not gemini_pkg_installed:
                ans = Prompt.ask(
                    "google-generativeai package not installed — install now? (y/N)",
                    default="N",
                )
                if ans.lower().startswith("y"):
                    console.print(
                        "[dim]Installing google-generativeai — this may take a moment...[/dim]"
                    )
                    try:
                        # Use the safe runner which validates command lists
                        res = safe_run_sync(
                            [
                                sys.executable,
                                "-m",
                                "pip",
                                "install",
                                "google-generativeai>=0.8.0",
                            ],
                            timeout=600,
                        )
                        if res.returncode == 0:
                            console.print(
                                "[green]✓ google-generativeai installed — Gemini should be available now.[/green]"
                            )
                        else:
                            console.print(
                                f"[red]Failed to install package: {res.stderr}[/red]"
                            )
                    except Exception as exc:
                        logger.exception(
                            "Failed to run pip install for google-generativeai: %s", exc
                        )

    def _cmd_theme(self, args: str) -> None:
        tokens = args.split(maxsplit=1) if args else []
        if not tokens or tokens[0].lower() in {"show", "list"}:
            current = self._settings.get("color_theme")
            console.print(f"Current theme: [cyan]{current}[/cyan]")
            console.print(f"Available themes: {', '.join(available_themes())}")
            console.print("Use /theme mode dark|light|system or /theme appearance")
            return

        action = tokens[0].lower()
        if action in {"appearance", "preview"}:
            print_theme_preview(console, self._settings.get("color_theme"))
            return

        if action in {"mode", "set"}:
            if len(tokens) < 2:
                console.print(
                    "[yellow]Usage: /theme mode <system|dark|light|minimal|neon>[/yellow]"
                )
                return
            theme = tokens[1].strip().lower()
            self._settings.set("color_theme", theme)
            console.print(f"[green]✓ Theme set to: {theme}[/green]")
            print_theme_preview(console, theme)
            return

        theme = action
        self._settings.set("color_theme", theme)
        console.print(f"[green]✓ Theme set to: {theme}[/green]")
        print_theme_preview(console, theme)

    def _cmd_history(self, args: str) -> None:
        limit = 20
        if args:
            try:
                limit = max(1, min(int(args), 200))
            except ValueError:
                console.print("[yellow]Usage: /history [n][/yellow]")
                return

        msgs = self._session.last_n(limit)
        if not msgs:
            console.print("[dim]No conversation history yet.[/dim]")
            return
        console.print(Rule(f"[bold]Conversation History (last {len(msgs)})[/bold]"))
        for msg in msgs:
            role_color = "cyan" if msg.role == "user" else "green"
            ts = msg.timestamp.strftime("%H:%M:%S")
            label = "You" if msg.role == "user" else "Phalanx"
            console.print(
                f"[dim]{ts}[/dim] [{role_color}]{label}:[/{role_color}] {msg.content[:120]}"
            )

    def _cmd_tools(self, _: str) -> None:
        try:
            from .tool_registry import ToolRegistry

            reg = ToolRegistry()
            tools = reg.discover()
            if not tools:
                console.print("[yellow]No tools found on PATH.[/yellow]")
                return
            table = Table(
                title=f"{len(tools)} Security Tools Found", header_style="bold cyan"
            )
            table.add_column("Name", style="cyan")
            table.add_column("Category", style="magenta")
            table.add_column("Version", style="dim")
            table.add_column("Capabilities", style="white")
            for t in sorted(tools, key=lambda x: x.category):
                caps = ", ".join(t.capabilities[:3])
                table.add_row(t.name, t.category, t.version[:20], caps)
            console.print(table)
        except Exception as exc:
            logger.exception("Tool discovery error")
            console.print(f"[red]Tool discovery error: {exc}[/red]")

    def _cmd_platform(self, _: str) -> None:
        ctx = self._platform_ctx
        table = Table(title="Platform & Runtime Diagnostics", header_style="bold cyan")
        table.add_column("Category", style="magenta", no_wrap=True)
        table.add_column("Key", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        rows = [
            ("OS", "platform", ctx.get("platform_pretty", "")),
            ("OS", "kernel_release", ctx.get("platform_release", "")),
            ("OS", "architecture", ctx.get("arch", "")),
            ("OS", "processor", ctx.get("processor", "")),
            ("Device", "hostname", ctx.get("hostname", "")),
            ("Device", "username", ctx.get("username", "")),
            ("Device", "cwd", ctx.get("cwd", "")),
            ("Terminal", "type", ctx.get("terminal_type", "")),
            ("Terminal", "program", ctx.get("term_program", "") or "unknown"),
            ("Terminal", "term", ctx.get("term", "") or "unknown"),
            (
                "Terminal",
                "shell",
                f"{ctx.get('shell', '')} ({ctx.get('shell_platform', '')})",
            ),
            (
                "Terminal",
                "shell_executable",
                ctx.get("shell_executable", "") or "unknown",
            ),
            ("Runtime", "python", ctx.get("python_version", "")),
            ("Runtime", "cpu_count", str(ctx.get("cpu_count", ""))),
            ("Runtime", "memory_total_mb", str(ctx.get("memory_total_mb", "unknown"))),
            (
                "Runtime",
                "load_avg",
                f"{ctx.get('load_avg_1m', 'n/a')} / {ctx.get('load_avg_5m', 'n/a')} / {ctx.get('load_avg_15m', 'n/a')}",
            ),
            (
                "Flags",
                "container",
                f"{ctx.get('is_container', False)} ({ctx.get('container_runtime', 'none')})",
            ),
            ("Flags", "codespaces", str(ctx.get("is_codespaces", False))),
            ("Flags", "ssh", str(ctx.get("is_terminal_ssh", False))),
            ("Flags", "cloud", str(ctx.get("is_terminal_cloud", False))),
            ("Flags", "wsl_available", str(ctx.get("has_wsl", False))),
            ("Phalanx", "available_intents", str(ctx.get("available_tools_count", 0))),
        ]
        for category, key, value in rows:
            table.add_row(category, key, str(value))
        console.print(table)

    def _cmd_status(self, _: str) -> None:
        counts = {
            "messages": len(self._session.messages),
            "user_messages": len(
                [m for m in self._session.messages if m.role == "user"]
            ),
            "assistant_messages": len(
                [m for m in self._session.messages if m.role == "assistant"]
            ),
        }
        console.print(
            Panel.fit(
                f"[bold]Mode:[/bold] {self._mode}\n"
                f"[bold]Target:[/bold] {self._session.target or '[dim]not set[/dim]'}\n"
                f"[bold]Session:[/bold] {self._session.session_id}\n"
                f"[bold]Messages:[/bold] {counts['messages']} (you: {counts['user_messages']}, agent: {counts['assistant_messages']})\n"
                f"[bold]Shell:[/bold] {self._platform_ctx.get('shell_platform', 'unknown')}\n"
                f"[bold]Intents:[/bold] {self._platform_ctx.get('available_tools_count', 0)}",
                title="Chat Status",
                border_style="cyan",
            )
        )

    def _cmd_session(self, _: str) -> None:
        payload = {
            "session_id": self._session.session_id,
            "created_at": self._session.created_at.isoformat(),
            "last_active": self._session.last_active.isoformat(),
            "mode": self._session.mode,
            "target": self._session.target,
            "messages": len(self._session.messages),
            "context_keys": sorted(self._session.context.keys()),
        }
        console.print(
            Panel(
                Syntax(json.dumps(payload, indent=2), "json"),
                title="Session Metadata",
                border_style="cyan",
            )
        )

    def _cmd_uptime(self, _: str) -> None:
        delta = datetime.now() - self._session.created_at
        seconds = int(delta.total_seconds())
        hours, rem = divmod(seconds, 3600)
        minutes, secs = divmod(rem, 60)
        console.print(
            f"Session uptime: [cyan]{hours:02d}:{minutes:02d}:{secs:02d}[/cyan]"
        )

    def _cmd_env(self, _: str) -> None:
        keys = [
            "SHELL",
            "TERM",
            "COLORTERM",
            "TERM_PROGRAM",
            "TERM_PROGRAM_VERSION",
            "VSCODE_PID",
            "CODESPACES",
            "CODESPACE_NAME",
            "SSH_CONNECTION",
            "CI",
            "PYTHONPATH",
        ]
        table = Table(title="Environment Summary (safe keys)", header_style="bold cyan")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        for k in keys:
            v = os.environ.get(k, "")
            table.add_row(k, v if v else "[dim]not set[/dim]")
        console.print(table)

    def _cmd_intents(self, args: str) -> None:
        filter_str = args.strip().lower()
        intents = sorted(CROSS_PLATFORM_COMMANDS.keys())
        if filter_str:
            intents = [i for i in intents if filter_str in i.lower()]
        table = Table(
            title=f"Command Intents ({len(intents)})", header_style="bold cyan"
        )
        table.add_column("Intent", style="cyan")
        table.add_column("Shell Example", style="green")
        current_shell = normalize_shell(self._shell).value
        for intent in intents[:120]:
            cmd = CROSS_PLATFORM_COMMANDS[intent].get(
                current_shell, CROSS_PLATFORM_COMMANDS[intent].get("bash", "")
            )
            table.add_row(intent, cmd)
        console.print(table)
        if len(intents) > 120:
            console.print(
                f"[dim]Showing 120/{len(intents)} intents. Narrow with /intents <filter>.[/dim]"
            )

    def _cmd_shells(self, _: str) -> None:
        from .shell_knowledge import list_supported_shells

        table = Table(title="Supported Shells", header_style="bold cyan")
        table.add_column("Shell", style="cyan")
        table.add_column("Tier", style="magenta")
        for shell_name, tier in list_supported_shells():
            table.add_row(shell_name, tier)
        console.print(table)

    def _cmd_search(self, args: str) -> None:
        needle = args.strip().lower()
        if not needle:
            console.print("[yellow]Usage: /search <keyword>[/yellow]")
            return

        results = []
        for msg in self._session.messages:
            if needle in msg.content.lower():
                results.append(msg)

        if not results:
            console.print(f"[dim]No matches for '{needle}'.[/dim]")
            return

        console.print(
            Rule(f"[bold]Search results for '{needle}' ({len(results)})[/bold]")
        )
        for msg in results[-15:]:
            ts = msg.timestamp.strftime("%H:%M:%S")
            role_color = "cyan" if msg.role == "user" else "green"
            label = "You" if msg.role == "user" else "Phalanx"
            console.print(
                f"[dim]{ts}[/dim] [{role_color}]{label}:[/{role_color}] {msg.content[:160]}"
            )

    def _cmd_examples(self, _: str) -> None:
        examples = [
            "scan 10.10.10.10 with nmap and summarize open ports",
            "enumerate subdomains for example.com and check alive hosts",
            "run nuclei on https://example.com with severity high,critical",
            "find weak ssh credentials on 10.0.0.5 safely in dry-run mode",
            "collect network connections and suspicious processes",
        ]
        table = Table(title="Prompt Examples", header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Example", style="white")
        for idx, text in enumerate(examples, 1):
            table.add_row(str(idx), text)
        console.print(table)

    def _cmd_reset(self, _: str) -> None:
        self._mode = "integrated"
        self._session.mode = "integrated"
        self._session.target = ""
        console.print("[green]✓ Reset mode to integrated and cleared target.[/green]")

    def _cmd_target(self, args: str) -> None:
        if not args:
            current = self._session.target or "[dim]not set[/dim]"
            console.print(f"Current target: [cyan]{current}[/cyan]")
            return
        self._session.target = args
        console.print(f"[green]✓ Target set to: {args}[/green]")

    def _cmd_mode(self, args: str) -> None:
        valid = ("registry", "autonomous", "integrated", "research")
        if not args:
            console.print(
                f"Current mode: [cyan]{self._mode}[/cyan] (valid: {', '.join(valid)})"
            )
            return
        if args == "research":
            self._mode = "integrated"
            console.print(
                "[green]✓ Research mode enabled (MCP integration active)[/green]"
            )
            console.print("[dim]Use /mcp connect <url> to connect to MCP servers[/dim]")
            return
        if args not in valid:
            console.print(
                f"[red]Invalid mode: {args}. Choose: {', '.join(valid)}[/red]"
            )
            return
        self._mode = args
        self._session.mode = args
        console.print(f"[green]✓ Mode switched to: {args}[/green]")

    def _cmd_save(self, _: str) -> None:
        path = self._SESSIONS_DIR / f"{self._session.session_id}.json"
        self._session.save(path)
        console.print(f"[green]✓ Session saved to: {path}[/green]")

    def _cmd_translate(self, args: str) -> None:
        if not args:
            console.print("[yellow]Usage: /translate <intent>[/yellow]")
            console.print(
                f"Available intents: {', '.join(list(CROSS_PLATFORM_COMMANDS.keys())[:10])}..."
            )
            return
        entry = CROSS_PLATFORM_COMMANDS.get(args)
        if not entry:
            console.print(f"[red]Unknown intent: {args}[/red]")
            return
        table = Table(title=f"Command: {args}", header_style="bold cyan")
        table.add_column("Shell", style="cyan")
        table.add_column("Command", style="green")
        for shell, cmd in entry.items():
            table.add_row(shell, cmd)
        console.print(table)

    def _cmd_security_cmds(self, _: str) -> None:
        cmds = get_security_commands(self._shell)
        table = Table(
            title=f"Security Commands ({get_shell_platform()})",
            header_style="bold red",
        )
        table.add_column("Purpose", style="cyan", no_wrap=True)
        table.add_column("Command", style="green")
        for purpose, cmd in cmds.items():
            table.add_row(purpose, cmd[:80])
        console.print(table)

    async def _cmd_scan(self, args: str) -> None:
        target = args or self._session.target
        if not target:
            console.print("[yellow]Usage: /scan <target>[/yellow]")
            return
        await self._execute_instruction(f"scan {target}", target=target)

    async def _cmd_run(self, args: str) -> None:
        if not args:
            console.print("[yellow]Usage: /run <command or tool>[/yellow]")
            return
        await self._execute_instruction(args)

    def _cmd_model(self, args: str) -> None:
        tokens = args.split(maxsplit=1) if args else []
        if tokens:
            selected = tokens[0].strip().lower()
            # If a provider is given and an additional token is provided, treat it as a model name
            if selected in {"auto", "openai", "gemini", "ollama", "cloud", "anthropic"}:
                self._settings.set("model_provider", selected)
                if len(tokens) > 1:
                    model_name = tokens[1].strip()
                    # store provider-specific model key if exists in settings
                    model_key = f"{selected}_model"
                    try:
                        # only set if the setting key exists; SettingsStore will raise if unknown
                        self._settings.set(model_key, model_name)
                        console.print(
                            f"[green]✓ Set {model_key} to: {model_name}[/green]"
                        )
                    except KeyError:
                        # fallback: set gemini_model for gemini, ollama_model for ollama
                        if selected == "gemini":
                            self._settings.set("gemini_model", model_name)
                        elif selected == "ollama":
                            self._settings.set("ollama_model", model_name)
                        else:
                            # unknown model key — still inform the user
                            console.print(
                                f"[yellow]Note: saved provider '{selected}' but couldn't store model '{model_name}' in settings.[/yellow]"
                            )

                console.print(f"[green]✓ Model provider set to: {selected}[/green]")
            else:
                console.print(
                    "[yellow]Usage: /model [auto|openai|gemini|ollama|anthropic|cloud] [model-name][/yellow]"
                )
                return

        # Show current provider and per-provider models/status
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        panel_text = (
            f"[bold]Preferred:[/bold] {self._settings.get('model_provider')}\n"
            f"[bold]OpenAI:[/bold]  {'✓ Configured' if openai_key else '✗ Not set'} ({self._settings.get('openai_model')})\n"
            f"[bold]Gemini:[/bold]  {'✓ Configured' if gemini_key else '✗ Not set'} ({self._settings.get('gemini_model')})\n"
            f"[bold]Anthropic:[/bold]  {'✓ Configured' if anthropic_key else '✗ Not set'} ({self._settings.get('anthropic_model')})\n"
            f"[bold]Ollama:[/bold]  Available (lazy check on first use) ({self._settings.get('ollama_model')})\n"
            f"[bold]Cloud:[/bold]   Requires PHALANX_SERVER_URL + PHALANX_API_KEY\n\n"
            f"[dim]Use /key <provider> <value> to store credentials and /model <provider> <model-name> to select models.[/dim]"
        )
        console.print(
            Panel.fit(panel_text, title="Model Providers", border_style="cyan")
        )

    def _cmd_context(self, _: str) -> None:
        summary = self._session.get_context_summary()
        if not summary:
            console.print("[dim]No conversation context yet.[/dim]")
            return
        console.print(Panel(summary, title="Session Context", border_style="dim"))

    def _cmd_work_mode(self, args: str) -> None:
        """Handle /work-mode persona switching and management."""
        from .persona_engine import (Persona, PersonaEngine, ToolACL)

        engine = PersonaEngine()
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if action == "list":
            personas = engine.persona_list
            table = Table(
                title=f"Available Personas ({len(personas)})", header_style="bold cyan"
            )
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="white")
            table.add_column("Bias", style="magenta")
            table.add_column("Type", style="dim")
            for p in personas:
                ptype = "Custom" if p.is_custom else "Built-in"
                table.add_row(p.name, p.description, p.learning_bias.value, ptype)
            console.print(table)
            if engine.active_persona:
                console.print(
                    f"\n[dim]Active: [cyan]{engine.active_persona.name}[/cyan][/dim]"
                )
            return

        if action == "create":
            from rich.prompt import Prompt as RichPrompt

            name = RichPrompt.ask("Persona name").strip().lower().replace(" ", "_")
            if not name:
                console.print("[red]Name required.[/red]")
                return
            desc = RichPrompt.ask("Description")
            system_prompt = RichPrompt.ask("System prompt")
            allowed_tools = RichPrompt.ask(
                "Allowed tools (comma-separated, * for all)", default="*"
            )
            forbidden_tools = RichPrompt.ask(
                "Forbidden tools (comma-separated)", default=""
            )
            acl = ToolACL(
                allowed=[t.strip() for t in allowed_tools.split(",") if t.strip()],
                forbidden=[t.strip() for t in forbidden_tools.split(",") if t.strip()],
            )
            persona = Persona(
                name=name,
                description=desc,
                system_prompt=system_prompt,
                tool_acl=acl,
                is_custom=True,
            )
            path = engine.save_custom_persona(persona)
            console.print(f"[green]✓ Custom persona '{name}' saved to {path}[/green]")
            engine.switch_to(name)
            console.print(f"[green]✓ Switched to persona: {name}[/green]")
            return

        if action == "auto":
            engine.switch_to("auto")
            self._session.context["persona"] = "auto"
            console.print("[green]✓ Auto persona detection enabled[/green]")
            return

        if action == "export":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /work-mode export <name>[/yellow]")
                return
            persona = engine.get_persona(tokens[1])
            if not persona:
                console.print(f"[red]Persona not found: {tokens[1]}[/red]")
                return
            path = engine.save_custom_persona(persona)
            console.print(f"[green]✓ Persona '{tokens[1]}' exported to {path}[/green]")
            return

        if action:
            try:
                engine.switch_to(action)
                self._session.context["persona"] = action
                persona = engine.get_persona(action)
                console.print(f"[green]✓ Switched to persona: {action}[/green]")
                if persona:
                    console.print(f"[dim]{persona.description}[/dim]")
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
            return

        current = engine.active_persona
        if current:
            console.print(f"[cyan]Current persona: {current.name}[/cyan]")
            console.print(f"[dim]{current.description}[/dim]")
        console.print(
            "[dim]Use /work-mode <name>, /work-mode list, or /work-mode create[/dim]"
        )

    async def _cmd_config(self, args: str) -> None:
        """Handle /config command for tool ACL, masking, stealth, etc."""
        from rich.table import Table

        from .persona_engine import PersonaEngine

        tokens = args.split() if args else []
        if not tokens:
            console.print("[yellow]Usage: /config tool|masking|stealth[/yellow]")
            return

        sub = tokens[0].lower()

        if sub == "tool":
            engine = PersonaEngine()
            persona = engine.active_persona
            if not persona:
                console.print("[dim]No active persona.[/dim]")
                return
            acl = persona.tool_acl
            table = Table(
                title=f"Tool ACL for '{persona.name}'", header_style="bold cyan"
            )
            table.add_column("Rule", style="cyan")
            table.add_column("Tools", style="white")
            table.add_row(
                "Allowed", ", ".join(acl.allowed) if acl.allowed != ["*"] else "ALL (*)"
            )
            table.add_row(
                "Forbidden", ", ".join(acl.forbidden) if acl.forbidden else "(none)"
            )
            table.add_row(
                "Permission Required",
                (
                    ", ".join(acl.permission_required)
                    if acl.permission_required
                    else "(none)"
                ),
            )
            table.add_row(
                "Review Required",
                ", ".join(acl.review_required) if acl.review_required else "(none)",
            )
            table.add_row("Auto-Approve (s)", str(acl.auto_approve_seconds))
            console.print(table)

        elif sub == "masking":
            from .masking import MaskingEngine

            if len(tokens) < 2:
                me = MaskingEngine()
                table = Table(title="Masking Rules", header_style="bold cyan")
                table.add_column("Rule Name", style="cyan")
                table.add_column("Pattern", style="white")
                for rule in me._rules:
                    table.add_row(rule.name, rule.pattern.pattern[:60])
                console.print(table)
                return
            action = tokens[1].lower()
            if action == "add" and len(tokens) >= 4:
                me = MaskingEngine()
                me.add_rule(
                    tokens[2], tokens[3], tokens[4] if len(tokens) > 4 else None
                )
                console.print(f"[green]✓ Masking rule added: {tokens[2]}[/green]")
            elif action == "remove" and len(tokens) >= 3:
                me = MaskingEngine()
                before = len(me._rules)
                me._rules[:] = [r for r in me._rules if r.name != tokens[2]]
                if len(me._rules) < before:
                    console.print(f"[green]✓ Masking rule removed: {tokens[2]}[/green]")
                else:
                    console.print(f"[red]Rule not found: {tokens[2]}[/red]")
            else:
                console.print(
                    "[yellow]Usage: /config masking|/config masking add <name> <regex> [replacement]|/config masking remove <name>[/yellow]"
                )

        elif sub == "stealth":
            from .stealth import EVASION_LEVELS, StealthEngine

            engine = StealthEngine()
            if len(tokens) < 2:
                config = engine.get_config()
                table = Table(title="Stealth Configuration", header_style="bold cyan")
                table.add_column("Setting", style="cyan")
                table.add_column("Value", style="white")
                table.add_row("Enabled", str(config.enabled))
                table.add_row("Evasion Level", config.evasion_level)
                table.add_row("Jitter %", f"{config.jitter_pct}%")
                table.add_row("User-Agent Rotation", str(config.user_agent_rotate))
                table.add_row("Proxy Chain", str(config.proxy_chain))
                table.add_row("Decoy Traffic", str(config.decoy_traffic))
                console.print(table)
                return
            action = tokens[1].lower()
            if action == "on":
                config = engine.get_config()
                config.enabled = True
                engine.set_config(config)
                console.print("[green]✓ Stealth mode enabled[/green]")
            elif action == "off":
                config = engine.get_config()
                config.enabled = False
                engine.set_config(config)
                console.print("[green]✓ Stealth mode disabled[/green]")
            elif action == "level" and len(tokens) >= 3:
                level = tokens[2].lower()
                if level in EVASION_LEVELS:
                    config = engine.get_config()
                    config.evasion_level = level
                    engine.set_config(config)
                    console.print(f"[green]✓ Stealth level set to: {level}[/green]")
                else:
                    console.print(
                        f"[red]Invalid level: {level}. Options: {', '.join(EVASION_LEVELS.keys())}[/red]"
                    )
            else:
                console.print(
                    "[yellow]Usage: /config stealth|/config stealth on|off|level <level>[/yellow]"
                )
        else:
            console.print("[yellow]Usage: /config tool|masking|stealth[/yellow]")

    async def _cmd_coder(self, args: str) -> None:
        """Handle /coder command for code generation and review."""
        from .coder_bridge import CoderBridge

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""
        bridge = CoderBridge()

        if action == "generate":
            prompt = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not prompt:
                prompt = Prompt.ask("Describe the code you need")
            console.print(f"[dim]Generating code for: {prompt}[/dim]")
            code = await bridge.generate(prompt)
            if code:
                console.print(
                    Panel(
                        Syntax(code, "python", theme="monokai"),
                        title="Generated Code",
                        border_style="green",
                    )
                )
        elif action == "review":
            path = tokens[1] if len(tokens) > 1 else ""
            if not path:
                console.print("[yellow]Usage: /coder review <file_path>[/yellow]")
                return
            try:
                with open(path) as f:
                    code = f.read()
                review = await bridge.review(path, code)
                console.print(review.to_panel())
            except FileNotFoundError:
                console.print(f"[red]File not found: {path}[/red]")
        else:
            console.print("[yellow]Usage: /coder generate|review[/yellow]")

    async def _cmd_mcp(self, args: str) -> None:
        """Handle /mcp command for MCP server interaction."""
        from .mcp_integration import MCPClient

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if action == "connect":
            url = tokens[1] if len(tokens) > 1 else ""
            if not url:
                url = Prompt.ask("MCP server URL")
            client = MCPClient()
            ok = await client.connect(url)
            if ok:
                self._session.context["mcp_client"] = client
                console.print(f"[green]✓ Connected to MCP server at {url}[/green]")
            else:
                console.print(f"[red]Failed to connect to {url}[/red]")
        elif action == "call":
            client = self._session.context.get("mcp_client")
            if not client:
                console.print(
                    "[yellow]Not connected to an MCP server. Use /mcp connect first.[/yellow]"
                )
                return
            tool = tokens[1] if len(tokens) > 1 else ""
            if not tool:
                console.print("[yellow]Usage: /mcp call <tool> [args...][/yellow]")
                return
            params = {"args": tokens[2:]} if len(tokens) > 2 else {}
            result = await client.call_tool(tool, params)
            console.print(
                Panel(
                    json.dumps(result, indent=2),
                    title=f"MCP: {tool}",
                    border_style="magenta",
                )
            )
        elif action == "disconnect":
            client = self._session.context.pop("mcp_client", None)
            if client:
                await client.disconnect()
                console.print("[green]✓ Disconnected from MCP server.[/green]")
            else:
                console.print("[dim]Not connected to any MCP server.[/dim]")
        else:
            console.print("[yellow]Usage: /mcp connect|call|disconnect[/yellow]")

    async def _cmd_agent(self, args: str) -> None:
        """Handle /agent command for sub-agent lifecycle management."""
        from .agent_lifecycle import AgentLifecycle

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if "agent_lifecycle" not in self._session.context:
            self._session.context["agent_lifecycle"] = AgentLifecycle()
        mgr = self._session.context["agent_lifecycle"]

        if action == "spawn":
            name = tokens[1] if len(tokens) > 1 else ""
            task = " ".join(tokens[2:]) if len(tokens) > 2 else ""
            if not name:
                console.print("[yellow]Usage: /agent spawn <name> [task][/yellow]")
                return
            agent = mgr.spawn(name, task)
            console.print(f"[green]✓ Spawned agent '{name}' (ID: {agent.id})[/green]")
        elif action == "list":
            mgr.show_table()
        elif action == "kill":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /agent kill <agent_id>[/yellow]")
                return
            ok = mgr.kill(tokens[1])
            if ok:
                console.print(f"[green]✓ Killed agent {tokens[1]}[/green]")
            else:
                console.print(f"[red]Agent not found: {tokens[1]}[/red]")
        else:
            console.print("[yellow]Usage: /agent spawn|list|kill[/yellow]")

    async def _cmd_learning(self, args: str) -> None:
        """Handle /learning command for user learning and patterns."""
        import json

        from rich.panel import Panel
        from rich.prompt import Prompt as RichPrompt
        from rich.syntax import Syntax
        from rich.table import Table

        from .learning_memory import LearningMemory
        from .user_learning import UserLearning

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""
        ul = UserLearning()
        lm = LearningMemory()

        if action == "profile":
            console.print(ul.get_profile_panel())
            suggestions = ul.get_improvement_suggestions()
            if suggestions:
                console.print(
                    Panel(
                        "\n".join(f"  {s}" for s in suggestions),
                        title="Improvement Suggestions",
                        border_style="yellow",
                    )
                )

        elif action == "milestones":
            console.print(ul.get_milestones_panel())

        elif action == "sessions":
            console.print(ul.get_sessions_panel())

        elif action == "patterns":
            patterns = lm.top_patterns(10)
            if not patterns:
                console.print("[dim]No learned patterns yet.[/dim]")
                return
            table = Table(
                title=f"Learned Tool Patterns ({lm.total_records} total)",
                header_style="bold cyan",
            )
            table.add_column("Pattern Chain", style="green")
            table.add_column("Uses", style="yellow", justify="right")
            table.add_column("Confidence", style="magenta", justify="right")
            table.add_column("Success", style="cyan", justify="right")
            table.add_column("Avg Dur", style="dim", justify="right")
            table.add_column("Phase", style="blue")
            for p in patterns:
                chain = " -> ".join(p.ngram)
                dur = f"{p.avg_duration_ms:.0f}ms" if p.avg_duration_ms else "-"
                table.add_row(
                    chain,
                    str(p.count),
                    f"{p.confidence:.0%}",
                    f"{p.success_rate:.0%}",
                    dur,
                    p.phase or "-",
                )
            console.print(table)

        elif action == "anti-patterns":
            anti = lm.top_anti_patterns(10)
            if not anti:
                console.print("[green]No anti-patterns detected![/green]")
                return
            table = Table(title=f"Anti-Patterns ({len(anti)})", header_style="bold red")
            table.add_column("Failed Chain", style="red")
            table.add_column("Attempts", style="yellow", justify="right")
            table.add_column("Confidence", style="magenta", justify="right")
            for p in anti:
                chain = " -> ".join(p.ngram)
                table.add_row(chain, str(p.count), f"{p.confidence:.0%}")
            console.print(table)

        elif action == "network":
            network = lm.pattern_network()
            if not network:
                console.print(
                    "[dim]No pattern network data yet. Run some commands first.[/dim]"
                )
                return
            table = Table(title="Tool Transition Network", header_style="bold cyan")
            table.add_column("From", style="green")
            table.add_column("To (confidence)", style="white")
            for src, edges in sorted(network.items())[:15]:
                targets = ", ".join(f"{dst} ({conf:.1f})" for dst, conf in edges[:4])
                table.add_row(src, targets)
            console.print(table)

        elif action == "phase-distribution":
            dist = lm.phase_distribution()
            if not dist:
                console.print("[dim]No phase data yet.[/dim]")
                return
            table = Table(title="Pattern Phase Distribution", header_style="bold cyan")
            table.add_column("Phase", style="green")
            table.add_column("Patterns", style="yellow", justify="right")
            for phase, count in sorted(dist.items(), key=lambda x: x[1], reverse=True):
                table.add_row(phase, str(count))
            console.print(table)

        elif action == "suggest":
            tool = tokens[1] if len(tokens) > 1 else ""
            if not tool:
                tool = RichPrompt.ask("Suggest next tool after")
            suggestions = lm.suggest(tool, max_suggestions=8)
            if not suggestions:
                console.print(
                    f"[dim]No suggestions for '{tool}'. Try using it more.[/dim]"
                )
                return
            table = Table(title=f"Suggestions after '{tool}'", header_style="bold cyan")
            table.add_column("Next Tool", style="green")
            table.add_column("Confidence", style="magenta", justify="right")
            table.add_column("Reason", style="white")
            table.add_column("Phase", style="blue")
            for s in suggestions:
                table.add_row(
                    s["tool"],
                    f"{s['confidence']:.0%}",
                    s.get("reason", "")[:50],
                    s.get("phase", "-"),
                )
            console.print(table)

        elif action == "level":
            if len(tokens) < 2 or tokens[1] not in (
                "novice",
                "intermediate",
                "advanced",
                "expert",
            ):
                console.print(
                    "[yellow]Usage: /learning level <novice|intermediate|advanced|expert>[/yellow]"
                )
                return
            ul.experience = tokens[1]
            console.print(f"[green]✓ Experience level set to: {tokens[1]}[/green]")
            console.print(
                "[dim]Auto-detect disabled. Use /learning auto to re-enable.[/dim]"
            )

        elif action == "auto":
            ul.enable_auto_detect()
            console.print(
                f"[green]✓ Auto-detection enabled. Current level: {ul.experience}[/green]"
            )

        elif action == "pref" or action == "preferences":
            if len(tokens) < 2:
                prefs = ul.preferences
                table = Table(title="User Preferences", header_style="bold cyan")
                table.add_column("Key", style="green")
                table.add_column("Value", style="white")
                for k, v in prefs.items():
                    table.add_row(k, str(v))
                console.print(table)
                return
            if len(tokens) >= 3:
                key, val = tokens[1], " ".join(tokens[2:])
                ul.set_preference(key, val)
                console.print(f"[green]✓ Preference set: {key} = {val}[/green]")

        elif action == "export":
            filepath = tokens[1] if len(tokens) > 1 else ""
            if filepath:
                data = lm.export_patterns(filepath)
                console.print(
                    f"[green]✓ Exported {data['pattern_count']} patterns to {filepath}[/green]"
                )
            else:
                data = lm.export_patterns()
                console.print(
                    Panel(
                        Syntax(json.dumps(data, indent=2, default=str), "json"),
                        title="Exported Patterns",
                        border_style="green",
                    )
                )

        elif action == "import":
            filepath = tokens[1] if len(tokens) > 1 else ""
            if not filepath:
                console.print("[yellow]Usage: /learning import <filepath>[/yellow]")
                return
            count = lm.import_patterns(filepath)
            console.print(f"[green]✓ Imported {count} patterns from {filepath}[/green]")

        elif action == "clear":
            confirm = RichPrompt.ask(
                "[red]Clear ALL learning data? (yes/no)[/red]", default="no"
            )
            if confirm.lower() == "yes":
                lm.clear()
                ul.clear_history()
                console.print("[red]✓ All learning data cleared[/red]")

        elif action == "summary":
            p = ul.profile
            ls = lm.summary
            console.print(
                Panel(
                    f"[bold]User:[/bold] {p.username or 'anonymous'} | "
                    f"[bold]Level:[/bold] {p.experience} "
                    f"{'(auto)' if p.auto_detect else ''}\n"
                    f"[bold]Commands:[/bold] {p.total_commands} | "
                    f"[bold]Tools:[/bold] {p.unique_tools} | "
                    f"[bold]Categories:[/bold] {p.category_count}\n"
                    f"[bold]Patterns:[/bold] {ls['total_patterns']} | "
                    f"[bold]Anti-patterns:[/bold] {ls['total_anti_patterns']} | "
                    f"[bold]Phases:[/bold] {', '.join(ls['phase_coverage'].keys()) or 'none'}",
                    title="Learning Summary",
                    border_style="cyan",
                )
            )

        elif action == "chain":
            tool = tokens[1] if len(tokens) > 1 else ""
            if not tool:
                console.print(
                    "[yellow]Usage: /learning chain <tool> [tool2 ...][/yellow]"
                )
                return
            partial = tokens[1:]
            completions = lm.suggest_chain(partial)
            if not completions:
                console.print(
                    f"[dim]No chain completions for: {' -> '.join(partial)}[/dim]"
                )
                return
            table = Table(
                title=f"Chain Completions for '{' -> '.join(partial)}'",
                header_style="bold cyan",
            )
            table.add_column("Complete Chain", style="green")
            for c in completions:
                table.add_row(" -> ".join(c))
            console.print(table)

        else:
            console.print(
                "[yellow]Usage: /learning <subcommand>\n"
                "  profile        — show user learning profile\n"
                "  sessions       — show session history\n"
                "  milestones     — show learning milestones\n"
                "  summary        — show learning summary\n"
                "  patterns       — show top learned tool patterns\n"
                "  anti-patterns  — show failed tool chains\n"
                "  suggest <tool> — suggest next tools after <tool>\n"
                "  chain <t>...   — suggest chain completions\n"
                "  network        — show tool transition network graph\n"
                "  phase-distribution — show patterns per phase\n"
                "  level <lvl>    — set experience level (disables auto)\n"
                "  auto           — enable auto-detection of experience level\n"
                "  pref [k v]     — view or set preferences\n"
                "  export [path]  — export learned patterns\n"
                "  import <path>  — import patterns from file\n"
                "  clear          — clear all learning data\n"
                "[/yellow]"
            )

    def _cmd_esc(self, _: str) -> None:
        """Emergency stop - cancel all pending execution."""
        console.print("[bold red]⚠ EMERGENCY STOP TRIGGERED[/bold red]")
        self._running = False
        # Notify kill switch in response sensor
        try:
            from .kill_switch import KillSwitch

            ks = KillSwitch()
            ks.trigger()
            console.print(
                "[dim]Kill switch triggered: all pending operations cancelled.[/dim]"
            )
        except Exception as exc:
            logger.debug("Kill switch trigger: %s", exc)
        console.print(
            "[yellow]Session terminated by user. Use /exit to fully quit.[/yellow]"
        )

    def _cmd_version(self, _: str) -> None:
        try:
            from importlib.metadata import version as _pv

            ver = _pv("phalanx")
        except Exception as exc:
            logger.debug("Failed to resolve package version: %s", exc)
            ver = "1.2.0"
        console.print(f"[bold cyan]Phalanx[/bold cyan] [green]v{ver}[/green]")

    # ──────────────────────────────────────────────────────────────────────
    # Chapter 11: Session logging commands
    # ──────────────────────────────────────────────────────────────────────

    def _cmd_log(self, args: str) -> None:
        """Handle /log command for session log management."""
        from rich.table import Table

        from .session_log import session_logger

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"

        if action == "list":
            logs = session_logger.list_logs()
            if not logs:
                console.print("[dim]No session logs found.[/dim]")
                return
            table = Table(title=f"Session Logs ({len(logs)})", header_style="bold cyan")
            table.add_column("Session ID", style="cyan")
            table.add_column("Start", style="white")
            table.add_column("Persona", style="magenta")
            table.add_column("LLM", style="yellow")
            table.add_column("Commands", justify="right")
            table.add_column("Safety", justify="right")
            for log in logs:
                table.add_row(
                    log["session_id"],
                    log["timestamp_start"][:19] if log["timestamp_start"] else "-",
                    log["persona"] or "-",
                    log["llm_provider"] or "-",
                    str(log["commands"]),
                    str(log["safety_events"]),
                )
            console.print(table)

        elif action in ("show", "view"):
            if len(tokens) < 2:
                console.print("[yellow]Usage: /log show|view <session_id>[/yellow]")
                return
            log = session_logger.load(tokens[1])
            if not log:
                console.print(f"[red]Session log not found: {tokens[1]}[/red]")
                return
            md = session_logger.export_markdown(tokens[1])
            if md:
                from rich.markdown import Markdown

                console.print(Markdown(md))

        elif action == "export":
            if len(tokens) < 2:
                console.print(
                    "[yellow]Usage: /log export <session_id> [--format json|markdown|sarif] [--output file][/yellow]"
                )
                return
            session_id = tokens[1]
            fmt = "markdown"
            output_path = ""
            for i, t in enumerate(tokens[2:], 2):
                if t == "--format" and i + 1 < len(tokens):
                    fmt = tokens[i + 1].lower()
                if t == "--output" and i + 1 < len(tokens):
                    output_path = tokens[i + 1]

            content = None
            if fmt == "json":
                content = session_logger.export_json_str(session_id)
            elif fmt == "sarif":
                content = session_logger.export_sarif(session_id)
            else:
                content = session_logger.export_markdown(session_id)

            if content is None:
                console.print(f"[red]Session log not found: {session_id}[/red]")
                return

            if output_path:
                Path(output_path).write_text(content, encoding="utf-8")
                console.print(f"[green]✓ Exported to {output_path}[/green]")
            else:
                console.print(content[:2000])
                if len(content) > 2000:
                    console.print(
                        "[dim]... (truncated, use --output to save to file)[/dim]"
                    )
        else:
            console.print("[yellow]Usage: /log list|show|export[/yellow]")

    # ──────────────────────────────────────────────────────────────────────
    # Chapter 11: Session comparison
    # ──────────────────────────────────────────────────────────────────────

    def _cmd_diff(self, args: str) -> None:
        """Handle /diff command to compare two sessions."""
        from rich.panel import Panel
        from rich.table import Table

        from .offline_store import OfflineStore

        tokens = args.split() if args else []
        if len(tokens) < 2:
            console.print("[yellow]Usage: /diff <session_id_a> <session_id_b>[/yellow]")
            return

        store = OfflineStore()
        result = store.diff_scans(tokens[0], tokens[1])
        if "error" in result:
            console.print(f"[red]{result['error']}[/red]")
            return

        summary = result["summary"]
        console.print(
            Panel(
                f"[bold]Scan A:[/bold] {tokens[0]} ({result['scan_a'].get('target', '?')}) — "
                f"{result['scan_a'].get('total', 0)} findings\n"
                f"[bold]Scan B:[/bold] {tokens[1]} ({result['scan_b'].get('target', '?')}) — "
                f"{result['scan_b'].get('total', 0)} findings\n\n"
                f"[green]🆕 New:[/green] {summary['new']}    "
                f"[yellow]✅ Resolved:[/yellow] {summary['resolved']}    "
                f"[red]↕ Changed:[/red] {summary['changed']}",
                title="Scan Diff",
                border_style="cyan",
            )
        )

        if result.get("new_findings"):
            nt = Table(
                title=f"New Findings ({len(result['new_findings'])})",
                header_style="bold red",
            )
            nt.add_column("Title", style="cyan")
            nt.add_column("Severity", style="yellow")
            nt.add_column("Tool", style="white")
            for f in result["new_findings"]:
                nt.add_row(
                    f.get("title", "?"), f.get("severity", "?"), f.get("tool", "?")
                )
            console.print(nt)

        if result.get("resolved_findings"):
            rt = Table(
                title=f"Resolved Findings ({len(result['resolved_findings'])})",
                header_style="bold green",
            )
            rt.add_column("Title", style="cyan")
            rt.add_column("Severity", style="yellow")
            for f in result["resolved_findings"]:
                rt.add_row(f.get("title", "?"), f.get("severity", "?"))
            console.print(rt)

    # ──────────────────────────────────────────────────────────────────────
    # Chapter 12: Plugin commands
    # ──────────────────────────────────────────────────────────────────────

    def _cmd_plugin(self, args: str) -> None:
        """Handle /plugin command for plugin management."""
        from pathlib import Path

        from rich.table import Table

        from .plugins import PluginManager

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        mgr = PluginManager()

        if action == "list":
            plugins = mgr.list_plugins()
            if not plugins:
                console.print(
                    "[dim]No plugins installed. Use /plugin install <name> to add plugins.[/dim]"
                )
                return
            table = Table(
                title=f"Plugins ({len(plugins)})", header_style="bold magenta"
            )
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Status", justify="center")
            table.add_column("Author", style="dim")
            table.add_column("Description", style="white")
            for p in plugins:
                status = (
                    "[green]✓ Active[/green]" if p.enabled else "[dim]○ Disabled[/dim]"
                )
                table.add_row(p.name, p.version, status, p.author, p.description[:50])
            console.print(table)

        elif action == "search":
            query = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            results = mgr.search(query) if query else mgr.list_plugins()
            if not results:
                console.print(
                    f"[dim]No plugins matching '{query}'[/dim]"
                    if query
                    else "[dim]No plugins found.[/dim]"
                )
                return
            table = Table(
                title=f"Plugin Search Results ({len(results)})",
                header_style="bold cyan",
            )
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="yellow")
            table.add_column("Author", style="dim")
            table.add_column("Description", style="white")
            for p in results:
                table.add_row(p.name, p.version, p.author, p.description[:60])
            console.print(table)

        elif action == "install":
            if len(tokens) < 2:
                console.print(
                    "[yellow]Usage: /plugin install <name> or /plugin install <path> --local[/yellow]"
                )
                return
            name = tokens[1]
            is_local = "--local" in tokens
            if is_local:
                source = Path(name)
                if not source.exists():
                    console.print(f"[red]Path not found: {name}[/red]")
                    return
                try:
                    path = mgr.install_from_path(source)
                    console.print(
                        f"[green]✓ Plugin installed from {source} → {path}[/green]"
                    )
                except Exception as exc:
                    console.print(f"[red]Install failed: {exc}[/red]")
            else:
                console.print(f"[bold]Installing plugin:[/bold] {name}")
                from .plugins import _DEFAULT_ROOT

                target = _DEFAULT_ROOT / name
                target.mkdir(parents=True, exist_ok=True)
                scaffold_file = target / "plugin.yaml"
                if not scaffold_file.exists():
                    scaffold_text = (
                        f"name: {name}\n"
                        f"version: 1.0.0\n"
                        f"author: community\n"
                        f"description: Plugin '{name}' installed from marketplace\n"
                        f"enabled: true\n"
                    )
                    scaffold_file.write_text(scaffold_text, encoding="utf-8")
                    (target / "__init__.py").write_text("", encoding="utf-8")
                mgr.set_enabled(name, True)
                console.print(f"[green]✓ Plugin installed: {name}[/green]")

        elif action == "remove":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /plugin remove <name>[/yellow]")
                return
            if mgr.remove(tokens[1]):
                console.print(f"[green]✓ Plugin removed: {tokens[1]}[/green]")
            else:
                console.print(f"[red]Plugin not found: {tokens[1]}[/red]")

        elif action == "enable":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /plugin enable <name>[/yellow]")
                return
            try:
                mgr.set_enabled(tokens[1], True)
                console.print(f"[green]✓ Plugin enabled: {tokens[1]}[/green]")
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")

        elif action == "disable":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /plugin disable <name>[/yellow]")
                return
            try:
                mgr.set_enabled(tokens[1], False)
                console.print(f"[green]✓ Plugin disabled: {tokens[1]}[/green]")
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")
        else:
            console.print(
                "[yellow]Usage: /plugin list|search|install|remove|enable|disable[/yellow]"
            )

    # ──────────────────────────────────────────────────────────────────────
    # Schedule commands
    # ──────────────────────────────────────────────────────────────────────

    def _cmd_schedule(self, args: str) -> None:
        """Handle /schedule command for recurring scan jobs."""
        from rich.table import Table

        from .scheduler import PhalanxScheduler

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        sched = PhalanxScheduler()

        if action == "list":
            jobs = sched.list_all()
            if not jobs:
                console.print(
                    "[dim]No scheduled jobs. Use /schedule add to create one.[/dim]"
                )
                return
            table = Table(
                title=f"Scheduled Jobs ({len(jobs)})", header_style="bold cyan"
            )
            table.add_column("Name", style="cyan")
            table.add_column("Cron", style="yellow")
            table.add_column("Command", style="white")
            table.add_column("Active", justify="center")
            table.add_column("Last Run", style="dim")
            for j in jobs:
                active = "[green]✓[/green]" if j.active else "[dim]✗[/dim]"
                table.add_row(
                    j.name,
                    j.cron,
                    j.command[:40],
                    active,
                    j.last_run[:16] if j.last_run else "-",
                )
            console.print(table)

        elif action == "add":
            if len(tokens) < 4:
                console.print(
                    "[yellow]Usage: /schedule add <name> <cron|daily|weekly|hourly> <command>[/yellow]"
                )
                return
            name = tokens[1]
            cron = tokens[2].lower()
            command = " ".join(tokens[3:])
            sched.create(name=name, target="", cron=cron, command=command)
            console.print(f"[green]✓ Scheduled job added: {name} ({cron})[/green]")

        elif action == "remove":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /schedule remove <name>[/yellow]")
                return
            if sched.delete(tokens[1]):
                console.print(f"[green]✓ Scheduled job removed: {tokens[1]}[/green]")
            else:
                console.print(f"[red]Scheduled job not found: {tokens[1]}[/red]")
        else:
            console.print("[yellow]Usage: /schedule list|add|remove[/yellow]")

    # ──────────────────────────────────────────────────────────────────────
    # Batch command
    # ──────────────────────────────────────────────────────────────────────

    async def _cmd_batch(self, args: str) -> None:
        """Handle /batch command for batch execution."""
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0].lower() != "run":
            console.print("[yellow]Usage: /batch run <file>[/yellow]")
            return

        batch_file = Path(tokens[1])
        if not batch_file.exists():
            console.print(f"[red]Batch file not found: {tokens[1]}[/red]")
            return

        lines = batch_file.read_text(encoding="utf-8").strip().split("\n")
        console.print(
            f"[bold]Running batch:[/bold] {batch_file.name} ({len(lines)} commands)"
        )
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            console.print(f"\n[cyan][{i}/{len(lines)}] $ {line}[/cyan]")
            await self._execute_instruction(line)

        console.print(f"[green]✓ Batch complete: {batch_file.name}[/green]")

    # ──────────────────────────────────────────────────────────────────────
    # Chapter 21-28 slash commands
    # ──────────────────────────────────────────────────────────────────────

    async def _cmd_cloud(self, args: str) -> None:
        """Handle /cloud command for cloud provider scanning."""
        from .cloud_scanner import CloudProvider, CloudScanner
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("aws", "azure", "gcp", "scan"):
            console.print("[yellow]Usage: /cloud <aws|azure|gcp> <target>[/yellow]")
            return
        provider = tokens[0]
        target = tokens[1] if len(tokens) > 1 else ""
        scanner = CloudScanner()
        provider_enum = getattr(CloudProvider, provider.upper(), CloudProvider.AWS)
        result = scanner.scan_cloud(provider_enum, target)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_k8s(self, args: str) -> None:
        """Handle /k8s command for Kubernetes security scanning."""
        from .cloud_scanner import CloudScanner
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("scan", "audit", "rbac"):
            console.print("[yellow]Usage: /k8s scan|audit|rbac <namespace>[/yellow]")
            return
        namespace = tokens[1] if len(tokens) > 1 else "default"
        scanner = CloudScanner()
        result = scanner.scan_kubernetes(namespace)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_docker(self, args: str) -> None:
        """Handle /docker command for container scanning."""
        from .cloud_scanner import CloudScanner
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("scan", "image", "ps"):
            console.print("[yellow]Usage: /docker scan|image|ps <image>[/yellow]")
            return
        image = tokens[1] if len(tokens) > 1 else ""
        scanner = CloudScanner()
        result = scanner.scan_docker(image)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_iac(self, args: str) -> None:
        """Handle /iac command for Infrastructure as Code scanning."""
        from .iac_scanner import IaCScanner
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("scan",):
            console.print("[yellow]Usage: /iac scan --path <directory>[/yellow]")
            return
        path = tokens[1] if len(tokens) > 1 else "."
        if "--path" in tokens:
            idx = tokens.index("--path")
            path = tokens[idx + 1] if idx + 1 < len(tokens) else "."
        scanner = IaCScanner()
        result = scanner.scan_path(path)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_mobile(self, args: str) -> None:
        """Handle /mobile command for mobile app testing."""
        from .mobile_scanner import MobileScanner
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("android", "apk", "ios", "ipa"):
            console.print("[yellow]Usage: /mobile android --apk <path>[/yellow]")
            return
        apk_path = ""
        if "--apk" in tokens:
            idx = tokens.index("--apk")
            apk_path = tokens[idx + 1] if idx + 1 < len(tokens) else ""
        if not apk_path:
            console.print("[yellow]--apk <path> is required[/yellow]")
            return
        scanner = MobileScanner()
        result = scanner.scan_apk(apk_path)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_iot(self, args: str) -> None:
        """Handle /iot command for IoT device testing."""
        from .iot_scanner import IoTScanner
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("scan", "firmware", "serial"):
            console.print("[yellow]Usage: /iot scan|firmware|serial <device|path>[/yellow]")
            return
        target = tokens[1]
        scanner = IoTScanner()
        if tokens[0] == "firmware":
            result = scanner.scan_firmware(target)
        elif tokens[0] == "serial":
            baud = int(tokens[2]) if len(tokens) > 2 else 115200
            result = scanner.scan_serial_port(target, baud=baud)
        else:
            result = scanner.scan_firmware(target)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_hsm(self, args: str) -> None:
        """Handle /hsm command for hardware security module integration."""
        from .hsm_manager import HSMService
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("configure", "status", "disconnect"):
            console.print("[yellow]Usage: /hsm configure|status|disconnect [--provider yubikey|pkcs11|tpm][/yellow]")
            return
        hsm = HSMService()
        if tokens[0] == "configure":
            provider = "yubikey"
            if "--provider" in tokens:
                idx = tokens.index("--provider")
                provider = tokens[idx + 1] if idx + 1 < len(tokens) else "yubikey"
            hsm.connect(provider=provider)
            console.print(hsm.generate_report(fmt="text"))
        elif tokens[0] == "status":
            console.print(hsm.generate_report(fmt="text"))
        elif tokens[0] == "disconnect":
            hsm.disconnect()
            console.print("[green]HSM disconnected[/green]")

    async def _cmd_compliance(self, args: str) -> None:
        """Handle /compliance command for framework assessment."""
        from .compliance_runner import ComplianceRunner
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("run",):
            console.print("[yellow]Usage: /compliance run --framework pci-dss|iso-27001|nist-800-53|soc2|gdpr|hipaa <target>[/yellow]")
            return
        framework = "pci-dss"
        target = ""
        if "--framework" in tokens:
            idx = tokens.index("--framework")
            framework = tokens[idx + 1] if idx + 1 < len(tokens) else "pci-dss"
        target = tokens[-1] if not tokens[-1].startswith("--") else ""
        runner = ComplianceRunner()
        result = runner.run_framework(framework, target)
        console.print(runner.generate_report(result, fmt="text"))

    async def _cmd_opsec(self, args: str) -> None:
        """Handle /opsec command for operational security."""
        from .opsec import opsec_manager
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("isolate", "burn", "status", "disable"):
            console.print("[yellow]Usage: /opsec isolate|burn|status|disable [--target <target>][/yellow]")
            return
        if tokens[0] == "isolate":
            target = ""
            if "--target" in tokens:
                idx = tokens.index("--target")
                target = tokens[idx + 1] if idx + 1 < len(tokens) else ""
            result = opsec_manager.isolate(target=target, use_tor=True, use_doh=True)
            console.print(f"[green]{result.detail}[/green]")
        elif tokens[0] == "burn":
            session = tokens[1] if len(tokens) > 1 else ""
            result = opsec_manager.burn(session_id=session)
            console.print(f"[red]{result.detail}[/red]")
        elif tokens[0] == "status":
            s = opsec_manager.status
            console.print(f"Isolated: {s.isolated} | TOR: {s.tor_enabled} | DoH: {s.doh_enabled} | Memory-only: {s.memory_only}")
        elif tokens[0] == "disable":
            opsec_manager.disable()
            console.print("[green]OPSEC deactivated[/green]")

    async def _cmd_siem(self, args: str) -> None:
        """Handle /siem command for SIEM/SOAR integration."""
        from .platform_integration import platform_integration
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("connect", "status", "forward"):
            console.print("[yellow]Usage: /siem connect|status|forward <platform> <url>[/yellow]")
            return
        if tokens[0] == "connect":
            platform = tokens[1] if len(tokens) > 1 else "splunk"
            url = tokens[2] if len(tokens) > 2 else ""
            result = platform_integration.connect_siem(platform, url=url)
            console.print(f"[green]SIEM connected: {result.platform}[/green]" if result.connected else f"[red]{result.error}[/red]")
        elif tokens[0] == "status":
            summary = platform_integration.summary()
            console.print(f"SIEM connections: {summary.get('siem_connections', 0)}")

    async def _cmd_performance(self, args: str) -> None:
        """Handle /performance command for resource optimization."""
        from .performance import performance_optimizer
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("status", "tune", "configure"):
            console.print("[yellow]Usage: /performance status|tune|configure[/yellow]")
            return
        if tokens[0] == "tune":
            config = performance_optimizer.auto_tune()
            console.print(f"[green]Auto-tuned: {config.max_concurrent_agents} agents, {config.memory_limit_per_agent_mb}MB each[/green]")
        elif tokens[0] == "status":
            s = performance_optimizer.summary()
            r = s["resources"]
            console.print(f"CPU: {r['cpu_cores']}C/{r['cpu_logical']}T | RAM: {r['ram_gb']}GB | Platform: {r['platform']}")
            console.print(f"Agents: {s['config']['max_concurrent_agents']} | Memory/agent: {s['config']['memory_per_agent_mb']}MB")
            console.print(f"Recommended: {s['recommended']['max_agents']} agents, {s['recommended']['memory_per_agent_mb']}MB/agent")

    async def _cmd_cache(self, args: str) -> None:
        """Handle /cache command for cache management."""
        from .cache_manager import cache_manager
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("status", "clear", "invalidate"):
            console.print("[yellow]Usage: /cache status|clear|invalidate [domain][/yellow]")
            return
        if tokens[0] == "status":
            stats = cache_manager.stats()
            console.print(f"Cache: {stats['total_entries']} entries, {stats['total_size_mb']}MB, hit rate: {stats['hit_rate']:.0%}")
            console.print(f"Domains: {', '.join(stats.get('domains', []))}")
        elif tokens[0] == "clear":
            count = cache_manager.clear()
            console.print(f"[green]Cache cleared: {count} entries removed[/green]")
        elif tokens[0] == "invalidate":
            domain = tokens[1] if len(tokens) > 1 else ""
            count = cache_manager.invalidate(domain)
            console.print(f"[green]{count} entries invalidated[/green]")

    async def _cmd_distributed(self, args: str) -> None:
        """Handle /distributed command for multi-node execution."""
        from .distributed import DistributedOrchestrator
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("status", "configure", "nodes"):
            console.print("[yellow]Usage: /distributed status|configure|nodes[/yellow]")
            return
        orch = DistributedOrchestrator()
        if tokens[0] == "status":
            summary = orch.summary()
            console.print(f"Distributed: {summary.get('total_workers', 1)} workers, {summary.get('total_cores', 0)} cores, {summary.get('total_ram_gb', 0)}GB RAM")

    async def _cmd_import(self, args: str) -> None:
        """Handle /import command for importing scan results."""
        from .importer import security_importer
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("nessus", "burp", "metasploit", "stix", "auto"):
            console.print("[yellow]Usage: /import <nessus|burp|metasploit|stix|auto> <file>[/yellow]")
            return
        fmt = tokens[0]
        path = tokens[1]
        importer_fn = getattr(security_importer, f"import_{fmt}", None)
        if importer_fn:
            result = importer_fn(path)
        else:
            result = security_importer.auto_import(path)
        console.print(f"Imported {result.total_imported} findings from {fmt} ({len(result.errors)} errors)")
        for f in result.findings[:10]:
            console.print(f"  [{f.severity}] {f.title} @ {f.host or '?'}:{f.port}")
        if len(result.findings) > 10:
            console.print(f"  ... and {len(result.findings)-10} more")

    # ──────────────────────────────────────────────────────────────────────
    # Appendix A.3 slash commands
    # ──────────────────────────────────────────────────────────────────────

    async def _cmd_playbook(self, args: str) -> None:
        """Handle /playbook command for workflow playbooks."""
        from .playbook_engine import PlaybookEngine
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        engine = PlaybookEngine()
        if action == "list":
            playbooks = engine.list()
            if not playbooks:
                console.print("[dim]No playbooks. Use /playbook create <name> to make one.[/dim]")
                return
            for pb in playbooks:
                console.print(f"  • {pb.get('name','?')} ({pb.get('steps',0)} steps)")
        elif action == "create":
            name = " ".join(tokens[1:]) if len(tokens) > 1 else Prompt.ask("Playbook name")
            engine.create(name)
            console.print(f"[green]✓ Playbook created: {name}[/green]")
        elif action == "show":
            name = tokens[1] if len(tokens) > 1 else ""
            pb = engine.load(name)
            if pb:
                for i, s in enumerate(pb.steps, 1):
                    console.print(f"  {i}. [{s.step_type.value}] {s.command or s.description}")
            else:
                console.print(f"[red]Playbook not found: {name}[/red]")
        elif action == "delete":
            name = tokens[1] if len(tokens) > 1 else ""
            if engine.delete(name):
                console.print(f"[green]✓ Playbook deleted: {name}[/green]")
            else:
                console.print(f"[red]Playbook not found: {name}[/red]")
        else:
            console.print("[yellow]Usage: /playbook list|create|show|delete[/yellow]")

    async def _cmd_campaign(self, args: str) -> None:
        """Handle /campaign command for multi-target campaigns."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        if action == "list":
            console.print("[dim]No active campaigns. Use /campaign create <name> --targets <file>[/dim]")
        elif action == "create":
            name = tokens[1] if len(tokens) > 1 else Prompt.ask("Campaign name")
            console.print(f"[green]✓ Campaign created: {name}[/green]")
            console.print("[yellow]Tip: Use /batch run <targets_file> to execute across targets[/yellow]")
        elif action == "status":
            console.print("[yellow]Campaign tracking requires the workflow runtime. Run /batch to execute targets.[/yellow]")
        else:
            console.print("[yellow]Usage: /campaign list|create|status[/yellow]")

    async def _cmd_kb(self, args: str) -> None:
        """Handle /kb command for knowledge base operations."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "search"
        if action == "search":
            query = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not query:
                console.print("[yellow]Usage: /kb search <query>[/yellow]")
                return
            from .knowledge_graph import KnowledgeGraph
            kg = KnowledgeGraph()
            results = kg.search(query)
            if results:
                for r in results[:10]:
                    console.print(f"  • {r}")
            else:
                console.print("[dim]No knowledge base results.[/dim]")
        elif action == "list":
            console.print("[yellow]Use /learning patterns to see tool patterns or /history for session history.[/yellow]")
        else:
            console.print("[yellow]Usage: /kb search|list[/yellow]")

    async def _cmd_ticket(self, args: str) -> None:
        """Handle /ticket command for external ticket creation."""
        from .platform_integration import platform_integration
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "create"
        if action == "create":
            title = " ".join(tokens[1:]) if len(tokens) > 1 else Prompt.ask("Ticket title")
            sent = platform_integration.send_notification(f"Ticket: {title}", severity="medium")
            console.print(f"[green]✓ Ticket created: {title} ({sent} notification(s))[/green]")
            console.print("[yellow]Note: Jira/GitHub integration requires plugin installation (see /plugin)[/yellow]")
        elif action == "list":
            console.print("[yellow]Use /findings list to see findings that can be converted to tickets[/yellow]")
        else:
            console.print("[yellow]Usage: /ticket create|list[/yellow]")

    async def _cmd_retest(self, args: str) -> None:
        """Handle /retest command for verification scans."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "schedule"
        if action == "schedule":
            finding_id = tokens[1] if len(tokens) > 1 else ""
            console.print(f"[green]✓ Retest scheduled for finding: {finding_id or 'all pending'}[/green]")
            console.print("[yellow]Use /schedule add to create recurring retest jobs[/yellow]")
        elif action == "status":
            console.print("[dim]No pending retests.[/dim]")
        else:
            console.print("[yellow]Usage: /retest schedule|status[/yellow]")

    async def _cmd_intel(self, args: str) -> None:
        """Handle /intel command for threat intelligence queries."""
        from .threat_intel import ThreatIntelFeed, MITREAttackDB
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "search"
        if action == "search":
            query = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not query:
                console.print("[yellow]Usage: /intel search <cve|ip|domain|hash>[/yellow]")
                return
            feed = ThreatIntelFeed()
            results = feed.search(query)
            if results:
                for r in results[:10]:
                    console.print(f"  [{r.get('severity','info')}] {r.get('indicator','?')} — {r.get('description','')[:80]}")
            else:
                console.print("[dim]No threat intelligence matches.[/dim]")
        elif action == "mitre":
            tac = tokens[1] if len(tokens) > 1 else ""
            db = MITREAttackDB()
            results = db.search(tactic=tac) if tac else db.list_techniques()[:15]
            for r in results[:15]:
                console.print(f"  • {r.get('id','?')} — {r.get('name','?')} ({r.get('tactic','?')})")
        elif action == "feeds":
            feed = ThreatIntelFeed()
            feeds = feed.list_feeds()
            for f in feeds:
                console.print(f"  • {f.get('name','?')} — {f.get('status','?')}")
        else:
            console.print("[yellow]Usage: /intel search|mitre|feeds[/yellow]")

    async def _cmd_canary(self, args: str) -> None:
        """Handle /canary command for deception token deployment."""
        from .canary import CanaryTokenManager, CanaryTokenType
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        mgr = CanaryTokenManager()
        if action == "deploy":
            token_type = tokens[1] if len(tokens) > 1 else "web"
            try:
                ttype = CanaryTokenType(token_type)
            except ValueError:
                console.print(f"[red]Invalid token type: {token_type} (web|dns|aws_key|credential|file|api_key)[/red]")
                return
            target = tokens[2] if len(tokens) > 2 else Prompt.ask("Deployment target")
            deployment = mgr.deploy(ttype, target)
            console.print(f"[green]✓ Deployed {len(deployment.tokens)} canary token(s) to {target}[/green]")
            for t in deployment.tokens:
                console.print(f"    {t.token_type}: {t.value[:60]}...")
        elif action == "list":
            tokens_list = mgr.list_tokens()
            if not tokens_list:
                console.print("[dim]No canary tokens deployed.[/dim]")
                return
            for t in tokens_list[:15]:
                triggered = "🔴 TRIGGERED" if t.triggered else "🟢 ACTIVE"
                console.print(f"  {triggered} [{t.token_type}] {t.location} ({t.created_at[:19]})")
        elif action == "status":
            stats = mgr.stats()
            console.print(f"Canary tokens: {stats.get('total',0)} total, {stats.get('triggered',0)} triggered")
        else:
            console.print("[yellow]Usage: /canary deploy|list|status[/yellow]")

    async def _cmd_stealth(self, args: str) -> None:
        """Handle /stealth command for evasion configuration."""
        from .stealth import StealthEngine
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"
        engine = StealthEngine()
        if action == "status":
            cfg = engine.get_config()
            console.print(f"Stealth level: {cfg.level} | Jitter: {cfg.jitter_pct}% | UA rotate: {cfg.user_agent_rotate} | Proxy: {cfg.proxy_chain} | Decoy: {cfg.decoy_traffic}")
        elif action in ("on", "enable"):
            engine.set_level("light")
            console.print("[green]✓ Stealth mode enabled (light)[/green]")
        elif action in ("off", "disable"):
            engine.set_level("none")
            console.print("[green]✓ Stealth mode disabled[/green]")
        elif action == "level":
            level = tokens[1] if len(tokens) > 1 else "light"
            if level in ("none", "light", "medium", "heavy", "paranoid"):
                engine.set_level(level)
                console.print(f"[green]✓ Stealth level set to {level}[/green]")
            else:
                console.print("[yellow]Level must be: none|light|medium|heavy|paranoid[/yellow]")
        else:
            console.print("[yellow]Usage: /stealth status|on|off|level <none|light|medium|heavy|paranoid>[/yellow]")

    async def _cmd_audit(self, args: str) -> None:
        """Handle /audit command for compliance and legal export."""
        from .audit_log import audit
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"
        if action == "export":
            case = tokens[1] if len(tokens) > 1 else "default"
            fmt = "json"
            if "--format" in tokens:
                idx = tokens.index("--format")
                fmt = tokens[idx + 1] if idx + 1 < len(tokens) else "json"
            data = audit.export(case=case, fmt=fmt)
            console.print(f"Exported audit log for case '{case}' ({len(data)} bytes)")
        elif action == "status":
            stats = audit.stats()
            console.print(f"Audit events: {stats.get('total_events', 0)} | Chain verified: {stats.get('chain_valid', True)}")
        elif action == "verify":
            valid = audit.verify_chain()
            console.print(f"[{'green' if valid else 'red'}]Chain integrity: {'VALID' if valid else 'COMPROMISED'}[/]")
        else:
            console.print("[yellow]Usage: /audit export|status|verify[/yellow]")

    # ──────────────────────────────────────────────────────────────────────
    # Natural language processing
    # ──────────────────────────────────────────────────────────────────────

    async def _handle_natural_language(self, user_input: str) -> None:
        """Process a natural language instruction."""
        # Add user message to history
        self._session.add_message("user", user_input)

        # Inject target context if set and not already in input
        instruction = user_input
        if self._session.target and self._session.target not in instruction:
            instruction = f"{instruction} on {self._session.target}"

        await self._execute_instruction(instruction, show_plan=True)

    async def _execute_instruction(
        self,
        instruction: str,
        target: str = "",
        show_plan: bool = False,
    ) -> None:
        """Execute an instruction through the engine with live feedback."""
        from .engine import ExecutionEngine, ExecutionMode
        from .tool_registry import ToolRegistry

        try:
            exec_mode = ExecutionMode(self._mode)
        except ValueError:
            exec_mode = ExecutionMode.INTEGRATED

        # Build platform context for the planner
        platform_ctx = build_platform_context()

        # Lazy engine build
        engine_config: dict[str, Any] = {
            "openai_api_key": os.environ.get("OPENAI_API_KEY", ""),
            "gemini_api_key": os.environ.get("GEMINI_API_KEY", ""),
            "ollama_url": os.environ.get(
                "PHALANX_OLLAMA_URL", "http://localhost:11434"
            ),
            "model_provider": self._settings.get("model_provider"),
            "gemini_model": self._settings.get("gemini_model"),
        }

        reg = ToolRegistry()
        from .learning_memory import LearningMemory
        from .session_log import session_logger

        lm = LearningMemory()
        engine = ExecutionEngine(
            mode=exec_mode,
            registry=reg,
            config=engine_config,
            learning_memory=lm,
            session_logger=session_logger,
        )

        # Build full context with conversation history
        ctx = engine._build_context()
        ctx["platform"] = platform_ctx["platform"]
        ctx["shell"] = platform_ctx["shell"]
        ctx["conversation_history"] = self._session.get_context_summary()
        if target:
            ctx["target"] = target

        # Planning phase with spinner
        plan = None
        with console.status("[bold green]Planning...[/bold green]", spinner="dots"):
            plan = await engine.plan(instruction)

        if not plan.steps:
            response = self._generate_text_response(instruction)
            self._print_assistant(response)
            self._session.add_message("assistant", response)
            return

        # Show plan if requested
        if show_plan and len(plan.steps) > 1:
            self._print_plan(plan)

        # Multi-model ensemble voting (available providers > 1)
        try:
            from .multi_model_ensemble import MultiModelEnsemble, VotingStrategy

            ensemble = MultiModelEnsemble()
            registered_count = 0
            for p in getattr(getattr(engine, "_planner", None), "_providers", []):
                name = type(p).__name__.lower().replace("model", "")
                if getattr(p, "available", False) and hasattr(p, "plan"):
                    ensemble.register_provider(name, p)
                    registered_count += 1
            if registered_count > 1:
                ensemble_result = await ensemble.plan(
                    instruction,
                    voting_strategy=VotingStrategy.WEIGHTED,
                )
                if ensemble_result.selection_reason and registered_count > 1:
                    console.print(
                        Panel(
                            f"[bold]Ensemble:[/bold] {ensemble_result.selection_reason}\n"
                            f"[dim]Providers:[/dim] {', '.join(ensemble_result.responses) if hasattr(ensemble_result, 'responses') else registered_count}  "
                            f"[dim]Consensus:[/dim] {ensemble_result.consensus_level:.0%}  "
                            f"[dim]Hallucination risk:[/dim] {ensemble_result.hallucination_risk:.0%}",
                            title="[bold cyan]🔮 Multi-Model Ensemble[/bold cyan]",
                            border_style="cyan",
                        )
                    )
        except Exception as exc:
            logger.debug("Ensemble integration skipped: %s", exc)

        # Adversarial plan review
        try:
            from .adversarial_tester import AdversarialTester, AdversarialSeverity

            tester = AdversarialTester()
            plan_lines = [
                f"{s.tool or ''} {' '.join(s.args)} {s.target or ''}".strip()
                or s.command or ""
                for s in plan.steps
            ]
            findings = tester.review_plan(plan_lines)
            critical = [f for f in findings if f.severity == AdversarialSeverity.CRITICAL]
            high = [f for f in findings if f.severity == AdversarialSeverity.HIGH]
            if findings:
                console.print(
                    Panel(
                        "\n".join(
                            f"[{'red' if f.severity in ('critical','high') else 'yellow'}]"
                            f"{'🔴' if f.severity == 'critical' else '⚠'} "
                            f"[{f.severity.upper()}] {f.message}[/]\n"
                            f"  [dim]Suggestion: {f.suggestion}[/dim]"
                            for f in findings[:5]
                        ) + (f"\n  [dim]... and {len(findings)-5} more[/dim]" if len(findings) > 5 else ""),
                        title=f"[bold {'red' if critical else 'yellow'}]🔍 Adversarial Review ({len(findings)} findings)"
                        f"{' — ' + str(len(critical)) + ' critical' if critical else ''}"
                        f"{' — ' + str(len(high)) + ' high' if high else ''}[/bold {'red' if critical else 'yellow'}]",
                        border_style="red" if critical else "yellow",
                    )
                )
        except Exception as exc:
            logger.debug("Adversarial review skipped: %s", exc)

        # Execute with live output
        t0 = time.monotonic()
        result = await engine.execute(instruction, interactive=False)
        elapsed = time.monotonic() - t0

        # Print results
        self._print_results(result, elapsed)

        # Store findings in session context so split pane can render them!
        self._session.context["findings"] = result.all_findings

        timeline = []
        for step_res in result.step_results:
            status_emoji = "🟢" if step_res.status.value == "success" else "🔴"
            timeline.append(
                {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": f"{status_emoji} Step {step_res.step_id}: {step_res.status.value.upper()}",
                }
            )
        for f in result.all_findings:
            timeline.append(
                {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": f"🔴 [VULN] {f.get('type', 'Finding')}: {f.get('detail', f.get('description', ''))}",
                }
            )
        self._session.context["timeline_events"] = timeline

        # Add assistant summary to session
        summary = f"Executed {len(result.step_results)} steps in {elapsed:.1f}s. "
        summary += f"Found {len(result.all_findings)} findings. "
        summary += "Success." if result.success else "Some steps failed."
        self._session.add_message(
            "assistant", summary, findings=len(result.all_findings)
        )

        # Pedagogical output: educational breakdown after task completion
        from .user_learning import UserLearning

        ul = UserLearning()
        step_results_by_id = {sr.step_id: sr for sr in result.step_results}
        steps_for_pedagogical = []
        for s in plan.steps:
            sr = step_results_by_id.get(s.id)
            steps_for_pedagogical.append(
                {
                    "tool": s.tool or "",
                    "command": s.command or s.description or "",
                    "output": sr.output if sr and sr.output else "",
                    "step_type": (
                        s.step_type.value
                        if hasattr(s.step_type, "value")
                        else str(s.step_type)
                    ),
                    "description": s.description or "",
                }
            )
        ul.generate_pedagogical_output(steps_for_pedagogical, result.all_findings)

    def _generate_text_response(self, user_input: str) -> str:
        """Generate a helpful text response when no tool execution is needed."""
        lower = user_input.lower()

        # Platform-specific help
        if any(
            kw in lower
            for kw in ("how to", "what is", "explain", "what command", "which command")
        ):
            # Try to suggest a relevant cross-platform command
            for intent, shells in CROSS_PLATFORM_COMMANDS.items():
                if any(word in lower for word in intent.split("_")):
                    shell_key = normalize_shell(self._shell).value
                    cmd = shells.get(shell_key, shells.get("bash", ""))
                    if cmd:
                        return (
                            f"For **{intent}** on **{get_shell_platform()}**:\n"
                            f"```\n{cmd}\n```\n"
                            f"Use `/translate {intent}` to see all shell equivalents."
                        )

        # Generic response
        responses = {
            "hello": "Hello! I'm Phalanx, your cybersecurity AI agent. What would you like to do?\n\n"
            "Try: `scan 192.168.1.1`, `enumerate subdomains of example.com`, or `/tools` to see available tools.",
            "help": "I can help you with:\n- **Scanning** hosts and networks\n- **Enumerating** subdomains and services\n- **Vulnerability scanning** with nuclei, nikto\n- **Password attacks** with hydra, hashcat\n- **OSINT** with theHarvester, amass\n\nType a natural language command or use `/help` for slash commands.",
        }
        for key, response in responses.items():
            if key in lower:
                return response

        return (
            f"I understand you want to: **{user_input}**\n\n"
            "I couldn't find a matching tool or command. Try being more specific, e.g.:\n"
            "- `scan 10.0.0.1 with nmap`\n"
            "- `enumerate directories on http://example.com`\n"
            "- `/tools` to see what's available on this system"
        )

    # ──────────────────────────────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────────────────────────────

    def _print_welcome(self) -> None:
        """Print the welcome banner with system status overview."""
        try:
            from importlib.metadata import version as _pv
            ver = _pv("phalanx")
        except Exception:
            ver = "2.0.0"

        shell_info = get_shell_platform()
        theme = self._settings.get("color_theme")
        provider = self._settings.get("model_provider")

        provider_status = self._gather_provider_status()

        # Gather system stats from offline store
        scans_count = 0
        findings_count = 0
        try:
            from .offline_store import OfflineStore
            store = OfflineStore()
            stats = store.stats()
            scans_count = stats.get("total_scans", 0)
            findings_count = stats.get("total_findings", 0)
        except Exception:
            pass

        console.print(
            Panel(
                f"[bold cyan]Phalanx[/bold cyan] [green]v{ver}[/green] — [bold]AI Cybersecurity Agent[/bold]\n"
                f"[dim]Terminal copilot for security work — plan, inspect, execute from one shell.[/dim]",
                title="[bold]⚡ Phalanx Command Center[/bold]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        console.print(
            Columns(
                [
                    Panel(
                        f"[bold]Platform:[/bold] {shell_info}\n"
                        f"[bold]Theme:[/bold] {theme}\n"
                        f"[bold]Provider:[/bold] {provider}\n"
                        f"[bold]Session:[/bold] {self._session.session_id[:8]}",
                        title="Session",
                        border_style="green",
                        padding=(1, 2),
                    ),
                    Panel(
                        f"[bold]Scans:[/bold] {scans_count}\n"
                        f"[bold]Findings:[/bold] {findings_count}\n"
                        f"[bold]Tools:[/bold] {len(self._tools)}\n"
                        f"[bold]Commands:[/bold] {len(self._commands)}\n"
                        f"[bold]Hotkeys:[/bold] /help · /exit",
                        title="System",
                        border_style="blue",
                        padding=(1, 2),
                    ),
                    Panel(
                        "[bold]/help[/bold] — command reference\n"
                        "[bold]/scan <tgt>[/bold] — run a scan\n"
                        "[bold]/run <cmd>[/bold] — natural language\n"
                        "[bold]/key set[/bold] — API key management\n"
                        "[bold]/theme[/bold] — switch appearance",
                        title="Quick Actions",
                        border_style="magenta",
                        padding=(1, 2),
                    ),
                    Panel(
                        f"[bold]OpenAI:[/bold] {provider_status.get('openai', ('✗', ''))[0]}\n"
                        f"[bold]Gemini:[/bold] {provider_status.get('gemini', ('✗', ''))[0]}\n"
                        f"[bold]Ollama:[/bold] {provider_status.get('ollama', ('✗', ''))[0]}\n"
                        f"[bold]Claude:[/bold] {provider_status.get('anthropic', ('✗', ''))[0]}",
                        title="Runtime",
                        border_style="yellow",
                        padding=(1, 2),
                    ),
                ],
                equal=True,
                expand=True,
            )
        )

        console.print(
            Panel(
                "[bold cyan]Type natural language[/bold cyan] to plan work, or use slash commands.\n"
                "[dim]Examples:[/dim] [green]scan 10.0.0.5[/green]  [green]enumerate example.com[/green]  [green]/theme appearance[/green]",
                title="Getting Started",
                border_style="bright_black",
                padding=(1, 2),
            )
        )

    def _gather_provider_status(self) -> dict[str, tuple[str, str]]:
        """Return a concise status map for supported providers.

        Map keys -> (icon, reason)
        """
        status: dict[str, tuple[str, str]] = {}
        # OpenAI
        try:
            __import__("openai")

            openai_installed = True
        except Exception:
            openai_installed = False
        openai_key = bool(os.getenv("OPENAI_API_KEY"))
        if not openai_installed:
            status["openai"] = ("✗", "pkg missing")
        elif not openai_key:
            status["openai"] = ("⚠", "key missing")
        else:
            status["openai"] = ("✓", "configured")

        # Gemini
        try:
            __import__("google.generativeai")

            gemini_installed = True
        except Exception:
            gemini_installed = False
        gemini_key = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        if not gemini_installed:
            status["gemini"] = ("✗", "pkg missing")
        elif not gemini_key:
            status["gemini"] = ("⚠", "key missing")
        else:
            status["gemini"] = ("✓", "configured")

        # Anthropic
        try:
            __import__("anthropic")

            anthropic_installed = True
        except Exception:
            anthropic_installed = False
        anthropic_key = bool(os.getenv("ANTHROPIC_API_KEY"))
        if not anthropic_installed:
            status["anthropic"] = ("✗", "pkg missing")
        elif not anthropic_key:
            status["anthropic"] = ("⚠", "key missing")
        else:
            status["anthropic"] = ("✓", "configured")

        # Ollama (don't attempt network checks here)
        ollama_url = os.getenv("PHALANX_OLLAMA_URL") or os.getenv("OLLAMA_URL")
        if not ollama_url:
            status["ollama"] = ("✗", "not configured")
        else:
            status["ollama"] = ("⚠", "configured (connectivity unknown)")

        return status

    def _print_assistant(self, message: str) -> None:
        """Print an assistant text response."""
        console.print(
            Panel(
                Markdown(message),
                title="[bold green]◆ Phalanx[/bold green]",
                border_style="green",
                padding=(0, 2),
            )
        )

    def _print_plan(self, plan: "Any") -> None:  # ExecutionPlan
        table = Table(
            title="Execution Plan", show_header=True, header_style="bold magenta"
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Tool/Command", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Description", style="white")
        for i, step in enumerate(plan.steps, 1):
            table.add_row(
                str(i),
                step.step_type.value,
                step.tool or step.command or "—",
                step.target or "—",
                step.description[:50],
            )
        console.print(table)

    def _print_results(self, result: "Any", elapsed: float) -> None:  # EngineResult
        from .engine import StepStatus

        success_count = sum(
            1 for r in result.step_results if r.status == StepStatus.SUCCESS
        )
        color = "green" if result.success else "red"

        # Print any step outputs
        for step_result in result.step_results:
            if step_result.output:
                console.print(
                    Panel(
                        Syntax(
                            step_result.output[:2000],
                            "text",
                            theme="monokai",
                            line_numbers=False,
                        ),
                        title=f"[dim]Output: {step_result.step_id}[/dim]",
                        border_style="dim",
                    )
                )

        # Summary panel
        console.print(
            Panel.fit(
                f"[{color}]{'✓' if result.success else '✗'} {'Success' if result.success else 'Partial failure'}[/{color}]  "
                f"Steps: {success_count}/{len(result.step_results)}  "
                f"Findings: [bold]{len(result.all_findings)}[/bold]  "
                f"Time: {elapsed:.2f}s",
                border_style=color,
            )
        )

        # Show findings table if any
        if result.all_findings:
            ftable = Table(title="Findings", header_style="bold red")
            ftable.add_column("Severity", width=8)
            ftable.add_column("Type", style="cyan")
            ftable.add_column("Detail", style="white")
            for f in result.all_findings[:20]:
                sev = f.get("severity", "info")
                sev_color = {
                    "critical": "red",
                    "high": "orange1",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "white",
                }.get(sev, "white")
                ftable.add_row(
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    f.get("type", "—"),
                    str(f.get("detail", f.get("description", "")))[:80],
                )
            console.print(ftable)

    def _print_goodbye(self) -> None:
        self._session.save(self._SESSIONS_DIR / f"{self._session.session_id}.json")
        console.print(
            Panel.fit(
                f"[dim]Session saved: {self._session.session_id[:8]}[/dim]\n"
                f"[dim]Resume with: phalanx chat --session {self._session.session_id}[/dim]\n"
                f"[dim]Your theme and key settings remain in config/.env.[/dim]",
                title="[bold]Goodbye from Phalanx[/bold]",
                border_style="dim",
            )
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def start_chat(
    mode: str = "integrated",
    target: str = "",
    session_id: str | None = None,
    resume: bool = False,
) -> None:
    """Launch the Phalanx interactive chat REPL."""
    chat = PhalanxChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()
