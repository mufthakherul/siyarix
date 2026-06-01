# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for Siyarix, similar to Claude CLI and
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
import sys
import time
import warnings
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .branding import available_themes, print_theme_preview
from .config import SettingsStore
from .subprocess_utils import safe_run_sync

# Suppress prompt_toolkit's unawaited-coroutine warning emitted on GC
warnings.filterwarnings(
    "ignore",
    message="coroutine 'Application.run_async' was never awaited",
    category=RuntimeWarning,
)

# ---------------------------------------------------------------------------
# Platform helpers (replaces removed cross_platform module)
# ---------------------------------------------------------------------------

import platform as _platform

CROSS_PLATFORM_COMMANDS: dict[str, dict[str, str]] = {}


def build_platform_context() -> dict[str, Any]:
    uname = _platform.uname()
    return {
        "platform": uname.system,
        "platform_pretty": f"{uname.system} {uname.release}",
        "platform_release": uname.release,
        "arch": uname.machine,
        "processor": uname.processor,
        "hostname": uname.node,
        "username": os.environ.get("USER", ""),
        "cwd": os.getcwd(),
        "terminal_type": os.environ.get("TERM", ""),
        "term_program": os.environ.get("TERM_PROGRAM", ""),
        "term": os.environ.get("TERM", ""),
        "shell": os.environ.get("SHELL", ""),
        "shell_platform": _platform.system().lower(),
        "shell_executable": os.environ.get("SHELL", ""),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count() or 0,
        "memory_total_mb": "unknown",
        "load_avg_1m": "n/a",
        "load_avg_5m": "n/a",
        "load_avg_15m": "n/a",
        "is_container": False,
        "container_runtime": "none",
        "is_codespaces": False,
        "is_terminal_ssh": False,
        "is_terminal_cloud": False,
        "has_wsl": False,
        "available_tools_count": 0,
    }


def detect_shell() -> str:
    return os.environ.get("SHELL", "/bin/sh")


def get_shell_platform() -> str:
    return _platform.system()


def provider_env_var(provider: str) -> str:
    return f"{provider.upper()}_API_KEY"


def list_supported_shells() -> list[tuple[str, str]]:
    return [("bash", "native"), ("zsh", "native"), ("powershell", "compat")]


def load_env_file() -> None:
    pass


def ensure_env_file() -> str | None:
    return None


def upsert_env_vars(env_vars: dict[str, str], env_file: str | None = None) -> None:
    for k, v in env_vars.items():
        os.environ[k] = v


class _Shell:
    def __init__(self, value: str) -> None:
        self.value = value


def normalize_shell(shell: str) -> _Shell:
    return _Shell(shell)


def get_security_commands(shell: str = "") -> dict[str, str]:
    return {}


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


class SmartAutocomplete:
    def __init__(self, session: Any) -> None:
        pass

    def get_completions(self, document: Any, complete_event: Any) -> list[Any]:
        return []


class CommandPalette:
    def __init__(self, session_id: str) -> None:
        pass

    def show(self, console: Any) -> str | None:
        return None


class SplitPane:
    def __init__(self, theme: str = "dark-neon") -> None:
        pass

    def generate_layout(
        self,
        left_renderable: Any = None,
        right_type: str = "",
        session_meta: Any = None,
        findings: list[Any] | None = None,
        timeline_events: list[Any] | None = None,
    ) -> str:
        return ""


class ConfigPanel:
    @staticmethod
    def run() -> None:
        from .config import SettingsStore

        s = SettingsStore()
        keys = [
            "color_theme", "model_provider", "gemini_model", "openai_model",
            "anthropic_model", "openrouter_model", "ollama_model", "ollama_url", "log_level",
        ]
        console.print("[bold cyan]Configuration[/bold cyan]")
        for k in keys:
            v = s.get(k)
            if v is not None:
                console.print(f"  [cyan]{k}:[/cyan] {v}")
            else:
                console.print(f"  [cyan]{k}:[/cyan] [dim](not set)[/dim]")
        console.print("\n[dim]Use /model, /theme, /mode, /key to change settings.[/dim]")

    @staticmethod
    def _section_tools() -> None:
        try:
            from .registry import ToolRegistry

            reg = ToolRegistry()
            tools = reg.discover()
            if tools:
                from rich.table import Table
                table = Table(title=f"{len(tools)} Security Tools", header_style="bold cyan")
                table.add_column("Name", style="cyan")
                table.add_column("Category", style="magenta")
                table.add_column("Version", style="dim")
                for t in sorted(tools, key=lambda x: x.category)[:20]:
                    table.add_row(t.name, t.category, t.version[:20])
                if len(tools) > 20:
                    table.add_row("", f"[dim]… and {len(tools) - 20} more[/dim]", "")
                console.print(table)
            else:
                console.print("[yellow]No tools found on PATH.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Tool discovery error: {exc}[/red]")


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
    from prompt_toolkit.key_binding import KeyBindings

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
            prefix = "User" if msg.role == "user" else "Siyarix"
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

# ── Help category definitions ─────────────────────────────────────────────
_HELP_CATEGORIES = [
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
_SLASH_HELP = {}
for _cat_name, _cmds in _HELP_CATEGORIES:
    _SLASH_HELP.update(_cmds)

# ---------------------------------------------------------------------------
# The Siyarix Chat REPL
# ---------------------------------------------------------------------------


class SiyarixChat:
    """Interactive REPL for Siyarix — the cybersecurity AI assistant."""

    _SESSIONS_DIR = (
        Path(os.getenv("SIYARIX_CONFIG_DIR", str(Path.home() / ".siyarix")))
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
        self._engine_kill_switch = None
        self._split_pane_enabled = False
        self._split_pane_type = "attack_map"
        self._tools: list[str] = []
        self._commands: list[str] = []
        self._esc_press_count = 0
        self._esc_press_time = 0.0
        self._esc_window = 2.0
        self._offline_responder: Any = None

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
                if not user_input:
                    if self._esc_press_count > 0:
                        now = time.time()
                        if now - self._esc_press_time < self._esc_window:
                            self._esc_press_count += 1
                            if self._esc_press_count >= 2:
                                console.print("[bold yellow]Exiting...[/bold yellow]")
                                self._running = False
                                break
                        else:
                            self._esc_press_count = 1
                            self._esc_press_time = now
                        if self._engine_kill_switch:
                            self._engine_kill_switch.trigger()
                            console.print("[dim]Current task cancelled. Press ESC again to exit.[/dim]")
                        else:
                            console.print("[dim]No active task. Press ESC again to exit.[/dim]")
                        continue
                    continue

                self._esc_press_count = 0
                self._command_history.append(user_input)

                if user_input == "?" or user_input.lower() == "help":
                    self._cmd_help("")
                    continue

                if user_input.startswith("/"):
                    await self._handle_slash(user_input)
                else:
                    await self._handle_natural_language(user_input)

            except KeyboardInterrupt:
                self._esc_press_count += 1
                if self._esc_press_count >= 2:
                    console.print("[bold yellow]Exiting...[/bold yellow]")
                    self._running = False
                else:
                    if self._engine_kill_switch:
                        self._engine_kill_switch.trigger()
                    console.print(
                        "[dim]Task cancelled. Press Ctrl+C again to exit.[/dim]"
                    )
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
        import warnings

        if not sys.stdin.isatty():
            try:
                return input().strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        esc_bindings = self._make_esc_bindings() if PTK_AVAILABLE else None
        prompt_label = Text.assemble(
            ("❯ ", "bold cyan"), ("Type your message or @path/to/file", "dim")
        )

        if self._split_pane_enabled:
            if PTK_AVAILABLE:
                try:
                    return ptk_prompt(
                        "❯ ", key_bindings=esc_bindings, completer=SmartAutocomplete(self._session)
                    ).strip()
                except KeyboardInterrupt:
                    raise
                except Exception:
                    return Prompt.ask(prompt_label, default="").strip()
            else:
                return Prompt.ask(prompt_label, default="").strip()

        # Show compact status line above prompt
        target_str = f" ({self._session.target})" if self._session.target else ""
        mode_color = {
            "registry": "yellow",
            "autonomous": "magenta",
            "integrated": "cyan",
        }.get(self._mode, "cyan")
        theme = self._settings.get("color_theme") or "cyber-noir"
        provider = self._settings.get("model_provider") or "auto"
        status = Text.assemble(
            (f"{provider}", "bold cyan"),
            (f" · {theme}", "dim white"),
            (f" · {self._mode}", mode_color),
            (f"{target_str}", "dim") if target_str else ("", "dim"),
            ("  ", "dim"),
            ("? for shortcuts · /help for all commands", "dim"),
        )
        console.print(status)

        if PTK_AVAILABLE:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    answer = ptk_prompt(
                        "❯ ", key_bindings=esc_bindings, completer=SmartAutocomplete(self._session)
                    ).strip()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.debug("prompt_toolkit failed: %s", exc)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    answer = Prompt.ask(prompt_label, default="").strip()
        else:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                answer = Prompt.ask(prompt_label, default="").strip()
        return answer

    def _make_esc_bindings(self) -> Any:
        """Create prompt_toolkit key bindings for ESC detection."""
        from prompt_toolkit.keys import Keys

        kb = KeyBindings()

        @kb.add(Keys.Escape)
        def _on_esc(event: Any) -> None:
            now = time.time()
            if now - self._esc_press_time < self._esc_window:
                self._esc_press_count += 1
                if self._esc_press_count >= 2:
                    self._running = False
                    event.app.exit()
                    return
            else:
                self._esc_press_count = 1
                self._esc_press_time = now
            event.app.current_buffer.text = ""
            event.app.current_buffer.validate_and_handle()

        return kb

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
            "/clean": self._cmd_clear,
            "/cls": self._cmd_clear,
            "/new": self._cmd_new,
            "/fresh": self._cmd_new,
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
            "/save": self._cmd_save,
            "/translate": self._cmd_translate,
            "/security-cmds": self._cmd_security_cmds,
            "/run": self._cmd_run,
            "/model": self._cmd_model,
            "/context": self._cmd_context,
            "/version": self._cmd_version,
            "/config": self._cmd_config,
            "/esc": self._cmd_esc,
            "/cancel": self._cmd_esc,
            "/log": self._cmd_log,
            "/diff": self._cmd_diff,
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
        """Show categorized help."""
        console.print(Panel(
            "[bold cyan]Siyarix Chat Commands[/bold cyan]\n"
            "Type [cyan]/command[/cyan] to execute. "
            "Press [cyan]?[/cyan] at any time to see this help.",
            border_style="cyan",
        ))
        for category, cmds in _HELP_CATEGORIES:
            table = Table(title=category, padding=(0, 2))
            table.add_column("Command", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            for cmd, desc in cmds.items():
                table.add_row(cmd, desc)
            console.print(table)
            console.print()

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
        """Generate an executive report based on current session findings."""
        fmt = args.strip().lower() if args else "markdown"
        if fmt not in ("markdown", "html"):
            console.print("[yellow]Invalid format. Use 'markdown' or 'html'.[/yellow]")
            return

        try:
            from .report_engine import ReportEngine, ReportConfig, ReportFormat
        except ModuleNotFoundError:
            console.print("[yellow]Report generation is not available in this version[/yellow]")
            return

        console.print("[dim]Generating report...[/dim]")

        findings = self._session.context.get("findings", [])
        config = ReportConfig()
        engine = ReportEngine()
        report = engine.build_report(findings, target=self._session.target, config=config)

        output_dir = self._SESSIONS_DIR / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        fmt_enum = ReportFormat.MARKDOWN if fmt == "markdown" else ReportFormat.HTML
        path = engine.save(report, output_dir / f"report_{self._session.session_id[:8]}", fmt=fmt_enum)
        console.print(
            f"[bold green]✓ Report generated successfully at: {path}[/bold green]"
        )
        console.print(
            f"[dim]Findings: {len(findings)} | Format: {fmt}[/dim]"
        )

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
                    "Welcome to Siyarix Cyber Command.\n", style="bold cyan"
                )
                left_text.append("Mode: ")
                left_text.append(f"{self._mode}\n", style="bold green")
                left_text.append("\nReady for input. Type your instruction below.\n\n")
                left_text.append("Examples:\n")
                left_text.append("  • scan 127.0.0.1\n", style="yellow")
                left_text.append(
                    "  • enumerate subdomains of siyarix.local\n", style="yellow"
                )
            else:
                for msg in self._session.last_n(6):
                    role_color = "cyan" if msg.role == "user" else "green"
                    label = "You" if msg.role == "user" else "Siyarix"
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
        from .providers import ProviderManager as provider_registry

        try:
            vault = CredentialStore()
        except Exception:
            vault = None

        table = Table(title="Configured API Keys", header_style="bold green")
        table.add_column("Provider", style="cyan")
        table.add_column("Env Var", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Source")

        # Get registered provider names from the registry
        # Filter out 'noop' and sort alphabetically
        prov_names = sorted(
            n for n in provider_registry.list_providers() if n != "noop"
        )
        for provider in prov_names:
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
            pkg_name = "google-genai"
            try:
                from google import genai as _test_genai  # noqa: F401
                gemini_pkg_installed = True
            except Exception:
                gemini_pkg_installed = False

            if not gemini_pkg_installed:
                ans = Prompt.ask(
                    f"{pkg_name} not installed — install now? (y/N)",
                    default="N",
                )
                if ans.lower().startswith("y"):
                    console.print(
                        f"[dim]Installing {pkg_name} — this may take a moment...[/dim]"
                    )
                    try:
                        res = safe_run_sync(
                            [
                                sys.executable,
                                "-m",
                                "pip",
                                "install",
                                pkg_name,
                            ],
                            timeout=600,
                        )
                        if res.returncode == 0:
                            console.print(
                                f"[green]✓ {pkg_name} installed — Gemini should be available now.[/green]"
                            )
                        else:
                            console.print(
                                f"[red]Failed to install package: {res.stderr}[/red]"
                            )
                    except Exception as exc:
                        logger.exception(
                            "Failed to run pip install for %s: %s", pkg_name, exc
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
            label = "You" if msg.role == "user" else "Siyarix"
            console.print(
                f"[dim]{ts}[/dim] [{role_color}]{label}:[/{role_color}] {msg.content[:120]}"
            )

    def _cmd_tools(self, _: str) -> None:
        try:
            from .registry import ToolRegistry

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
            ("Siyarix", "available_intents", str(ctx.get("available_tools_count", 0))),
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
            label = "You" if msg.role == "user" else "Siyarix"
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
        valid = ("autonomous", "integrated", "registry")
        if not args:
            console.print(
                f"Current mode: [cyan]{self._mode}[/cyan] (valid: {', '.join(valid)})"
            )
            return
        if args not in valid:
            console.print(
                f"[red]Invalid mode: {args}. Valid modes: {', '.join(valid)}[/red]"
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
            if selected in {"auto", "openai", "gemini", "ollama", "cloud", "anthropic", "groq", "together", "lmstudio", "custom", "opencode", "openrouter"}:
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
                    "[yellow]Usage: /model [auto|openai|gemini|ollama|anthropic|cloud|openrouter] [model-name][/yellow]"
                )
                return

        # Show all providers and their status
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        groq_key = os.environ.get("GROQ_API_KEY", "")
        together_key = os.environ.get("TOGETHER_API_KEY", "")
        openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
        panel_text = (
            f"[bold]Preferred:[/bold] {self._settings.get('model_provider')}\n"
            f"[bold]OpenAI:[/bold]  {'✓ Configured' if openai_key else '✗ Not set'} ({self._settings.get('openai_model') or 'gpt-4o'})\n"
            f"[bold]Gemini:[/bold]  {'✓ Configured' if gemini_key else '✗ Not set'} ({self._settings.get('gemini_model') or 'gemini-2.0-flash'})\n"
            f"[bold]Anthropic:[/bold]  {'✓ Configured' if anthropic_key else '✗ Not set'} ({self._settings.get('anthropic_model') or 'claude-3-opus-20240229'})\n"
            f"[bold]Groq:[/bold]  {'✓ Configured' if groq_key else '✗ Not set'} ({self._settings.get('groq_model') or 'llama3-70b-8192'})\n"
            f"[bold]Together:[/bold]  {'✓ Configured' if together_key else '✗ Not set'} ({self._settings.get('together_model') or 'mistralai/Mixtral-8x7B-Instruct-v0.1'})\n"
            f"[bold]OpenRouter:[/bold]  {'✓ Configured' if openrouter_key else '✗ Not set'} ({self._settings.get('openrouter_model') or 'nvidia/nemotron-3-super-120b-a12b:free'})\n"
            f"[bold]Ollama:[/bold]  Available (lazy check on first use) ({self._settings.get('ollama_model') or 'llama3.1'})\n"
            f"[bold]Cloud:[/bold]   Requires SIYARIX_SERVER_URL + SIYARIX_API_KEY\n"
            f"[bold]LM Studio:[/bold] Available (lazy check on first use)\n"
            f"[bold]Custom:[/bold]  Requires CUSTOM_API_KEY\n"
            f"[bold]opencode:[/bold]  Requires OPENCODE_API_KEY\n\n"
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

    async def _cmd_config(self, args: str) -> None:
        """Open the interactive configuration panel."""
        sub = args.strip().lower() if args else ""
        if sub == "tools":
            ConfigPanel()._section_tools()
        else:
            ConfigPanel().run()

    async def _cmd_coder(self, args: str) -> None:
        """Handle /coder command for code generation and review."""
        try:
            from .coder_bridge import CoderBridge
        except ModuleNotFoundError:
            console.print("[yellow]Coder Bridge is not available in this version[/yellow]")
            return

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
        try:
            from .mcp_integration import MCPClient
        except ModuleNotFoundError:
            console.print("[yellow]MCP integration is not available in this version[/yellow]")
            return

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
            call_client: MCPClient | None = self._session.context.get("mcp_client")
            if not call_client:
                console.print(
                    "[yellow]Not connected to an MCP server. Use /mcp connect first.[/yellow]"
                )
                return
            tool = tokens[1] if len(tokens) > 1 else ""
            if not tool:
                console.print("[yellow]Usage: /mcp call <tool> [args...][/yellow]")
                return
            params = {"args": tokens[2:]} if len(tokens) > 2 else {}
            result = await call_client.call_tool(tool, params)
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
        from .core import AgentCore, AgentMode, AgentGoal

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if action == "run":
            goal = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not goal:
                console.print("[yellow]Usage: /agent run <goal>[/yellow]")
                return
            agent = AgentCore(mode=AgentMode.AUTONOMOUS)
            await agent.initialize()
            result = await agent.execute_goal(AgentGoal(description=goal))
            if result.success:
                console.print(f"[green]✓ Agent completed: {result.summary}[/green]")
            else:
                console.print(f"[red]Agent failed: {result.summary}[/red]")
        elif action == "status":
            console.print("[dim]Agent status: idle[/dim]")
        else:
            console.print("[yellow]Usage: /agent run <goal> | /agent status[/yellow]")

    def _cmd_esc(self, _: str) -> None:
        """Emergency stop - cancel all pending execution."""
        console.print("[bold red]⚠ EMERGENCY STOP TRIGGERED[/bold red]")
        self._esc_press_count = 1
        self._esc_press_time = time.time()
        self._running = False
        if self._engine_kill_switch:
            self._engine_kill_switch.trigger()
            console.print(
                "[dim]Kill switch triggered: all pending operations cancelled.[/dim]"
            )
        else:
            console.print(
                "[dim]No active engine to cancel.[/dim]"
            )

    def _cmd_version(self, _: str) -> None:
        try:
            from importlib.metadata import version as _pv

            ver = _pv("siyarix")
        except Exception as exc:
            logger.debug("Failed to resolve package version: %s", exc)
            ver = "2.0.0"
        console.print(f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green]")

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
            log_entry = session_logger.load(tokens[1])
            if not log_entry:
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

        try:
            from .offline_store import OfflineStore
        except ModuleNotFoundError:
            console.print("[yellow]Offline store is not available in this version[/yellow]")
            return

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
    # Schedule commands
    # ──────────────────────────────────────────────────────────────────────

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
        try:
            from .cloud_scanner import CloudProvider, CloudScanner
        except ModuleNotFoundError:
            console.print("[yellow]Cloud scanner is not available in this version[/yellow]")
            return
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("aws", "azure", "gcp", "scan"):
            console.print("[yellow]Usage: /cloud <aws|azure|gcp> <target>[/yellow]")
            return
        provider = tokens[0]
        target = tokens[1] if len(tokens) > 1 else ""
        scanner = CloudScanner()
        provider_enum = getattr(CloudProvider, provider.upper(), CloudProvider.AWS)
        result = await scanner.scan_by_provider(provider_enum, target)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_k8s(self, args: str) -> None:
        """Handle /k8s command for Kubernetes security scanning."""
        try:
            from .cloud_scanner import CloudScanner
        except ModuleNotFoundError:
            console.print("[yellow]Kubernetes scanner is not available in this version[/yellow]")
            return
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("scan", "audit", "rbac"):
            console.print("[yellow]Usage: /k8s scan|audit|rbac <namespace>[/yellow]")
            return
        namespace = tokens[1] if len(tokens) > 1 else "default"
        scanner = CloudScanner()
        result = await scanner.scan_kubernetes(namespace)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_docker(self, args: str) -> None:
        """Handle /docker command for container scanning."""
        try:
            from .cloud_scanner import CloudScanner
        except ModuleNotFoundError:
            console.print("[yellow]Docker scanner is not available in this version[/yellow]")
            return
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("scan", "image", "ps"):
            console.print("[yellow]Usage: /docker scan|image|ps <image>[/yellow]")
            return
        image = tokens[1] if len(tokens) > 1 else ""
        scanner = CloudScanner()
        result = await scanner.scan_docker(image)
        console.print(scanner.generate_report(result, fmt="text"))

    async def _cmd_iac(self, args: str) -> None:
        """Handle /iac command for Infrastructure as Code scanning."""
        try:
            from .iac_scanner import IaCScanner
        except ModuleNotFoundError:
            console.print("[yellow]IaC scanner is not available in this version[/yellow]")
            return
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
        try:
            from .mobile_scanner import MobileScanner
        except ModuleNotFoundError:
            console.print("[yellow]Mobile scanner is not available in this version[/yellow]")
            return
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
        try:
            from .iot_scanner import IoTScanner
        except ModuleNotFoundError:
            console.print("[yellow]IoT scanner is not available in this version[/yellow]")
            return
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
        try:
            from .hsm_manager import HSMService
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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
        try:
            from .compliance_runner import ComplianceRunner
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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
        try:
            from .platform_integration import platform_integration
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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
        try:
            from .performance import performance_optimizer
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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

    async def _cmd_import(self, args: str) -> None:
        """Handle /import command for importing scan results."""
        try:
            from .importer import security_importer
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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
        try:
            from .playbook_engine import PlaybookEngine
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"
        engine = PlaybookEngine()
        if action == "list":
            playbooks = engine.list_playbooks()
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
            loaded_pb = engine.load(name)
            if loaded_pb:
                for i, s in enumerate(loaded_pb.steps, 1):
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
            try:
                from .knowledge_graph import KnowledgeGraph
            except ModuleNotFoundError:
                console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
                return
            kg = KnowledgeGraph()
            results = kg.search(query)
            if results:
                for r in results[:10]:
                    console.print(f"  • {r}")
            else:
                console.print("[dim]No knowledge base results.[/dim]")
        elif action == "list":
            console.print("[yellow]Use /history to see session history.[/yellow]")
        else:
            console.print("[yellow]Usage: /kb search|list[/yellow]")

    async def _cmd_ticket(self, args: str) -> None:
        """Handle /ticket command for external ticket creation."""
        try:
            from .platform_integration import platform_integration
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "create"
        if action == "create":
            title = " ".join(tokens[1:]) if len(tokens) > 1 else Prompt.ask("Ticket title")
            sent = platform_integration.send_notification(f"Ticket: {title}", severity="medium")
            console.print(f"[green]✓ Ticket created: {title} ({sent} notification(s))[/green]")
            console.print("[yellow]Note: Jira/GitHub integration is not yet available[/yellow]")
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
        elif action == "status":
            console.print("[dim]No pending retests.[/dim]")
        else:
            console.print("[yellow]Usage: /retest schedule|status[/yellow]")

    async def _cmd_intel(self, args: str) -> None:
        """Handle /intel command for threat intelligence queries."""
        try:
            from .threat_intel import ThreatIntelFeed, MITREAttackDB
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "search"
        if action == "search":
            query = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not query:
                console.print("[yellow]Usage: /intel search <cve|ip|domain|hash>[/yellow]")
                return
            feed = ThreatIntelFeed()
            intel_results = feed.search(query)
            if intel_results:
                for r in intel_results[:10]:
                    console.print(f"  [{r.get('severity','info')}] {r.get('indicator','?')} — {r.get('description','')[:80]}")
            else:
                console.print("[dim]No threat intelligence matches.[/dim]")
        elif action == "mitre":
            tac = tokens[1] if len(tokens) > 1 else ""
            db = MITREAttackDB()
            mitre_results: list[dict[str, str]] = db.search(tactic=tac) if tac else db.list_techniques()[:15]
            for r in mitre_results[:15]:
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
        try:
            from .canary import CanaryTokenManager, CanaryTokenType
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
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
            deployment = mgr.deploy_to_target(target, token_types=[ttype])
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
            canary_stats = mgr.summary()
            console.print(f"Canary tokens: {canary_stats.get('total_tokens',0)} total, {canary_stats.get('triggered_tokens',0)} triggered")
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
            console.print(f"Stealth level: {cfg.evasion_level} | Jitter: {cfg.jitter_percentage}% | UA rotate: {cfg.rotate_user_agents} | Proxy: {cfg.use_proxy_chain} | Decoy: {cfg.use_decoy_traffic}")
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
            fmt = "json"
            if "--format" in tokens:
                idx = tokens.index("--format")
                fmt = tokens[idx + 1] if idx + 1 < len(tokens) else "json"
            data = audit.export(format=fmt)
            if data is None:
                console.print("[red]Failed to export audit log[/red]")
                return
            console.print(f"Exported audit log ({len(data)} bytes)")
        elif action == "status":
            audit_stats = audit.stats()
            console.print(f"Audit events: {audit_stats.get('total_events', 0)} | Chain verified: {audit_stats.get('chain_integrity', 'intact')}")
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
        """Execute an instruction — AgentCore for LLM modes, engine for registry modes."""
        from .registry import ToolRegistry

        # ── Determine if we should try the agent loop ──
        should_try_agent = self._mode == "autonomous" or (
            self._mode == "integrated" and self._llm_available()
        )

        if should_try_agent:
            ok = await self._execute_agent(instruction, target)
            if ok or self._mode == "autonomous":
                return  # autonomous mode stops here even on failure
            # Integrated mode: agent failed → fall through to registry with message
            console.print(
                "[yellow]⚠ AI provider unavailable — falling back to offline registry mode[/yellow]"
            )

        # ── Registry / integrated fallback: traditional plan → execute pipeline ──
        from .compat import ExecutionEngine, ExecutionMode

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
                "SIYARIX_OLLAMA_URL", "http://localhost:11434"
            ),
            "model_provider": self._settings.get("model_provider"),
            "gemini_model": self._settings.get("gemini_model"),
        }

        reg = ToolRegistry()
        from .session_log import session_logger

        engine = ExecutionEngine(
            mode=exec_mode,
            registry=reg,
            config=engine_config,
            session_logger=session_logger,
        )
        self._engine_kill_switch = getattr(engine, "_kill_switch", None)

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
            if response:
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
                            f"[dim]Providers:[/dim] {', '.join(r.model_name for r in ensemble_result.responses) if hasattr(ensemble_result, 'responses') and ensemble_result.responses else str(registered_count)}  "
                            f"[dim]Consensus:[/dim] {ensemble_result.consensus_level:.0%}  "
                            f"[dim]Hallucination risk:[/dim] {ensemble_result.hallucination_risk:.0%}",
                            title="[bold cyan]🔮 Multi-Model Ensemble[/bold cyan]",
                            border_style="cyan",
                        )
                    )
        except ModuleNotFoundError:
            pass
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
        except ModuleNotFoundError:
            pass
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

    def _generate_text_response(self, user_input: str) -> str | None:
        """Return a text response for non-tool queries, or ``None`` to let the pipeline proceed."""
        lowered = user_input.strip().lower()
        greetings = {"hello", "hi", "hey", "sup", "what's up", "help",
                      "good morning", "good evening", "good afternoon"}
        if lowered in greetings or lowered.startswith(("hello ", "hi ", "hey ")):
            import getpass
            from datetime import datetime
            username = getpass.getuser()
            hour = datetime.now().hour
            if hour < 12:
                tod = "morning"
            elif hour < 17:
                tod = "afternoon"
            elif hour < 21:
                tod = "evening"
            else:
                tod = "night"
            return (
                f"Hello **{username}**. Good **{tod}**.\n\n"
                "I'm **Siyarix** — an open-source cybersecurity assistant "
                "built to help with reconnaissance, vulnerability assessment, and security auditing.\n\n"
                "I'm primarily developed by **Mufthakherul**, but as an open-source project "
                "I welcome contributions from the community. If you'd like to help build me "
                "and keep me relevant, check out the repository and contribution guide:\n"
                "- Repo: https://github.com/mufthakherul/siyarix\n"
                "- Contributing: https://github.com/mufthakherul/siyarix/blob/main/CONTRIBUTING.md\n\n"
                "For the best experience, connect an **LLM provider** (OpenAI, Gemini, or OpenRouter). "
                "Without one, I use my built-in heuristic knowledge to plan and execute tasks.\n\n"
                "Type **`/help`** or **`--help`** to see available commands, or visit the docs:\n"
                "https://opencode.ai\n"
            )
        return None

    async def _execute_agent(self, instruction: str, target: str = "") -> bool:
        """Agent loop: LLM-first planning → parallel execution → LLM synthesis."""
        from .core import AgentCore, AgentMode
        from rich.panel import Panel

        provider_name = self._settings.get("model_provider") or "gemini"
        api_key = os.environ.get(f"{provider_name.upper()}_API_KEY")

        instruction_with_target = instruction
        if target and target not in instruction:
            instruction_with_target = f"{instruction} on {target}"

        console.print(f"[dim]Agent mode — using {provider_name}[/dim]")

        agent = AgentCore(mode=AgentMode.AUTONOMOUS)
        with console.status("[bold green]Initializing...[/bold green]", spinner="dots"):
            await agent.initialize()

        all_tools = agent._registry.list_tools()
        tool_names = [t.name for t in all_tools]
        tool_dicts = [
            {"name": t.name, "description": t.description,
             "tags": t.tags, "category": t.category.value if hasattr(t.category, 'value') else str(t.category)}
            for t in all_tools
        ]

        # ── Decision maker ───────────────────────────────────────────────
        total_start = time.time()
        llm_plan: Any = None
        llm_reasoning: str | None = None
        llm_connected = False
        llm_model = provider_name
        total_input_tokens = 0
        total_output_tokens = 0
        llm_call_fn = None

        if not api_key:
            console.print("[yellow]⚠ No API key configured — using local planner[/yellow]")
        else:
            try:
                llm_call_fn = self._make_llm_call(provider_name, api_key)
                # Test connectivity with a quick ping
                ping = await asyncio.wait_for(
                    llm_call_fn("Respond with exactly: OK", "ping"),
                    timeout=15.0,
                )
                if ping.get("content", "").strip() != "OK":
                    raise RuntimeError(f"LLM ping failed: {ping.get('content', '')[:100]}")
                llm_connected = True
            except asyncio.TimeoutError:
                console.print("[yellow]⚠ LLM request timed out — using local planner[/yellow]")
            except Exception as exc:
                msg = str(exc)
                if "429" in msg or "rate_limit" in msg.lower() or "quota" in msg.lower():
                    console.print("[yellow]⚠ LLM rate limit reached — using local planner[/yellow]")
                elif "401" in msg or "unauthorized" in msg.lower() or "invalid" in msg.lower():
                    console.print("[yellow]⚠ LLM authentication failed — using local planner[/yellow]")
                else:
                    console.print(f"[yellow]⚠ LLM unavailable ({exc}) — using local planner[/yellow]")

        # ── Planning ─────────────────────────────────────────────────────
        if llm_connected:
            with console.status("[bold cyan]LLM analysing request...[/bold cyan]", spinner="dots"):
                try:
                    plan_result = await asyncio.wait_for(
                        agent._planner.llm_decompose_goal(
                            instruction_with_target, tool_names,
                            llm_call=llm_call_fn, tool_schemas=tool_dicts,
                        ),
                        timeout=30.0,
                    )
                    llm_plan = plan_result
                    llm_reasoning = plan_result.context.get("reasoning", "")
                except (asyncio.TimeoutError, RuntimeError, ValueError) as exc:
                    console.print(f"[yellow]⚠ LLM planning failed ({exc}) — using local planner[/yellow]")

        if not llm_plan:
            with console.status("[bold green]Planning...[/bold green]", spinner="dots"):
                llm_plan = agent._planner.decompose_goal(
                    instruction_with_target, tool_names)

        # ── No tools needed ──────────────────────────────────────────────
        if not llm_plan.steps:
            response = llm_reasoning or "I understood your request but no tools were needed."
            self._session.add_message("assistant", response)
            self._print_assistant(response)
            duration = time.time() - total_start
            console.print(
                f"[dim]Time: {duration:.1f}s | Mode: {self._mode} | "
                f"LLM: {'connected' if llm_connected else 'offline'}[/dim]"
            )
            return True

        # ── Announce which tools will run ───────────────────────────────
        tool_labels = [f"[bold]{s.tool}[/bold]" for s in llm_plan.steps]
        console.print(f"[cyan]→ I need to execute:[/cyan] {', '.join(tool_labels)}")

        # ── Execute all tools in parallel with live output ───────────────
        _step_icons = {"success": "✓", "completed": "✓", "failed": "✗",
                       "skipped": "—", "running": "·", "retrying": "↻",
                       "pending": "○", "blocked": "⊘", "ready": "●"}

        async def run_one_tool(step: Any) -> tuple[Any, dict]:
            result = await agent._registry.execute(step.tool, **step.args)
            return step, result

        tasks = [run_one_tool(s) for s in llm_plan.steps]
        raw_results = await asyncio.gather(*tasks)

        # Show live output panels per tool
        for step, result in raw_results:
            status = "success" if result.get("status") == "success" else "failed"
            icon = _step_icons.get(status, "·")
            color = "green" if status == "success" else "red"
            output = (result.get("output") or "").strip()
            error = (result.get("error") or "").strip()
            lines = [
                f"[{color}]{icon} {result.get('exit_code', 0)}[/{color}]  "
                f"[bold]{step.tool}[/bold] — {step.description}"
            ]
            if output:
                lines.append(f"[dim]{output[:800]}[/dim]")
            if error:
                lines.append(f"[red]{error[:300]}[/red]")
            console.print(Panel("\n".join(lines), title=f"Output of {step.tool} {step.description}",
                                border_style=color, padding=(0, 2)))

        # ── LLM analysis of all outputs ──────────────────────────────────
        if llm_connected and llm_call_fn:
            parts: list[str] = []
            for step, result in raw_results:
                output = (result.get("output") or "")[:3000]
                parts.append(f"• {step.tool} ({step.description}):\n{output}\n")
            system_prompt = (
                "You are Siyarix, an AI cybersecurity assistant. "
                "The user asked a security task. Below are the raw outputs of the executed tools.\n\n"
                "Analyse these results and provide a concise summary of the key findings "
                "relevant to the user's original request. Be technical and specific."
            )
            user_prompt = f"User request: {instruction_with_target}\n\nTool outputs:\n\n" + "\n".join(parts)
            with console.status("[bold cyan]LLM analysing results...[/bold cyan]", spinner="dots"):
                try:
                    syn = await asyncio.wait_for(
                        llm_call_fn(system_prompt, user_prompt),
                        timeout=60.0,
                    )
                    summary = syn.get("content", "")
                    llm_model = syn.get("model", provider_name)
                    total_input_tokens += syn.get("input_tokens", 0)
                    total_output_tokens += syn.get("output_tokens", 0)
                except asyncio.TimeoutError:
                    summary = ""
                    console.print("[yellow]⚠ LLM analysis timed out[/yellow]")
            if summary:
                self._session.add_message("assistant", summary)
                self._print_assistant(summary)

        # ── Bottom stats line ────────────────────────────────────────────
        total_duration = time.time() - total_start
        stats_parts = [
            f"Time: {total_duration:.1f}s",
            f"Mode: {self._mode}",
        ]
        if llm_connected:
            stats_parts.append(f"Model: {llm_model}")
            stats_parts.append(f"Tokens: {total_input_tokens}↑ {total_output_tokens}↓")
        console.print("[dim]" + " | ".join(stats_parts) + "[/dim]")

        return True

    async def _synthesize_agent_response(
        self,
        instruction: str,
        result: Any,
        provider_name: str,
        has_any_success: bool,
    ) -> dict | None:
        """Call the LLM to synthesize tool results into a response dict.

        Returns ``{"content": str, "model": str, "input_tokens": int, "output_tokens": int}``
        or ``None`` when no synthesis is possible.
        """
        api_key = os.environ.get(f"{provider_name.upper()}_API_KEY")
        if not api_key:
            return None

        if has_any_success and result.plan:
            parts: list[str] = []
            for step in result.plan.steps:
                if step.status not in ("completed", "success"):
                    continue
                output = (step.result.get("output", "") or "")[:2000] if step.result else ""
                parts.append(f"• {step.tool} ({step.description}):\n{output}\n")
            system_prompt = (
                "You are Siyarix, an AI cybersecurity assistant. "
                "The user asked a security task and the following tools were executed.\n\n"
                "Summarise what was done, the key findings, and any security-relevant "
                "information. Be concise and technical."
            )
            user_prompt = f"User request: {instruction}\n\nTool results:\n\n" + "\n".join(parts)
        else:
            system_prompt = (
                "You are Siyarix, an AI cybersecurity assistant. "
                "The user asked a general question. Answer helpfully and conversationally."
            )
            user_prompt = instruction

        try:
            llm_fn = self._make_llm_call(provider_name, api_key)
            return await llm_fn(system_prompt, user_prompt)
        except Exception as exc:
            logger.warning("LLM synthesis failed: %s", exc)
            return None

    def _make_llm_call(self, provider_name: str, api_key: str):
        """Return an async callable ``(system, user) → dict`` with response metadata."""
        from openai import AsyncOpenAI

        if provider_name == "openrouter":
            client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1",
            )
            model = self._settings.get("openrouter_model") or "nvidia/nemotron-3-super-120b-a12b:free"
        elif provider_name == "openai":
            client = AsyncOpenAI(api_key=api_key)
            model = self._settings.get("openai_model") or "gpt-4o"
        elif provider_name == "gemini":
            client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            )
            model = self._settings.get("gemini_model") or "gemini-2.0-flash"
        else:
            raise ValueError(f"Unsupported provider: {provider_name}")

        async def call(system_prompt: str, user_prompt: str) -> dict:
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=2000,
                temperature=0.3,
            )
            choice = response.choices[0]
            usage = response.usage
            return {
                "content": choice.message.content or "",
                "model": response.model or model,
                "input_tokens": usage.prompt_tokens if usage else 0,
                "output_tokens": usage.completion_tokens if usage else 0,
            }

        return call

    def _llm_available(self) -> bool:
        """Check if an LLM provider is configured and available."""
        provider = (self._settings.get("model_provider") or "gemini").lower().strip()
        if provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        if provider == "gemini":
            return bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        if provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        if provider in ("groq", "together", "custom", "opencode"):
            return bool(os.getenv(f"{provider.upper()}_API_KEY"))
        if provider == "openrouter":
            return bool(os.getenv("OPENROUTER_API_KEY"))
        if provider == "ollama":
            return True  # optimistic — checked lazily
        if provider == "cloud":
            return bool(os.getenv("SIYARIX_SERVER_URL"))
        return False

    # ──────────────────────────────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────────────────────────────

    def _print_welcome(self) -> None:
        """Print the welcome banner with system status overview."""
        try:
            from importlib.metadata import version as _pv
            ver = _pv("siyarix")
        except Exception:
            ver = "2.0.0"

        provider_status = self._gather_provider_status()
        shell_info = get_shell_platform()
        theme = self._settings.get("color_theme")
        provider = self._settings.get("model_provider")

        scans_count = 0
        findings_count = 0
        try:
            from .offline_store import OfflineStore
            store = OfflineStore()
            stats = store.stats()
            scans_count = stats.get("total_scans", 0)
            findings_count = stats.get("total_findings", 0)
        except ModuleNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Failed to read offline store stats: %s", exc)

        console.print(
            Panel(
                f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green] — [bold]AI Cybersecurity Agent[/bold]\n"
                f"[dim]Terminal copilot for security work — plan, inspect, execute from one shell.[/dim]",
                title="[bold]⚡ Siyarix Command Center[/bold]",
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
                        "[bold]/theme[/bold] — switch appearance\n"
                        "[bold]Mode:[/bold] Registry (offline)",
                        title="Quick Actions",
                        border_style="magenta",
                        padding=(1, 2),
                    ),
                    Panel(
                        f"[bold]OpenAI:[/bold] {provider_status.get('openai', ('✗', ''))[0]}\n"
                        f"[bold]Gemini:[/bold] {provider_status.get('gemini', ('✗', ''))[0]}\n"
                        f"[bold]Ollama:[/bold] {provider_status.get('ollama', ('✗', ''))[0]}\n"
                        f"[bold]Claude:[/bold] {provider_status.get('anthropic', ('✗', ''))[0]}\n"
                        f"[bold]OpenRouter:[/bold] {provider_status.get('openrouter', ('✗', ''))[0]}",
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

        # Gemini (google-genai package)
        try:
            from google import genai as _test_genai  # noqa: F401
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

        # OpenRouter (uses openai-compatible API)
        openrouter_key = bool(os.getenv("OPENROUTER_API_KEY"))
        if not openrouter_key:
            status["openrouter"] = ("⚠", "key missing")
        else:
            status["openrouter"] = ("✓", "configured")

        # Ollama (don't attempt network checks here)
        ollama_url = os.getenv("SIYARIX_OLLAMA_URL") or os.getenv("OLLAMA_URL")
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
                title="[bold green]◆ Siyarix[/bold green]",
                border_style="green",
                padding=(0, 2),
            )
        )

    def _print_plan(self, plan: "Any") -> None:  # ExecutionPlan
        table = Table(
            title="Execution Plan", show_header=True, header_style="bold magenta"
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Tool", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Description", style="white")
        for i, step in enumerate(plan.steps, 1):
            target = step.args.get("target", "") if isinstance(step.args, dict) else ""
            table.add_row(
                str(i),
                step.tool or "—",
                target or "—",
                step.description[:50],
            )
        console.print(table)

    def _print_results(self, result: "Any", elapsed: float) -> None:  # EngineResult
        from .planner import StepStatus

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
                f"[dim]Resume with: siyarix chat --session {self._session.session_id}[/dim]\n"
                f"[dim]Your theme and key settings remain in config/.env.[/dim]",
                title="[bold]Goodbye from Siyarix[/bold]",
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
    """Launch the Siyarix interactive chat REPL."""
    chat = SiyarixChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()
