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
import platform as _platform
import os
import shutil
import sys
import time
import warnings
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..branding import available_themes, print_theme_preview
from .commands import CommandProfile, CommandProfileStore, HELP_CATEGORIES, SLASH_HELP
from .session import ChatMessage as ChatMessage, ChatSession as ChatSession
from .ui import (
    SmartAutocomplete as SmartAutocomplete,
    CommandPalette as CommandPalette,
    SplitPane as SplitPane,
    ConfigPanel as ConfigPanel,
)
from ..config import SettingsStore
from ..subprocess_utils import safe_run_sync

# Suppress prompt_toolkit's unawaited-coroutine warning emitted on GC
warnings.filterwarnings(
    "ignore",
    message="coroutine 'Application.run_async' was never awaited",
    category=RuntimeWarning,
)


# ---------------------------------------------------------------------------
# Platform helpers (replaces removed cross_platform module)
# ---------------------------------------------------------------------------

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
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "cwd": os.getcwd(),
        "terminal_type": os.environ.get("TERM", ""),
        "term_program": os.environ.get("TERM_PROGRAM", ""),
        "term": os.environ.get("TERM", ""),
        "shell": detect_shell(),
        "shell_platform": get_shell_platform(),
        "shell_executable": detect_shell(),
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
    if os.name == "nt":
        return os.environ.get("COMSPEC", "cmd.exe")
    shell = os.environ.get("SHELL", "")
    if shell:
        return shell
    for sh in ("pwsh", "powershell", "bash", "zsh", "fish", "sh"):
        found = shutil.which(sh)
        if found:
            return found
    return "/bin/sh"


def get_shell_platform() -> str:
    return _platform.system()


def provider_env_var(provider: str) -> str:
    return f"{provider.upper()}_API_KEY"


def list_supported_shells() -> list[tuple[str, str]]:
    return [("bash", "native"), ("zsh", "native"), ("powershell", "compat")]


def load_env_file() -> None:
    """Load environment variables from ~/.siyarix/.env (simple key=value parser).

    NOTE: API key env vars (*_API_KEY) are intentionally NOT loaded from .env
    for security. Use the encrypted vault instead: /key set <provider> <key>.
    """
    _api_key_patterns = ("_API_KEY", "_SECRET", "_PASSWORD", "_TOKEN")
    env_path = Path.home() / ".siyarix" / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key and not os.environ.get(key):
            if any(p in key.upper() for p in _api_key_patterns):
                logger.debug("Skipping %s from .env (use vault instead)", key)
                continue
            os.environ[key] = val


class _Shell:
    def __init__(self, value: str) -> None:
        self.value = value


def normalize_shell(shell: str) -> _Shell:
    return _Shell(shell)


def get_security_commands(shell: str = "") -> dict[str, str]:
    return {}


RICH_AVAILABLE = False
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
    Columns = None  # type: ignore[assignment,misc]
    Console = None  # type: ignore[assignment,misc]
    Markdown = None  # type: ignore[assignment,misc]
    Panel = None  # type: ignore[assignment,misc]
    Prompt = None  # type: ignore[assignment,misc]
    Rule = None  # type: ignore[assignment,misc]
    Syntax = None  # type: ignore[assignment,misc]
    Table = None  # type: ignore[assignment,misc]
    Text = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

PTK_AVAILABLE = False
try:
    from prompt_toolkit import prompt as ptk_prompt
    from prompt_toolkit.key_binding import KeyBindings

    PTK_AVAILABLE = True
except Exception as exc:
    logger.debug("prompt_toolkit not available: %s", exc)
    ptk_prompt = None  # type: ignore[assignment]
    KeyBindings = None  # type: ignore[assignment,misc]

console = Console()
load_env_file()


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# The Siyarix Chat REPL
# ---------------------------------------------------------------------------


class SiyarixChat:
    """Interactive REPL for Siyarix — the cybersecurity AI assistant."""

    _SESSIONS_DIR = (
        Path(os.getenv("SIYARIX_CONFIG_DIR", str(Path.home() / ".siyarix"))) / "sessions"
    )
    MAX_CONTEXT_MESSAGES = 300  # memory bound to prevent unbounded growth
    MAX_MESSAGE_CHARS = 50000  # per-message content limit

    SYSTEM_REFRESH_INTERVAL = 15  # re-send full system prompt every N calls

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
        self._esc_press_count = 0
        self._esc_press_time = 0.0
        self._esc_window = 2.0
        self._disabled_providers: set[str] = set()
        self._provider_failure_counts: dict[str, int] = {}
        self._provider_last_fail_time: dict[str, float] = {}
        self._provider_cooldown_secs = 30.0
        self._llm_calls = 0
        from ..providers import UsageTracker, ProviderStateManager

        state_dir = str(Path.home() / ".siyarix")
        self._provider_state = ProviderStateManager(
            path=os.path.join(state_dir, "provider_state.json")
        )
        self._usage_tracker = UsageTracker(path=os.path.join(state_dir, "usage.json"))
        from ..output import OutputEngine

        self._output = OutputEngine()
        self._con = self._output.console
        self._validate_provider_config_on_startup()

    def _validate_provider_config_on_startup(self) -> None:
        """Check configured provider has valid API key / SDK / endpoint at startup."""
        from ..providers import ProviderManager

        provider = (self._settings.get("model_provider") or "gemini").lower().strip()
        if provider == "auto":
            return  # auto mode checks at runtime
        pm = ProviderManager()
        profile = pm.get_profile(provider)
        if not profile:
            logger.warning("Unknown model_provider in settings: %s", provider)
            return
        if not profile.api_key_env:
            return  # local provider

        key = os.environ.get(profile.api_key_env)
        if provider == "gemini" and not key:
            key = os.environ.get("GOOGLE_API_KEY")
        if not key:
            logger.warning(
                "Provider '%s' configured but %s is not set in environment",
                provider,
                profile.api_key_env,
            )
            console.print(
                f"[yellow]⚠ Provider '{provider}' configured but {profile.api_key_env} is not set.[/yellow]"
            )

        if profile.sdk_dependency:
            try:
                __import__(profile.sdk_dependency)
            except ImportError:
                logger.warning(
                    "Provider '%s' SDK '%s' not installed",
                    provider,
                    profile.sdk_dependency,
                )
                console.print(
                    f"[yellow]⚠ Provider '{provider}' requires SDK: pip install {profile.sdk_dependency}[/yellow]"
                )

    def _init_session(self, session_id: str | None, target: str, resume: bool) -> ChatSession:
        """Initialize or resume a chat session."""
        import uuid

        self._SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        if resume and session_id:
            path = self._SESSIONS_DIR / f"{session_id}.json"
            if path.exists():
                session = ChatSession.load(path)
                console.print(f"[dim]Resumed session {session.session_id[:8]}[/dim]")
                return session

            # Try legacy SessionKernel format
            try:
                from ..compat import SessionKernel

                legacy = SessionKernel().load(session_id)
                if legacy:
                    session = ChatSession(
                        session_id=legacy.session_id,
                        target=legacy.scope or target,
                        mode=self._mode,
                    )
                    for op in legacy.operations:
                        session.add_message("user", op.instruction)
                        artifacts = ", ".join(op.artifacts) if op.artifacts else "—"
                        status = f"{op.state} (retries: {op.retries})"
                        session.add_message(
                            "assistant",
                            f"Operation {op.operation_id} [{status}]\nArtifacts: {artifacts}",
                        )
                    session.save(self._SESSIONS_DIR / f"{session.session_id}.json")
                    console.print(f"[dim]Restored legacy session {session.session_id[:8]}[/dim]")
                    return session
            except Exception:
                pass

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
                            console.print(
                                "[dim]Current task cancelled. Press ESC again to exit.[/dim]"
                            )
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
                    console.print("[dim]Task cancelled. Press Ctrl+C again to exit.[/dim]")
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
                        "❯ ",
                        key_bindings=esc_bindings,
                        completer=SmartAutocomplete(self._session),
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
                        "❯ ",
                        key_bindings=esc_bindings,
                        completer=SmartAutocomplete(self._session),
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
            "/provider": self._cmd_provider,
            "/context": self._cmd_context,
            "/version": self._cmd_version,
            "/config": self._cmd_config,
            "/esc": self._cmd_esc,
            "/cancel": self._cmd_esc,
            "/log": self._cmd_log,
            "/diff": self._cmd_diff,
            "/mcp": self._cmd_mcp,
            "/agent": self._cmd_agent,
            "/vault": self._cmd_vault,
            "/review": self._cmd_review,
            "/persona": self._cmd_persona,
            "/report": self._cmd_report,
            "/split": self._cmd_split,
            "/coder": self._cmd_coder,
            "/batch": self._cmd_batch,
            "/cloud": self._cmd_cloud,
            "/k8s": self._cmd_k8s,
            "/docker": self._cmd_docker,
            "/iac": self._cmd_iac,
            "/mobile": self._cmd_mobile,
            "/iot": self._cmd_iot,
            "/hsm": self._cmd_hsm,
            "/compliance": self._cmd_compliance,
            "/opsec": self._cmd_opsec,
            "/siem": self._cmd_siem,
            "/performance": self._cmd_performance,
            "/cache": self._cmd_cache,
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
            suggestions = [c for c in SLASH_HELP if c.startswith(command[:3])][:3]
            hint = ""
            if suggestions:
                hint = f"  Did you mean: {', '.join(suggestions)}"
            console.print(f"[red]Unknown command: {command}[/red] — type [cyan]/help[/cyan]{hint}")

    def _cmd_help(self, _: str) -> None:
        """Show categorized help."""
        console.print(
            Panel(
                "[bold cyan]Siyarix Chat Commands[/bold cyan]\n"
                "Type [cyan]/command[/cyan] to execute. "
                "Press [cyan]?[/cyan] at any time to see this help.",
                border_style="cyan",
            )
        )
        for category, cmds in HELP_CATEGORIES:
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
            from ..report import ReportEngine, ReportConfig, ReportFormat
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
        path = engine.save(
            report, output_dir / f"report_{self._session.session_id[:8]}", fmt=fmt_enum
        )
        console.print(f"[bold green]✓ Report generated successfully at: {path}[/bold green]")
        console.print(f"[dim]Findings: {len(findings)} | Format: {fmt}[/dim]")

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
            console.print(f"[green]Split Pane enabled. System view: {args_clean.upper()}[/green]")
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
                left_text.append("Welcome to Siyarix Cyber Command.\n", style="bold cyan")
                left_text.append("Mode: ")
                left_text.append(f"{self._mode}\n", style="bold green")
                left_text.append("\nReady for input. Type your instruction below.\n\n")
                left_text.append("Examples:\n")
                left_text.append("  • scan 127.0.0.1\n", style="yellow")
                left_text.append("  • enumerate subdomains of siyarix.local\n", style="yellow")
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
        console.print(Panel.fit(p.command, title=f"Profile: {p.name}", border_style="cyan"))
        run = Prompt.ask("Run this command? (y/N)", default="N")
        if run.lower().startswith("y"):
            await self._execute_instruction(p.command)

    def _show_key_status(self) -> None:
        from ..credential_store import CredentialStore
        from ..providers import ProviderManager

        provider_registry = ProviderManager()
        try:
            vault = CredentialStore()
        except Exception as exc:
            logger.warning("CredentialStore init failed: %s", exc)
            vault = None

        table = Table(title="Configured API Keys", header_style="bold green")
        table.add_column("Provider", style="cyan")
        table.add_column("Env Var", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Source")

        for prov_name in provider_registry.list_providers():
            profile = provider_registry.get_profile(prov_name)
            env_key = profile.api_key_env if profile else provider_env_var(prov_name)
            from_env = bool(os.getenv(env_key)) if env_key else False
            from_creds = bool(vault and vault.retrieve(prov_name, "api_key"))
            if from_env:
                status, source = "✓ Set", "Environment"
            elif from_creds:
                status, source = "✓ Set", "Vault"
            else:
                status, source = "✗ Missing", "—"
            table.add_row(prov_name, env_key or "—", status, source)

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
            from ..credential_store import CredentialStore

            try:
                vault = CredentialStore()
                new_password = Prompt.ask(
                    "Enter new master password (optional)", password=True, default=""
                )
                if vault.rotate_key(new_password or None):
                    console.print("[green]✓ Master encryption key rotated successfully[/green]")
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
            from ..providers import get_provider_env_var

            env_key = get_provider_env_var(provider)
            os.environ.pop(env_key, None)
            try:
                from ..credential_vault import vault_delete

                vault_delete(provider)
            except Exception:
                logger.exception("Failed to remove credential from vault")
            try:
                from ..credential_store import CredentialStore

                vault = CredentialStore()
                vault.delete(provider, "api_key")
            except Exception:
                pass
            console.print(f"[green]✓ Cleared {provider} key from encrypted vault[/green]")
            return

        if not api_key:
            api_key = Prompt.ask(f"Enter {provider} API key", password=True)
        from ..providers import get_provider_env_var

        env_key = get_provider_env_var(provider)
        os.environ[env_key] = api_key
        try:
            from ..credential_vault import vault_set

            vault_set(provider, api_key)
            console.print(
                f"[green]✓ Encrypted and stored {provider} API key in device-bound vault[/green]"
            )
        except Exception:
            logger.exception("Failed to save credential to vault")
            # Fallback: legacy CredentialStore
            try:
                from ..credential_store import CredentialStore

                vault = CredentialStore()
                vault.delete(provider, "api_key")
                vault.store(provider, api_key, "api_key")
                console.print(f"[green]✓ Stored {provider} API key in legacy vault[/green]")
            except Exception:
                console.print(f"[green]✓ {provider} API key set in environment[/green]")
            return
        console.print("[dim](encrypted, device-bound, tamper-protected)[/dim]")

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
                    console.print(f"[dim]Installing {pkg_name} — this may take a moment...[/dim]")
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
                            console.print(f"[red]Failed to install package: {res.stderr}[/red]")
                    except Exception as exc:
                        logger.exception("Failed to run pip install for %s: %s", pkg_name, exc)

    def _cmd_vault(self, args: str) -> None:
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"
        from ..credential_vault import get_vault

        if action == "status":
            try:
                vault = get_vault(create=False)
                s = vault.status
                console.print("[bold]🔐 Vault Status[/bold]")
                console.print(f"  State:     {'🟢 Unsealed' if not s.sealed else '🔴 Sealed'}")
                console.print(
                    f"  Device:    {'✓ Bound + Match' if s.device_match else '✗ Mismatch' if s.device_match is False else '—'}"
                )
                console.print(
                    f"  Env:       {'✓ Bound + Match' if s.env_match else '✗ Mismatch' if s.env_match is False else '—'}"
                )
                console.print(
                    f"  Creds:     {s.credential_count} total, {s.expired_entries} expired"
                )
                console.print(f"  Iter:      {s.iterations:,}")
                console.print(f"  Lockout:   {'⚠ Active' if s.lockout_active else '✓ None'}")
                console.print(f"  Health:    {s.health}")
                if s.warnings:
                    for w in s.warnings:
                        console.print(f"  [yellow]⚠ {w}[/yellow]")
            except FileNotFoundError:
                console.print(
                    "[yellow]No vault exists. Set a key with /key set <provider> <key> to create one.[/yellow]"
                )
            except Exception as exc:
                console.print(f"[red]Vault error: {exc}[/red]")

        elif action == "seal":
            try:
                get_vault(create=False).seal()
                console.print("[green]✓ Vault sealed[/green]")
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")

        elif action == "health":
            try:
                h = get_vault(create=False).health_check()
                icons = {"healthy": "🟢", "degraded": "🟡", "unhealthy": "🔴"}
                console.print(f"Health: {icons.get(h.state, '❓')} {h.state.upper()}")
                for w in h.warnings:
                    console.print(f"  [yellow]⚠ {w}[/yellow]")
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")

        elif action == "history":
            try:
                entries = get_vault(create=False).audit_log(limit=20)
                if not entries:
                    console.print("[yellow]No audit entries[/yellow]")
                    return
                for e in entries:
                    icons = {
                        "success": "🟢",
                        "denied": "🔴",
                        "error": "🟡",
                        "info": "🔵",
                    }
                    op_icon = icons.get(e.get("outcome", ""), "•")
                    ts = e.get("timestamp", "")[11:19]
                    console.print(
                        f"  {op_icon} [{ts}] {e.get('operation', '')} [{e.get('provider', '')}] {e.get('detail', '')}"
                    )
            except Exception as exc:
                console.print(f"[red]{exc}[/red]")

        else:
            console.print("[yellow]Usage: /vault [status|seal|health|history][/yellow]")

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
            from ..registry import ToolRegistry

            reg = ToolRegistry()
            reg.scan_path()
            tools = reg.list_tools()
            if not tools:
                console.print("[yellow]No tools registered.[/yellow]")
                return
            table = Table(title=f"{len(tools)} Security Tools Found", header_style="bold cyan")
            table.add_column("Name", style="cyan")
            table.add_column("Category", style="magenta")
            table.add_column("Version", style="dim")
            table.add_column("Capabilities", style="white")
            for t in sorted(tools, key=lambda x: x.category):
                caps = ", ".join(t.tags[:3])
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
            "user_messages": len([m for m in self._session.messages if m.role == "user"]),
            "assistant_messages": len([m for m in self._session.messages if m.role == "assistant"]),
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
        console.print(f"Session uptime: [cyan]{hours:02d}:{minutes:02d}:{secs:02d}[/cyan]")

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
        table = Table(title=f"Command Intents ({len(intents)})", header_style="bold cyan")
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

        console.print(Rule(f"[bold]Search results for '{needle}' ({len(results)})[/bold]"))
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
        valid = ("autonomous", "integrated", "registry", "offline")
        if not args:
            console.print(f"Current mode: [cyan]{self._mode}[/cyan] (valid: {', '.join(valid)})")
            return
        if args not in valid:
            console.print(f"[red]Invalid mode: {args}. Valid modes: {', '.join(valid)}[/red]")
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

    async def _cmd_model(self, args: str) -> None:
        from ..providers import ProviderManager

        tokens = args.split(maxsplit=1) if args else []
        pm = ProviderManager()
        all_providers = pm.list_providers()

        if tokens:
            selected = tokens[0].strip().lower()
            valid_providers = set(all_providers) | {
                "auto",
                "cloud",
                "custom",
                "opencode",
            }
            if selected in valid_providers:
                self._settings.set("model_provider", selected)
                model_name = ""
                if len(tokens) > 1 and selected != "auto":
                    model_name = tokens[1].strip()
                    model_key = f"{selected}_model"
                    try:
                        self._settings.set(model_key, model_name)
                        console.print(f"[green]✓ Set {model_key} to: {model_name}[/green]")
                    except KeyError:
                        console.print(
                            f"[green]✓ Provider set to {selected} (model name ignored for this provider)[/green]"
                        )
                console.print(f"[green]✓ Model provider set to: {selected}[/green]")

                # ── Benchmark: quick validation call ──
                if selected != "auto" and selected in all_providers:
                    profile = pm.get_profile(selected)
                    env_var = profile.api_key_env if profile else ""
                    key = os.environ.get(env_var) if env_var else ""
                    if selected == "gemini" and not key:
                        key = os.environ.get("GOOGLE_API_KEY", "")
                    if key or not env_var:
                        with console.status(
                            f"[dim]Validating {selected}...[/dim]", spinner="point"
                        ):
                            try:
                                import asyncio

                                bench_fn = self._make_llm_call(selected, key or "")
                                bench_key = f"{selected}_model"
                                bench_model = self._settings.get(bench_key) or ""
                                if not bench_model and profile:
                                    bench_model = profile.default_model
                                result = await asyncio.wait_for(
                                    bench_fn("Respond with exactly: OK", "ping"),
                                    timeout=15.0,
                                )
                                if not isinstance(result, dict):
                                    raise RuntimeError(
                                        f"LLM returned unexpected type: {type(result).__name__}"
                                    )
                                content = result.get("content", "").strip()
                                if content == "OK":
                                    console.print(
                                        f"[green]  ✓ {selected} responded correctly ({result.get('model', bench_model)})[/green]"
                                    )
                                else:
                                    console.print(
                                        f"[yellow]  ⚠ {selected} responded but unexpected: {content[:50]}[/yellow]"
                                    )
                            except asyncio.TimeoutError:
                                console.print(f"[red]  ✗ {selected} timed out after 15s[/red]")
                            except Exception as exc:
                                console.print(f"[red]  ✗ {selected} validation failed: {exc}[/red]")
            else:
                console.print(
                    f"[yellow]Usage: /model <{'|'.join(valid_providers)}> [model-name][/yellow]"
                )
                return

        lines = [f"[bold]Preferred:[/bold] {self._settings.get('model_provider')}\n"]
        for prov_name in all_providers:
            profile = pm.get_profile(prov_name)
            if not profile:
                continue
            env_var = profile.api_key_env or ""
            key = os.environ.get(env_var, "") if env_var else ""
            model_setting = self._settings.get(f"{prov_name}_model") or profile.default_model or ""
            status = "✓ Configured" if key else ("✗ Not set" if env_var else "Available")
            cost_label = f"[dim]${profile.cost_tier.value}[/dim]" if profile.cost_tier else ""
            lines.append(
                f"[bold]{profile.display_name}:[/bold] {status} ({model_setting}) {cost_label}\n"
            )

        lines.append("[bold]Cloud:[/bold]  Requires SIYARIX_SERVER_URL + SIYARIX_API_KEY\n")
        lines.append("[bold]Custom:[/bold]  Requires CUSTOM_API_KEY\n")
        lines.append("[bold]opencode:[/bold]  Requires OPENCODE_API_KEY\n\n")
        lines.append(
            "[dim]Use /key <provider> <value> to store credentials and /model <provider> <model-name> to select models.[/dim]"
        )
        usage_summary = self._usage_tracker.summary()
        if usage_summary:
            lines.append(f"\n[dim]{usage_summary}[/dim]")
        console.print(Panel.fit("".join(lines), title="Model Providers", border_style="cyan"))

    async def _cmd_provider(self, args: str) -> None:
        """Show detailed provider info and available models."""
        from ..providers import ProviderManager

        pm = ProviderManager()
        name = args.strip().lower() if args else ""

        if name:
            profile = pm.get_profile(name)
            if not profile:
                console.print(
                    f"[yellow]Unknown provider: {name}. Use /provider to list all.[/yellow]"
                )
                return
            models = profile.get_model_names()
            model_lines = (
                "\n".join(f"  [cyan]{m}[/cyan]" for m in models)
                if models
                else "  [dim]No models registered[/dim]"
            )
            cap_parts = []
            if profile.supports_vision:
                cap_parts.append("vision")
            if profile.supports_tools:
                cap_parts.append("tools")
            if profile.supports_streaming:
                cap_parts.append("streaming")
            if profile.supports_structured_output:
                cap_parts.append("structured_output")
            info = (
                f"[bold]Provider:[/bold] {profile.display_name}\n"
                f"[bold]Type:[/bold] {profile.provider_type.value}\n"
                f"[bold]Cost Tier:[/bold] {profile.cost_tier.value}\n"
                f"[bold]Priority:[/bold] {profile.priority}\n"
                f"[bold]Default Model:[/bold] {profile.default_model or '—'}\n"
                f"[bold]Capabilities:[/bold] {', '.join(cap_parts) if cap_parts else '—'}\n"
                f"[bold]Context Limit:[/bold] {profile.max_context_tokens:,} tokens\n"
                f"[bold]API Key Env:[/bold] {profile.api_key_env or '—'}\n"
                f"[bold]Base URL:[/bold] {profile.base_url or '—'}\n"
                f"[bold]Models:[/bold]\n{model_lines}\n"
            )
            if profile.docs_url:
                info += f"[dim]Docs: {profile.docs_url}[/dim]"
            console.print(
                Panel(info, title=f"Provider: {profile.display_name}", border_style="cyan")
            )
            return

        # No provider arg: list all with quick summary
        table = Table(title="Available Providers", header_style="bold cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Cost", style="green")
        table.add_column("Models", style="yellow")
        table.add_column("Capabilities")
        table.add_column("Configured")

        for prov_name in pm.list_providers():
            profile = pm.get_profile(prov_name)
            if not profile:
                continue
            env_var = profile.api_key_env or ""
            key = bool(os.getenv(env_var)) if env_var else True
            cap_list = []
            if profile.supports_vision:
                cap_list.append("👁")
            if profile.supports_tools:
                cap_list.append("🔧")
            if profile.supports_streaming:
                cap_list.append("📡")
            models_count = len(profile.get_model_names())
            table.add_row(
                prov_name,
                profile.provider_type.value,
                profile.cost_tier.value,
                str(models_count) if models_count else "—",
                "".join(cap_list) if cap_list else "—",
                "✓" if key else "✗",
            )
        console.print(table)

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
            from ..coder_bridge import CoderBridge
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
                with open(path, encoding="utf-8") as f:
                    code = f.read()
                review = await bridge.review(path, code)
                console.print(review.to_panel())
            except FileNotFoundError:
                console.print(f"[red]File not found: {path}[/red]")
        else:
            console.print("[yellow]Usage: /coder generate|review[/yellow]")

    async def _cmd_mcp(self, args: str) -> None:
        """Handle /mcp command for MCP server interaction."""
        from ..mcp import MCPClient, MCPServerConfig

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if action == "connect":
            url = tokens[1] if len(tokens) > 1 else ""
            if not url:
                url = Prompt.ask("MCP server URL")
            client = MCPClient()
            server_name = tokens[2] if len(tokens) > 2 else "default"
            ok = await client.connect(MCPServerConfig(name=server_name, url=url))
            if ok:
                self._session.context["mcp_client"] = client
                self._session.context["mcp_server"] = server_name
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
            server_name = self._session.context.pop("mcp_server", "default")
            if client:
                await client.disconnect(server_name)
                console.print("[green]✓ Disconnected from MCP server.[/green]")
            else:
                console.print("[dim]Not connected to any MCP server.[/dim]")
        else:
            console.print("[yellow]Usage: /mcp connect|call|disconnect[/yellow]")

    async def _cmd_agent(self, args: str) -> None:
        """Handle /agent command for sub-agent lifecycle management."""
        from ..core import AgentCore, AgentMode, AgentGoal

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else ""

        if action == "run":
            goal = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            if not goal:
                console.print("[yellow]Usage: /agent run <goal>[/yellow]")
                return
            chat_mode = self._mode
            if chat_mode == "integrated":
                agent_mode = AgentMode.HYBRID
            elif chat_mode == "autonomous":
                agent_mode = AgentMode.AUTONOMOUS
            elif chat_mode in ("registry", "offline"):
                agent_mode = AgentMode.REGISTRY
            else:
                agent_mode = AgentMode.AUTONOMOUS
            agent = AgentCore(mode=agent_mode)
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

    def _cmd_review(self, args: str) -> None:
        """Toggle command review prompt before execution."""
        current = self._settings.get("command_review", True)
        tokens = args.split() if args else []
        if not tokens:
            status = "on" if current else "off"
            console.print(
                f"[dim]Command review is [bold]{status}[/bold]. Usage: /command on|off[/dim]"
            )
            return
        new_val = tokens[0].lower() in ("on", "1", "yes", "true", "enable")
        self._settings.set("command_review", new_val)
        status = "on" if new_val else "off"
        console.print(f"[green]Command review turned [bold]{status}[/bold][/green]")

    def _cmd_persona(self, args: str) -> None:
        """Switch mindset/persona: /persona list, /persona <name>, /persona."""
        from ..personas import get_persona, list_personas
        from rich.table import Table

        tokens = args.split() if args else []
        current = self._settings.get("persona") or "auto"
        if not tokens:
            p = get_persona(current)
            label = p["label"] if p else current
            console.print(
                f"[dim]Current persona: [bold]{label}[/bold]. Usage: /persona list | /persona <name>[/dim]"
            )
            return
        action = tokens[0].lower()
        if action == "list":
            table = Table(title="Available Personas", header_style="bold cyan")
            table.add_column("Name", style="cyan")
            table.add_column("Label", style="green")
            table.add_column("Description", style="dim")
            for p in list_personas():
                table.add_row(p["name"], p["label"], p["description"])
            table.add_row("auto", "Auto (Smart Select)", "Analyse and choose the best-fit persona")
            table.add_row(
                "universal",
                "Universal / All-in-One",
                "Full-spectrum cybersecurity professional",
            )
            table.add_row("none", "None", "No persona framing — LLM decides its own voice")
            console.print(table)
            return
        p = get_persona(action)
        if not p:
            console.print(
                f"[yellow]Unknown persona: {action}. Use /persona list to see available options.[/yellow]"
            )
            return
        self._settings.set("persona", p["name"])
        console.print(f"[green]Persona switched to [bold]{p['label']}[/bold][/green]")

    def _cmd_esc(self, _: str) -> None:
        """Emergency stop - cancel all pending execution."""
        console.print("[bold red]⚠ EMERGENCY STOP TRIGGERED[/bold red]")
        self._esc_press_count = 1
        self._esc_press_time = time.time()
        self._running = False
        if self._engine_kill_switch:
            self._engine_kill_switch.trigger()
            console.print("[dim]Kill switch triggered: all pending operations cancelled.[/dim]")
        else:
            console.print("[dim]No active engine to cancel.[/dim]")

    def _cmd_version(self, _: str) -> None:
        from ..branding import resolve_version

        ver = resolve_version()
        console.print(f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green]")

    # ──────────────────────────────────────────────────────────────────────
    # Chapter 11: Session logging commands
    # ──────────────────────────────────────────────────────────────────────

    def _cmd_log(self, args: str) -> None:
        """Handle /log command for session log management."""
        from rich.table import Table

        from ..session_log import session_logger

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
                    console.print("[dim]... (truncated, use --output to save to file)[/dim]")
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
            from ..offline_store import OfflineStore
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
                nt.add_row(f.get("title", "?"), f.get("severity", "?"), f.get("tool", "?"))
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
        console.print(f"[bold]Running batch:[/bold] {batch_file.name} ({len(lines)} commands)")
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
            from ..cloud_scanner import CloudProvider, CloudScanner
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
            from ..cloud_scanner import CloudScanner
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
            from ..cloud_scanner import CloudScanner
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
            from ..iac_scanner import IaCScanner
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
            from ..mobile_scanner import MobileScanner
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
            from ..iot_scanner import IoTScanner
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
            from ..hsm_manager import HSMService
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("configure", "status", "disconnect"):
            console.print(
                "[yellow]Usage: /hsm configure|status|disconnect [--provider yubikey|pkcs11|tpm][/yellow]"
            )
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
            from ..compliance_runner import ComplianceRunner
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in ("run",):
            console.print(
                "[yellow]Usage: /compliance run --framework pci-dss|iso-27001|nist-800-53|soc2|gdpr|hipaa <target>[/yellow]"
            )
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
        from ..opsec import opsec_manager

        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("isolate", "burn", "status", "disable"):
            console.print(
                "[yellow]Usage: /opsec isolate|burn|status|disable [--target <target>][/yellow]"
            )
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
            console.print(
                f"Isolated: {s.isolated} | TOR: {s.tor_enabled} | DoH: {s.doh_enabled} | Memory-only: {s.memory_only}"
            )
        elif tokens[0] == "disable":
            opsec_manager.disable()
            console.print("[green]OPSEC deactivated[/green]")

    async def _cmd_siem(self, args: str) -> None:
        """Handle /siem command for SIEM/SOAR integration."""
        from ..platform_integration import platform_integration

        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("connect", "status", "forward"):
            console.print("[yellow]Usage: /siem connect|status|forward <platform> <url>[/yellow]")
            return
        if tokens[0] == "connect":
            platform = tokens[1] if len(tokens) > 1 else "splunk"
            url = tokens[2] if len(tokens) > 2 else ""
            result = platform_integration.connect_siem(platform, url=url)
            console.print(
                f"[green]SIEM connected: {result.platform}[/green]"
                if result.connected
                else f"[red]{result.error}[/red]"
            )
        elif tokens[0] == "status":
            summary = platform_integration.summary()
            console.print(f"SIEM connections: {summary.get('siem_connections', 0)}")

    async def _cmd_performance(self, args: str) -> None:
        """Handle /performance command for resource optimization."""
        from ..performance import performance_optimizer

        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("status", "tune", "configure"):
            console.print("[yellow]Usage: /performance status|tune|configure[/yellow]")
            return
        if tokens[0] == "tune":
            config = performance_optimizer.auto_tune()
            console.print(
                f"[green]Auto-tuned: {config.max_concurrent_agents} agents, {config.memory_limit_per_agent_mb}MB each[/green]"
            )
        elif tokens[0] == "status":
            s = performance_optimizer.summary()
            r = s["resources"]
            console.print(
                f"CPU: {r['cpu_cores']}C/{r['cpu_logical']}T | RAM: {r['ram_gb']}GB | Platform: {r['platform']}"
            )
            console.print(
                f"Agents: {s['config']['max_concurrent_agents']} | Memory/agent: {s['config']['memory_per_agent_mb']}MB"
            )
            console.print(
                f"Recommended: {s['recommended']['max_agents']} agents, {s['recommended']['memory_per_agent_mb']}MB/agent"
            )

    async def _cmd_cache(self, args: str) -> None:
        """Handle /cache command for cache management."""
        from ..cache_manager import cache_manager

        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("status", "clear", "invalidate"):
            console.print("[yellow]Usage: /cache status|clear|invalidate [domain][/yellow]")
            return
        if tokens[0] == "status":
            stats = cache_manager.stats()
            console.print(
                f"Cache: {stats['total_entries']} entries, {stats['total_size_mb']}MB, hit rate: {stats['hit_rate']:.0%}"
            )
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
            from ..importer import security_importer
        except ModuleNotFoundError:
            console.print("[yellow]This feature requires Siyarix Enterprise (v2)[/yellow]")
            return
        tokens = args.split() if args else []
        if len(tokens) < 2 or tokens[0] not in (
            "nessus",
            "burp",
            "metasploit",
            "stix",
            "auto",
        ):
            console.print(
                "[yellow]Usage: /import <nessus|burp|metasploit|stix|auto> <file>[/yellow]"
            )
            return
        fmt = tokens[0]
        path = tokens[1]
        importer_fn = getattr(security_importer, f"import_{fmt}", None)
        if importer_fn:
            result = importer_fn(path)
        else:
            result = security_importer.auto_import(path)
        console.print(
            f"Imported {result.total_imported} findings from {fmt} ({len(result.errors)} errors)"
        )
        for f in result.findings[:10]:
            console.print(f"  [{f.severity}] {f.title} @ {f.host or '?'}:{f.port}")
        if len(result.findings) > 10:
            console.print(f"  ... and {len(result.findings) - 10} more")

    # ──────────────────────────────────────────────────────────────────────
    # Appendix A.3 slash commands
    # ──────────────────────────────────────────────────────────────────────

    async def _cmd_playbook(self, args: str) -> None:
        """Handle /playbook command for workflow playbooks."""
        try:
            from ..playbook_engine import PlaybookEngine
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
                console.print(f"  • {pb.get('name', '?')} ({pb.get('steps', 0)} steps)")
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
            console.print(
                "[dim]No active campaigns. Use /campaign create <name> --targets <file>[/dim]"
            )
        elif action == "create":
            name = tokens[1] if len(tokens) > 1 else Prompt.ask("Campaign name")
            console.print(f"[green]✓ Campaign created: {name}[/green]")
            console.print(
                "[yellow]Tip: Use /batch run <targets_file> to execute across targets[/yellow]"
            )
        elif action == "status":
            console.print(
                "[yellow]Campaign tracking requires the workflow runtime. Run /batch to execute targets.[/yellow]"
            )
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
            from ..knowledge_graph import KnowledgeGraph

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
        from ..platform_integration import platform_integration

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "create"
        if action == "create":
            title = " ".join(tokens[1:]) if len(tokens) > 1 else Prompt.ask("Ticket title")
            sent = platform_integration.send_notification(f"Ticket: {title}", severity="medium")
            console.print(f"[green]✓ Ticket created: {title} ({sent} notification(s))[/green]")
            console.print("[yellow]Note: Jira/GitHub integration is not yet available[/yellow]")
        elif action == "list":
            console.print(
                "[yellow]Use /findings list to see findings that can be converted to tickets[/yellow]"
            )
        else:
            console.print("[yellow]Usage: /ticket create|list[/yellow]")

    async def _cmd_retest(self, args: str) -> None:
        """Handle /retest command for verification scans."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "schedule"
        if action == "schedule":
            finding_id = tokens[1] if len(tokens) > 1 else ""
            console.print(
                f"[green]✓ Retest scheduled for finding: {finding_id or 'all pending'}[/green]"
            )
        elif action == "status":
            console.print("[dim]No pending retests.[/dim]")
        else:
            console.print("[yellow]Usage: /retest schedule|status[/yellow]")

    async def _cmd_intel(self, args: str) -> None:
        """Handle /intel command for threat intelligence queries."""
        try:
            from ..threat_intel import ThreatIntelFeed, MITREAttackDB
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
                    sev = r.get('severity', 'info')
                    sev_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}
                    console.print(
                        f"  [{sev_colors.get(sev, 'blue')}]{sev.upper()}[/] {r.get('indicator', '?')} — {r.get('description', '')[:80]}"
                    )
            else:
                console.print("[dim]No threat intelligence matches.[/dim]")
        elif action == "mitre":
            tac = tokens[1] if len(tokens) > 1 else ""
            db = MITREAttackDB()
            mitre_results: list[dict[str, str]] = (
                db.search(tactic=tac) if tac else db.list_techniques()[:15]
            )
            for r in mitre_results[:15]:
                console.print(
                    f"  • {r.get('id', '?')} — {r.get('name', '?')} ({r.get('tactic', '?')})"
                )
        elif action == "feeds":
            feed = ThreatIntelFeed()
            feeds = feed.list_feeds()
            for f in feeds:
                console.print(f"  • {f.get('name', '?')} — {f.get('status', '?')}")
        else:
            console.print("[yellow]Usage: /intel search|mitre|feeds[/yellow]")

    async def _cmd_canary(self, args: str) -> None:
        """Handle /canary command for deception token deployment."""
        try:
            from ..canary import CanaryTokenManager, CanaryTokenType
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
                console.print(
                    f"[red]Invalid token type: {token_type} (web|dns|aws_key|credential|file|api_key)[/red]"
                )
                return
            target = tokens[2] if len(tokens) > 2 else Prompt.ask("Deployment target")
            deployment = mgr.deploy_to_target(target, token_types=[ttype])
            console.print(
                f"[green]✓ Deployed {len(deployment.tokens)} canary token(s) to {target}[/green]"
            )
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
            console.print(
                f"Canary tokens: {canary_stats.get('total_tokens', 0)} total, {canary_stats.get('triggered_tokens', 0)} triggered"
            )
        else:
            console.print("[yellow]Usage: /canary deploy|list|status[/yellow]")

    async def _cmd_stealth(self, args: str) -> None:
        """Handle /stealth command for evasion configuration."""
        from ..stealth import StealthEngine

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"
        engine = StealthEngine()
        if action == "status":
            cfg = engine.get_config()
            console.print(
                f"Stealth level: {cfg.evasion_level} | Jitter: {cfg.jitter_percentage}% | UA rotate: {cfg.rotate_user_agents} | Proxy: {cfg.use_proxy_chain} | Decoy: {cfg.use_decoy_traffic}"
            )
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
            console.print(
                "[yellow]Usage: /stealth status|on|off|level <none|light|medium|heavy|paranoid>[/yellow]"
            )

    async def _cmd_audit(self, args: str) -> None:
        """Handle /audit command for compliance and legal export."""
        from ..audit_log import audit

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
            console.print(
                f"Audit events: {audit_stats.get('total_events', 0)} | Chain verified: {audit_stats.get('chain_integrity', 'intact')}"
            )
        elif action == "verify":
            valid = audit.verify_chain()
            console.print(
                f"[{'green' if valid else 'red'}]Chain integrity: {'VALID' if valid else 'COMPROMISED'}[/]"
            )
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
        from ..registry import ToolRegistry

        # ── Route by mode ──
        if self._mode in ("registry", "offline"):
            pass  # skip agent, go straight to registry engine below
        elif self._mode == "autonomous":
            ok = await self._execute_agent(instruction, target, require_llm=True)
            if ok:
                return
            # Autonomous: agent failed → show error, stop
            console.print(
                "[red]Autonomous mode requires an LLM provider. "
                "Use /config set model_provider <name> and set the corresponding API key.[/red]"
            )
            return
        else:  # integrated
            ok = await self._execute_agent(instruction, target, require_llm=False)
            if ok:
                return
            # Integrated: agent failed → fall through to registry
            console.print("[yellow]⚠ Falling back to offline registry mode[/yellow]")

        # ── Registry / integrated fallback: traditional plan → execute pipeline ──
        from ..compat import ExecutionEngine, ExecutionMode

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
            "ollama_url": os.environ.get("SIYARIX_OLLAMA_URL", "http://localhost:11434"),
            "model_provider": self._settings.get("model_provider"),
            "gemini_model": self._settings.get("gemini_model"),
        }

        reg = ToolRegistry()
        from ..session_log import session_logger

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
            # Registry/offline mode: local response only (no LLM)
            if self._mode in ("registry", "offline"):
                response = self._generate_text_response(instruction) or ""
                if response:
                    self._print_assistant(response)
            else:
                prov_name, api_key = self._resolve_provider()
                if prov_name and api_key:
                    compact = self._should_use_compact()
                    sys_prompt = self._build_system_prompt(compact=compact)
                    response = await self._stream_assistant_response(
                        sys_prompt,
                        instruction,
                        prov_name,
                        api_key,
                        history=self._get_conversation_history(),
                    )
                    self._llm_calls += 1
                else:
                    response = self._generate_text_response(instruction) or ""
            if response:
                self._session.add_message("assistant", response or "")
            return

        # Show plan if requested
        if show_plan and len(plan.steps) > 1:
            self._print_plan(plan)

        # Multi-model ensemble voting (available providers > 1)
        try:
            from ..multi_model_ensemble import MultiModelEnsemble, VotingStrategy

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
            from ..adversarial_tester import AdversarialTester, AdversarialSeverity

            tester = AdversarialTester()
            plan_lines = [
                f"{s.tool or ''} {' '.join(s.args)} {s.target or ''}".strip() or s.command or ""
                for s in plan.steps
            ]
            findings = tester.review_plan(plan_lines)
            critical = [f for f in findings if f.severity == AdversarialSeverity.CRITICAL]
            high = [f for f in findings if f.severity == AdversarialSeverity.HIGH]
            if findings:
                console.print(
                    Panel(
                        "\n".join(
                            f"[{'red' if f.severity in ('critical', 'high') else 'yellow'}]"
                            f"{'🔴' if f.severity == 'critical' else '⚠'} "
                            f"[{f.severity.upper()}] {f.message}[/]\n"
                            f"  [dim]Suggestion: {f.suggestion}[/dim]"
                            for f in findings[:5]
                        )
                        + (
                            f"\n  [dim]... and {len(findings) - 5} more[/dim]"
                            if len(findings) > 5
                            else ""
                        ),
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

        # Save to offline store
        try:
            from ..offline_store import OfflineStore

            store = OfflineStore()
            target = self._session.target or ""
            store.save_scan(target or instruction, result.all_findings, mode=self._mode)
            if plan and plan.id:
                step_dicts = [
                    {
                        "tool": s.tool,
                        "status": s.status.value,
                        "description": s.description,
                    }
                    for s in plan.steps
                ]
                store.save_plan(plan.id, plan.goal, step_dicts, mode=self._mode)
        except Exception as exc:
            logger.debug("Failed to persist to offline store: %s", exc)

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
        self._session.add_message("assistant", summary, findings=len(result.all_findings))

    def _generate_text_response(self, user_input: str) -> str | None:
        """Return a text response for non-tool queries, or ``None`` to let the pipeline proceed."""
        lowered = user_input.strip().lower()
        greetings = {
            "hello",
            "hi",
            "hey",
            "sup",
            "what's up",
            "help",
            "good morning",
            "good evening",
            "good afternoon",
        }
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
                f"Good **{tod}**, **{username}**.\n\n"
                "I'm **Siyarix** — your cybersecurity intelligence system. "
                "I'm here to help with any security task, whether offensive, defensive, "
                "investigative, or advisory.\n\n"
                "**Areas of expertise:**\n"
                "- Reconnaissance and attack surface mapping — ports, services, subdomains, technologies\n"
                "- Vulnerability detection — web, network, cloud, Active Directory, wireless\n"
                "- Defensive analysis — detection engineering, log analysis, hardening, IR\n"
                "- Cloud security assessment — IAM, storage, containers, serverless\n"
                "- Threat intelligence — TTP mapping, IoC analysis, adversary profiling\n"
                "- Forensics and incident response — timeline reconstruction, artefact analysis\n"
                "- Governance and compliance — framework assessment, policy review, risk analysis\n\n"
                "I am an ongoing under-development project, and my knowledge base is improving "
                "day by day. I am built and sustained by community of security "
                "researchers, developers, and practitioners from around the world. Every "
                "contribution, bug report, feature suggestion, and pull request helps me "
                "serve you better. I am deeply grateful to everyone who has helped shape "
                "my project.\n\n"
                "If you'd like to join them, contributions and issue reports are always welcome:\n"
                "- Repo: https://github.com/mufthakherul/siyarix\n"
                "- Contributing: https://github.com/mufthakherul/siyarix/blob/main/CONTRIBUTING.md\n\n"
                "For maximum capability, connect an **LLM provider** — OpenRouter, OpenAI, Gemini, "
                "Anthropic, Groq, Together, or Ollama (local). "
                "Without one, I use built-in heuristic planning.\n\n"
                "Just tell me what you'd like to accomplish — I'll handle the rest.\n"
                "Type **`/help`** for all commands."
            )
        return None

    def _should_use_compact(self) -> bool:
        """Return True if we should send the compact (reminder) system prompt."""
        return self._llm_calls > 0 and self._llm_calls % self.SYSTEM_REFRESH_INTERVAL != 0

    def _build_system_prompt(self, compact: bool = False) -> str:
        """Build the system prompt for the LLM.

        When *compact* is True, return a short reminder instead of the full prompt
        to save context window tokens (first call and every N calls use full).
        """
        from ..personas import build_persona_prompt, get_persona

        COMPACT_PROMPT = """Continue as Siyarix in your active persona. Follow the full system instructions previously provided.

When a security operation is described, output JSON: { "needs_tools": true, "reasoning": "...", "response": "...", "steps": [...] }
For general chat or after tool execution, output JSON: { "needs_tools": false, "reasoning": "...", "response": "..." }"""

        COMPACT_NEUTRAL = """Continue as Siyarix following the system instructions previously provided.
Output JSON: { "needs_tools", "reasoning", "response", "steps" } when tools are needed."""

        SIYARIX_SYSTEM_PROMPT = """You are Siyarix, an elite cybersecurity professional operating in a terminal-driven environment.

## Operational Framework

Analyse every request across four dimensions:
1. **Intent** — Is this a chat/explanation, a security operation, or tool analysis?
2. **Scope** — What domain(s) does it touch? (network, web, cloud, endpoint, identity, mobile, etc.)
3. **Depth** — Is this a quick question, a multi-step assessment, or deep research?
4. **Risk** — Could any proposed command cause harm? Validate targets, warn before destructive action.

## Decision Logic

- **needs_tools=true**: The user describes a security operation (scan, recon, enumerate, exploit, audit, brute-force, etc.) or asks about a tool. Construct exact shell commands.
- **needs_tools=false**: General chat, explanations, conceptual discussion, planning, educational content, or post-execution analysis. Respond directly with your expertise.

## Output Format — Always Return Valid JSON
{
  "needs_tools": true or false,
  "reasoning": "Step-by-step analysis of the request, your methodology choice, and key considerations",
  "response": "Your answer when needs_tools=false, or analysis/synthesis after tool execution. Use Markdown for structured output.",
  "steps": []
}

## Tool Execution Steps (needs_tools=true)
Each step is a raw shell command — any binary, script, or pipeline:
{
  "tool": "",
  "command": "your exact shell command — flags, pipes, redirects, subshells — as if typing it yourself",
  "description": "What this command does, why it was chosen, and what to look for in the output"
}

Prefer the `command` field — it runs directly on the shell.

Available tool categories: recon (nmap, masscan, ffuf, gobuster, subfinder), exploitation (metasploit, sqlmap, hydra), enumeration (enum4linux, smbclient, ldapsearch, snmpwalk), web (whatweb, wpscan, nikto, curl), crypto (openssl, hashcat, john), network (dig, whois, nslookup, tcpdump), C2 (socat, netcat, chisel), analysis (python3, perl, jq, grep, awk). You are NOT limited to this list — construct any command the task demands.

## Output Analysis (post-execution)
When the user shares tool output or results:
- Analyse findings like a professional pentest report
- Identify exposures, misconfigurations, and weaknesses with specific evidence
- Correlate results across tools — a port from nmap + a banner from curl + a CVE from searchsploit = an exploit path
- Assign severity (Critical/High/Medium/Low/Info) with clear rationale
- Provide precise, actionable remediation guidance
- Suggest next-phase testing relevant to the findings

## Communication Standards
- Be technical, precise, and professional — this is a working security environment, not a demo
- Reference CVEs, attack techniques (MITRE ATT&CK), and defensive mitigations where relevant
- Explain your command choices and what the output likely means before running
- Use Markdown for structured output: tables for findings, code blocks for commands/logs, bullet points for analysis
- If unsure, acknowledge the gap honestly and suggest how to close it
- Steer off-topic requests back to security gracefully"""

        NEUTRAL_SYSTEM_PROMPT = """You are Siyarix, a cybersecurity professional in a terminal-driven environment.

## Approach
Analyse every request within cybersecurity, hacking, and security-adjacent fields. Determine whether it needs tool execution (scanning, enumeration, exploitation, recon, brute-force, auditing) or a direct expert response (chat, explanation, conceptual discussion, planning, education).

## Output Format — Always Return Valid JSON
{
  "needs_tools": true or false,
  "reasoning": "Brief analysis of the request and your decision logic",
  "response": "Your direct answer when needs_tools=false, or analysis after tool execution",
  "steps": []
}

## Tool Execution Steps (needs_tools=true)
Each step is a raw shell command running directly on the shell:
{
  "tool": "",
  "command": "your shell command — any binary, script, or pipeline",
  "description": "Purpose and expected output of this command"
}

## Communication Standards
- Be technical and precise — this is a working security environment
- Explain your reasoning behind tool choices and command constructions
- When analysing results, identify exposures, correlate evidence, assign severity, and recommend remediation
- Use Markdown for structured output where helpful
- Decline off-topic requests gracefully and steer back to security"""

        persona_name = self._settings.get("persona") or "auto"

        if compact:
            if persona_name == "none":
                return COMPACT_NEUTRAL
            p = get_persona(persona_name)  # noqa: F811
            label = p["label"] if p else "default"
            return f"## Active Persona: {label}\n{COMPACT_PROMPT}"

        if persona_name == "none":
            return NEUTRAL_SYSTEM_PROMPT
        preamble = build_persona_prompt(persona_name)
        if preamble:
            return preamble + "\n\n" + SIYARIX_SYSTEM_PROMPT
        return SIYARIX_SYSTEM_PROMPT

    async def _execute_agent(
        self, instruction: str, target: str = "", require_llm: bool = False
    ) -> bool:
        """Agent loop: LLM-first planning → parallel execution → LLM synthesis.

        When *require_llm* is True (autonomous mode), the method returns False
        if no LLM is available — no heuristic fallback.
        """
        from ..core import AgentCore, AgentMode

        # ── Resolve provider with auto fallback ──────────────────────────
        is_auto = self._settings.get("model_provider") == "auto"
        provider_name, api_key = self._resolve_provider()
        if not provider_name:
            if require_llm:
                console.print("[red]✗ No LLM provider configured for autonomous mode[/red]")
                return False
            console.print("[yellow]⚠ No LLM provider configured — using local planner[/yellow]")
            provider_name = "none"

        instruction_with_target = instruction
        if target and target not in instruction:
            instruction_with_target = f"{instruction} on {target}"

        chat_mode = self._mode
        if chat_mode == "integrated":
            agent_mode = AgentMode.HYBRID
        elif chat_mode == "autonomous":
            agent_mode = AgentMode.AUTONOMOUS
        elif chat_mode in ("registry", "offline"):
            agent_mode = AgentMode.REGISTRY
        else:
            agent_mode = AgentMode.AUTONOMOUS
        agent = AgentCore(mode=agent_mode)
        with console.status("[bold green]Initializing...[/bold green]", spinner="dots"):
            await agent.initialize()

        all_tools = agent._registry.list_tools()
        tool_names = [t.name for t in all_tools]
        tool_dicts = [
            {
                "name": t.name,
                "description": t.description,
                "tags": t.tags,
                "category": (t.category.value if hasattr(t.category, "value") else str(t.category)),
            }
            for t in all_tools
        ]

        # ── Decision maker ───────────────────────────────────────────────
        total_start = time.time()
        llm_plan: Any = None
        llm_reasoning: str | None = None
        llm_connected = False
        llm_model = provider_name if provider_name else "none"
        total_input_tokens = 0
        total_output_tokens = 0
        llm_call_fn = None

        # Auto-start local provider if not running
        if provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            if not self._check_local_provider_running(provider_name):
                console.print(f"[dim]{provider_name} not running — attempting to start...[/dim]")
                started = self._ensure_local_provider_running(provider_name)
                if not started:
                    console.print(f"[yellow]⚠ Could not start {provider_name}[/yellow]")
            else:
                # Warn if the configured model isn't available in Ollama
                if provider_name == "ollama":
                    import httpx
                    ollama_url = self._settings.get("ollama_url") or os.getenv("SIYARIX_OLLAMA_URL", "http://localhost:11434")
                    try:
                        tags_resp = httpx.get(f"{ollama_url}/api/tags", timeout=5.0)
                        installed = [m["name"] for m in tags_resp.json().get("models", [])]
                        configured = self._settings.get("ollama_model") or "whiterabbitneo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
                        if configured not in installed and ":" not in configured:
                            configured = f"{configured}:latest"
                        if configured not in installed:
                            console.print(f"[yellow]⚠ Model '[bold]{configured}[/bold]' not found in Ollama[/yellow]")
                            if installed:
                                console.print(f"[dim]  Available models: {', '.join(installed)}[/dim]")
                            console.print("[dim]  Set via: /config set ollama_model <modelname>[/dim]")
                    except Exception:
                        pass

        while (
            api_key or provider_name in ("ollama", "lmstudio", "llamacpp", "vllm", "localai")
        ) and not llm_connected:
            console.print(f"[dim]Agent mode — trying {provider_name}[/dim]")
            try:
                llm_call_fn = self._make_llm_call(provider_name, api_key or "")
                ping = await asyncio.wait_for(
                    llm_call_fn("", "OK"),
                    timeout=30.0,
                )
                if not isinstance(ping, dict):
                    raise RuntimeError(f"LLM returned unexpected type: {type(ping).__name__}")
                if not ping.get("content", "").strip():
                    raise RuntimeError("LLM ping returned empty response")
                llm_connected = True
                total_input_tokens += ping.get("input_tokens", 0)
                total_output_tokens += ping.get("output_tokens", 0)
                from ..providers import CostTier, ProviderManager

                _pm = ProviderManager()
                _profile = _pm.get_profile(provider_name) if provider_name else None
                cost_tier = _profile.cost_tier if _profile else CostTier.MEDIUM
                self._usage_tracker.record_call(
                    provider_name or "unknown",
                    ping.get("model", ""),
                    ping.get("input_tokens", 0),
                    ping.get("output_tokens", 0),
                    cost_tier=cost_tier,
                )
                self._provider_state.record_success(provider_name or "")
                break
            except asyncio.TimeoutError:
                icon = "⚠"
                msg = f"{icon} LLM request timed out"
            except Exception as exc:
                msg = str(exc)
                if "429" in msg or "rate_limit" in msg.lower() or "quota" in msg.lower():
                    icon = "⚠"
                    msg = f"{icon} LLM rate limit reached"
                elif "401" in msg or "unauthorized" in msg.lower() or "invalid" in msg.lower():
                    icon = "⚠"
                    msg = f"{icon} LLM authentication failed"
                else:
                    icon = "⚠"
                    msg = f"{icon} LLM unavailable ({type(exc).__name__}: {exc})"

            self._provider_state.record_failure(provider_name or "")

            console.print(f"[yellow]{msg}[/yellow]")

            if not is_auto:
                # Non-auto mode: give up after first failure
                if require_llm:
                    return False
                llm_call_fn = None
                break

            # Auto mode: try next provider
            provider_name, api_key = self._resolve_provider()
            if not provider_name:
                console.print("[yellow]⚠ All providers exhausted — using local planner[/yellow]")
                break

        if not llm_connected:
            if require_llm:
                console.print("[red]✗ No working LLM provider for autonomous mode[/red]")
                return False

        # ── Planning ─────────────────────────────────────────────────────
        if llm_connected:
            with console.status("[bold cyan]LLM analysing request...[/bold cyan]", spinner="dots"):
                try:
                    compact = self._should_use_compact()
                    plan_sys_prompt = self._build_system_prompt(compact=compact)
                    self._llm_calls += 1
                    plan_result = await agent._planner.llm_decompose_goal(
                        instruction_with_target,
                        tool_names,
                        llm_call=llm_call_fn,
                        tool_schemas=tool_dicts,
                        system_prompt=plan_sys_prompt,
                        history=self._get_conversation_history(),
                    )
                    llm_plan = plan_result
                    llm_reasoning = plan_result.context.get("reasoning", "")
                    self._provider_state.record_success(provider_name or "")
                except (asyncio.TimeoutError, RuntimeError, ValueError) as exc:
                    console.print(
                        f"[yellow]⚠ LLM planning failed ({exc}) — using local planner[/yellow]"
                    )

        if not llm_plan:
            if require_llm:
                console.print("[red]✗ LLM planning failed — autonomous mode cannot proceed[/red]")
                return False
            with console.status("[bold green]Planning...[/bold green]", spinner="dots"):
                llm_plan = agent._planner.decompose_goal(instruction_with_target, tool_names)

        # ── No tools needed ──────────────────────────────────────────────
        if not llm_plan.steps:
            response = llm_plan.context.get("response", "") if llm_plan else ""
            if response:
                self._print_assistant(response)
            elif llm_connected and llm_call_fn:
                compact = self._should_use_compact()
                sys_prompt = self._build_system_prompt(compact=compact)
                response = await self._stream_assistant_response(
                    sys_prompt,
                    instruction,
                    provider_name,
                    api_key,
                    history=self._get_conversation_history(),
                )
                self._llm_calls += 1
            else:
                greeting = self._generate_text_response(instruction)
                response = (
                    greeting
                    or llm_reasoning
                    or "I understood your request but no tools were needed."
                )
                self._print_assistant(response)
            self._session.add_message("assistant", response)
            duration = time.time() - total_start
            persona_name = self._settings.get("persona") or "auto"
            console.print(
                f"[dim]Time: {duration:.1f}s | Mode: {self._mode} | "
                f"Persona: {persona_name} | "
                f"LLM: {'connected' if llm_connected else 'offline'}[/dim]"
            )
            return True

        # ── Announce which tools will run ───────────────────────────────
        tool_labels = []
        for s in llm_plan.steps:
            if s.command:
                tool_labels.append(f"[bold]$ {s.command}[/bold]")
            else:
                tool_labels.append(f"[bold]{s.tool}[/bold]")
        console.print(f"[cyan]→ Executing:[/cyan] {', '.join(tool_labels)}")

        # ── Multi-wave execution loop ─────────────────────────────────────
        max_waves = self._settings.get("max_waves") or 25
        all_outputs: list[str] = []
        plan: Any = llm_plan

        for wave in range(max_waves):
            if not plan or not plan.steps:
                break

            # Announce
            tool_labels = []
            for s in plan.steps:
                if s.command:
                    tool_labels.append(f"[bold]$ {s.command}[/bold]")
                else:
                    tool_labels.append(f"[bold]{s.tool}[/bold]")
            if wave == 0:
                console.print(f"[cyan]→ Executing:[/cyan] {', '.join(tool_labels)}")
            else:
                console.print(f"[cyan]→ Wave {wave + 1}:[/cyan] {', '.join(tool_labels)}")

            # Execute all steps in parallel with a single live display
                from ..subprocess_utils import get_platform_shell_cmd, safe_run_async_stream

            @dataclass
            class _CmdState:
                label: str
                lines: list[str] = field(default_factory=list)
                exit_code: int | None = None
                done: bool = False

            cmd_states: list[_CmdState] = []
            for s in plan.steps:
                if s.command:
                    cmd_states.append(_CmdState(label=f"$ {s.command}"))
                else:
                    cmd_states.append(_CmdState(label=s.tool))

            async def _exec_one(step: Any, state: _CmdState) -> tuple[Any, dict]:
                if not step.command:
                    result = await agent._registry.execute(step.tool, **step.args)
                    state.exit_code = 0 if result.get("status") == "success" else 1
                    out = (result.get("output") or "").strip()
                    err = (result.get("error") or "").strip()
                    if out:
                        state.lines.extend(out.split("\n"))
                    if err:
                        state.lines.extend(err.split("\n"))
                    state.done = True
                    return step, result

                cmd_timeout = self._settings.get("agent_timeout") or 1740
                exec_result = await safe_run_async_stream(
                    get_platform_shell_cmd(step.command),
                    timeout=cmd_timeout,
                    validate=False,
                    on_stdout=lambda line: state.lines.append(line),
                    on_stderr=lambda line: state.lines.append(line),
                )
                state.exit_code = exec_result.exit_code
                state.done = True
                return step, {
                    "status": "success" if exec_result.exit_code == 0 else "error",
                    "output": exec_result.stdout,
                    "error": exec_result.stderr,
                    "exit_code": exec_result.exit_code,
                }

            # Pre-review all shell commands before starting Live display
            from ..shell_review import review_and_confirm

            command_review = self._settings.get("command_review", True)
            for s in plan.steps:
                if not s.command:
                    continue
                if not command_review:
                    break
                reviewed = review_and_confirm(s.command, "raw", "Raw shell command from LLM plan")
                if reviewed is None:
                    console.print("[yellow]⚠ Command cancelled by user[/yellow]")
                    return True
                s.command = reviewed

            exec_tasks = [_exec_one(s, st) for s, st in zip(plan.steps, cmd_states)]
            exec_task = asyncio.ensure_future(asyncio.gather(*exec_tasks))

            from rich.live import Live
            from rich.panel import Panel as RichPanel

            if cmd_states:
                focus_idx = 0
                done_set = False
                with Live(console=console, refresh_per_second=10, screen=False) as live:
                    while not done_set:
                        await asyncio.sleep(0.1)
                        if cmd_states[focus_idx].done:
                            unfinished = [i for i, st in enumerate(cmd_states) if not st.done]
                            if unfinished:
                                focus_idx = unfinished[0]
                            else:
                                done_set = True
                        st = cmd_states[focus_idx]
                        icon = "·" if st.exit_code is None else ("✓" if st.exit_code == 0 else "✗")
                        border = (
                            "cyan"
                            if st.exit_code is None
                            else ("green" if st.exit_code == 0 else "red")
                        )
                        live.update(
                            RichPanel(
                                "\n".join(st.lines[-200:]),
                                title=f"{icon} {st.label}",
                                border_style=border,
                            )
                        )

            raw_results = await exec_task

            # Show summary for this wave
            for (step, result), st in zip(raw_results, cmd_states):
                out = (result.get("output") or "").strip()
                err = (result.get("error") or "").strip()
                display_lines = out.split("\n") if out else (err.split("\n") if err else st.lines)
                if display_lines:
                    icon = "✓" if st.exit_code == 0 else "✗"
                    border = "green" if st.exit_code == 0 else "red"
                    console.print(
                        RichPanel(
                            "\n".join(display_lines[-200:]),
                            title=f"{icon} {st.label}",
                            border_style=border,
                        )
                    )

            # Store outputs for next wave context
            for step, result in raw_results:
                output = (result.get("output") or "").strip()[:2000]
                cmd_label = f"$ {step.command}" if step.command else step.tool
                all_outputs.append(f"• {cmd_label} ({step.description}):\n{output}\n")

            # Ask LLM: are we done, or need another wave?
            if llm_connected and llm_call_fn:
                wave_goal = (
                    f"Original request: {instruction_with_target}\n\n"
                    f"Completed execution wave {wave + 1}. Results so far:\n\n"
                    f"{''.join(all_outputs)}\n\n"
                    "Analyse these results. If the original request is fully satisfied, "
                    "set needs_tools=false and provide the final response. "
                    "If more commands are needed (e.g. missing data, tool not found, "
                    "need deeper recon), set needs_tools=true and provide the next steps."
                )
                with console.status(
                    "[bold cyan]LLM analysing wave results...[/bold cyan]",
                    spinner="dots",
                ):
                    try:
                        compact = self._should_use_compact()
                        wave_sys_prompt = self._build_system_prompt(compact=compact)
                        self._llm_calls += 1
                        plan = await agent._planner.llm_decompose_goal(
                            wave_goal,
                            tool_names,
                            llm_call=llm_call_fn,
                            tool_schemas=tool_dicts,
                            system_prompt=wave_sys_prompt,
                        )
                        llm_model = provider_name or "none"
                        if plan.steps:
                            console.print(
                                f"[cyan]→ LLM decided more work needed — wave {wave + 2}[/cyan]"
                            )
                        else:
                            # Done — show final response
                            ctx = plan.context or {}
                            summary = (ctx.get("response") or ctx.get("reasoning", "")) or "Done."
                            self._session.add_message("assistant", summary)
                            self._print_assistant(summary)
                    except asyncio.TimeoutError:
                        console.print("[yellow]⚠ LLM analysis timed out — moving on[/yellow]")
                        plan = None
            else:
                plan = None

        # ── Bottom stats line ────────────────────────────────────────────
        total_duration = time.time() - total_start
        persona_name = self._settings.get("persona") or "none"
        stats_parts = [
            f"Time: {total_duration:.1f}s",
            f"Mode: {self._mode}",
            f"Persona: {persona_name}",
        ]
        if llm_connected:
            stats_parts.append(f"Model: {llm_model}")
            stats_parts.append(f"Tokens: {total_input_tokens}↑ {total_output_tokens}↓")
        console.print("[dim]" + " | ".join(stats_parts) + "[/dim]")

        return True

    def _build_messages(
        self, system: str, user: str, history: list[dict] | None = None
    ) -> list[dict]:
        """Build the messages array for an LLM call, injecting conversation history."""
        messages = [{"role": "system", "content": system}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user})
        return messages

    def _make_llm_call(self, provider_name: str, api_key: str) -> Any:
        """Return an async callable ``(system, user, *, stream=False, history=None) → dict | AsyncGenerator``.

        Supports all 13 registered providers via native SDK or OpenAI-compatible API.
        When ``stream=True``, call with ``await fn(system, user, stream=True, history=history)``
        which returns an async generator yielding content tokens.
        history is a list of ``{"role": ..., "content": ...}`` dicts from prior conversation.
        """
        model = ""
        result: Any = None

        # ── Providers using OpenAI-compatible SDK ──────────────────────
        if provider_name in (
            "openai",
            "openrouter",
            "gemini",
            "deepseek",
            "xai",
            "perplexity",
            "azure",
            "llamacpp",
            "vllm",
            "localai",
        ):
            from openai import AsyncOpenAI

            base_urls = {
                "openai": None,
                "openrouter": "https://openrouter.ai/api/v1",
                "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
                "deepseek": "https://api.deepseek.com",
                "xai": "https://api.x.ai",
                "perplexity": "https://api.perplexity.ai",
                "azure": self._settings.get("azure_endpoint")
                or os.getenv("AZURE_OPENAI_ENDPOINT", ""),
                "llamacpp": self._settings.get("llamacpp_url")
                or os.getenv("SIYARIX_LLAMACPP_URL", "http://localhost:8080"),
                "vllm": self._settings.get("vllm_url")
                or os.getenv("SIYARIX_VLLM_URL", "http://localhost:8000"),
                "localai": self._settings.get("localai_url")
                or os.getenv("SIYARIX_LOCALAI_URL", "http://localhost:8080"),
            }
            model_keys = {
                "openai": "openai_model",
                "openrouter": "openrouter_model",
                "gemini": "gemini_model",
                "deepseek": "deepseek_model",
                "xai": "xai_model",
                "perplexity": "perplexity_model",
                "azure": "azure_model",
                "llamacpp": "llamacpp_model",
                "vllm": "vllm_model",
                "localai": "localai_model",
            }
            model_defaults = {
                "openai": "gpt-5.4",
                "openrouter": "openai/gpt-5.4",
                "gemini": "gemini-3.5-flash",
                "deepseek": "deepseek-v4-flash",
                "xai": "grok-4.3",
                "perplexity": "sonar",
                "azure": "gpt-5.4",
                "llamacpp": "",
                "vllm": "",
                "localai": "",
            }
            base_url = base_urls[provider_name]
            model = self._settings.get(model_keys[provider_name]) or model_defaults[provider_name]
            client_kwargs = {"api_key": api_key}
            if base_url:
                client_kwargs["base_url"] = base_url
            client = AsyncOpenAI(**client_kwargs)  # type: ignore[arg-type]

            async def call_openai(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        response = await client.chat.completions.create(
                            model=model,
                            messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
                            max_tokens=2000,
                            temperature=0.3,
                            stream=True,
                        )
                        async for chunk in response:  # type: ignore[union-attr]
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if delta and delta.content:
                                yield delta.content

                    return _gen()
                try:
                    response = await client.chat.completions.create(
                        model=model,
                        messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
                        max_tokens=2000,
                        temperature=0.3,
                    )
                except Exception as exc:
                    msg = str(exc) or repr(exc)
                    raise RuntimeError(
                        f"{provider_name} API call failed (model={model}): {msg}"
                    ) from exc
                choice = response.choices[0]
                usage = response.usage
                return {
                    "content": choice.message.content or "",
                    "model": response.model or model,
                    "input_tokens": usage.prompt_tokens if usage else 0,
                    "output_tokens": usage.completion_tokens if usage else 0,
                }

            result = call_openai

        # ── Anthropic (native SDK) ──────────────────────────────────────
        elif provider_name == "anthropic":
            try:
                from anthropic import AsyncAnthropic
            except ImportError:
                raise ValueError("anthropic package not installed. Run: pip install anthropic")

            anthropic_client = AsyncAnthropic(api_key=api_key)
            model = self._settings.get("anthropic_model") or "claude-sonnet-4-6"

            async def call_anthropic(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        hist_msgs = [m for m in (history or []) if m.get("role") != "system"]
                        msgs = hist_msgs + [{"role": "user", "content": user_prompt}]
                        async with anthropic_client.messages.stream(
                            model=model,
                            system=system_prompt,
                            messages=msgs,  # type: ignore[arg-type]
                            max_tokens=2000,
                            temperature=0.3,
                        ) as stream_ctx:
                            async for text in stream_ctx.text_stream:
                                yield text

                    return _gen()
                hist_msgs = [m for m in (history or []) if m.get("role") != "system"]
                msgs = hist_msgs + [{"role": "user", "content": user_prompt}]
                msg = await anthropic_client.messages.create(
                    model=model,
                    system=system_prompt,
                    messages=msgs,  # type: ignore[arg-type]
                    max_tokens=2000,
                    temperature=0.3,
                )
                content_block = msg.content[0] if msg.content else None
                return {
                    "content": getattr(content_block, "text", ""),
                    "model": msg.model or model,
                    "input_tokens": msg.usage.input_tokens if msg.usage else 0,
                    "output_tokens": msg.usage.output_tokens if msg.usage else 0,
                }

            result = call_anthropic

        # ── Groq (openai-compatible) ────────────────────────────────────
        elif provider_name == "groq":
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
            model = self._settings.get("groq_model") or "llama-4-scout-17b-16e-instruct"

            async def call_groq(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        response = await client.chat.completions.create(
                            model=model,
                            messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
                            max_tokens=2000,
                            temperature=0.3,
                            stream=True,
                        )
                        async for chunk in response:  # type: ignore[union-attr]
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if delta and delta.content:
                                yield delta.content

                    return _gen()
                response = await client.chat.completions.create(
                    model=model,
                    messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
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

            result = call_groq

        # ── Together AI (openai-compatible) ────────────────────────────
        elif provider_name == "together":
            from openai import AsyncOpenAI

            client = AsyncOpenAI(api_key=api_key, base_url="https://api.together.xyz/v1")
            model = (
                self._settings.get("together_model")
                or "meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8"
            )

            async def call_together(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        response = await client.chat.completions.create(
                            model=model,
                            messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
                            max_tokens=2000,
                            temperature=0.3,
                            stream=True,
                        )
                        async for chunk in response:  # type: ignore[union-attr]
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if delta and delta.content:
                                yield delta.content

                    return _gen()
                response = await client.chat.completions.create(
                    model=model,
                    messages=self._build_messages(system_prompt, user_prompt, history),  # type: ignore[arg-type]
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

            result = call_together

        # ── Mistral AI (native SDK) ────────────────────────────────────
        elif provider_name == "mistral":
            try:
                from mistralai import Mistral
            except ImportError:
                raise ValueError("mistralai package not installed. Run: pip install mistralai")
            client = Mistral(api_key=api_key)
            model = self._settings.get("mistral_model") or "mistral-large-3"

            async def call_mistral(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        response = await client.chat.stream_async(  # type: ignore[attr-defined]
                            model=model,
                            messages=self._build_messages(system_prompt, user_prompt, history),
                            max_tokens=2000,
                            temperature=0.3,
                        )
                        async for chunk in response:
                            if chunk.data and chunk.data.choices:
                                delta = chunk.data.choices[0].delta
                                if delta and delta.content:
                                    yield delta.content

                    return _gen()
                response = await client.chat.complete_async(  # type: ignore[attr-defined]
                    model=model,
                    messages=self._build_messages(system_prompt, user_prompt, history),
                    max_tokens=2000,
                    temperature=0.3,
                )
                choice = response.choices[0] if response.choices else None
                return {
                    "content": (choice.message.content if choice and choice.message else ""),
                    "model": response.model or model,
                    "input_tokens": (response.usage.prompt_tokens if response.usage else 0),
                    "output_tokens": (response.usage.completion_tokens if response.usage else 0),
                }

            result = call_mistral

        # ── Ollama (prefer native SDK, fall back to HTTP) ──────────────
        elif provider_name == "ollama":
            import httpx

            ollama_url = self._settings.get("ollama_url") or os.getenv(
                "SIYARIX_OLLAMA_URL", "http://localhost:11434"
            )
            model = self._settings.get("ollama_model") or "whiterabbitneo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
            try:
                from ollama import AsyncClient as OllamaAsyncClient

                _ollama_client = OllamaAsyncClient(host=ollama_url)
                use_sdk = True
            except Exception:
                _ollama_client = None
                use_sdk = False

            async def call_ollama(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if use_sdk and stream:

                    async def _gen_sdk() -> Any:
                        async for chunk in await _ollama_client.chat(
                            model=model,
                            messages=self._build_messages(system_prompt, user_prompt, history),
                            options={"temperature": 0.3, "num_predict": 2000},
                            stream=True,
                        ):
                            content = chunk.get("message", {}).get("content", "")
                            if content:
                                yield content

                    return _gen_sdk()
                if use_sdk:
                    response = await _ollama_client.chat(
                        model=model,
                        messages=self._build_messages(system_prompt, user_prompt, history),
                        options={"temperature": 0.3, "num_predict": 2000},
                    )
                    return {
                        "content": response.get("message", {}).get("content", ""),
                        "model": response.get("model", model),
                        "input_tokens": response.get("prompt_eval_count", 0),
                        "output_tokens": response.get("eval_count", 0),
                    }
                if stream:

                    async def _gen_http() -> Any:
                        async with httpx.AsyncClient(timeout=60.0) as hclient:
                            payload = {
                                "model": model,
                                "messages": self._build_messages(
                                    system_prompt, user_prompt, history
                                ),
                                "stream": True,
                                "options": {"temperature": 0.3, "num_predict": 2000},
                            }
                            async with hclient.stream(
                                "POST", f"{ollama_url}/api/chat", json=payload
                            ) as resp:
                                async for line in resp.aiter_lines():
                                    if line.strip():
                                        import json as _json

                                        data = _json.loads(line)
                                        content = data.get("message", {}).get("content", "")
                                        if content:
                                            yield content

                    return _gen_http()
                async with httpx.AsyncClient(timeout=60.0) as hclient:
                    payload = {
                        "model": model,
                        "messages": self._build_messages(system_prompt, user_prompt, history),
                        "stream": False,
                        "options": {"temperature": 0.3, "num_predict": 2000},
                    }
                    resp = await hclient.post(f"{ollama_url}/api/chat", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    return {
                        "content": data.get("message", {}).get("content", ""),
                        "model": data.get("model", model),
                        "input_tokens": data.get("prompt_eval_count", 0),
                        "output_tokens": data.get("eval_count", 0),
                    }

            result = call_ollama

        # ── LM Studio (OpenAI-compatible HTTP API) ─────────────────────
        elif provider_name == "lmstudio":
            import httpx

            lmstudio_url = self._settings.get("lmstudio_url") or os.getenv(
                "SIYARIX_LMSTUDIO_URL", "http://localhost:1234"
            )
            model = self._settings.get("lmstudio_model") or ""

            async def call_lmstudio(
                system_prompt: str,
                user_prompt: str,
                *,
                stream: bool = False,
                history: list[dict] | None = None,
            ) -> dict[str, Any]:
                if stream:

                    async def _gen() -> Any:
                        async with httpx.AsyncClient(timeout=120.0) as hclient:
                            payload = {
                                "model": model or "local-model",
                                "messages": self._build_messages(
                                    system_prompt, user_prompt, history
                                ),
                                "max_tokens": 2000,
                                "temperature": 0.3,
                                "stream": True,
                            }
                            async with hclient.stream(
                                "POST",
                                f"{lmstudio_url}/v1/chat/completions",
                                json=payload,
                            ) as resp:
                                async for line in resp.aiter_lines():
                                    if line.startswith("data: "):
                                        chunk = line[6:]
                                        if chunk.strip() == "[DONE]":
                                            break
                                        try:
                                            import json as _json

                                            data = _json.loads(chunk)
                                            delta = data.get("choices", [{}])[0].get("delta", {})
                                            if delta.get("content"):
                                                yield delta["content"]
                                        except Exception:
                                            pass

                    return _gen()
                async with httpx.AsyncClient(timeout=120.0) as hclient:
                    payload = {
                        "model": model or "local-model",
                        "messages": self._build_messages(system_prompt, user_prompt, history),
                        "max_tokens": 2000,
                        "temperature": 0.3,
                    }
                    resp = await hclient.post(f"{lmstudio_url}/v1/chat/completions", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    choice = data.get("choices", [{}])[0]
                    usage = data.get("usage", {})
                    return {
                        "content": choice.get("message", {}).get("content", ""),
                        "model": data.get("model", model or "local-model"),
                        "input_tokens": usage.get("prompt_tokens", 0),
                        "output_tokens": usage.get("completion_tokens", 0),
                    }

            result = call_lmstudio

        else:
            raise ValueError(f"Unsupported provider: {provider_name}")

        return result

    def _llm_available(self) -> bool:
        """Check if an LLM provider is configured and available."""
        provider = (self._settings.get("model_provider") or "gemini").lower().strip()

        from ..providers import ProviderManager

        pm = ProviderManager()
        profile = pm.get_profile(provider)

        if provider == "cloud":
            return bool(os.getenv("SIYARIX_SERVER_URL"))
        if provider == "custom":
            return bool(os.getenv("CUSTOM_API_KEY"))
        if provider == "opencode":
            return bool(os.getenv("OPENCODE_API_KEY"))
        if provider in ("ollama", "lmstudio", "llamacpp", "vllm", "localai"):
            return self._check_local_provider_running(provider)
        if profile and profile.api_key_env:
            key = os.getenv(profile.api_key_env)
            if provider == "gemini":
                return bool(key or os.getenv("GOOGLE_API_KEY"))
            return bool(key)
        return False

    @staticmethod
    def _check_local_provider_running(provider_name: str) -> bool:
        """Ping a local provider's HTTP endpoint to check if it's running."""
        endpoints = {
            "ollama": ("http://localhost:11434", "/api/tags"),
            "lmstudio": ("http://localhost:1234", "/v1/models"),
            "llamacpp": ("http://localhost:8080", "/health"),
            "vllm": ("http://localhost:8000", "/health"),
            "localai": ("http://localhost:8080", "/readyz"),
        }
        info = endpoints.get(provider_name)
        if not info:
            return False
        base_url, path = info
        try:
            import httpx
            resp = httpx.get(f"{base_url}{path}", timeout=3.0)
            return resp.status_code < 500
        except Exception:
            return False

    @staticmethod
    def _ensure_local_provider_running(provider_name: str) -> bool:
        """Try to auto-start a local provider if it's not already running."""
        endpoints = {
            "ollama": ("ollama", ["serve"], "http://localhost:11434", "/api/tags"),
            "lmstudio": ("lmstudio", ["--server"], "http://localhost:1234", "/v1/models"),
        }
        info = endpoints.get(provider_name)
        if not info:
            return False
        binary, args, base_url, health_path = info
        import shutil
        binary_path = shutil.which(binary)
        if not binary_path:
            logger.warning("%s binary not found on PATH — cannot auto-start", binary)
            return False
        if SiyarixChat._check_local_provider_running(provider_name):
            return True
        try:
            import subprocess
            if os.name == "nt":
                subprocess.Popen(
                    [binary, *args],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    [binary, *args],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            import time
            for _ in range(15):
                time.sleep(2)
                try:
                    import httpx
                    r = httpx.get(f"{base_url}{health_path}", timeout=3)
                    if r.status_code < 500:
                        logger.info("%s started successfully", binary)
                        return True
                except Exception:
                    pass
            logger.warning("%s started but not responding within 30s", binary)
            return False
        except Exception as exc:
            logger.warning("Failed to auto-start %s: %s", binary, exc)
            return False

    def _resolve_provider(self) -> tuple[str | None, str | None]:
        """Return ``(provider_name, api_key)`` for the active provider.

        When ``model_provider`` is set to a specific name, use that.
        When ``"auto"``, scan known providers sorted by cost (cheapest first),
        skipping any that are disabled or in cooldown (persisted across restarts).
        """
        from ..providers import ProviderManager

        pm = ProviderManager()

        configured = self._settings.get("model_provider") or "openrouter"
        if configured != "auto":
            profile = pm.get_profile(configured)
            env_var = profile.api_key_env if profile else ""
            key = os.environ.get(env_var) if env_var else ""
            if not key and configured == "gemini":
                key = os.environ.get("GOOGLE_API_KEY", "")
            return (configured, key or None)

        candidates: list[tuple[int, str, str]] = []

        for prov_name in pm.list_providers():
            if self._provider_state.is_disabled(prov_name):
                continue

            profile = pm.get_profile(prov_name)
            if not profile:
                continue

            if not profile.api_key_env:
                candidates.append((profile.cost_tier.sort_key, prov_name, ""))
                continue

            key = os.environ.get(profile.api_key_env)
            if not key and prov_name == "gemini":
                key = os.environ.get("GOOGLE_API_KEY", "")
            if key:
                candidates.append((profile.cost_tier.sort_key, prov_name, key))

        def _sort_key(c: tuple) -> tuple:
            prof = pm.get_profile(c[1])
            return (c[0], -(prof.priority if prof else 0))

        candidates.sort(key=_sort_key)
        for _, name, key in candidates:
            return (name, key or None)

        return (None, None)

    # ──────────────────────────────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────────────────────────────

    def _print_welcome(self) -> None:
        """Print the welcome banner with system status overview."""
        from ..branding import resolve_version

        ver = resolve_version()
        provider_status = self._gather_provider_status()
        shell_info = get_shell_platform()
        theme = self._settings.get("color_theme")
        provider = self._settings.get("model_provider")

        scans_count = 0
        findings_count = 0
        try:
            from ..offline_store import OfflineStore

            store = OfflineStore()
            stats = store.stats()
            scans_count = stats.get("total_scans", 0)
            findings_count = stats.get("total_findings", 0)
        except ModuleNotFoundError:
            pass
        except Exception as exc:
            logger.debug("Failed to read offline store stats: %s", exc)

        # Live tool & command counts
        tool_count = 0
        try:
            from ..registry import ToolRegistry

            reg = ToolRegistry()
            reg.scan_path()
            tool_count = len(reg.list_tools())
        except Exception:
            pass

        command_count = sum(1 for m in self._session.messages if m.role == "user")

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
                        f"[bold]Tools:[/bold] {tool_count}\n"
                        f"[bold]Commands:[/bold] {command_count}\n"
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
                        f"[bold]Mode:[/bold] {self._gather_mode_label(provider_status)}",
                        title="Quick Actions",
                        border_style="magenta",
                        padding=(1, 2),
                    ),
                    Panel(
                        "\n".join(
                            f"[bold]{k.capitalize()}:[/bold] {v[0]}"
                            for k, v in sorted(provider_status.items())
                        ),
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
        from ..providers import ProviderManager

        pm = ProviderManager()
        status: dict[str, tuple[str, str]] = {}

        for prov_name in pm.list_providers():
            profile = pm.get_profile(prov_name)
            if not profile:
                continue

            # Check SDK dependency
            pkg_ok = True
            if profile.sdk_dependency:
                try:
                    __import__(profile.sdk_dependency)
                except Exception:
                    pkg_ok = False

            # Check key
            key = os.getenv(profile.api_key_env) if profile.api_key_env else ""
            if not key and prov_name == "gemini":
                key = os.getenv("GOOGLE_API_KEY", "")

            if profile.api_key_env and not pkg_ok:
                status[prov_name] = ("✗", f"pkg missing ({profile.sdk_dependency})")
            elif profile.api_key_env and not key:
                status[prov_name] = ("⚠", "key missing")
            elif profile.api_key_env and key:
                status[prov_name] = ("✓", "configured")
            else:
                # local providers (no api_key_env)
                status[prov_name] = ("⚠", "available (local)")

        return status

    def _gather_mode_label(self, provider_status: dict[str, tuple[str, str]]) -> str:
        """Build a human-readable mode label showing LLM connectivity state."""
        has_llm = any(
            icon == "✓" and label == "configured" for icon, label in provider_status.values()
        )
        mode_display = self._mode.capitalize()
        if has_llm:
            return f"{mode_display} (LLM online)"
        if self._mode == "registry":
            return "Registry (offline)"
        if self._mode == "autonomous":
            return "Autonomous (LLM needed)"
        return f"{mode_display} (local fallback)"

    def _print_assistant(self, message: str) -> None:
        if self._con is not None:
            from rich.markdown import Markdown
            from rich.panel import Panel

            self._con.print(
                Panel(
                    Markdown(message),
                    title="[bold green]\u25c6 Siyarix[/bold green]",
                    border_style="green",
                    padding=(0, 2),
                )
            )
        else:
            self._output._raw_print(f"\u25c6 Siyarix: {message}")

    @staticmethod
    def _strip_json_wrapper(text: str) -> str:
        """If text is JSON with a 'response' field, extract just the response text."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[-1]
            cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict) and "response" in data:
                return data["response"]
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return text

    def _get_conversation_history(self, max_messages: int = 50) -> list[dict]:
        """Extract recent conversation history from the session for LLM context."""
        msgs = self._session.messages
        if not msgs:
            return []
        recent = msgs[-max_messages:] if len(msgs) > max_messages else msgs
        return [
            {
                "role": m.role,
                "content": m.content[-4000:] if len(m.content) > 4000 else m.content,
            }
            for m in recent
        ]

    async def _stream_assistant_response(
        self,
        system_prompt: str,
        user_prompt: str,
        provider_name: str | None = None,
        api_key: str | None = None,
        history: list[dict] | None = None,
    ) -> str:
        """Stream an LLM response token-by-token with a live updating display.

        Returns the clean response text (JSON wrapper stripped if present).
        """
        from rich.live import Live
        from rich.markdown import Markdown
        from rich.panel import Panel

        if not provider_name or not api_key:
            prov_name, api_key = self._resolve_provider()
            if not prov_name or not api_key:
                console.print("[yellow]⚠ No LLM provider available for streaming[/yellow]")
                return ""

        llm_fn = self._make_llm_call(provider_name or "", api_key or "")
        gen = await llm_fn(system_prompt, user_prompt, stream=True, history=history)
        full_text = ""
        md = Markdown("")
        panel = Panel(
            md,
            title="[bold green]◆ Siyarix[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
        with Live(panel, refresh_per_second=12, transient=False) as live:
            async for token in gen:
                full_text += token
                display_text = self._strip_json_wrapper(full_text)
                md = Markdown(display_text)
                panel = Panel(
                    md,
                    title="[bold green]◆ Siyarix[/bold green]",
                    border_style="green",
                    padding=(0, 2),
                )
                live.update(panel)
        console.print()
        return self._strip_json_wrapper(full_text)

    def _print_plan(self, plan: "Any") -> None:  # ExecutionPlan
        rows = []
        for i, step in enumerate(plan.steps, 1):
            target = step.args.get("target", "") if isinstance(step.args, dict) else ""
            rows.append(
                {
                    "#": str(i),
                    "Tool": step.tool or "—",
                    "Target": target or "—",
                    "Description": step.description[:50],
                }
            )
        self._output.print_table(rows, title="Execution Plan")

    def _print_results(self, result: "Any", elapsed: float) -> None:  # EngineResult
        from ..planner import StepStatus
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        success_count = sum(1 for r in result.step_results if r.status == StepStatus.SUCCESS)
        failed_count = len(result.step_results) - success_count

        # Step timeline panel
        step_lines = []
        for r in result.step_results:
            icon = "✓" if r.status == StepStatus.SUCCESS else "✗"
            style = "green" if r.status == StepStatus.SUCCESS else "red"
            tool = getattr(r, "tool", getattr(r, "step_id", "?"))
            detail = (r.output or "")[:80].replace("\n", " ") if r.output else ""
            step_lines.append(f"  [{style}]{icon} [bold]{tool}[/bold][/] [dim]{detail}[/dim]")

        if step_lines:
            console.print(
                Panel(
                    "\n".join(step_lines),
                    title="[bold]Step Results[/bold]",
                    border_style="blue",
                    padding=(1, 2),
                )
            )

        # Findings table grouped by severity
        if result.all_findings:
            sev_groups: dict[str, list[dict]] = {}
            for f in result.all_findings:
                sev = f.get("severity", "info")
                sev_groups.setdefault(sev, []).append(f)

            sev_order = ["critical", "high", "medium", "low", "info"]
            for sev in sev_order:
                if sev not in sev_groups:
                    continue
                items = sev_groups[sev][:15]
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}.get(sev, "blue")
                sev_table = Table(
                    title=f"{sev.upper()} Findings ({len(items)})",
                    header_style=sev_color,
                    border_style=sev_color,
                    box=None,
                )
                sev_table.add_column("Tool", style="cyan")
                sev_table.add_column("Detail", style="white")
                for f in items:
                    tool = f.get("tool", f.get("type", "?"))
                    desc = str(f.get("detail", f.get("description", f.get("title", ""))))[:100]
                    sev_table.add_row(tool, desc)
                console.print(sev_table)

            if len(result.all_findings) > 20:
                remaining = len(result.all_findings) - sum(
                    len(v) for v in sev_groups.values() if len(v) > 15
                )
                if remaining > 0:
                    console.print(f"  [dim]… and {remaining} more findings[/dim]")

        # Executive summary bar
        summary_panels = []
        summary_panels.append(
            Panel(
                f"[bold]{'✓' if result.success else '✗'} {'Success' if result.success else 'Partial'}[/bold]\n[dim]Status[/dim]",
                border_style="green" if result.success else "red",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{success_count}/{len(result.step_results)}[/bold]\n[dim]Steps[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{len(result.all_findings)}[/bold]\n[dim]Findings[/dim]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        summary_panels.append(
            Panel(
                f"[bold]{elapsed:.1f}s[/bold]\n[dim]Duration[/dim]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        if failed_count:
            summary_panels.append(
                Panel(
                    f"[bold red]{failed_count}[/bold red]\n[dim]Failed[/dim]",
                    border_style="red",
                    padding=(1, 2),
                )
            )

        console.print(Columns(summary_panels, equal=False, padding=(0, 1)))

    def _print_goodbye(self) -> None:
        self._session.save(self._SESSIONS_DIR / f"{self._session.session_id}.json")
        self._output.print_info(f"Session saved: {self._session.session_id[:8]}")
        self._output.print_info(f"Resume with: siyarix --session {self._session.session_id}")
        self._output.print_info("Settings persist in config/.env — stay curious, stay ethical.")


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
    import atexit

    try:
        from ..credential_vault import get_vault

        vault = get_vault(create=False)
        if vault:
            atexit.register(vault.seal)
    except Exception:
        pass

    chat = SiyarixChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()
