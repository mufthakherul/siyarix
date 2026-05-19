"""NexSec Chat — Interactive REPL / Conversation Mode.

A full-featured interactive shell for NexSec, similar to Claude CLI and
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
import os
import platform
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)

from .config import SettingsStore
from .environment import ensure_env_file, load_env_file, provider_env_var, upsert_env_vars
from .branding import print_theme_preview, available_themes
from .shell_knowledge import (
    build_platform_context,
    detect_shell,
    normalize_shell,
    get_security_commands,
    get_shell_platform,
    CROSS_PLATFORM_COMMANDS,
)
from .command_profiles import CommandProfileStore, CommandProfile

try:
    from prompt_toolkit import prompt as ptk_prompt
    from prompt_toolkit.completion import WordCompleter

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
            prefix = "User" if msg.role == "user" else "NexSec"
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
    "/save": "Save current session to ~/.nexsec/sessions/",
    "/translate <intent>": "Translate a command intent to all shells",
    "/security-cmds": "Show security commands for current platform",
    "/scan <target>": "Quick scan shortcut",
    "/run <command>": "Run a tool or shell command",
    "/model <provider>": "Show/switch AI model provider",
    "/context": "Show current session context",
    "/version": "Show NexSec version",
}


# ---------------------------------------------------------------------------
# The NexSec Chat REPL
# ---------------------------------------------------------------------------


class NexSecChat:
    """Interactive REPL for NexSec — the cybersecurity AI assistant."""

    _SESSIONS_DIR = Path(os.getenv("NEXSEC_CONFIG_DIR", str(Path.home() / ".nexsec"))) / "sessions"

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
        target_str = f" [dim]({self._session.target})[/dim]" if self._session.target else ""
        mode_color = {"registry": "yellow", "autonomous": "magenta", "integrated": "cyan"}.get(
            self._mode, "cyan"
        )
        prompt_str = (
            f"\n[bold {mode_color}]nexsec[/bold {mode_color}][dim cyan]>{target_str}[/dim cyan] "
        )
        return Prompt.ask(prompt_str, default="").strip()

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
            "/save": self._cmd_save,
            "/translate": self._cmd_translate,
            "/security-cmds": self._cmd_security_cmds,
            "/scan": self._cmd_scan,
            "/run": self._cmd_run,
            "/model": self._cmd_model,
            "/context": self._cmd_context,
            "/version": self._cmd_version,
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
            console.print(f"[red]Unknown command: {command}[/red] — type [cyan]/help[/cyan]{hint}")

    def _cmd_help(self, _: str) -> None:
        table = Table(title="NexSec Chat Commands", show_header=True, header_style="bold cyan")
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

    def _cmd_palette(self, _: str) -> None:
        """Interactive command palette to select an intent or saved command."""
        store = CommandProfileStore()
        intents = sorted(CROSS_PLATFORM_COMMANDS.keys())
        options = [f"intent: {i}" for i in intents]
        # include saved commands at the end
        saved = store.list_credentials()
        options += [f"saved: {p.name} -> {p.command}" for p in saved]

        console.print("[dim]Type a search term to filter. Press Enter to show full list.[/dim]")
        query = ""
        try:
            if PTK_AVAILABLE:
                completer = WordCompleter(options, ignore_case=True)
                query = ptk_prompt("Search: ", completer=completer).strip().lower()
            else:
                query = Prompt.ask("Search", default="").strip().lower()
        except Exception as exc:
            logger.exception("Command palette input failed: %s", exc)
            query = Prompt.ask("Search", default="").strip().lower()

        filtered = [o for o in options if query in o.lower()] if query else options
        if not filtered:
            console.print("[dim]No items found.[/dim]")
            return

        table = Table(title="Command Palette", header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", style="magenta")
        table.add_column("Entry", style="cyan")
        for i, entry in enumerate(filtered[:200], 1):
            t, rest = entry.split(":", 1)
            table.add_row(str(i), t.strip(), rest.strip())
        console.print(table)

        sel = Prompt.ask("Select # to insert/execute (blank to cancel)", default="").strip()
        if not sel:
            return
        try:
            idx = int(sel) - 1
            choice = filtered[idx]
        except Exception as exc:
            logger.exception("Invalid selection input: %s", exc)
            console.print("[red]Invalid selection[/red]")
            return

        if choice.startswith("intent:"):
            intent = choice.split(":", 1)[1].strip()
            cmd = CROSS_PLATFORM_COMMANDS.get(intent, {}).get(
                normalize_shell(self._shell).value, ""
            )
            console.print(f"[green]Inserted command:[/green] {cmd}")
            run = Prompt.ask("Run this command? (y/N)", default="N")
            if run.lower().startswith("y"):
                asyncio.run(self._execute_instruction(cmd))
        else:
            # saved command
            name = choice.split(":", 1)[1].split("->", 1)[0].strip()
            profile = store.get(name)
            if not profile:
                console.print("[red]Saved profile missing[/red]")
                return

            # detect placeholders and prompt for values
            cps = CommandProfileStore()
            placeholders = cps.extract_placeholders(profile.command)
            params: dict[str, str] = {}
            for ph in placeholders:
                val = Prompt.ask(f"Value for '{ph}'", default="")
                params[ph] = val

            rendered = cps.render(profile.command, params)
            console.print(f"[green]Rendered command:[/green] {rendered}")
            run = Prompt.ask("Run this command? (y/N)", default="N")
            if run.lower().startswith("y"):
                asyncio.run(self._execute_instruction(rendered))

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

    def _cmd_cmd(self, args: str) -> None:
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
            asyncio.run(self._execute_instruction(p.command))

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
        console.print(f"[green]✓ Stored {provider} API key in the vault and .env[/green]")

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
            label = "You" if msg.role == "user" else "NexSec"
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
            table = Table(title=f"{len(tools)} Security Tools Found", header_style="bold cyan")
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
            ("Terminal", "shell", f"{ctx.get('shell', '')} ({ctx.get('shell_platform', '')})"),
            ("Terminal", "shell_executable", ctx.get("shell_executable", "") or "unknown"),
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
            ("NexSec", "available_intents", str(ctx.get("available_tools_count", 0))),
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

        console.print(Rule(f"[bold]Search results for '{needle}' ({len(results)})[/bold]"))
        for msg in results[-15:]:
            ts = msg.timestamp.strftime("%H:%M:%S")
            role_color = "cyan" if msg.role == "user" else "green"
            label = "You" if msg.role == "user" else "NexSec"
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
        valid = ("registry", "autonomous", "integrated")
        if not args:
            console.print(f"Current mode: [cyan]{self._mode}[/cyan] (valid: {', '.join(valid)})")
            return
        if args not in valid:
            console.print(f"[red]Invalid mode: {args}. Choose: {', '.join(valid)}[/red]")
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
            if selected in {"auto", "openai", "gemini", "ollama", "cloud"}:
                self._settings.set("model_provider", selected)
                if selected == "gemini" and len(tokens) > 1:
                    self._settings.set("gemini_model", tokens[1].strip())
                console.print(f"[green]✓ Model provider set to: {selected}[/green]")
            else:
                console.print(
                    "[yellow]Usage: /model [auto|openai|gemini|ollama|cloud] [gemini-model][/yellow]"
                )
                return
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        console.print(
            Panel.fit(
                f"[bold]Preferred:[/bold] {self._settings.get('model_provider')}\n"
                f"[bold]OpenAI:[/bold]  {'✓ Configured' if openai_key else '✗ Not set'}\n"
                f"[bold]Gemini:[/bold]  {'✓ Configured' if gemini_key else '✗ Not set'} ({self._settings.get('gemini_model')})\n"
                f"[bold]Ollama:[/bold]  Available (lazy check on first use)\n"
                f"[bold]Cloud:[/bold]   Requires NEXSEC_SERVER_URL + NEXSEC_API_KEY\n\n"
                f"[dim]Use /key openai <value> or /key gemini <value> to store credentials.[/dim]",
                title="Model Providers",
                border_style="cyan",
            )
        )

    def _cmd_context(self, _: str) -> None:
        summary = self._session.get_context_summary()
        if not summary:
            console.print("[dim]No conversation context yet.[/dim]")
            return
        console.print(Panel(summary, title="Session Context", border_style="dim"))

    def _cmd_version(self, _: str) -> None:
        try:
            from importlib.metadata import version as _pv

            ver = _pv("nexsec")
        except Exception as exc:
            logger.debug("Failed to resolve package version: %s", exc)
            ver = "1.2.0"
        console.print(f"[bold cyan]NexSec[/bold cyan] [green]v{ver}[/green]")

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
            "ollama_url": os.environ.get("NEXSEC_OLLAMA_URL", "http://localhost:11434"),
            "model_provider": self._settings.get("model_provider"),
            "gemini_model": self._settings.get("gemini_model"),
        }

        reg = ToolRegistry()
        engine = ExecutionEngine(mode=exec_mode, registry=reg, config=engine_config)

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

        # Execute with live output
        t0 = time.monotonic()
        result = await engine.execute(instruction, interactive=False)
        elapsed = time.monotonic() - t0

        # Print results
        self._print_results(result, elapsed)

        # Add assistant summary to session
        summary = f"Executed {len(result.step_results)} steps in {elapsed:.1f}s. "
        summary += f"Found {len(result.all_findings)} findings. "
        summary += "Success." if result.success else "Some steps failed."
        self._session.add_message("assistant", summary, findings=len(result.all_findings))

    def _generate_text_response(self, user_input: str) -> str:
        """Generate a helpful text response when no tool execution is needed."""
        lower = user_input.lower()

        # Platform-specific help
        if any(
            kw in lower for kw in ("how to", "what is", "explain", "what command", "which command")
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
            "hello": "Hello! I'm NexSec, your cybersecurity AI agent. What would you like to do?\n\n"
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
        """Print the welcome banner."""
        try:
            from importlib.metadata import version as _pv

            ver = _pv("nexsec")
        except Exception as exc:
            logger.debug("Failed to resolve package version: %s", exc)
            ver = "1.2.0"

        shell_info = get_shell_platform()
        tools_hint = "Run [cyan]/tools[/cyan] to see available tools"

        console.print(
            Panel(
                f"[bold cyan]NexSec[/bold cyan] [green]v{ver}[/green] — [bold]AI Cybersecurity Agent[/bold]\n\n"
                f"[dim]Platform:[/dim] {shell_info}   "
                f"[dim]Mode:[/dim] [cyan]{self._mode}[/cyan]   "
                f"[dim]Session:[/dim] {self._session.session_id[:8]}\n\n"
                f"Type a [bold]natural language command[/bold] or a [cyan]/slash command[/cyan].\n"
                f"{tools_hint}   [cyan]/help[/cyan] for commands   [cyan]/exit[/cyan] to quit",
                title="[bold]⚡ NexSec Chat[/bold]",
                border_style="cyan",
                padding=(1, 3),
            )
        )

    def _print_assistant(self, message: str) -> None:
        """Print an assistant text response."""
        console.print(
            Panel(
                Markdown(message),
                title="[bold green]◆ NexSec[/bold green]",
                border_style="green",
                padding=(0, 2),
            )
        )

    def _print_plan(self, plan: "Any") -> None:  # ExecutionPlan
        table = Table(title="Execution Plan", show_header=True, header_style="bold magenta")
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

        success_count = sum(1 for r in result.step_results if r.status == StepStatus.SUCCESS)
        color = "green" if result.success else "red"

        # Print any step outputs
        for step_result in result.step_results:
            if step_result.output:
                console.print(
                    Panel(
                        Syntax(
                            step_result.output[:2000], "text", theme="monokai", line_numbers=False
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
                f"[dim]Resume with: nexsec chat --session {self._session.session_id}[/dim]",
                title="[bold]Goodbye from NexSec[/bold]",
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
    """Launch the NexSec interactive chat REPL."""
    chat = NexSecChat(mode=mode, target=target, session_id=session_id, resume=resume)
    chat.run()
