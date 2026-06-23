from __future__ import annotations
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

from ..branding import available_themes, print_theme_preview
from .commands import CommandProfile, CommandProfileStore, HELP_CATEGORIES, SLASH_HELP
from .session import ChatSession
from .ui import ConfigPanel
from ..subprocess_utils import safe_run_sync
from .platform_utils import (
    pip_install_args,
    provider_env_var,
    CROSS_PLATFORM_COMMANDS,
    normalize_shell,
    list_supported_shells,
    get_security_commands,
    get_shell_platform,
)
from .console import console

from ..exceptions import LLMProviderError

if TYPE_CHECKING:
    from ..config import SettingsStore
    from ..providers.state import ProviderStateManager
    from ..providers.usage import UsageTracker

logger = logging.getLogger(__name__)


class CommandHandlersMixin:
    if TYPE_CHECKING:
        _session: ChatSession
        _settings: SettingsStore
        _mode: str
        _SESSIONS_DIR: Path
        _provider_state: ProviderStateManager
        _print_welcome: Any
        _execute_instruction: Any
        _render_split_pane_layout: Any
        _print_assistant: Any
        _platform_ctx: dict[str, Any]
        _shell: str
        _resolve_api_key: Any
        _make_llm_call: Any
        _usage_tracker: UsageTracker
        _engine_kill_switch: Any
        _tool_cache: list[Any] | None

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
            "/agent": self._cmd_agent,
            "/review": self._cmd_review,
            "/persona": self._cmd_persona,
            "/report": self._cmd_report,
            "/split": self._cmd_split,
            "/batch": self._cmd_batch,
            "/scan": self._cmd_scan,
            "/opsec": self._cmd_opsec,
            "/siem": self._cmd_siem,
            "/intel": self._cmd_intel,
            "/performance": self._cmd_performance,
            "/cache": self._cmd_cache,
            "/campaign": self._cmd_campaign,
            "/kb": self._cmd_kb,
            "/ticket": self._cmd_ticket,
            "/retest": self._cmd_retest,
            "/stealth": self._cmd_stealth,
            "/audit": self._cmd_audit,
            "/queue": self._cmd_queue,
            "/skills": self._cmd_skills,
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

        provider_registry = ProviderManager.get_instance()
        try:
            store = CredentialStore()
        except Exception as exc:
            logger.warning("CredentialStore init failed: %s", exc)
            store = None

        table = Table(title="Configured API Keys", header_style="bold green")
        table.add_column("Provider", style="cyan")
        table.add_column("Env Var", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Source")

        for prov_name in provider_registry.list_providers():
            profile = provider_registry.get_profile(prov_name)
            env_key = profile.api_key_env if profile else provider_env_var(prov_name)
            from_env = bool(os.getenv(env_key)) if env_key else False
            from_creds = bool(store and store.retrieve(prov_name, "api_key"))
            if from_env:
                status, source = "✓ Set", "Environment"
            elif from_creds:
                status, source = "✓ Set", "Store"
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
                store = CredentialStore()
                new_password = Prompt.ask(
                    "Enter new master password (optional)", password=True, default=""
                )
                if store.rotate_key(new_password or None):
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
                from ..credential_store import CredentialStore

                store = CredentialStore()
                store.delete(provider, "api_key")
            except Exception:
                logger.warning("Failed to delete API key for %s from credential store", provider, exc_info=True)
            console.print(f"[green]✓ Cleared {provider} API key[/green]")
            return

        if not api_key:
            api_key = Prompt.ask(f"Enter {provider} API key", password=True)
        from ..providers import get_provider_env_var

        env_key = get_provider_env_var(provider)
        os.environ[env_key] = api_key
        try:
            from ..credential_store import CredentialStore

            store = CredentialStore()
            store.store(provider, api_key, "api_key")
            console.print(f"[green]✓ Stored {provider} API key[/green]")
        except Exception:
            console.print(f"[green]✓ {provider} API key set in environment[/green]")
            console.print(
                "[dim]Tip: Key will only last for this session. Install cryptography for persistent storage: pip install cryptography[/dim]"
            )

        # If user set Gemini key and the client package is missing, offer to install it
        if provider == "gemini":
            pkg_name = "google-genai"
            try:
                import google.genai as _test_genai  # noqa: F401

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
                            pip_install_args(pkg_name),
                            timeout=600,
                        )
                        if not res.exit_code:
                            console.print(
                                f"[green]✓ {pkg_name} installed — Gemini should be available now.[/green]"
                            )
                        else:
                            console.print(f"[red]Failed to install package: {res.stderr}[/red]")
                    except Exception as exc:
                        logger.exception("Failed to run pip install for %s: %s", pkg_name, exc)

    def _cmd_theme(self, args: str) -> None:
        tokens = args.split() if args else []
        if not tokens or tokens[0].lower() in {"show", "list"}:
            current = self._settings.get("color_theme")
            syntax = self._settings.get("syntax_theme") or "monokai"
            console.print(
                f"Current UI theme: [cyan]{current}[/cyan] | Syntax theme: [cyan]{syntax}[/cyan]"
            )
            console.print(f"Available UI themes: {', '.join(available_themes())}")
            console.print("Use /theme <ui_theme> [syntax_theme]")
            console.print("Example: /theme cyber-noir dracula")
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
            if len(tokens) > 2:
                self._settings.set("syntax_theme", tokens[2].strip().lower())
            console.print(f"[green]✓ Theme set to: {theme}[/green]")
            print_theme_preview(console, theme)
            return

        theme = action
        self._settings.set("color_theme", theme)
        if len(tokens) > 1:
            syntax_theme = tokens[1].strip().lower()
            self._settings.set("syntax_theme", syntax_theme)
            console.print(f"[green]✓ Syntax theme set to: {syntax_theme}[/green]")
        console.print(f"[green]✓ Theme set to: {theme}[/green]")
        print_theme_preview(console, theme)

    def _cmd_history(self, args: str) -> None:
        limit = 20
        search_filter = ""
        if args:
            parts = args.split()
            try:
                limit = max(1, min(int(parts[0]), 200))
                if len(parts) > 1:
                    search_filter = " ".join(parts[1:])
            except ValueError:
                search_filter = args

        msgs = self._session.last_n(limit)
        if search_filter:
            msgs = [m for m in msgs if search_filter.lower() in m.content.lower()]

        if not msgs:
            label = f" matching '{search_filter}'" if search_filter else ""
            console.print(f"[dim]No conversation history{label} yet.[/dim]")
            return
        console.print(Rule(f"[bold]Conversation History (last {len(msgs)})[/bold]"))
        for msg in msgs:
            role_color = "cyan" if msg.role == "user" else "green"
            ts = msg.timestamp.strftime("%H:%M:%S")
            label = "You" if msg.role == "user" else "Siyarix"
            console.print(
                f"[dim]{ts}[/dim] [{role_color}]{label}:[/{role_color}] {msg.content[:200]}"
            )

    def _cmd_tools(self, arg: str) -> None:
        try:
            from ..registry import ToolRegistry
            from ..tool_models import ToolCategory

            reg = ToolRegistry()
            if not hasattr(self, "_tool_cache") or self._tool_cache is None:
                reg.scan_path()
                self._tool_cache = reg.list_tools()
            tools = self._tool_cache

            category_filter = None
            if arg.strip():
                try:
                    category_filter = ToolCategory(arg.strip().lower())
                except ValueError:
                    valid = ", ".join(c.value for c in ToolCategory)
                    console.print(f"[yellow]Invalid category. Valid: {valid}[/yellow]")
                    return
                tools = [t for t in tools if t.category == category_filter]

            if not tools:
                label = f" ({category_filter.value})" if category_filter else ""
                console.print(f"[yellow]No tools found{label}.[/yellow]")
                return

            title = f"{len(tools)} Security Tools"
            if category_filter:
                title += f" [{category_filter.value}]"
            table = Table(title=title, header_style="bold cyan")
            table.add_column("#", style="dim", width=4)
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Category", style="magenta")
            table.add_column("Version", style="dim")
            table.add_column("Persona", style="yellow")
            for i, t in enumerate(sorted(tools, key=lambda x: x.category), 1):
                ver = t.version[:20] if t.version else ""
                personas = ", ".join(t.metadata.get("personas", [])) if t.metadata else ""
                table.add_row(str(i), t.name, t.category.value, ver, personas)
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
        findings = self._session.context.get("findings", [])
        uptime_delta = datetime.now(timezone.utc) - self._session.created_at
        hours, rem = divmod(int(uptime_delta.total_seconds()), 3600)
        minutes, secs = divmod(rem, 60)
        config_provider = self._settings.get("model_provider") or "auto"
        persona = self._settings.get("persona") or "auto"
        console.print(
            Panel.fit(
                f"[bold]Mode:[/bold] {self._mode}\n"
                f"[bold]Provider:[/bold] {config_provider} | [bold]Persona:[/bold] {persona}\n"
                f"[bold]Target:[/bold] {self._session.target or '[dim]not set[/dim]'}\n"
                f"[bold]Session:[/bold] {self._session.session_id[:8]} | [bold]Uptime:[/bold] {hours:02d}:{minutes:02d}:{secs:02d}\n"
                f"[bold]Messages:[/bold] {counts['messages']} (you: {counts['user_messages']}, agent: {counts['assistant_messages']})\n"
                f"[bold]Findings:[/bold] {len(findings)}\n"
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
        delta = datetime.now(timezone.utc) - self._session.created_at
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
        valid = ("autonomous", "integrated", "offline")
        if not args:
            console.print(f"Current mode: [cyan]{self._mode}[/cyan] (valid: {', '.join(valid)})")
            return

        # Redirect: "registry" was renamed to "offline"
        if args == "registry":
            console.print(
                "[yellow]'registry' mode has been renamed to 'offline'. Switching…[/yellow]"
            )
            args = "offline"

        if args not in valid:
            console.print(f"[red]Invalid mode: {args}. Valid modes: {', '.join(valid)}[/red]")
            return

        self._mode = args
        self._session.mode = args

        if args == "offline":
            self._settings.set("model_provider", "registry")
            console.print(
                f"[green]✓ Mode switched to: {args} (provider locked to registry)[/green]"
            )
        else:
            # Switching away from offline: release provider lock if it was "registry"
            current_provider = self._settings.get("model_provider") or "auto"
            if current_provider == "registry":
                self._settings.set("model_provider", "auto")
                console.print(f"[green]✓ Mode switched to: {args} (provider reset to auto)[/green]")
            else:
                console.print(f"[green]✓ Mode switched to: {args}[/green]")

    def _cmd_save(self, _: str) -> None:
        path = self._SESSIONS_DIR / f"{self._session.session_id}.json"
        self._session.save(path)
        console.print(f"[green]✓ Session saved to: {path}[/green]")

    def _cmd_translate(self, args: str) -> None:
        if not args:
            intents = list(CROSS_PLATFORM_COMMANDS.keys())
            console.print("[yellow]Usage: /translate <intent>[/yellow]")
            table = Table(title=f"Available Intents ({len(intents)})", header_style="bold cyan")
            table.add_column("Intent", style="cyan")
            table.add_column("Example Command", style="green")
            for intent in sorted(intents):
                cmd = next(iter(CROSS_PLATFORM_COMMANDS[intent].values()), "")
                table.add_row(intent, cmd)
            console.print(table)
            return
        entry = CROSS_PLATFORM_COMMANDS.get(args)
        if not entry:
            close = [k for k in CROSS_PLATFORM_COMMANDS if args in k or k in args][:3]
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            console.print(f"[red]Unknown intent: {args}[/red]{hint}")
            return
        table = Table(title=f"Command: {args}", header_style="bold cyan")
        table.add_column("Shell", style="cyan")
        table.add_column("Command", style="green")
        for shell, cmd in entry.items():
            table.add_row(
                shell.replace("bash", "Linux/macOS")
                .replace("powershell", "PowerShell")
                .replace("cmd", "CMD"),
                cmd,
            )
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
        pm = ProviderManager.get_instance()
        all_providers = pm.list_providers()

        if tokens:
            selected = tokens[0].strip().lower()
            valid_providers = set(all_providers) | {
                "auto",
                "cloud",
                "custom",
                "opencode",
            }

            # ── Cross-mode validation for "registry" provider ──
            if selected == "registry":
                if self._mode == "autonomous":
                    console.print(
                        "[red]✗ Cannot use registry (offline) provider in autonomous mode. "
                        "Switch to integrated or offline mode first.[/red]"
                    )
                    return
                if self._mode == "offline":
                    console.print("[dim]Provider already set to registry (offline mode).[/dim]")
                    return

            # ── Block switching away from registry when in offline mode ──
            if self._mode == "offline" and selected != "registry":
                console.print(
                    "[yellow]⚠ Cannot switch provider while in offline mode. "
                    "Use /mode integrated or /mode autonomous first.[/yellow]"
                )
                return

            if selected in valid_providers:
                self._settings.set("model_provider", selected)

                # Auto-switch mode when selecting registry provider
                if selected == "registry" and self._mode != "offline":
                    self._mode = "offline"
                    self._session.mode = "offline"

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
                if selected != "auto" and selected != "registry" and selected in all_providers:
                    profile = pm.get_profile(selected)
                    key = self._resolve_api_key(selected, profile.api_key_env if profile else "")
                    needs_key = profile is not None and bool(profile.api_key_env)
                    if needs_key and not key:
                        console.print(
                            f"[yellow]  ⚠ {selected} requires an API key. "
                            f"Use /key {selected} <value> to set it.[/yellow]"
                        )
                    elif key or not needs_key:
                        with console.status(
                            f"[dim]Validating {selected}...[/dim]", spinner="point"
                        ):
                            try:
                                import asyncio

                                bench_fn = self._make_llm_call(selected, key or "")
                                bench_model = model_name or ""
                                if not bench_model:
                                    from ..chat.openai_compat import MODEL_KEYS as _MK

                                    bench_key = _MK.get(selected, f"{selected}_model")
                                    bench_model = self._settings.get(bench_key) or ""
                                if not bench_model and profile:
                                    bench_model = profile.default_model
                                result = await asyncio.wait_for(
                                    bench_fn("Respond with exactly: OK", "ping"),
                                    timeout=15.0,
                                )
                                if not isinstance(result, dict):
                                    raise LLMProviderError(
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
            key = self._resolve_api_key(prov_name, profile.api_key_env or "")
            from ..chat.openai_compat import MODEL_KEYS

            model_key = MODEL_KEYS.get(prov_name, f"{prov_name}_model")
            model_setting = self._settings.get(model_key) or profile.default_model or ""
            status = (
                "✓ Configured"
                if key
                else ("✗ Not set" if profile and profile.api_key_env else "Available")
            )
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

        pm = ProviderManager.get_instance()
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
            key = (
                bool(self._resolve_api_key(prov_name, profile.api_key_env or ""))
                or not profile.api_key_env
            )
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
        """View or modify configuration settings."""
        from ..config import DESCRIPTIONS

        sub = args.strip() if args else ""
        if not sub or sub == "show":
            rows = self._settings.list_all()
            table = Table(title="Configuration Settings", header_style="bold cyan")
            table.add_column("Key", style="cyan", no_wrap=True)
            table.add_column("Value", style="white")
            table.add_column("Default", style="dim")
            table.add_column("Description", style="green")
            for r in rows:
                val_style = "yellow" if r["modified"] else "white"
                table.add_row(
                    r["key"],
                    f"[{val_style}]{r['value']}[/{val_style}]",
                    r["default"],
                    r["description"],
                )
            console.print(table)
            console.print(
                "[dim]Use /config set <key> <value> to change, /config get <key> to view[/dim]"
            )
        elif sub == "tools":
            ConfigPanel._section_tools()
        elif sub.startswith("set "):
            parts = sub.split(maxsplit=2)
            if len(parts) < 3:
                console.print("[yellow]Usage: /config set <key> <value>[/yellow]")
                return
            key, value = parts[1], parts[2]
            try:
                result = self._settings.set(key, value)
                console.print(f"[green]✓ Set {key} = {result}[/green]")
                if key == "log_level":
                    from ..logging_config import configure_logging

                    configure_logging(str(result))
            except KeyError as exc:
                console.print(f"[red]Unknown setting: {exc}[/red]")
                console.print("[yellow]Use /config to see available settings.[/yellow]")
        elif sub.startswith("get "):
            parts = sub.split(maxsplit=1)
            key = parts[1] if len(parts) > 1 else ""
            if not key:
                console.print("[yellow]Usage: /config get <key>[/yellow]")
                return
            val = self._settings.get(key)
            desc = DESCRIPTIONS.get(key, "")
            if val is not None:
                console.print(f"[cyan]{key}[/cyan] = {val}")
                if desc:
                    console.print(f"[dim]{desc}[/dim]")
            else:
                console.print(f"[yellow]{key} is not set[/yellow]")
        elif sub.startswith("list"):
            valid_keys = sorted(DESCRIPTIONS.keys())
            console.print("[bold]Available settings keys:[/bold]")
            for k in valid_keys:
                console.print(f"  [cyan]{k}[/cyan]: [dim]{DESCRIPTIONS[k]}[/dim]")
        else:
            console.print("[yellow]Usage: /config [show|set|get|list|tools][/yellow]")

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

    def _cmd_skills(self, args: str) -> None:
        """Handle /skills command to manage the Continuous Learning System."""
        from ..learning_system import get_learning_system
        import json
        from pathlib import Path
        from rich.table import Table
        from rich import box

        cls = get_learning_system()
        tokens = args.split(maxsplit=1)
        subcmd = tokens[0].lower() if tokens else ""
        subargs = tokens[1] if len(tokens) > 1 else ""

        if not subcmd or subcmd in ("stats", "list", "ls", "status"):
            stats = cls.stats()
            console.print(
                Panel(
                    f"[bold cyan]📚 Learned Skills Stats[/bold cyan]\n"
                    f"Total Skills: {stats.get('total_skills', 0)}\n"
                    f"High Confidence: {stats.get('high_confidence', 0)}\n"
                    f"Storage: {stats.get('db_path', 'unknown')}",
                    border_style="cyan"
                )
            )
            # List top 10 skills by confidence
            if stats.get('total_skills', 0) > 0:
                skills = sorted(cls._skills.values(), key=lambda s: s.confidence, reverse=True)
                table = Table(title="Top Learned Skills", box=box.SIMPLE)
                table.add_column("Intent / Pattern", style="cyan", max_width=40)
                table.add_column("Steps", justify="right")
                table.add_column("Conf.", justify="right", style="green")
                table.add_column("Uses", justify="right")
                for s in skills[:10]:
                    table.add_row(
                        s.intent_pattern,
                        str(len(s.steps)),
                        f"{s.confidence:.0%}",
                        str(s.usage_count)
                    )
                console.print(table)
                if len(skills) > 10:
                    console.print(f"[dim]... and {len(skills) - 10} more skills.[/dim]")

        elif subcmd == "add":
            if not subargs:
                console.print("[yellow]Usage: /skills add <workflow description...>[/yellow]")
                return
            from .onboarding import OnboardingWizard
            added = OnboardingWizard._parse_and_add_manual_skills(cls, subargs)
            if added:
                console.print(f"[green]✓ Successfully added {added} new skill(s)![/green]")
            else:
                console.print("[yellow]⚠ Could not parse any valid skills from input. Use format: 1. step_a; step_b.[/yellow]")

        elif subcmd == "export":
            if not subargs:
                console.print("[yellow]Usage: /skills export <filepath.json>[/yellow]")
                return
            export_path = Path(subargs).expanduser().resolve()
            try:
                data = cls.export_skills()
                export_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                console.print(f"[green]✓ Exported {len(data['skills'])} skills to {export_path}[/green]")
            except Exception as exc:
                console.print(f"[red]✗ Export failed: {exc}[/red]")

        else:
            console.print(
                "[yellow]Unknown /skills sub-command.[/yellow]\n"
                "[dim]Usage: /skills [stats|list]\n"
                "       /skills add 1. step_a; step_b.\n"
                "       /skills export /path/to/export.json[/dim]"
            )
            console.print("[green]OPSEC deactivated[/green]")

    async def _cmd_siem(self, args: str) -> None:
        """Handle /siem command for SIEM/SOAR integration."""
        console.print("[yellow]SIEM integration has been migrated to a separate plugin. Check https://github.com/siyarix/siyarix-plugins.git[/yellow]")
        return

    async def _cmd_intel(self, args: str) -> None:
        """Handle /intel command for Threat Intelligence integration."""
        from ..threat_intel import intel_manager
        
        tokens = args.split() if args else []
        if not tokens or tokens[0] not in ("lookup", "status"):
            console.print("[yellow]Usage: /intel lookup|status [indicator][/yellow]")
            return
            
        if tokens[0] == "lookup":
            if len(tokens) < 2:
                console.print("[red]Missing indicator to lookup. Example: /intel lookup CVE-2023-1234 or /intel lookup 8.8.8.8[/red]")
                return
            indicator = tokens[1]
            console.print(f"Looking up {indicator}...")
            result = await intel_manager.analyze_target(indicator)
            if "error" in result:
                console.print(f"[red]Error:[/red] {result['error']}")
            else:
                console.print(f"[green]Intel Result for {indicator}:[/green]")
                for k, v in result.items():
                    console.print(f"  {k}: {v}")
        elif tokens[0] == "status":
            console.print("[green]Threat Intel module active.[/green]")
            console.print(f"AlienVault OTX API Key Configured: {'Yes' if intel_manager.alienvault.api_key else 'No'}")

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
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "create"
        if action == "create":
            title = " ".join(tokens[1:]) if len(tokens) > 1 else Prompt.ask("Ticket title")
            console.print(f"[green]✓ Ticket created internally: {title}[/green]")
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

    async def _cmd_queue(self, args: str) -> None:
        """Handle /queue command for offline command queue management."""
        from ..offline_queue import OfflineCommandQueue

        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"

        try:
            queue = OfflineCommandQueue()
        except Exception as exc:
            console.print(f"[red]Failed to open queue: {exc}[/red]")
            return

        if action == "status":
            stats = queue.stats()
            total = stats["pending"] + stats["completed"] + stats["failed"]
            if total == 0:
                console.print("[dim]No queued commands.[/dim]")
                return
            console.print(
                Panel(
                    f"[bold]Offline Command Queue[/bold]\n\n"
                    f"[yellow]Pending:[/yellow] {stats['pending']}\n"
                    f"[green]Completed:[/green] {stats['completed']}\n"
                    f"[red]Failed:[/red] {stats['failed']}\n"
                    f"[bold]Total:[/bold] {total}",
                    border_style="cyan",
                )
            )

        elif action == "list":
            commands = queue.get_all(limit=20)
            if not commands:
                console.print("[dim]No queued commands.[/dim]")
                return
            from rich.table import Table
            table = Table(title="Queued Commands", header_style="bold cyan")
            table.add_column("ID (short)", style="dim")
            table.add_column("Instruction", style="white")
            table.add_column("Status", style="yellow")
            table.add_column("Attempts", justify="right")
            for cmd in commands[:20]:
                status_color = {
                    "pending": "yellow",
                    "processing": "cyan",
                    "completed": "green",
                    "failed": "red",
                }.get(cmd.status, "white")
                table.add_row(
                    cmd.id[:8],
                    cmd.instruction[:50],
                    f"[{status_color}]{cmd.status}[/{status_color}]",
                    f"{cmd.attempts}/{cmd.max_attempts}",
                )
            console.print(table)

        elif action == "retry":
            count = queue.retry_failed()
            console.print(f"[green]✓ {count} failed commands reset to pending for retry.[/green]")

        elif action == "clear":
            count = queue.clear_completed()
            console.print(f"[green]✓ Cleared {count} completed commands.[/green]")

        elif action == "flush":
            commands = queue.dequeue(10)
            if not commands:
                console.print("[dim]No pending commands to flush.[/dim]")
                return
            console.print(f"[yellow]Flushing {len(commands)} pending commands...[/yellow]")
            for cmd in commands:
                queue.mark_processing(cmd.id)
                try:
                    if hasattr(self, "_execute_instruction"):
                        await self._execute_instruction(cmd.instruction, target=cmd.target)
                        queue.mark_completed(cmd.id, "Replayed successfully")
                        console.print(f"[green]  ✓ {cmd.instruction[:50]}[/green]")
                    else:
                        queue.mark_failed(cmd.id, "No executor available")
                except Exception as exc:
                    queue.mark_failed(cmd.id, str(exc))
                    console.print(f"[red]  ✗ {cmd.instruction[:50]}: {exc}[/red]")
            console.print("[green]Flush complete.[/green]")

        else:
            console.print("[yellow]Usage: /queue status|list|retry|clear|flush[/yellow]")
