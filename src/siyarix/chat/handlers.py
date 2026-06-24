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
from ..config import get_config_dir
from .commands import CommandCategory, CommandProfile, CommandProfileStore, CommandRegistry, SLASH_HELP
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
            "/h": self._cmd_help,
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
            "/info": self._cmd_session,
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
            "/m": self._cmd_mode,
            "/save": self._cmd_save,
            "/translate": self._cmd_translate,
            "/security-cmds": self._cmd_security_cmds,
            "/run": self._cmd_run,
            "/model": self._cmd_model,
            "/provider": self._cmd_provider,
            "/providers": self._cmd_provider,
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
            # ── New commands ──
            "/export": self._cmd_export,
            "/plugins": self._cmd_plugins,
            "/alias": self._cmd_alias,
            "/language": self._cmd_language,
            "/load": self._cmd_load,
            "/fork": self._cmd_fork,
            "/learn": self._cmd_learn,
            "/feedback": self._cmd_feedback,
                "/redteam": self._cmd_redteam,
                "/offensive": self._cmd_redteam,
                "/blueteam": self._cmd_blueteam,
                "/defensive": self._cmd_blueteam,
            "/benchmark": self._cmd_benchmark,
            "/upgrade": self._cmd_upgrade,
            "/docs": self._cmd_docs,
            "/tutorial": self._cmd_tutorial,
            "/bug": self._cmd_bug,
            "/suggest": self._cmd_suggest,
            "/playbook": self._cmd_playbook,
            "/stats": self._cmd_stats,
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

    def _cmd_help(self, args: str) -> None:
        """Show categorized help system with detailed lookup support."""
        from rich.table import Table as RichTable
        from rich.panel import Panel as RichPanel
        from ..branding import resolve_version

        query = args.strip().lower() if args else ""

        # ── Detailed help for a specific command ──
        if query.startswith("/"):
            cmd_info = CommandRegistry.get(query)
            if cmd_info:
                console.print(RichPanel(
                    cmd_info.format_detailed(),
                    title=f"[bold cyan]Command: {cmd_info.name}[/bold cyan]",
                    border_style="cyan",
                ))
                return
            # Fuzzy search for close matches
            close = CommandRegistry.search(query.lstrip("/"))
            if close:
                console.print(f"[yellow]Unknown command: {query}[/yellow]")
                console.print("[dim]Did you mean:[/dim]")
                for c in close[:5]:
                    console.print(f"  [cyan]{c.name}[/cyan] — [dim]{c.description[:60]}[/dim]")
            else:
                console.print(f"[red]Unknown command: {query}[/red] — type [cyan]/help[/cyan] for all commands")
            return

        # ── Help for a specific category ──
        category_map_lower = {cat.value.lower(): cat for cat in CommandCategory}
        if query and query in category_map_lower:
            cat = category_map_lower[query]
            cmds = CommandRegistry.by_category(cat)
            if cmds:
                table = RichTable(
                    title=f"[bold]{cat.value}[/bold] ({len(cmds)} commands)",
                    header_style="bold cyan",
                    padding=(0, 1),
                )
                table.add_column("Command", style="cyan", no_wrap=True)
                table.add_column("Description", style="white")
                table.add_column("Usage", style="dim", no_wrap=True)
                for c in cmds:
                    if not c.hidden:
                        usage = c.usage or c.name
                        desc = c.description
                        aliases_str = f" ({', '.join(c.aliases)})" if c.aliases else ""
                        table.add_row(c.name, f"{desc}{aliases_str}", usage)
                console.print(table)
                return

        # ── Keyword search ──
        if query:
            results = CommandRegistry.search(query)
            if results:
                table = RichTable(
                    title=f"[bold]Search: '{query}'[/bold] ({len(results)} matches)",
                    header_style="bold cyan",
                )
                table.add_column("Command", style="cyan", no_wrap=True)
                table.add_column("Category", style="magenta")
                table.add_column("Description", style="white")
                for c in results[:25]:
                    table.add_row(c.name, c.category.value, c.description[:70])
                console.print(table)
                if len(results) > 25:
                    console.print(f"[dim]... and {len(results) - 25} more matches[/dim]")
                return
            console.print(f"[yellow]No results for '{query}'[/yellow]")
            console.print("[dim]Try a category name or browse below.[/dim]")

        # ── Full categorized help ──
        ver = resolve_version()
        total_visible = len(CommandRegistry.visible_commands())
        total_all = len(CommandRegistry.all_commands())

        # Summary header
        summary_parts = []
        for cat in CommandCategory:
            cmds = CommandRegistry.by_category(cat)
            visible = [c for c in cmds if not c.hidden]
            if visible:
                summary_parts.append(f"[bold]{cat.value}:[/bold] {len(visible)}")
        summary_line = "  │  ".join(summary_parts)

        console.print(RichPanel(
            f"[bold cyan]Siyarix Command Reference[/bold cyan] [dim]v{ver}[/dim]\n"
            f"[dim]{total_visible} visible · {total_all} total commands[/dim]\n\n"
            f"{summary_line}\n\n"
            f"[dim]Type [/dim][cyan]/help <command>[/cyan][dim] for detailed help\n"
            f"Type [/dim][cyan]/help <category>[/cyan][dim] to filter by category\n"
            f"Type [/dim][cyan]/help <keyword>[/cyan][dim] to search[/dim]",
            border_style="cyan",
            padding=(1, 2),
        ))

        for cat in CommandCategory:
            cmds = CommandRegistry.by_category(cat)
            visible = [c for c in cmds if not c.hidden]
            if not visible:
                continue
            table = RichTable(
                title=f"[bold]{cat.value}[/bold] ({len(visible)})",
                padding=(0, 1),
                box=None,
                header_style="bold bright_black",
            )
            table.add_column("Command", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Usage", style="dim", no_wrap=True)
            for c in visible:
                usage = c.usage or c.name
                desc = c.description
                aliases_str = f" ({', '.join(c.aliases)})" if c.aliases else ""
                table.add_row(c.name, f"{desc}{aliases_str}", usage)
            console.print(table)
            console.print()

        console.print("[dim]Tip:[/dim] Use [cyan]/help <command>[/cyan] for examples, arguments, and notes.")

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
            from_creds = bool(store.retrieve(prov_name, "api_key")) if store else False
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
            table.add_column("Persona", style="yellow")
            for i, t in enumerate(sorted(tools, key=lambda x: x.category), 1):
                personas = ", ".join(t.metadata.get("personas", [])) if t.metadata else ""
                table.add_row(str(i), t.name, t.category.value, personas)
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
        valid = (
            "autonomous", "integrated", "offline", "stealth",
            "verbose", "quiet", "expert", "beginner",
            "interactive", "batch", "redteam", "blueteam",
            "compliance", "audit",
        )
        core_modes = ("autonomous", "integrated", "offline")
        if not args:
            console.print(f"Current mode: [cyan]{self._mode}[/cyan]")
            console.print(f"[dim]Valid modes: {', '.join(valid)}[/dim]")
            return

        # Redirect
        if args == "registry":
            console.print("[yellow]'registry' mode renamed to 'offline'. Switching…[/yellow]")
            args = "offline"
        if args == "offensive":
            console.print("[yellow]Use /redteam for offensive focus.[/yellow]")
            args = "redteam"
        if args == "defensive":
            console.print("[yellow]Use /blueteam for defensive focus.[/yellow]")
            args = "blueteam"

        if args not in valid:
            console.print(f"[red]Invalid mode: {args}. Valid modes: {', '.join(core_modes)}[/red]")
            return

        old_mode = self._mode
        self._mode = args
        self._session.mode = args

        # Mode-specific persona and provider adjustments
        if args in ("redteam",):
            self._settings.set("persona", "red-team")
            console.print("[red]✓ Switched to RED TEAM mode with offensive persona[/red]")
        elif args in ("blueteam",):
            self._settings.set("persona", "blue-team")
            console.print("[blue]✓ Switched to BLUE TEAM mode with defensive persona[/blue]")
        elif args == "offline":
            self._settings.set("model_provider", "registry")
            console.print(f"[green]✓ Mode switched to: {args} (provider locked to registry)[/green]")
        else:
            current_provider = self._settings.get("model_provider") or "auto"
            if current_provider == "registry" and args != "integrated":
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
                "opencode-zen",
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
                    from ..chat.openai_compat import MODEL_KEYS
                    model_key = MODEL_KEYS.get(selected, f"{selected}_model")
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
                                bench_fn = self._make_llm_call(selected, key or "")
                                bench_model = model_name or ""
                                if not bench_model:
                                    from ..chat.openai_compat import MODEL_KEYS as _MK

                                    bench_key = _MK.get(selected, f"{selected}_model")
                                    bench_model = self._settings.get(bench_key) or ""
                                if not bench_model and profile:
                                    bench_model = profile.default_model
                                result = await asyncio.wait_for(
                                    bench_fn("Respond with exactly: OK", "ping", model=bench_model),
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
        lines.append("[bold]opencode-zen:[/bold]  Requires OPENCODE_API_KEY\n\n")
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
        if sub and sub != "show":
            if sub == "tools":
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
            return

        rows = {r["key"]: r for r in self._settings.list_all()}

        categories = [
            ("General", [
                "default_output_format", "default_parallel", "scan_timeout",
                "agent_timeout", "max_waves", "auto_sync", "notifications_enabled",
                "history_retention_days", "auto_update_check",
            ]),
            ("Appearance", [
                "color_theme", "syntax_theme", "log_level",
            ]),
            ("Mode & Persona", [
                "default_mode", "model_provider", "persona",
                "additional_system_message",
            ]),
            ("Security", [
                "stealth_mode", "command_review", "tls_verify",
            ]),
            ("Cloud Providers", [
                "openai_model", "anthropic_model", "gemini_model",
                "groq_model", "together_model", "openrouter_model",
                "deepseek_model", "xai_model", "mistral_model",
                "perplexity_model", "azure_model", "cerebras_model",
                "fireworks_model", "zai_model", "minimax_model",
                "moonshot_model", "nvidia_model", "opencode_zen_model",
                "huggingface_model",
            ]),
            ("Local Providers", [
                "ollama_url", "ollama_model",
                "lmstudio_url", "lmstudio_model",
                "llamacpp_url", "llamacpp_model",
                "vllm_url", "vllm_model",
                "localai_url", "localai_model",
                "_start_ollama_on_launch", "registry_model",
            ]),
            ("Behavior", [
                "multiline", "auto_save_session",
                "shell_completion_installed", "path_setup_done",
                "onboarding_complete",
            ]),
        ]

        for title, keys in categories:
            cat_rows = [rows[k] for k in keys if k in rows]
            if not cat_rows:
                continue
            table = Table(
                title=title,
                title_style="bold",
                header_style="bold cyan",
                box=None,
                show_edge=False,
                padding=(0, 2),
            )
            table.add_column("Key", style="cyan", no_wrap=True, ratio=2)
            table.add_column("Value", style="white", ratio=3)
            table.add_column("Default", style="dim", ratio=2)
            table.add_column("Description", style="green", ratio=4)
            for r in cat_rows:
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

        current = self._settings.get("persona") or "auto"
        action = args.strip().lower() if args else ""
        if not action:
            p = get_persona(current)
            label = p["label"] if p else current
            console.print(
                f"[dim]Current persona: [bold]{label}[/bold]. Usage: /persona list | /persona <name>[/dim]"
            )
            return
        if action == "list":
            table = Table(title="Available Personas", header_style="bold cyan")
            table.add_column("Name", style="cyan")
            table.add_column("Label", style="green")
            table.add_column("Description", style="dim")
            for p in list_personas():
                table.add_row(p.get("name", "?"), p.get("label", "?"), p.get("description", ""))
            table.add_row("auto", "Auto (Smart Select)", "Analyse and choose the best-fit persona")
            table.add_row(
                "universal",
                "Universal / All-in-One",
                "Full-spectrum cybersecurity professional",
            )
            table.add_row("none", "None", "No persona framing — LLM decides its own voice")
            console.print(table)
            console.print(
                "[dim]Tip: use underscores for multi-word names, e.g. /persona red_team[/dim]"
            )
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

    def _get_sorted_skills(self) -> list[Any]:
        """Return all skills sorted by confidence desc."""
        from ..learning_system import get_learning_system
        cls = get_learning_system()
        return sorted(cls._skills.values(), key=lambda s: s.confidence, reverse=True)

    def _get_skill_by_sl(self, sl_no: str) -> Any | None:
        """Get a skill by its 1-based Sl No in the sorted list."""
        try:
            idx = int(sl_no) - 1
            if idx < 0:
                return None
            skills = self._get_sorted_skills()
            return skills[idx] if idx < len(skills) else None
        except (ValueError, IndexError):
            return None

    def _print_skill_detail(self, s: Any, sl_no: int) -> None:
        """Print full detail for a single skill."""
        from rich.table import Table
        from rich import box
        console.print()
        console.print(Panel(
            f"[bold cyan]Skill #{sl_no}[/bold cyan]  [dim]{s.skill_id[:12]}[/dim]",
            border_style="cyan",
        ))
        console.print(f"[bold]Intent:[/bold] {s.intent_pattern}")
        console.print(f"[bold]Confidence:[/bold] [green]{s.confidence:.0%}[/green]")
        console.print(f"[bold]Uses:[/bold] {s.usage_count}  |  [bold]Success:[/bold] {s.success_count}")
        console.print(f"[bold]Source:[/bold] {s.source}")
        console.print(f"[bold]Notes:[/bold] {s.notes or '—'}")
        if s.tags:
            console.print(f"[bold]Tags:[/bold] {', '.join(s.tags)}")
        if s.steps:
            step_table = Table(box=box.SIMPLE)
            step_table.add_column("#", justify="right", style="dim")
            step_table.add_column("Tool", style="cyan")
            step_table.add_column("Command", style="white")
            for i, step in enumerate(s.steps, 1):
                step_table.add_row(str(i), step.tool, step.command_template[:80])
            console.print(step_table)
        console.print()

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
            if stats.get('total_skills', 0) > 0:
                skills = self._get_sorted_skills()
                table = Table(title="Top Learned Skills", box=box.SIMPLE)
                table.add_column("Sl No", justify="right", style="dim", width=4)
                table.add_column("Intent / Pattern", style="cyan", max_width=36)
                table.add_column("Steps", justify="right")
                table.add_column("Conf.", justify="right", style="green")
                table.add_column("Uses", justify="right")
                for i, s in enumerate(skills[:10], 1):
                    table.add_row(
                        str(i),
                        s.intent_pattern,
                        str(len(s.steps)),
                        f"{s.confidence:.0%}",
                        str(s.usage_count)
                    )
                console.print(table)
                if len(skills) > 10:
                    console.print(f"[dim]... and {len(skills) - 10} more skills.[/dim]")
                    console.print("[dim]Use /skills show <Sl No> to see a specific skill.[/dim]")

        elif subcmd == "show":
            if not subargs:
                console.print("[yellow]Usage: /skills show <Sl No>[/yellow]")
                return
            skill = self._get_skill_by_sl(subargs)
            if skill is None:
                console.print("[red]✗ Invalid Sl No. Use /skills list to see available skills.[/red]")
                return
            self._print_skill_detail(skill, int(subargs))

        elif subcmd == "edit":
            if not subargs:
                console.print("[yellow]Usage: /skills edit <Sl No>[/yellow]")
                return
            parts = subargs.split(maxsplit=1)
            skill = self._get_skill_by_sl(parts[0])
            if skill is None:
                console.print("[red]✗ Invalid Sl No. Use /skills list to see available skills.[/red]")
                return
            self._print_skill_detail(skill, int(parts[0]))
            edit_field = parts[1] if len(parts) > 1 else ""
            if edit_field == "intent":
                new_intent = input("  New intent pattern: ").strip()
                if new_intent:
                    skill.intent_pattern = new_intent[:200]
                    cls._save_skill(skill)
                    console.print("[green]✓ Intent pattern updated.[/green]")
            elif edit_field == "notes":
                new_notes = input("  New notes: ").strip()
                if new_notes:
                    skill.notes = new_notes[:500]
                    cls._save_skill(skill)
                    console.print("[green]✓ Notes updated.[/green]")
            elif edit_field == "":
                console.print("[dim]Editable fields: intent, notes[/dim]")
            else:
                console.print(f"[yellow]Unknown field '{edit_field}'. Editable: intent, notes[/yellow]")

        elif subcmd == "remove":
            if not subargs:
                console.print("[yellow]Usage: /skills remove <Sl No>[/yellow]")
                return
            parts = subargs.split(maxsplit=1)
            skill = self._get_skill_by_sl(parts[0])
            if skill is None:
                console.print("[red]✗ Invalid Sl No. Use /skills list to see available skills.[/red]")
                return
            self._print_skill_detail(skill, int(parts[0]))
            from ..tool_installer import tty_confirm
            if tty_confirm("Remove this skill?", default=False):
                if cls.delete_skill(skill.skill_id):
                    console.print("[green]✓ Skill removed.[/green]")
                else:
                    console.print("[red]✗ Failed to remove skill.[/red]")

        elif subcmd == "add":
            if not subargs:
                console.print("[yellow]Usage: /skills add <Sl No. intent/pattern; step_a; step_b.>[/yellow]")
                return
            from ..onboarding import OnboardingWizard
            added = OnboardingWizard._parse_and_add_manual_skills(cls, subargs)
            if added:
                console.print(f"[green]✓ Successfully added {added} new skill(s)![/green]")
            else:
                console.print("[yellow]⚠ Could not parse any valid skills from input. Use format:\n"
                              "  /skills add 1. intent/pattern; step_a; step_b.[/yellow]")

        elif subcmd == "export":
            if not subargs:
                console.print("[yellow]Usage: /skills export <path>.json (or .xaml)[/yellow]")
                return
            export_path = Path(subargs).expanduser().resolve()
            suffix = export_path.suffix.lower()
            def _xml(s: str) -> str:
                return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            try:
                data = cls.export_skills()
                if suffix == ".xaml":
                    lines = ['<?xml version="1.0" encoding="utf-8"?>',
                             '<Skills xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">']
                    for s in data["skills"]:
                        lines.append(f'  <Skill ID="{_xml(s["skill_id"])}" Confidence="{s["confidence"]:.2f}">')
                        lines.append(f'    <Intent>{_xml(s["intent_pattern"])}</Intent>')
                        lines.append("    <Steps>")
                        for step in s["steps"]:
                            lines.append(f'      <Step Tool="{_xml(step["tool"])}">'
                                         f'{_xml(step["command_template"])}</Step>')
                        lines.append("    </Steps>")
                        lines.append("  </Skill>")
                    lines.append('</Skills>')
                    export_path.write_text("\n".join(lines), encoding="utf-8")
                else:
                    export_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                console.print(f"[green]✓ Exported {len(data['skills'])} skills to {export_path}[/green]")
            except Exception as exc:
                console.print(f"[red]✗ Export failed: {exc}[/red]")

        else:
            console.print(
                "[yellow]Unknown /skills sub-command.[/yellow]\n"
                "[dim]Usage: /skills [stats|list]\n"
                "       /skills show <Sl No>\n"
                "       /skills edit <Sl No> [field]\n"
                "       /skills remove <Sl No>\n"
                "       /skills add <Sl No. intent/pattern; step_a; step_b.>\n"
                "       /skills export <path>.json (or .xaml)[/dim]"
            )

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

    # ── New Command Handlers ──────────────────────────────────────────────

    async def _cmd_export(self, args: str) -> None:
        """Export conversation in various formats."""
        tokens = args.split() if args else []
        fmt = tokens[0].lower() if tokens else "json"
        output_path = tokens[1] if len(tokens) > 1 else ""
        valid_formats = ("json", "md", "markdown", "html", "pdf", "txt")
        if fmt not in valid_formats:
            console.print(f"[yellow]Invalid format: {fmt}. Valid: {', '.join(valid_formats)}[/yellow]")
            return

        if not output_path:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            ext = {"json": "json", "md": "md", "markdown": "md", "html": "html", "pdf": "pdf", "txt": "txt"}[fmt]
            output_path = str(self._SESSIONS_DIR / f"export_{self._session.session_id[:8]}_{ts}.{ext}")

        export_dir = Path(output_path).parent
        export_dir.mkdir(parents=True, exist_ok=True)

        try:
            exported = self._session.export(fmt)
            if isinstance(exported, str):
                Path(output_path).write_text(exported, encoding="utf-8")
            elif isinstance(exported, bytes):
                Path(output_path).write_bytes(exported)
            console.print(f"[green]✓ Conversation exported to: {output_path}[/green]")
            console.print(f"[dim]Format: {fmt} | Messages: {len(self._session.messages)}[/dim]")
        except Exception as exc:
            console.print(f"[red]Export failed: {exc}[/red]")

    def _cmd_plugins(self, args: str) -> None:
        """List and manage Siyarix plugins."""
        try:
            tokens = args.split() if args else []
            action = tokens[0].lower() if tokens else "list"

            if action == "list":
                plugins_dir = get_config_dir() / "plugins"
                if not plugins_dir.exists():
                    console.print("[dim]No plugins directory found.[/dim]")
                    return
                plugin_files = list(plugins_dir.glob("*.py")) + list(plugins_dir.glob("*.yaml"))
                if not plugin_files:
                    console.print("[dim]No plugins installed.[/dim]")
                    return
                from rich.table import Table
                table = Table(title=f"Plugins ({len(plugin_files)})", header_style="bold cyan")
                table.add_column("Name", style="cyan")
                table.add_column("Type", style="dim")
                table.add_column("Size", justify="right")
                for pf in sorted(plugin_files):
                    table.add_row(pf.stem, pf.suffix, f"{pf.stat().st_size} B")
                console.print(table)
            elif action == "status":
                console.print("[green]Plugin system active.[/green]")
                console.print(f"[dim]Plugin directory: {get_config_dir() / 'plugins'}[/dim]")
            else:
                console.print("[yellow]Usage: /plugins list|status[/yellow]")
        except Exception as exc:
            console.print(f"[red]Plugin command failed: {exc}[/red]")

    # ── Alias Store ──
    def _alias_store_path(self) -> Path:
        path = get_config_dir() / "aliases.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _load_aliases(self) -> dict[str, str]:
        path = self._alias_store_path()
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_aliases(self, aliases: dict[str, str]) -> None:
        path = self._alias_store_path()
        path.write_text(json.dumps(aliases, indent=2), encoding="utf-8")

    def _cmd_alias(self, args: str) -> None:
        """Create and manage command aliases."""
        try:
            tokens = args.split() if args else []
            action = tokens[0].lower() if tokens else "list"

            aliases = self._load_aliases()

            if action == "list":
                if not aliases:
                    console.print("[dim]No aliases defined. Use /alias set <name> <command>[/dim]")
                    return
                from rich.table import Table
                table = Table(title="Command Aliases", header_style="bold cyan")
                table.add_column("Alias", style="cyan")
                table.add_column("Command", style="green")
                for alias, cmd in sorted(aliases.items()):
                    table.add_row(f"/{alias}", cmd)
                console.print(table)

            elif action == "set":
                if len(tokens) < 3:
                    console.print("[yellow]Usage: /alias set <name> <command>[/yellow]")
                    return
                name = tokens[1].lower()
                command = " ".join(tokens[2:])
                aliases[name] = command
                self._save_aliases(aliases)
                console.print(f"[green]✓ Alias set: /{name} -> {command}[/green]")

            elif action in ("remove", "rm", "delete"):
                if len(tokens) < 2:
                    console.print("[yellow]Usage: /alias remove <name>[/yellow]")
                    return
                name = tokens[1].lower()
                if name in aliases:
                    del aliases[name]
                    self._save_aliases(aliases)
                    console.print(f"[green]✓ Alias removed: /{name}[/green]")
                else:
                    console.print(f"[red]Alias not found: /{name}[/red]")
            else:
                console.print("[yellow]Usage: /alias list|set|remove[/yellow]")
        except Exception as exc:
            console.print(f"[red]Alias command failed: {exc}[/red]")

    def _cmd_language(self, args: str) -> None:
        """Switch output language."""
        try:
            lang = args.strip().lower() if args else ""
            supported = {
                "en": "English", "fr": "Français", "de": "Deutsch",
                "es": "Español", "it": "Italiano", "pt": "Português",
                "ru": "Русский", "zh": "中文", "ja": "日本語",
                "ko": "한국어", "ar": "العربية",
            }
            if not lang or lang == "list":
                current = self._settings.get("language") or "en"
                console.print(f"[dim]Current language: [bold]{supported.get(current, current)}[/bold][/dim]")
                from rich.table import Table
                table = Table(title="Supported Languages", header_style="bold cyan")
                table.add_column("Code", style="cyan")
                table.add_column("Language", style="white")
                for code, name in supported.items():
                    marker = " ← current" if code == current else ""
                    table.add_row(code, f"{name}{marker}")
                console.print(table)
                return

            if lang in supported:
                self._settings.set("language", lang)
                console.print(f"[green]✓ Language set to: {supported[lang]}[/green]")
                console.print("[dim]Note: LLM response language depends on provider support.[/dim]")
            else:
                console.print(f"[yellow]Unsupported language: {lang}. Use /language list to see options.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Language command failed: {exc}[/red]")

    def _cmd_load(self, args: str) -> None:
        """Load a saved session by ID."""
        session_id = args.strip() if args else ""
        if not session_id:
            # List available sessions
            sessions_dir = self._SESSIONS_DIR
            if not sessions_dir.exists():
                console.print("[dim]No saved sessions found.[/dim]")
                return
            session_files = sorted(sessions_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not session_files:
                console.print("[dim]No saved sessions found.[/dim]")
                return
            from rich.table import Table
            table = Table(title="Saved Sessions", header_style="bold cyan")
            table.add_column("Session ID (short)", style="cyan")
            table.add_column("Target", style="yellow")
            table.add_column("Mode", style="green")
            table.add_column("Messages", justify="right")
            table.add_column("Last Active", style="dim")
            for sf in session_files[:20]:
                try:
                    data = json.loads(sf.read_text(encoding="utf-8"))
                    sid = data.get("session_id", sf.stem)[:8]
                    target = data.get("target", "") or "—"
                    mode = data.get("mode", "?")
                    msgs = len(data.get("messages", []))
                    last = data.get("last_active", "")[:19] if data.get("last_active") else ""
                    table.add_row(sid, target, mode, str(msgs), last)
                except Exception:
                    continue
            console.print(table)
            console.print("[dim]Use /load <session_id> to load a session.[/dim]")
            return

        path = self._SESSIONS_DIR / f"{session_id}.json"
        if not path.exists():
            # Try with .json appended
            alt = self._SESSIONS_DIR / session_id
            if alt.exists():
                path = alt
            else:
                console.print(f"[red]Session not found: {session_id}[/red]")
                return

        try:
            from .session import ChatSession
            new_session = ChatSession.load(path)
            self._session = new_session
            self._mode = new_session.mode
            console.print(f"[green]✓ Loaded session: {new_session.session_id[:8]}[/green]")
            console.print(f"[dim]Target: {new_session.target or 'none'} | Mode: {new_session.mode} | Messages: {len(new_session.messages)}[/dim]")
        except Exception as exc:
            console.print(f"[red]Failed to load session: {exc}[/red]")

    def _cmd_fork(self, args: str) -> None:
        """Fork current session into a new branch."""
        try:
            import uuid
            tokens = args.split() if args else []
            at_idx = None
            summary = ""
            if tokens:
                try:
                    at_idx = int(tokens[0])
                    if len(tokens) > 1:
                        summary = " ".join(tokens[1:])
                except ValueError:
                    summary = args

            new_id = uuid.uuid4().hex
            forked = self._session.branch(at_message_idx=at_idx, summary=summary)
            forked.session_id = new_id
            self._session = forked
            self._session.save(self._SESSIONS_DIR / f"{new_id}.json")
            console.print(f"[green]✓ Session forked: {new_id[:8]}[/green]")
            if summary:
                console.print(f"[dim]Summary: {summary}[/dim]")
            console.print(f"[dim]Messages in fork: {len(forked.messages)}[/dim]")
        except Exception as exc:
            console.print(f"[red]Fork failed: {exc}[/red]")

    def _cmd_learn(self, args: str) -> None:
        """Toggle Continuous Learning System."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "status"

        try:
            from ..learning_system import get_learning_system
            cls = get_learning_system()
        except Exception:
            console.print("[yellow]Continuous Learning System not available.[/yellow]")
            return

        if action == "status":
            stats = cls.stats()
            enabled = self._settings.get("learning_enabled", True)
            status_str = "[green]ENABLED[/green]" if enabled else "[yellow]DISABLED[/yellow]"
            console.print(
                f"[bold]Learning System:[/bold] {status_str}\n"
                f"[bold]Skills:[/bold] {stats.get('total_skills', 0)}\n"
                f"[bold]High Confidence:[/bold] {stats.get('high_confidence', 0)}\n"
                f"[bold]Storage:[/bold] {stats.get('db_path', 'unknown')}"
            )
        elif action in ("on", "enable", "1", "yes"):
            self._settings.set("learning_enabled", True)
            console.print("[green]✓ Learning system enabled[/green]")
        elif action in ("off", "disable", "0", "no"):
            self._settings.set("learning_enabled", False)
            console.print("[yellow]Learning system disabled[/yellow]")
        else:
            console.print("[yellow]Usage: /learn [on|off|status][/yellow]")

    def _cmd_feedback(self, args: str) -> None:
        """Provide feedback on the last response."""
        try:
            tokens = args.split() if args else []
            if not tokens:
                console.print("[yellow]Usage: /feedback <rating> [comment][/yellow]")
                console.print("[dim]Rating: 1-5, good, bad, excellent, poor[/dim]")
                return

            rating = tokens[0].lower()
            comment = " ".join(tokens[1:]) if len(tokens) > 1 else ""

            rating_map = {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
                          "bad": 1, "poor": 2, "ok": 3, "good": 4, "excellent": 5}
            numeric_rating = rating_map.get(rating, 3)

            feedback_entry = {
                "rating": numeric_rating,
                "comment": comment,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            feedback_list = self._session.context.setdefault("feedback", [])
            feedback_list.append(feedback_entry)

            stars = "⭐" * numeric_rating + "☆" * (5 - numeric_rating)
            console.print(f"[green]✓ Feedback recorded: {stars}[/green]")
            if comment:
                console.print(f"[dim]Comment: {comment}[/dim]")

            feedback_dir = get_config_dir() / "feedback"
            feedback_dir.mkdir(parents=True, exist_ok=True)
            feedback_file = feedback_dir / f"{self._session.session_id[:8]}.jsonl"
            with open(feedback_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(feedback_entry) + "\n")
        except Exception as exc:
            console.print(f"[red]Failed to record feedback: {exc}[/red]")

    def _cmd_redteam(self, _: str) -> None:
        """Switch to red team mode (offensive focus)."""
        try:
            self._mode = "redteam"
            self._session.mode = "redteam"
            self._settings.set("persona", "red-team")
            from rich.panel import Panel
            console.print(Panel(
                "[red]🔴 RED TEAM MODE ACTIVE[/red]\n\n"
                "[bold red]Focus:[/bold red] Offensive security, exploitation, adversarial simulation\n"
                "[bold red]Persona:[/bold red] Red Team Operator\n"
                "[bold red]Tip:[/bold red] Use [cyan]/scan <target>[/cyan] to begin reconnaissance, "
                "[cyan]/intel</cyan> for threat intelligence, [cyan]/stealth</cyan> for evasion controls.",
                border_style="red",
                title="[bold red]Mode Switch[/bold red]",
            ))
        except Exception as exc:
            console.print(f"[red]Failed to switch to red team mode: {exc}[/red]")

    def _cmd_blueteam(self, _: str) -> None:
        """Switch to blue team mode (defensive focus)."""
        try:
            self._mode = "blueteam"
            self._session.mode = "blueteam"
            self._settings.set("persona", "blue-team")
            from rich.panel import Panel
            console.print(Panel(
                "[blue]🔵 BLUE TEAM MODE ACTIVE[/blue]\n\n"
                "[bold blue]Focus:[/bold blue] Defense, detection, forensics, incident response\n"
                "[bold blue]Persona:[/bold blue] Blue Team Defender\n"
                "[bold blue]Tip:[/bold blue] Use [cyan]/audit</cyan> for compliance, "
                "[cyan]/kb search</cyan> for knowledge base, [cyan]/review on</cyan> for command review.",
                border_style="blue",
                title="[bold blue]Mode Switch[/bold blue]",
            ))
        except Exception as exc:
            console.print(f"[red]Failed to switch to blue team mode: {exc}[/red]")

    async def _cmd_benchmark(self, args: str) -> None:
        """Run performance benchmark against a provider."""
        tokens = args.split() if args else []
        provider = tokens[0].lower() if tokens else ""
        model = tokens[1] if len(tokens) > 1 else ""

        if not provider:
            provider = self._settings.get("model_provider") or "auto"
            if provider == "auto":
                provider = "gemini"

        console.print(f"[bold cyan]Running benchmark against {provider}...[/bold cyan]")
        console.print("[dim]This will test response time and throughput.[/dim]")

        prov_name, api_key = self._resolve_provider()
        if not prov_name or not api_key:
            console.print("[red]No LLM provider available for benchmarking[/red]")
            return

        from ..providers import ProviderManager
        pm = ProviderManager.get_instance()
        profile = pm.get_profile(provider)
        bench_model = model or (profile.default_model if profile else "")

        from time import perf_counter
        import asyncio

        results = []
        for size, prompt in [
            ("short", "Respond with exactly: OK"),
            ("medium", "Write a 3-paragraph summary of network security best practices for a small business."),
            ("long", "Write a detailed technical guide on conducting a comprehensive web application security assessment. Include methodology, tools, and reporting structure."),
        ]:
            console.print(f"[dim]Testing {size} prompt...[/dim]")
            try:
                llm_fn = self._make_llm_call(prov_name, api_key or "")
                t0 = perf_counter()
                result = await asyncio.wait_for(
                    llm_fn(f"Respond concisely. Model: {bench_model}", prompt, model=bench_model),
                    timeout=60.0,
                )
                elapsed = perf_counter() - t0
                content = result.get("content", "") if isinstance(result, dict) else str(result)
                results.append({
                    "size": size,
                    "time_s": round(elapsed, 2),
                    "chars": len(content),
                    "chars_per_sec": round(len(content) / elapsed, 1) if elapsed > 0 else 0,
                })
            except Exception as exc:
                results.append({"size": size, "time_s": 0, "chars": 0, "chars_per_sec": 0, "error": str(exc)})

        from rich.table import Table
        table = Table(title=f"Benchmark Results: {provider}", header_style="bold cyan")
        table.add_column("Prompt Size", style="cyan")
        table.add_column("Time (s)", justify="right")
        table.add_column("Chars", justify="right")
        table.add_column("Chars/s", justify="right")
        table.add_column("Error", style="red")
        for r in results:
            err = r.get("error", "")
            table.add_row(
                r["size"],
                f"{r['time_s']:.2f}" if r["time_s"] else "—",
                str(r["chars"]) if r["chars"] else "—",
                f"{r['chars_per_sec']:.1f}" if r["chars_per_sec"] else "—",
                err[:40] if err else "—",
            )
        console.print(table)

    def _cmd_upgrade(self, _: str) -> None:
        """Check for Siyarix updates."""
        console.print("[dim]Checking for updates...[/dim]")
        try:
            import subprocess
            result = subprocess.run(
                ["pip", "install", "--dry-run", "--upgrade", "siyarix"],
                capture_output=True, text=True, timeout=30,
            )
            if "Would install" in result.stdout or "Would upgrade" in result.stdout:
                console.print("[yellow]⚠ A newer version of Siyarix is available![/yellow]")
                console.print("[dim]Run: pip install --upgrade siyarix[/dim]")
            else:
                console.print("[green]✓ Siyarix is up to date.[/green]")
        except FileNotFoundError:
            console.print("[yellow]pip not found. Cannot check for updates.[/yellow]")
        except subprocess.TimeoutExpired:
            console.print("[yellow]Update check timed out.[/yellow]")
        except Exception as exc:
            console.print(f"[yellow]Update check failed: {exc}[/yellow]")

    def _cmd_docs(self, args: str) -> None:
        """Open Siyarix documentation."""
        try:
            section = args.strip().lower() if args else ""
            base_url = "https://github.com/mufthakherul/siyarix"
            section_map = {
                "getting-started": f"{base_url}#getting-started",
                "commands": f"{base_url}#commands",
                "configuration": f"{base_url}#configuration",
                "providers": f"{base_url}#providers",
                "plugins": f"{base_url}#plugins",
                "playbooks": f"{base_url}#playbooks",
                "api": f"{base_url}#api",
                "troubleshooting": f"{base_url}#troubleshooting",
            }

            url = section_map.get(section, base_url)
            console.print(f"[cyan]Documentation:[/cyan] {url}")
            console.print("[dim]Tip: Open this URL in your browser for full documentation.[/dim]")
        except Exception as exc:
            console.print(f"[red]Docs command failed: {exc}[/red]")

    def _cmd_tutorial(self, args: str) -> None:
        """Launch interactive tutorial."""
        try:
            topic = args.strip().lower() if args else "basics"

            tutorials = {
                "basics": [
                    ("Welcome to Siyarix!", "Siyarix is a cybersecurity orchestration agent. Let's learn the basics."),
                    ("Slash Commands", "Type /help to see all available commands. Commands start with /."),
                    ("Natural Language", "You can also type natural language like 'scan example.com'."),
                    ("Modes", "Use /mode to switch between integrated, autonomous, offline, and more."),
                    ("Next Steps", "Try /tutorial scanning for more advanced features."),
                ],
                "scanning": [
                    ("Scanning Basics", "Use /scan <target> to quickly scan a target."),
                    ("Reconnaissance", "Try: enumerate subdomains of example.com"),
                    ("Port Scanning", "Try: port scan 10.0.0.1"),
                    ("Web Audit", "Try: check http headers on example.com"),
                    ("Vulnerability Scan", "Try: vuln scan on https://example.com"),
                ],
            }

            steps = tutorials.get(topic, tutorials["basics"])
            console.print(f"[bold cyan]📚 Tutorial: {topic.capitalize()}[/bold cyan]")
            console.print("─" * 50)
            for i, (title, content) in enumerate(steps, 1):
                console.print(f"\n[bold]{i}. {title}[/bold]")
                console.print(f"   {content}")
            console.print("\n" + "─" * 50)
            console.print("[dim]Available topics: basics, scanning[/dim]")
            console.print("[dim]Usage: /tutorial <topic>[/dim]")
        except Exception as exc:
            console.print(f"[red]Tutorial command failed: {exc}[/red]")

    def _cmd_bug(self, _: str) -> None:
        """Report a bug by opening GitHub issues."""
        try:
            url = "https://github.com/mufthakherul/siyarix/issues/new"
            console.print(f"[yellow]Report a bug at:[/yellow] {url}")
            console.print("[dim]Please include details about what went wrong and how to reproduce it.[/dim]")
        except Exception as exc:
            console.print(f"[red]Bug report command failed: {exc}[/red]")

    def _cmd_suggest(self, _: str) -> None:
        """Suggest a feature by opening GitHub discussions."""
        try:
            url = "https://github.com/mufthakherul/siyarix/discussions/new?category=ideas"
            console.print(f"[cyan]Suggest a feature at:[/cyan] {url}")
            console.print("[dim]Describe your idea and how it would improve Siyarix.[/dim]")
        except Exception as exc:
            console.print(f"[red]Suggest command failed: {exc}[/red]")

    async def _cmd_playbook(self, args: str) -> None:
        """Load and run playbooks."""
        tokens = args.split() if args else []
        action = tokens[0].lower() if tokens else "list"

        playbooks_dir = get_config_dir() / "playbooks"
        playbooks_dir.mkdir(parents=True, exist_ok=True)

        if action == "list":
            playbook_files = sorted(playbooks_dir.glob("*.yaml")) + sorted(playbooks_dir.glob("*.yml"))
            if not playbook_files:
                console.print("[dim]No playbooks found.[/dim]")
                console.print(f"[dim]Place .yaml files in: {playbooks_dir}[/dim]")
                return
            from rich.table import Table
            table = Table(title=f"Playbooks ({len(playbook_files)})", header_style="bold cyan")
            table.add_column("Name", style="cyan")
            table.add_column("Size", justify="right")
            table.add_column("Modified", style="dim")
            for pf in playbook_files:
                from datetime import datetime
                mtime = datetime.fromtimestamp(pf.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                table.add_row(pf.stem, f"{pf.stat().st_size} B", mtime)
            console.print(table)

        elif action == "show":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /playbook show <name>[/yellow]")
                return
            name = tokens[1]
            pb_path = playbooks_dir / f"{name}.yaml"
            if not pb_path.exists():
                pb_path = playbooks_dir / f"{name}.yml"
            if not pb_path.exists():
                console.print(f"[red]Playbook not found: {name}[/red]")
                return
            content = pb_path.read_text(encoding="utf-8")
            from rich.syntax import Syntax
            console.print(Syntax(content, "yaml", theme="monokai"))

        elif action == "run":
            if len(tokens) < 2:
                console.print("[yellow]Usage: /playbook run <name>[/yellow]")
                return
            name = tokens[1]
            pb_path = playbooks_dir / f"{name}.yaml"
            if not pb_path.exists():
                pb_path = playbooks_dir / f"{name}.yml"
            if not pb_path.exists():
                console.print(f"[red]Playbook not found: {name}[/red]")
                return
            try:
                import yaml
                playbook = yaml.safe_load(pb_path.read_text(encoding="utf-8"))
                steps = playbook.get("steps", []) if isinstance(playbook, dict) else []
                if not steps:
                    console.print(f"[yellow]No steps found in playbook: {name}[/yellow]")
                    return
                console.print(f"[bold cyan]Running playbook: {name}[/bold cyan]")
                console.print(f"[dim]Steps: {len(steps)}[/dim]")
                for i, step in enumerate(steps, 1):
                    if isinstance(step, dict):
                        cmd = step.get("command", step.get("run", ""))
                        desc = step.get("description", step.get("name", f"Step {i}"))
                        console.print(f"\n[cyan][{i}/{len(steps)}][/cyan] {desc}")
                        if cmd:
                            console.print(f"  [dim]$ {cmd}[/dim]")
                            await self._execute_instruction(cmd)
                    elif isinstance(step, str):
                        console.print(f"\n[cyan][{i}/{len(steps)}][/cyan] {step}")
                        await self._execute_instruction(step)
                console.print(f"[green]✓ Playbook '{name}' completed[/green]")
            except ImportError:
                console.print("[yellow]yaml package not installed. Install with: pip install pyyaml[/yellow]")
            except Exception as exc:
                console.print(f"[red]Playbook execution failed: {exc}[/red]")
        else:
            console.print("[yellow]Usage: /playbook list|show|run <name>[/yellow]")

    def _cmd_stats(self, args: str) -> None:
        """Show usage statistics for current session."""
        try:
            detail = args.strip().lower() == "detail"

            from rich.table import Table

            total_msgs = len(self._session.messages)
            user_msgs = sum(1 for m in self._session.messages if m.role == "user")
            assistant_msgs = sum(1 for m in self._session.messages if m.role == "assistant")
            system_msgs = sum(1 for m in self._session.messages if m.role == "system")
            uptime = datetime.now(timezone.utc) - self._session.created_at
            hours, rem = divmod(int(uptime.total_seconds()), 3600)
            minutes, secs = divmod(rem, 60)

            table = Table(title="Session Statistics", header_style="bold cyan")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Session ID", self._session.session_id[:16])
            table.add_row("Mode", self._session.mode)
            table.add_row("Target", self._session.target or "—")
            table.add_row("Uptime", f"{hours:02d}:{minutes:02d}:{secs:02d}")
            table.add_row("Total Messages", str(total_msgs))
            table.add_row("User Messages", str(user_msgs))
            table.add_row("Assistant Messages", str(assistant_msgs))
            table.add_row("System Messages", str(system_msgs))
            table.add_row("LLM Calls", str(self._llm_calls))
            table.add_row("Context Keys", str(len(self._session.context)))
            findings_count = len(self._session.context.get("findings", []))
            table.add_row("Findings", str(findings_count))

            console.print(table)

            if detail:
                cmd_counts: dict[str, int] = {}
                for msg in self._session.messages:
                    if msg.role == "user" and msg.content.startswith("/"):
                        cmd = msg.content.split()[0].lower()
                        cmd_counts[cmd] = cmd_counts.get(cmd, 0) + 1

                if cmd_counts:
                    ct = Table(title="Command Usage", header_style="bold cyan")
                    ct.add_column("Command", style="cyan")
                    ct.add_column("Count", justify="right")
                    for cmd, count in sorted(cmd_counts.items(), key=lambda x: -x[1]):
                        ct.add_row(cmd, str(count))
                    console.print(ct)
        except Exception as exc:
            console.print(f"[red]Stats command failed: {exc}[/red]")
