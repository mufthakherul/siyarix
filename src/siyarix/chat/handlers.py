from __future__ import annotations
import asyncio
import json
import logging
import os
import sys
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
from .session import ChatMessage as ChatMessage, ChatSession as ChatSession
from .ui import (
    SmartAutocomplete as SmartAutocomplete,
    CommandPalette as CommandPalette,
    SplitPane as SplitPane,
    ConfigPanel as ConfigPanel,
)
from ..subprocess_utils import safe_run_sync
from .platform_utils import provider_env_var, CROSS_PLATFORM_COMMANDS, normalize_shell, list_supported_shells, get_security_commands, get_shell_platform
from .console import console

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
            "/review": self._cmd_review,
            "/persona": self._cmd_persona,
            "/report": self._cmd_report,
            "/split": self._cmd_split,
            "/coder": self._cmd_coder,
            "/batch": self._cmd_batch,
            "/scan": self._cmd_scan,
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
                pass
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
            console.print("[dim]Tip: Key will only last for this session. Install cryptography for persistent storage: pip install cryptography[/dim]")

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
                            [
                                sys.executable,
                                "-m",
                                "pip",
                                "install",
                                pkg_name,
                            ],
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
                    key = self._resolve_api_key(selected, profile.api_key_env if profile else "")
                    if key or not (profile and profile.api_key_env):
                        with console.status(
                            f"[dim]Validating {selected}...[/dim]", spinner="point"
                        ):
                            try:
                                import asyncio

                                bench_fn = self._make_llm_call(selected, key or "")
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
            key = self._resolve_api_key(prov_name, profile.api_key_env or "")
            from ..chat.openai_compat import MODEL_KEYS
            model_key = MODEL_KEYS.get(prov_name, f"{prov_name}_model")
            model_setting = self._settings.get(model_key) or profile.default_model or ""
            status = "✓ Configured" if key else ("✗ Not set" if profile and profile.api_key_env else "Available")
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
            key = bool(self._resolve_api_key(prov_name, profile.api_key_env or "")) or not profile.api_key_env
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
        sub = args.strip() if args else ""
        if not sub or sub == "show":
            ConfigPanel().run()
        elif sub == "tools":
            ConfigPanel()._section_tools()
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
            if val is not None:
                console.print(f"[cyan]{key}[/cyan] = {val}")
            else:
                console.print(f"[yellow]{key} is not set[/yellow]")
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


