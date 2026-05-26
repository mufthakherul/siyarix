"""Interactive Phalanx Configuration Panel.

Rich-based multi-level config navigator for tool ACL, masking,
stealth, provider, theme, performance, cache, learning, and keys.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

console = Console()


class ConfigPanel:
    """Interactive configuration panel with numbered menus."""

    def run(self) -> None:
        """Launch the main config menu loop."""
        while True:
            choice = self._main_menu()
            if choice == "q":
                break
            self._dispatch(choice)

    def _main_menu(self) -> str:
        """Render the main configuration menu and return the user's choice."""
        from . import resolve_theme

        theme_name = "cyber-noir"
        accent = "bright_cyan"
        mute = "bright_black"

        lines = [
            ("1.  Tool ACL", "View tool allow/forbid rules for active persona"),
            ("2.  Masking Rules", "Add/remove regex output masking patterns"),
            ("3.  Stealth / Evasion", "Toggle stealth, set evasion level"),
            ("4.  Model Provider", "Switch AI provider and model"),
            ("5.  Theme", "Change color theme and preview"),
            ("6.  Performance", "Tune performance optimizer settings"),
            ("7.  Cache", "View and clear caches"),
            ("8.  Learning Profile", "View/set experience level"),
            ("9.  API Keys", "Manage provider API credentials"),
        ]

        body = "\n".join(
            f"  [{accent}]{label}[/{accent}]  [{mute}]{desc}[/{mute}]"
            for label, desc in lines
        )

        console.print(
            Panel(
                Text.from_markup(body),
                title=f"[bold {accent}]\u2699 Phalanx Configuration[/bold {accent}]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        return Prompt.ask("  Enter number", default="q").strip().lower()

    def _dispatch(self, choice: str) -> None:
        """Route to the selected config section."""
        dispatch_map = {
            "1": self._section_tool_acl,
            "2": self._section_masking,
            "3": self._section_stealth,
            "4": self._section_provider,
            "5": self._section_theme,
            "6": self._section_performance,
            "7": self._section_cache,
            "8": self._section_learning,
            "9": self._section_keys,
        }
        handler = dispatch_map.get(choice)
        if handler:
            handler()
        else:
            console.print(f"[red]Unknown option: {choice}[/red]")

    # ------------------------------------------------------------------
    # Section: Tool ACL
    # ------------------------------------------------------------------

    def _section_tool_acl(self) -> None:
        from ..persona_engine import PersonaEngine

        engine = PersonaEngine()
        persona = engine.active_persona
        if not persona:
            console.print("[yellow]No active persona set.[/yellow]")
            return
        acl = persona.tool_acl
        table = Table(title=f"Tool ACL \u2014 '{persona.name}'", header_style="bold cyan")
        table.add_column("Rule", style="cyan")
        table.add_column("Tools", style="white")
        table.add_row("Allowed", ", ".join(acl.allowed) if acl.allowed != ["*"] else "ALL (*)")
        table.add_row("Forbidden", ", ".join(acl.forbidden) if acl.forbidden else "(none)")
        table.add_row("Permission Required", ", ".join(acl.permission_required) if acl.permission_required else "(none)")
        table.add_row("Review Required", ", ".join(acl.review_required) if acl.review_required else "(none)")
        table.add_row("Auto-Approve (s)", str(acl.auto_approve_seconds))
        console.print(table)
        Prompt.ask("[dim]Press Enter to return[/dim]")

    # ------------------------------------------------------------------
    # Section: Masking Rules
    # ------------------------------------------------------------------

    def _section_masking(self) -> None:
        from ..masking import MaskingEngine

        me = MaskingEngine()
        while True:
            table = Table(title="Masking Rules", header_style="bold cyan")
            table.add_column("#", style="dim", width=3)
            table.add_column("Rule Name", style="cyan")
            table.add_column("Pattern", style="white")
            for i, rule in enumerate(me._rules, 1):
                table.add_row(str(i), rule.name, rule.pattern.pattern[:60])
            console.print(table)

            action = Prompt.ask("[cyan][A]dd[/cyan] [red][R]emove[/red] [dim][B]ack[/dim]").strip().lower()
            if action == "b":
                break
            if action == "a":
                name = Prompt.ask("  Rule name")
                pattern = Prompt.ask("  Regex pattern")
                repl = Prompt.ask("  Replacement text (Enter for default)", default="")
                me.add_rule(name, pattern, repl or None)
                console.print(f"[green]\u2713 Masking rule added: {name}[/green]")
            elif action == "r":
                idx_str = Prompt.ask("  Rule number to remove")
                if idx_str.isdigit():
                    idx = int(idx_str) - 1
                    if 0 <= idx < len(me._rules):
                        removed = me._rules.pop(idx)
                        console.print(f"[green]\u2713 Removed: {removed.name}[/green]")
                    else:
                        console.print("[red]Invalid number[/red]")

    # ------------------------------------------------------------------
    # Section: Stealth / Evasion
    # ------------------------------------------------------------------

    def _section_stealth(self) -> None:
        from ..stealth import EVASION_LEVELS, StealthEngine

        engine = StealthEngine()
        while True:
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

            action = (
                Prompt.ask(
                    "[green][O]n[/green] [red][O]ff[/red] [cyan][L]evel[/cyan] [dim][B]ack[/dim]"
                )
                .strip()
                .lower()
            )
            if action == "b":
                break
            if action == "on":
                c = engine.get_config()
                c.enabled = True
                engine.set_config(c)
                console.print("[green]\u2713 Stealth enabled[/green]")
            elif action == "off":
                c = engine.get_config()
                c.enabled = False
                engine.set_config(c)
                console.print("[green]\u2713 Stealth disabled[/green]")
            elif action == "l":
                level = Prompt.ask(f"  Level ({', '.join(EVASION_LEVELS.keys())})")
                if level in EVASION_LEVELS:
                    c = engine.get_config()
                    c.evasion_level = level
                    engine.set_config(c)
                    console.print(f"[green]\u2713 Level set to {level}[/green]")
                else:
                    console.print(f"[red]Invalid. Options: {', '.join(EVASION_LEVELS.keys())}[/red]")

    # ------------------------------------------------------------------
    # Section: Model Provider
    # ------------------------------------------------------------------

    def _section_provider(self) -> None:
        from ..config import SettingsStore

        store = SettingsStore()
        current = store.get("model_provider") or "auto"
        providers = ["auto", "openai", "gemini", "ollama", "anthropic", "cloud", "groq", "together", "lmstudio", "custom"]

        table = Table(title="Model Provider", header_style="bold cyan")
        table.add_column("Provider", style="cyan")
        table.add_row(f"Current: [green]{current}[/green]")
        console.print(table)

        choice = Prompt.ask(f"  Provider ({', '.join(providers)})", default=current)
        if choice in providers:
            store.set("model_provider", choice)
            console.print(f"[green]\u2713 Provider set to: {choice}[/green]")
        else:
            console.print(f"[red]Invalid. Options: {', '.join(providers)}[/red]")

        model = Prompt.ask("  Model name (Enter to skip)", default="")
        if model:
            store.set("model_name", model)
            console.print(f"[green]\u2713 Model set to: {model}[/green]")

    # ------------------------------------------------------------------
    # Section: Theme
    # ------------------------------------------------------------------

    def _section_theme(self) -> None:
        from . import available_themes, resolve_theme, print_theme_preview

        themes = available_themes()
        table = Table(title="Available Themes", header_style="bold cyan")
        table.add_column("Theme", style="cyan")
        for t in themes:
            table.add_row(t)
        console.print(table)

        from ..config import SettingsStore
        store = SettingsStore()
        current = store.get("color_theme") or "cyber-noir"

        choice = Prompt.ask(f"  Theme name", default=current)
        resolved = resolve_theme(choice)
        if resolved:
            store.set("color_theme", resolved)
            console.print(f"[green]\u2713 Theme set to: {resolved}[/green]")
            print_theme_preview(console, resolved)
        else:
            console.print(f"[red]Invalid theme. Options: {', '.join(themes)}[/red]")
        Prompt.ask("[dim]Press Enter to return[/dim]")

    # ------------------------------------------------------------------
    # Section: Performance
    # ------------------------------------------------------------------

    def _section_performance(self) -> None:
        from ..performance import performance_optimizer

        opt = performance_optimizer
        table = Table(title="Performance Settings", header_style="bold cyan")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Parallelism", str(opt.config.max_parallel_tasks))
        table.add_row("Cache TTL (s)", str(opt.config.cache_ttl_seconds))
        table.add_row("Log Level", opt.config.log_level)
        table.add_row("Metrics Enabled", str(opt.config.enable_metrics))
        console.print(table)

        action = Prompt.ask("[cyan][T]une[/cyan] [dim][B]ack[/dim]").strip().lower()
        if action == "t":
            try:
                from ..performance import PerformanceConfig
                parallel = int(Prompt.ask("  Max parallel tasks", default=str(opt.config.max_parallel_tasks)))
                cache = int(Prompt.ask("  Cache TTL (seconds)", default=str(opt.config.cache_ttl_seconds)))
                opt.configure(PerformanceConfig(max_parallel_tasks=parallel, cache_ttl_seconds=cache))
                console.print("[green]\u2713 Performance tuned[/green]")
            except ValueError:
                console.print("[red]Invalid number[/red]")

    # ------------------------------------------------------------------
    # Section: Cache
    # ------------------------------------------------------------------

    def _section_cache(self) -> None:
        from ..cache_manager import cache_manager

        stats = cache_manager.stats()
        table = Table(title="Cache Status", header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Entries", str(stats.get("entries", 0)))
        table.add_row("Hits", str(stats.get("hits", 0)))
        table.add_row("Misses", str(stats.get("misses", 0)))
        console.print(table)

        action = Prompt.ask("[red][C]lear[/red] [dim][B]ack[/dim]").strip().lower()
        if action == "c":
            confirm = Prompt.ask("  Clear all caches?", choices=["y", "n"], default="n")
            if confirm == "y":
                cache_manager.clear()
                console.print("[green]\u2713 Cache cleared[/green]")

    # ------------------------------------------------------------------
    # Section: Learning Profile
    # ------------------------------------------------------------------

    def _section_learning(self) -> None:
        from ..user_learning import ExperienceLevel, UserLearning

        ul = UserLearning()
        table = Table(title="Learning Profile", header_style="bold cyan")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Experience Level", ul.profile.experience_level.value if ul.profile else "unknown")
        table.add_row("Sessions Completed", str(ul.profile.sessions_completed if ul.profile else 0))
        table.add_row("Patterns Learned", str(len(ul.patterns)))
        console.print(table)

        action = Prompt.ask("[cyan][S]et level[/cyan] [dim][B]ack[/dim]").strip().lower()
        if action == "s":
            levels = [e.value for e in ExperienceLevel]
            level = Prompt.ask(f"  Level ({', '.join(levels)})")
            if level in levels:
                ul.set_level(ExperienceLevel(level))
                console.print(f"[green]\u2713 Level set to {level}[/green]")
            else:
                console.print(f"[red]Invalid. Options: {', '.join(levels)}[/red]")

    # ------------------------------------------------------------------
    # Section: API Keys
    # ------------------------------------------------------------------

    def _section_keys(self) -> None:
        from ..credential_store import CredentialStore

        store = CredentialStore()
        creds = store.list_credentials()

        table = Table(title="API Keys", header_style="bold cyan")
        table.add_column("Provider", style="cyan")
        table.add_column("Status", style="white")
        for provider in ["openai", "gemini", "ollama", "anthropic", "cloud", "groq", "together"]:
            exists = any(c.name == provider for c in creds)
            table.add_row(provider, "[green]\u2713 configured[/green]" if exists else "[dim]not set[/dim]")
        console.print(table)

        action = Prompt.ask("[cyan][S]et key[/cyan] [dim][B]ack[/dim]").strip().lower()
        if action == "s":
            provider = Prompt.ask("  Provider name")
            key = Prompt.ask("  API key")
            store.store_credential(provider, key)
            console.print(f"[green]\u2713 Key stored for {provider}[/green]")
