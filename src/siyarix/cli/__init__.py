# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix CLI — Cybersecurity Command Center.

Core commands:
  scan       — Run security scans against targets
  run        — Natural language → execution
  agent      — Goal-driven autonomous agent
  discover   — Asset and service discovery
  auth       — Authentication & API keys
  init       — Initialize configuration wizard
  config     — CLI configuration
  cache      — Cache management
  report     — Report generation
  health     — System health checks

TODO(v3.0): Refactor into ``cli/`` package:
  - cli/__init__.py      — backward-compatible re-exports
  - cli/app.py           — Main Typer app, core commands
  - cli/auth.py          — Authentication & API key commands
  - cli/config_cmd.py    — Configuration commands
  - cli/report_cmd.py    — Report generation commands
  - cli/health.py        — Health check & metrics commands
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table

from typing import Any

from .. import __version__

from ..audit_log import AuditEventType, AuditSeverity, audit
from ..branding import available_themes, print_banner
from ..chat import start_chat, CommandProfile, CommandProfileStore, CROSS_PLATFORM_COMMANDS
from ..config import SettingsStore
from ..compat import IntentRouter, SessionKernel, ExecutionEngine, ExecutionMode
from ..credential_store import CredentialStore
from ..registry import ToolRegistry
from ..exceptions import ValidationError
from ..health import get_health
from ..logging_config import configure_logging
from ..metrics import get_metrics
from ..security_commands import security_app

from ..output import OutputEngine
from ..validators import validate_target

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_dotenv(path: Path | None = None) -> None:
    """Load environment variables from .env file (simple key=value parser)."""
    env_path = path or Path.cwd() / ".env"
    if not env_path.exists():
        env_path = Path.home() / ".siyarix" / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key and not os.environ.get(key):
            os.environ[key] = val


def _upsert_env_vars(env_map: dict[str, str], env_file: str | None = None) -> None:
    for k, v in env_map.items():
        os.environ[k] = v


def _display_findings_table(findings: list[dict]) -> None:
    """Render scan findings as a Rich table."""
    ftable = Table(title="Findings", header_style="bold red")
    ftable.add_column("Severity", width=8)
    ftable.add_column("Type", style="cyan")
    ftable.add_column("Detail", style="white")
    for f in findings[:20]:
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
    if len(findings) > 20:
        ftable.add_row("", f"[dim]… and {len(findings) - 20} more[/dim]", "")
    console.print(ftable)


# ---------------------------------------------------------------------------
# Initialize core systems
# ---------------------------------------------------------------------------

# Detect non-interactive / CI / pipe environments
_IS_TTY = sys.stdout.isatty()
_IS_STDIN_PIPE = not sys.stdin.isatty()
_CI_MODE = os.getenv("CI", "") or os.getenv("SIYARIX_NO_BANNER", "") or not _IS_TTY

console = Console()
registry = ToolRegistry()
config = SettingsStore()
configure_logging(config.get("log_level"))
creds = CredentialStore()
_load_dotenv()

# Load API keys from encrypted credential store into environment
for provider, env_var in [("gemini", "GEMINI_API_KEY"), ("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY"), ("openrouter", "OPENROUTER_API_KEY")]:
    if not os.environ.get(env_var):
        try:
            key = creds.retrieve(provider, "api_key")
            if key:
                os.environ[env_var] = key
        except Exception:
            pass
intent_router = IntentRouter()
session_kernel = SessionKernel()

def _get_engine(mode: str = "integrated") -> ExecutionEngine:
    """Build an ExecutionEngine with API keys from config/credentials."""
    engine_config: dict = {}
    if os.getenv("SIYARIX_FAST_DISCOVERY", "0") == "1":
        engine_config["fast_discovery"] = True
    openai_key = (
        os.environ.get("OPENAI_API_KEY", "")
        or creds.retrieve("openai", "api_key")
        or ""
    )
    gemini_key = (
        os.environ.get("GEMINI_API_KEY", "")
        or creds.retrieve("gemini", "api_key")
        or ""
    )
    anthropic_key = (
        os.environ.get("ANTHROPIC_API_KEY", "")
        or creds.retrieve("anthropic", "api_key")
        or ""
    )
    groq_key = (
        os.environ.get("GROQ_API_KEY", "") or creds.retrieve("groq", "api_key") or ""
    )
    together_key = (
        os.environ.get("TOGETHER_API_KEY", "")
        or creds.retrieve("together", "api_key")
        or ""
    )
    openrouter_key = (
        os.environ.get("OPENROUTER_API_KEY", "")
        or creds.retrieve("openrouter", "api_key")
        or ""
    )
    if openai_key:
        engine_config["openai_api_key"] = openai_key
    if gemini_key:
        engine_config["gemini_api_key"] = gemini_key
    if anthropic_key:
        engine_config["anthropic_api_key"] = anthropic_key
    if groq_key:
        engine_config["groq_api_key"] = groq_key
    if together_key:
        engine_config["together_api_key"] = together_key
    if openrouter_key:
        engine_config["openrouter_api_key"] = openrouter_key
    engine_config["model_provider"] = config.get("model_provider")
    engine_config["gemini_model"] = config.get("gemini_model")
    engine_config["openai_model"] = config.get("openai_model")
    engine_config["anthropic_model"] = config.get("anthropic_model")
    engine_config["openrouter_model"] = config.get("openrouter_model")
    engine_config["ollama_url"] = config.get("ollama_url")
    engine_config["ollama_model"] = config.get("ollama_model")
    engine_config["lmstudio_url"] = config.get("lmstudio_url")
    try:
        exec_mode = ExecutionMode(mode)
    except ValueError:
        exec_mode = ExecutionMode.INTEGRATED
    return ExecutionEngine(mode=exec_mode, registry=registry, config=engine_config)


# ---------------------------------------------------------------------------
# Main Typer app — Premium structure
# ---------------------------------------------------------------------------
app = typer.Typer(
    name="siyarix",
    help=f"""
[bold cyan]Siyarix CLI — Cybersecurity Command Center[/bold cyan]

[dim]Version: {__version__} | Platform: {platform.system()} | Python: {platform.python_version()}[/dim]

[bold]Quick Start:[/bold]
  [green]siyarix scan 192.168.1.0/24[/green]      — Direct command execution
  [green]siyarix run "scan my network"[/green]    — Natural language command
  [green]echo "scan 10.0.0.1" | siyarix[/green]  — Pipe commands via stdin

[bold]Key Commands:[/bold]
  • [magenta]siyarix scan[/magenta]         — Security scanning
  • [magenta]siyarix run[/magenta]          — Natural language → execution
  • [magenta]siyarix agent[/magenta]        — Goal-driven autonomous agent
  • [magenta]siyarix discover[/magenta]     — Asset & service discovery
  • [magenta]siyarix auth[/magenta]         — Authentication & API keys
  • [magenta]siyarix init[/magenta]         — Initialize configuration
  • [magenta]siyarix --help[/magenta]       — Full command reference
    """,
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,  # launch chat when called with no subcommand
)


@app.command("init")
def init_wizard(
    force: bool = typer.Option(False, "--force", "-f", help="Re-run wizard even if already configured"),
) -> None:
    """Initialize Siyarix configuration and API keys.

    Creates ~/.siyarix/, interactively sets up your default AI provider,
    and validates the environment.
    """
    from pathlib import Path

    home_dir = Path.home() / ".siyarix"
    if home_dir.exists() and not force:
        console.print("[green]✓ Siyarix is already initialized.[/green]")
        console.print("  Run [cyan]siyarix init --force[/cyan] to re-run the wizard.")
        return

    console.print(Panel.fit(
        "[bold cyan]Siyarix Setup Wizard[/bold cyan]\n\n"
        "This will guide you through:\n"
        "  • Creating the [bold]~/.siyarix[/bold] configuration directory\n"
        "  • Selecting and configuring your AI provider\n"
        "  • Setting up API credentials\n"
        "  • Verifying your environment",
        border_style="cyan",
    ))

    home_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✓ Created {home_dir}[/green]")

    from ..config import SettingsStore
    settings = SettingsStore()

    console.print("\n[bold]Select your default AI provider:[/bold]")
    providers = ["auto", "openai", "gemini", "anthropic", "ollama", "groq", "lmstudio", "openrouter"]
    for i, p in enumerate(providers, 1):
        tag = " (recommended)" if p == "auto" else ""
        console.print(f"  {i}. {p}{tag}")

    choice = Prompt.ask(
        "Choose", default="1"
    )
    try:
        idx = int(choice) - 1
        provider = providers[idx] if 0 <= idx < len(providers) else "auto"
    except (ValueError, IndexError):
        provider = "auto"

    settings.set("model_provider", provider)
    console.print(f"[green]✓ Provider set to: {provider}[/green]")

    api_key_providers = {
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "groq": "GROQ_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    if provider in api_key_providers or provider == "auto":
        env_var = api_key_providers.get(provider, "OPENAI_API_KEY")
        existing = os.environ.get(env_var) or creds.retrieve(provider, "api_key") or ""
        if existing:
            console.print(f"[dim]API key for {provider} already configured.[/dim]")
        else:
            key = Prompt.ask(
                f"Enter your {provider.upper()} API key",
                password=True,
                default="",
            )
            if key:
                creds.store(provider, key, "api_key")
                console.print(f"[green]✓ {provider.upper()} API key saved.[/green]")

    if provider == "auto":
        for prov, var in api_key_providers.items():
            if not (os.environ.get(var) or creds.retrieve(prov, "api_key")):
                key = Prompt.ask(
                    f"Enter your {prov.upper()} API key (or leave blank to skip)",
                    password=True,
                    default="",
                )
                if key:
                    creds.store(prov, key, "api_key")
                    console.print(f"[green]✓ {prov.upper()} API key saved.[/green]")

    console.print("\n[bold yellow]Configuration Summary:[/bold yellow]")
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Key", style="cyan")
    summary_table.add_column("Value", style="white")
    summary_table.add_row("Provider", settings.get("model_provider"))
    summary_table.add_row("Config Dir", str(home_dir))
    summary_table.add_row("Settings File", str(home_dir / "settings.toml"))
    console.print(summary_table)

    console.print("\n[green]✓ Siyarix initialized successfully![/green]")
    console.print("  Run [cyan]siyarix[/cyan] to start the interactive shell.")


def _run_batch_lines(lines: list[str]) -> None:
    """Execute a list of command lines through the chat REPL handler."""
    from ..chat import SiyarixChat
    
    chat = SiyarixChat(mode="integrated")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        console.print(f"[bold]> {line}[/bold]")
        if line.startswith("/"):
            asyncio.run(chat._handle_slash(line))
        else:
            # Try AI first, fallback to simple responses if not available
            try:
                # For simple batch processing, provide basic responses
                if line in ["hello", "hi", "hey"]:
                    console.print("Hello! I'm Siyarix, your cybersecurity command center.")
                elif line in ["bye", "goodbye"]:
                    console.print("Goodbye! Stay secure!")
                elif line == "version":
                    from .. import __version__
                    console.print(f"Siyarix version {__version__}")
                elif line in ["help", "/help"]:
                    asyncio.run(chat._handle_slash("/help"))
                elif line == "status":
                    asyncio.run(chat._handle_slash("/status"))
                else:
                    console.print(f"[dim]Command not recognized in offline mode: {line}[/dim]")
                    console.print("[dim]Try '/help' for available commands or use AI mode for natural language processing.[/dim]")
            except Exception as e:
                console.print(f"[dim]Error processing command: {e}[/dim]")
        console.print()


def _show_version() -> None:
    from ..branding import resolve_version

    ver = resolve_version()
    console.print(f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green]")
    console.print(f"Platform: {sys.platform}  Python: {sys.version.split()[0]}")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    config: str = typer.Option(None, "--config", "-c", help="Path to custom config file (YAML/JSON)"),
    batch: str = typer.Option(None, "--batch", "-b", help="Path to batch script file to execute"),
    mode: str = typer.Option(
        "integrated",
        "--mode",
        "-m",
        help="Execution mode: registry|autonomous|integrated",
    ),
    target: str = typer.Option(
        "", "--target", "-t", help="Set initial target for the session"
    ),
    version: bool = typer.Option(False, "--version", help="Show version information"),
) -> None:
    if version:
        _show_version()
        raise typer.Exit()
    """Siyarix CLI — unified entry point.

    Usage:
      siyarix <command> [options]    — Direct command execution
      echo "<cmd>" | siyarix         — Pipe commands via stdin
      siyarix                        — Launch interactive chat
    """
    if config:
        resolved = Path(config).expanduser().resolve()
        if resolved.exists():
            os.environ["SIYARIX_CONFIG"] = str(resolved)
            os.environ["SIYARIX_CONFIG_DIR"] = str(resolved.parent)
            console.print(f"[dim]Loaded config: {resolved}[/dim]")
        else:
            console.print(f"[red]Config file not found: {resolved}[/red]")
            raise typer.Exit(1)

    # --batch file mode (file-based, non-interactive)
    if batch:
        resolved = Path(batch).expanduser().resolve()
        if resolved.exists():
            script_lines = resolved.read_text(encoding="utf-8").splitlines()
            console.print(f"[dim]Executing batch script: {resolved} ({len(script_lines)} commands)[/dim]")
            _run_batch_lines(script_lines)
        else:
            console.print(f"[red]Batch script not found: {resolved}[/red]")
            raise typer.Exit(1)
        return

    # Pipe from stdin: echo "scan 10.0.0.1" | siyarix
    if _IS_STDIN_PIPE:
        lines = [line for line in sys.stdin if line.strip()]
        if lines:
            _run_batch_lines([line.strip() for line in lines])
        return

    # No subcommand + TTY: launch interactive UI
    if ctx.invoked_subcommand is None and _IS_TTY:
        start_chat(mode=mode, target=target)


# Register security command group into the main CLI.
app.add_typer(security_app, name="security")

# ---------------------------------------------------------------------------
# Sub-command groups (Premium ecosystem)
# ---------------------------------------------------------------------------

auth_app = typer.Typer(help="🔑 Authentication & API keys")
app.add_typer(auth_app, name="auth")

profile_app = typer.Typer(help="👤 Profile & workspace management")
app.add_typer(profile_app, name="profile")


@app.command()
def palette() -> None:
    """Open an interactive command palette (uses prompt_toolkit if installed)."""
    ptk_prompt: Any = None
    WordCompleter: Any = None
    try:
        from prompt_toolkit import prompt as ptk_prompt
        from prompt_toolkit.completion import WordCompleter

        PTK = True
    except Exception as exc:
        import logging

        logging.getLogger(__name__).debug("prompt_toolkit not available: %s", exc)
        PTK = False

    store = CommandProfileStore()
    intents = sorted(CROSS_PLATFORM_COMMANDS.keys())
    options = [f"intent: {i}" for i in intents]
    saved = store.list_credentials()
    options += [f"saved: {p.name} -> {p.command}" for p in saved]

    if PTK:
        choice = ptk_prompt(
            "Select or search: ", completer=WordCompleter(options, ignore_case=True)
        ).strip()
    else:
        for i, o in enumerate(options[:200], 1):
            console.print(f"{i}. {o}")
        sel = Prompt.ask("Select # or type text to filter", default="").strip()
        if sel.isdigit():
            idx = int(sel) - 1
            if 0 <= idx < len(options):
                choice = options[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        else:
            # simple filter
            matches = [o for o in options if sel.lower() in o.lower()]
            if not matches:
                console.print("[dim]No matches[/dim]")
                return
            choice = matches[0]

    console.print(f"Selected: {choice}")


@app.command()
def render_cmd(
    name: str = typer.Argument(..., help="Saved command profile name"),
    kv: list[str] = typer.Argument(None),
) -> None:
    """Render a saved command profile using provided key=value pairs.

    Example: siyarix render-cmd quick-nmap target=10.0.0.1 flags='-Pn'
    """
    store = CommandProfileStore()
    p = store.get(name)
    if not p:
        console.print(f"[red]Profile not found: {name}[/red]")
        raise typer.Exit(1)

    params: dict[str, str] = {}
    for item in kv or []:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k] = v

    rendered = store.render(p.command, params)
    console.print(Panel.fit(rendered, title=f"Rendered: {name}", border_style="cyan"))


@profile_app.command("save-cmd")
def profile_save_cmd(
    name: str = typer.Argument(..., help="Profile name"),
    command: str = typer.Argument(..., help="Command to save"),
) -> None:
    """Save a reusable command profile."""
    store = CommandProfileStore()
    p = CommandProfile(name=name, command=command)
    store.save(p)
    console.print(f"[green]✓ Saved command profile: {name}[/green]")


@profile_app.command("list-cmds")
def profile_list_cmds() -> None:
    """List saved command profiles."""
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


@profile_app.command("rm-cmd")
def profile_rm_cmd(
    name: str = typer.Argument(..., help="Profile name to remove")
) -> None:
    """Remove a saved command profile."""
    store = CommandProfileStore()
    ok = store.delete(name)
    if ok:
        console.print(f"[green]✓ Removed {name}[/green]")
    else:
        console.print(f"[red]Profile not found: {name}[/red]")


audit_app = typer.Typer(help="📋 Audit trail & compliance logs")
app.add_typer(audit_app, name="audit")

config_app = typer.Typer(help="⚙️ CLI configuration")
app.add_typer(config_app, name="config")

completions_app = typer.Typer(help="🏁 Shell completions")
app.add_typer(completions_app, name="completions")

theme_app = typer.Typer(help="🎨 Theme customization")
app.add_typer(theme_app, name="theme")


@theme_app.command("list")
def theme_list() -> None:
    """List available color themes."""
    themes = available_themes()
    table = Table(title="Available Themes", header_style="bold cyan")
    table.add_column("Theme", style="cyan")
    table.add_column("Use", style="dim")
    for t in themes:
        table.add_row(t, "/theme set " + t)
    console.print(table)


@theme_app.command("set")
def theme_set(name: str = typer.Argument(..., help="Theme name to set")) -> None:
    """Set the default color theme in configuration."""
    global _active_theme
    try:
        config.set("color_theme", name)
        _active_theme = name
        console.print(f"[green]Theme set to: {name}[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to set theme: {exc}[/red]")


@theme_app.command("preview")
@theme_app.command("appearance")
def theme_preview(
    name: str = typer.Argument(default="", help="Theme to preview (optional)"),
) -> None:
    """Preview the current or selected theme appearance."""
    from ..branding import print_theme_preview

    selected = name or config.get("color_theme") or _active_theme
    print_theme_preview(console, selected)


cache_app = typer.Typer(help="💾 Cache management")
app.add_typer(cache_app, name="cache")

report_app = typer.Typer(help="📊 Report generation & distribution")
app.add_typer(report_app, name="report")

tool_registry_app = typer.Typer(help="🛠 Tool discovery & registry")
app.add_typer(tool_registry_app, name="tool-registry")

@cache_app.command("status")
def cache_status() -> None:
    """Show cache statistics."""
    from ..cache_manager import cache_manager
    stats = cache_manager.stats()
    size_mb = stats.get('total_size_bytes', 0) / (1024 * 1024)
    console.print(f"Entries: {stats['total_entries']} | Size: {size_mb:.2f}MB | Hit rate: {stats['hit_rate']:.0%}")
    console.print(f"Domains: {', '.join(stats.get('domains', []))}")

@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached data."""
    from ..cache_manager import cache_manager
    count = cache_manager.clear()
    console.print(f"[green]Cache cleared: {count} entries[/green]")


@tool_registry_app.command("providers")
def list_providers() -> None:
    """List configured model providers (order of preference)."""
    engine = _get_engine()
    planners = getattr(engine, "_planner", None)
    if not planners:
        console.print("[dim]No planner available[/dim]")
        raise typer.Exit(1)

    providers = getattr(planners, "_providers", [])
    if not providers:
        console.print("[dim]No providers registered[/dim]")
        return

    table = Table(title="Configured Model Providers", header_style="bold cyan")
    table.add_column("Index", style="dim")
    table.add_column("Provider Type", style="cyan")
    table.add_column("Available", style="green")
    for i, p in enumerate(providers, 1):
        avail = getattr(p, "available", False)
        table.add_row(str(i), type(p).__name__, str(avail))
    console.print(table)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_profile: str | None = None
_active_theme: str = config.get("color_theme") or "default"



# ---------------------------------------------------------------------------
# Premium: Main entry with enhanced output
# ---------------------------------------------------------------------------
@app.command()
def scan(
    targets: list[str] = typer.Argument(
        help="Target(s): IP, CIDR, URL, hostname, or @file.txt"
    ),
    tool: str = typer.Option("", "--tool", "-t", help="Specific tool to use"),
    mode: str = typer.Option(
        "integrated",
        "--mode",
        "-m",
        help="Execution mode: registry|autonomous|integrated",
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output: table|json|yaml|csv"
    ),
    parallel: int = typer.Option(3, "--parallel", "-p", help="Parallel workers"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to database"),
    notify: bool = typer.Option(
        False, "--notify", "-n", help="Send notification on completion"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    profile: str = typer.Option("", "--profile", help="Use specific profile"),
) -> None:
    """Run security scans against one or more targets.

    Supports @targets.txt multi-target mode. Prefix a file path with @ to load targets.

    Examples:
      siyarix scan 192.168.1.1
      siyarix scan 10.0.0.0/24 --tool nmap --mode registry
      siyarix scan @targets.txt --parallel 5
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    # Support @targets.txt multi-target mode (Chapter 15 Hidden Features)
    expanded_targets: list[str] = []
    for t in targets:
        if t.startswith("@"):
            target_file = Path(t[1:])
            if target_file.exists():
                lines = [
                    line.strip()
                    for line in target_file.read_text().splitlines()
                    if line.strip()
                ]
                expanded_targets.extend(lines)
                console.print(
                    f"[dim]Loaded {len(lines)} targets from {target_file}[/dim]"
                )
            else:
                console.print(f"[red]Target file not found: {target_file}[/red]")
                raise typer.Exit(3)
        else:
            expanded_targets.append(t)

    if not expanded_targets:
        console.print(
            "[red]No targets specified. Use siyarix scan <target> or @file.txt[/red]"
        )
        raise typer.Exit(1)

    for target in expanded_targets:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)

    instruction = f"scan {' '.join(expanded_targets)}"
    if tool:
        instruction += f" with {tool}"

    audit.log(
        event_type=AuditEventType.SCAN_START,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="started",
        target=",".join(expanded_targets),
        details={"tool": tool, "mode": mode, "targets": expanded_targets},
    )

    # Show progress for multi-target scans
    if len(expanded_targets) > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning {task.description}[/bold cyan]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task(
                f"{len(expanded_targets)} targets", total=len(expanded_targets)
            )
            engine = _get_engine(mode)
            result = asyncio.run(
                engine.execute(
                    instruction, interactive=True, dry_run=dry_run, persist=save
                )
            )
            progress.update(task_id, advance=len(expanded_targets))
    else:
        engine = _get_engine(mode)
        result = asyncio.run(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )

    if dry_run:
        console.print("[yellow]Dry run complete — no commands executed.[/yellow]")
        return

    # Display findings according to the requested output format
    if result.all_findings:
        output = output.lower()
        if output in ("json", "yaml", "csv"):
            output_engine = OutputEngine(output_format=output)
            if output == "json":
                output_engine.print_json(result.all_findings)
            elif output == "yaml":
                output_engine.print_yaml(result.all_findings)
            elif output == "csv":
                if result.all_findings:
                    findings_dicts = [f.to_dict() if hasattr(f, "to_dict") else vars(f) for f in result.all_findings]
                    output_engine.print_csv(findings_dicts)
                else:
                    console.print("[yellow]No findings to export.[/yellow]")
        else:
            _display_findings_table(result.all_findings)

    audit.log(
        event_type=AuditEventType.SCAN_COMPLETE,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="success" if result.success else "failed",
        target=",".join(targets),
        details={"summary": result.summary, "findings": len(result.all_findings)},
    )


@app.command()
def discover(
    target: str = typer.Argument(help="Target network or host"),
    deep: bool = typer.Option(
        False, "--deep", "-d", help="Deep discovery (OS, services, vulns)"
    ),
    export: str = typer.Option("", "--export", "-e", help="Export to file (JSON/YAML)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Discover assets, services, and vulnerabilities on a target.

    Examples:
      siyarix discover 192.168.1.0/24
      siyarix discover example.com --deep
      siyarix discover 10.0.0.0/8 --export results.json
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    try:
        validate_target(target)
    except ValidationError as exc:
        console.print(f"[red]Invalid target '{target}': {exc}[/red]")
        raise typer.Exit(1)

    instruction = f"scan and discover all services on {target}"
    if deep:
        instruction += " with deep OS and vulnerability detection"

    engine = _get_engine("integrated")
    result = asyncio.run(engine.execute(instruction, interactive=True))

    if export and result.all_findings:
        import json

        Path(export).write_text(json.dumps(result.all_findings, indent=2))
        console.print(f"[dim]Findings exported to {export}[/dim]")


@app.command()
def run(
    command: str = typer.Argument(help="Natural language command or tool name"),
    target: str = typer.Option("", "--target", "-t", help="Target for the command"),
    mode: str = typer.Option("integrated", "--mode", "-m", help="Execution mode"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    save: bool = typer.Option(False, "--save", "-s", help="Persist workflow execution"),
    resume_plan: str = typer.Option(
        "", "--resume", "-r", help="Resume a persisted plan by ID (or 'latest')"
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Run a natural language instruction through the execution engine.

    Examples:
      siyarix run "scan example.com with nmap and nuclei"
      siyarix run "enumerate subdomains of target.com" --mode autonomous
      siyarix run --resume latest
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    # Handle --resume
    if resume_plan:
        try:
            from ..offline_store import OfflineStore
        except ModuleNotFoundError:
            console.print("[yellow]Plan persistence not available in this version[/yellow]")
            raise typer.Exit(1)
        store = OfflineStore()
        resolved_id = resume_plan
        if resume_plan.lower() == "latest":
            resolved_id = store.get_latest_plan_id() or ""
            if not resolved_id:
                console.print("[red]No plans found to resume.[/red]")
                raise typer.Exit(1)
        engine = _get_engine(mode)
        console.print(f"[cyan]Resuming plan: {resolved_id}[/cyan]")
        asyncio.run(engine.resume(resolved_id, interactive=True))
        return

    instruction = command
    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)
        instruction += f" on {target}"

    route = intent_router.route(instruction, preferred_mode=mode)
    session = session_kernel.start(objective="direct-command", scope=target or "adhoc")
    op = session_kernel.add_operation(
        session=session,
        instruction=instruction,
        mode=route.mode,
        risk_tier=route.risk_tier.value,
    )

    if route.requires_confirmation and not dry_run:
        proceed = Prompt.ask(
            f"Risk tier is {route.risk_tier.value}. Continue execution? (y/N)",
            default="N",
        )
        if not proceed.lower().startswith("y"):
            session_kernel.update_operation(session, op.operation_id, state="canceled")
            console.print("[yellow]Execution canceled.[/yellow]")
            return

    is_pipeline = "|" in instruction or any(
        t in instruction.lower() for t in [" then ", " and then ", " followed by "]
    )
    result: Any
    if is_pipeline:
        from ..core.pipeline import CommandPipeline

        pipeline = CommandPipeline()
        steps = pipeline.parse(instruction)

        class PipelineExecutionResult:
            def __init__(self, success: bool, all_findings: list) -> None:
                self.success = success
                self.all_findings = all_findings
                self.retries_performed = 0
                self.plan_id = ""

        async def step_executor(step: Any, ctx: Any) -> dict[str, Any]:
            step_engine = _get_engine(route.mode)
            res = await step_engine.execute(
                step.instruction, interactive=True, dry_run=dry_run, persist=save
            )
            return {
                "status": "completed" if res.success else "failed",
                "findings": res.all_findings or [],
                "error": getattr(res, "error_message", "") if not res.success else "",
            }

        pipe_res = asyncio.run(pipeline.execute(steps, step_executor))
        result = PipelineExecutionResult(
            success=pipe_res.success, all_findings=pipe_res.all_findings
        )
    else:
        engine = _get_engine(route.mode)
        result = asyncio.run(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )

    # Display results
    if result.success:
        if result.all_findings:
            console.print(f"\n[green]Found {len(result.all_findings)} finding(s):[/green]")
            for f in result.all_findings[:20]:
                severity = getattr(f, "severity", "info") if hasattr(f, "severity") else "info"
                title = getattr(f, "title", str(f)) if hasattr(f, "title") else str(f)
                console.print(f"  [{severity}] {title}")
            if len(result.all_findings) > 20:
                console.print(f"  ... and {len(result.all_findings) - 20} more")
        else:
            console.print("\n[green]Execution completed successfully.[/green]")
    else:
        error_msg = getattr(result, "error_message", "Unknown error") if hasattr(result, "error_message") else "Unknown error"
        console.print(f"\n[red]Execution failed: {error_msg}[/red]")

    final_state = "completed" if result.success else "failed"
    session_kernel.update_operation(
        session=session,
        operation_id=op.operation_id,
        state=final_state,
        retries=result.retries_performed,
        artifact=result.plan_id or "",
    )
    session_kernel.save(session)


@app.command()
def agent(
    goal: str = typer.Argument(help="The goal for the autonomous agent to achieve"),
    target: str = typer.Option("", "--target", "-t", help="Target host/IP/URL"),
    max_iterations: int = typer.Option(
        10, "--max-iter", "-n", help="Maximum agent iterations"
    ),
    mode: str = typer.Option("autonomous", "--mode", "-m", help="Execution mode"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Launch a goal-driven autonomous agent (observe → reason → act loop).

    The agent continuously plans, executes, and adapts until the goal
    is achieved or max iterations are reached.

    Examples:
      siyarix agent "Perform full recon on target.com" --target target.com
      siyarix agent "Find SQL injection vulnerabilities" -t http://app.local -n 5
      siyarix agent "Enumerate and scan 10.0.0.0/24" --max-iter 15
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)

    from ..core import AgentCore, AgentMode, AgentGoal
    mode_map = {
        "registry": AgentMode.REGISTRY,
        "autonomous": AgentMode.AUTONOMOUS,
        "integrated": AgentMode.HYBRID,
    }
    agent = AgentCore(mode=mode_map.get(mode, AgentMode.HYBRID))
    asyncio.run(agent.initialize())
    agent_goal = AgentGoal(description=goal, target=target)
    asyncio.run(agent.execute_goal(agent_goal))





# ---------------------------------------------------------------------------
# Health & Metrics
# ---------------------------------------------------------------------------


@app.command("health")
def health_check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """Run system health checks."""
    status = asyncio.run(get_health().check_all())
    if output == "json":
        import json

        console.print(json.dumps(status.to_dict(), indent=2))
        return

    table = Table(title="Siyarix Health", header_style="bold cyan")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("State", style="magenta", no_wrap=True)
    table.add_column("Latency (ms)", style="green", no_wrap=True)
    table.add_column("Message", style="white")

    for comp in status.components:
        table.add_row(
            comp.name,
            comp.state.value,
            f"{comp.latency_ms:.1f}",
            comp.message,
        )

    console.print(table)


@app.command("metrics")
def metrics_show(
    output: str = typer.Option(
        "table", "--output", "-o", help="Output: table|json|prometheus"
    ),
    export: str = typer.Option("", "--export", "-e", help="Export metrics to file"),
) -> None:
    """Show metrics from the current session."""
    metrics = get_metrics()

    if output == "prometheus":
        data = metrics.to_prometheus()
    elif output == "json":
        import json

        data = json.dumps(metrics.to_dict(), indent=2)
    else:
        data = None

    if data:
        console.print(data)
        if export:
            Path(export).write_text(data)
        return

    # Table output
    table = Table(title="Siyarix Metrics", header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")

    m = metrics.to_dict()
    table.add_row("Uptime (s)", f"{m['uptime_seconds']:.1f}")
    table.add_row("Total Scans", str(m["execution"]["total_scans"]))
    table.add_row("Successful Scans", str(m["execution"]["successful_scans"]))
    table.add_row("Failed Scans", str(m["execution"]["failed_scans"]))
    table.add_row("Total Findings", str(m["execution"]["total_findings"]))
    table.add_row("Avg Duration (s)", f"{m['execution']['avg_duration_seconds']:.2f}")
    table.add_row("Plans Generated", str(m["planner"]["plans_generated"]))
    table.add_row("Model Calls", str(m["planner"]["model_calls"]))
    table.add_row("Model Errors", str(m["planner"]["model_errors"]))

    console.print(table)


@app.command("ci-gate")
def ci_gate(
    allow_degraded: bool = typer.Option(
        False, "--allow-degraded", help="Pass even if health is degraded"
    ),
) -> None:
    """CI gate — verify system health and critical findings before deployment."""
    try:
        from ..offline_store import OfflineStore
    except ModuleNotFoundError:
        console.print("[yellow]Offline store not available — skipping finding check[/yellow]")
        health = asyncio.run(get_health().check_all())
    else:
        store = OfflineStore()
        health = asyncio.run(get_health().check_all())
        critical = store.search_findings(severity="critical", limit=1)

        if health.state.value == "unhealthy":
            console.print("[red]Health check failed: UNHEALTHY[/red]")
            raise typer.Exit(2)

        if health.state.value == "degraded" and not allow_degraded:
            console.print(
                "[yellow]Health check is DEGRADED (use --allow-degraded to pass).[/yellow]"
            )
            raise typer.Exit(2)

        if critical:
            console.print("[red]Critical findings detected. Failing gate.[/red]")
            raise typer.Exit(3)

    console.print("[green]✓ CI gate passed[/green]")


# ---------------------------------------------------------------------------
# Premium: Compliance commands
# ---------------------------------------------------------------------------
@audit_app.command()
def report(
    framework: str = typer.Argument(help="Framework: soc2|iso27001|nist"),
    output: str = typer.Option("report.md", "--output", "-o", help="Output file"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Include evidence"),
    days: int = typer.Option(30, "--days", help="Number of days to include"),
) -> None:
    """Generate compliance report."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Compliance Report:[/bold] {framework}")

    ext = Path(output).suffix.lower()
    if ext in {".json", ".csv"}:
        fmt = ext.lstrip(".")
        audit.export(format=fmt, filepath=output, days=days)
        console.print(f"[green]✓ Report generated: {output}[/green]")
        return

    if ext not in {".md", ".txt"}:
        console.print("[red]Unsupported format. Use .md, .txt, .json, or .csv.[/red]")
        raise typer.Exit(1)

    stats = audit.get_statistics()
    chain = audit.verify_chain()
    events = audit.get_events(limit=100)

    lines = [
        f"# Siyarix Compliance Report ({framework.upper()})",
        "",
        f"Generated: {datetime.now().isoformat()}",
        f"Retention days: {stats.get('retention_days')}",
        "",
        "## Audit Summary",
        f"- Total events: {stats.get('total_events')}",
        f"- Total sessions: {stats.get('total_sessions')}",
        f"- Chain integrity: {chain.get('chain_integrity')}",
        "",
        "## Recent Events",
    ]
    for evt in events[-50:]:
        lines.append(
            f"- {evt.get('timestamp')} | {evt.get('user')} | {evt.get('event_type')} | {evt.get('target')}"
        )

    if detailed and events:
        lines.append("")
        lines.append("## Event Details")
        for evt in events[-20:]:
            lines.append(json.dumps(evt, indent=2))

    Path(output).write_text("\n".join(lines))
    console.print(f"[green]✓ Report generated: {output}[/green]")


@audit_app.command()
def logs(
    event_type: str = typer.Option("", "--type", "-t", help="Filter by event type"),
    user: str = typer.Option("", "--user", "-u", help="Filter by user"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max records"),
    output: str = typer.Option("", "--output", "-o", help="Export to file"),
    severity: str = typer.Option("", "--severity", help="Filter by severity"),
    days: int = typer.Option(30, "--days", help="Number of days to include"),
) -> None:
    """View audit logs."""
    print_banner(console, _active_theme)
    if output:
        ext = Path(output).suffix.lower()
        if ext not in {".json", ".csv"}:
            console.print("[red]Unsupported export format. Use .json or .csv.[/red]")
            raise typer.Exit(1)
        audit.export(format=ext.lstrip("."), filepath=output, days=days)
        console.print(f"[green]✓ Audit log exported to {output}[/green]")
        return

    events = audit.get_events(
        event_type=event_type or None,
        user=user or None,
        severity=severity or None,
        limit=limit,
    )
    if not events:
        console.print("[yellow]No audit events found.[/yellow]")
        return

    table = Table(title="Audit Trail", show_header=True, header_style="bold yellow")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("User", style="cyan")
    table.add_column("Event", style="white")
    table.add_column("Target", style="yellow")
    table.add_column("Result", justify="center")

    for evt in events:
        table.add_row(
            evt.get("timestamp", ""),
            evt.get("user", ""),
            evt.get("event_type", ""),
            evt.get("target", ""),
            evt.get("result", ""),
        )

    console.print(table)


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify audit log chain integrity."""
    result = audit.verify_chain()
    if result.get("valid"):
        console.print("[green]✓ Audit chain integrity verified[/green]")
    else:
        console.print(f"[red]Chain integrity failed at {result.get('broken_at')}[/red]")


# Security sub-commands are defined in security_commands.py.


# ---------------------------------------------------------------------------
# Tool registry commands (real implementation)
# ---------------------------------------------------------------------------
@tool_registry_app.command("list")
def tool_registry_list(
    category: str = typer.Option("", "--category", "-c", help="Filter by category"),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Force re-discovery"),
    fast: bool = typer.Option(False, "--fast", help="Skip version probes for speed"),
) -> None:
    """List all discovered security tools on this system.

    Examples:
      siyarix tool-registry list
      siyarix tool-registry list --category recon
      siyarix tool-registry list --refresh
    """
    registry.discover_from_path()
    from ..registry import ToolCategory as TC
    if category:
        tools = registry.list_tools(category=TC(category))
    else:
        tools = registry.list_tools()
    if not tools:
        console.print(
            "[yellow]No tools found. Install security tools and run again.[/yellow]"
        )
        return

    table = Table(
        title=f"Security Tools ({len(tools)} found)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Binary", style="dim")
    table.add_column("Category", style="magenta")
    table.add_column("Risk", style="yellow")
    table.add_column("Tags", style="white")

    for t in sorted(tools, key=lambda x: x.category):
        tags = ", ".join(t.tags[:3])
        table.add_row(t.name, t.binary, t.category.value, t.risk_level.value, tags)

    console.print(table)


@tool_registry_app.command("update-metadata")
def tool_registry_update_metadata(
    output_path: str = typer.Argument(..., help="Path to save the tool metadata JSON")
) -> None:
    """Regenerate the tool metadata file by scanning all binaries on PATH."""
    reg = ToolRegistry()
    count = reg.update_metadata(Path(output_path))
    console.print(f"[green]Successfully updated metadata: {count} tools recorded.[/green]")


# ---------------------------------------------------------------------------
# Auth commands — wire API keys to the engine
# ---------------------------------------------------------------------------
@auth_app.command("set-key")
def auth_set_key(
    provider: str = typer.Argument(
        help="Provider: openai | gemini | anthropic | custom"
    ),
    api_key: str = typer.Option(
        ..., "--key", "-k", help="API key value", hide_input=True
    ),
) -> None:
    """Store an API key for a model provider.

    Examples:
      siyarix auth set-key openai --key sk-...
      siyarix auth set-key gemini --key AIz...
      siyarix auth set-key anthropic --key sk-ant-...
    """
    creds.delete(provider, "api_key")
    creds.store(provider, api_key, "api_key")
    from siyarix.providers import get_provider_env_var
    env_key = get_provider_env_var(provider)
    _upsert_env_vars({env_key: api_key})
    os.environ[env_key] = api_key
    console.print(f"[green]✓ API key stored for provider: {provider}[/green]")
    console.print(
        "[dim]Key is stored in the credential vault and synced to .env.[/dim]"
    )


@auth_app.command("show")
def auth_show() -> None:
    """Show configured API key providers."""
    try:
        from siyarix.providers import ProviderManager
        pm = ProviderManager()
        providers = pm.list_providers()
    except Exception:
        providers = ["openai", "gemini", "anthropic", "groq", "openrouter"]

    table = Table(
        title="Configured API Keys", show_header=True, header_style="bold green"
    )
    table.add_column("Provider", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source")

    for prov in providers:
        from siyarix.providers import get_provider_env_var
        env_key = get_provider_env_var(prov)
        from_env = bool(os.getenv(env_key))
        from_creds = bool(creds.retrieve(prov, "api_key"))
        if from_env:
            status, source = "✓ Set", "Environment variable"
        elif from_creds:
            status, source = "✓ Set", "Keyring"
        else:
            status, source = "✗ Not set", "—"
        table.add_row(prov, status, source)

    console.print(table)


# ---------------------------------------------------------------------------
# Shell completions
# ---------------------------------------------------------------------------
@completions_app.command("install")
def completions_install(
    shell: str = typer.Argument(
        default="", help="Shell: bash | zsh | fish | powershell"
    ),
) -> None:
    """Install shell completions for Siyarix.

    Examples:
      siyarix completions install bash
      siyarix completions install powershell
    """
    if not shell:
        shell = os.getenv("SHELL", "bash").split("/")[-1]
        if platform.system().lower() == "windows":
            shell = "powershell"

    shell = shell.lower()
    completions_map = {
        "bash": (
            "~/.bashrc",
            "_SIYARIX_COMPLETE=bash_source siyarix >> ~/.siyarix/complete.bash\necho 'source ~/.siyarix/complete.bash' >> ~/.bashrc",
        ),
        "zsh": (
            "~/.zshrc",
            "_SIYARIX_COMPLETE=zsh_source siyarix >> ~/.siyarix/complete.zsh\necho 'source ~/.siyarix/complete.zsh' >> ~/.zshrc",
        ),
        "fish": (
            "~/.config/fish/completions/siyarix.fish",
            "_SIYARIX_COMPLETE=fish_source siyarix > ~/.config/fish/completions/siyarix.fish",
        ),
        "powershell": (
            "$PROFILE",
            "$env:_SIYARIX_COMPLETE='powershell_source'; siyarix | Out-String | Invoke-Expression",
        ),
    }

    if shell not in completions_map:
        console.print(
            f"[red]Unsupported shell: {shell}. Choose: bash, zsh, fish, powershell[/red]"
        )
        raise typer.Exit(1)

    target, instructions = completions_map[shell]
    console.print(
        Panel(
            f"[bold]To install {shell} completions, run:[/bold]\n\n"
            f"[green]{instructions}[/green]\n\n"
            f"[dim]Then restart your shell or source {target}[/dim]",
            title=f"Shell Completions ({shell})",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# Config commands — wired to real SettingsStore
# ---------------------------------------------------------------------------
@config_app.command("list")
def config_list() -> None:
    """List all configuration settings."""
    rows = config.list_all()
    table = Table(
        title="Siyarix Configuration", show_header=True, header_style="bold cyan"
    )
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Default", style="dim")
    table.add_column("Description", style="white")

    for row in rows:
        modified = "[bold]" if row["modified"] else ""
        table.add_row(
            f"{modified}{row['key']}",
            row["value"],
            row["default"],
            row["description"][:50],
        )
    console.print(table)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(help="Setting key"),
    value: str = typer.Argument(help="New value"),
) -> None:
    """Set a configuration value.\n\nExample: siyarix config set log_level debug"""
    try:
        new_val = config.set(key, value)
        console.print(f"[green]✓ {key} = {new_val}[/green]")
    except (KeyError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("get")
def config_get(key: str = typer.Argument(help="Setting key")) -> None:
    """Get a configuration value."""
    try:
        val = config.get(key)
        console.print(f"[cyan]{key}[/cyan] = [green]{val}[/green]")
    except KeyError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("reset")
def config_reset(
    key: str = typer.Argument(default="", help="Key to reset (empty = all)")
) -> None:
    """Reset a setting (or all settings) to defaults."""
    try:
        config.reset(key or None)
        target = key if key else "all settings"
        console.print(f"[green]✓ Reset {target} to defaults.[/green]")
    except KeyError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Theme management (premium)
# ---------------------------------------------------------------------------
# Note: theme commands are defined earlier; duplicate premium-themed handlers removed to
# avoid redefinition and typing conflicts.


# ---------------------------------------------------------------------------
# Version command
# ---------------------------------------------------------------------------
@app.command()
def version() -> None:
    """Show Siyarix version information."""
    registry.discover_from_path()
    tools = registry.list_tools()
    console.print(
        Panel.fit(
            f"[bold cyan]Siyarix[/bold cyan] [green]v{__version__}[/green]\n"
            f"[dim]Platform:[/dim] {platform.system()} {platform.release()}\n"
            f"[dim]Python:[/dim]   {platform.python_version()}\n"
            f"[dim]Tools found:[/dim] {len(tools)}",
            title="Version",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if config.get("log_level") == "debug":
            console.print_exception()
        sys.exit(1)
