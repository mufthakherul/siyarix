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
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import Any, Optional

# Windows event loop policy for subprocess compatibility
if os.name == "nt" and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
import io
import platform
import sys

if sys.stdout and getattr(sys.stdout, "encoding", "").lower() != "utf-8":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        logging.warning("Failed to set stdout encoding to UTF-8")
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .. import __version__
from ..async_utils import run_async
from ..audit_log import AuditEventType, AuditSeverity, audit
from ..branding import available_themes, print_banner, resolve_theme
from ..chat import CROSS_PLATFORM_COMMANDS, CommandProfile, CommandProfileStore, start_chat
from ..compat import ExecutionEngine, ExecutionMode, SessionKernel
from ..config import SettingsStore, get_config_dir
from ..core.router import IntentRouter
from ..exceptions import ValidationError
from ..health import get_health
from ..logging_config import configure_logging
from ..metrics import get_metrics
from ..compat import EngineResult
from ..registry_factory import make_tool_registry
from ..security_commands import security_app
from ..validators import validate_target
from .plugins import plugins_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_dotenv(path: Path | None = None) -> None:
    """Load environment variables from .env file (simple key=value parser).

    NOTE: API key env vars (*_API_KEY) are intentionally NOT loaded from .env
    for security. Use `siyarix auth set-key` instead.

    Dangerous variables (PATH, LD_PRELOAD, PYTHONPATH, injectors, etc.) are blocked
    via :mod:`siyarix.dotenv_guard`.
    """
    from ..dotenv_guard import apply_dotenv_file

    env_path = path or Path.cwd() / ".env"
    if not env_path.exists():
        env_path = get_config_dir() / ".env"
    apply_dotenv_file(env_path)



def _display_findings_table(findings: list[Any]) -> None:
    """Render scan findings as a Rich table using theme-aware styling."""
    from ..branding import resolve_theme, severity_label

    settings = SettingsStore()
    theme = resolve_theme(settings.get("color_theme"))
    ftable = Table(title="Findings", header_style="bold", border_style="dim")
    ftable.add_column("Severity", width=12)
    ftable.add_column("Type", style="cyan")
    ftable.add_column("Detail", style="white")
    for f in findings[:20]:
        sev = f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info")
        f_type = f.get("type", "—") if isinstance(f, dict) else getattr(f, "type", "—")
        detail = (
            f.get("detail", f.get("description", str(f)))
            if isinstance(f, dict)
            else getattr(f, "detail", getattr(f, "description", str(f)))
        )
        ftable.add_row(
            severity_label(theme, str(sev)),
            str(f_type),
            str(detail)[:80],
        )
    if len(findings) > 20:
        ftable.add_row("", f"[dim]... and {len(findings) - 20} more[/dim]", "")
    console.print(ftable)


# ---------------------------------------------------------------------------
# Shell completion helpers
# ---------------------------------------------------------------------------


def _generate_completion(shell: str, output_path: Path) -> bool:
    """Generate a static shell completion script using Click's built-in
    completion classes. Returns True on success.

    The generated file is sourced from the shell rc file so that no Python
    process is launched on terminal open. Completions only run Python when
    Tab is pressed after ``siyarix`` (handled by the generated script).
    """
    _SHELL_MAP = {
        "bash": "BashComplete",
        "zsh": "ZshComplete",
        "fish": "FishComplete",
    }
    if shell not in _SHELL_MAP:
        return False

    import click.shell_completion as _sc

    comp_cls = _sc._available_shells.get(shell)
    if comp_cls is None:
        return False

    from typer.main import get_command as _get_command

    cmd = _get_command(app)
    comp = comp_cls(cmd, {}, "siyarix", "_SIYARIX_COMPLETE")  # type: ignore[arg-type]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(comp.source())
    return True


# ---------------------------------------------------------------------------
# Initialize core systems
# ---------------------------------------------------------------------------

# Detect non-interactive / CI / pipe environments
_IS_TTY = sys.stdout.isatty()
_IS_STDIN_PIPE = not sys.stdin.isatty()
_CI_MODE = os.getenv("CI", "") or os.getenv("SIYARIX_NO_BANNER", "") or not _IS_TTY

console = Console()
registry = make_tool_registry()
config = SettingsStore()
configure_logging(config.get("log_level"))
_load_dotenv()

_PROVIDER_ENV_MAP: dict[str, str] = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
}

intent_router = IntentRouter()
session_kernel = SessionKernel()


_creds_store: Any = None


def _get_creds() -> Any:
    global _creds_store
    if _creds_store is None:
        try:
            from ..credential_store import CredentialStore

            _creds_store = CredentialStore()
            for provider, env_var in _PROVIDER_ENV_MAP.items():
                if not os.environ.get(env_var):
                    try:
                        key = _creds_store.retrieve(provider, "api_key")
                        if key:
                            os.environ[env_var] = key
                    except Exception:
                        logger.debug("API key not available for provider %s", provider)
        except Exception:
            logger.debug("CredentialStore not available")
            _creds_store = False
    return _creds_store if _creds_store else None


def _make_deep_scan_engine():
    """Build DeepScanEngine with PermissionGate-aware executor injected."""
    from ..deep_scan import DeepScanEngine
    from ..executor_registry import RegistryExecutor

    executor = RegistryExecutor(
        registry=registry,
        permission_gate=getattr(registry, "_permission_gate", None),
    )
    return DeepScanEngine(registry=registry, executor=executor)


def _execute_deep_scan(target: str, output: str = "table", save: bool = False) -> None:
    """Execute a deep scan using the DeepScanEngine."""
    engine = _make_deep_scan_engine()
    result = run_async(engine.scan(target, persist=save))

    if output == "json":
        import json

        console.print_json(json.dumps(result, indent=2, default=str))
        return

    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    summary = result["severity_summary"]
    console.print(f"\n[bold cyan]Deep Scan Complete — {result['target']}[/bold cyan]")
    console.print(f"  Risk Score: [bold]{result['risk_score']}[/bold]")
    console.print(f"  Findings: {result['total_findings']} total")
    for sev in ("critical", "high", "medium", "low", "info"):
        color = severity_colors.get(sev, "white")
        count = summary.get(sev, 0)
        if count:
            console.print(f"    [{color}]{sev}: {count}[/{color}]")
    console.print(f"  Passes: {', '.join(result['passes_completed'])}")
    console.print(f"  Tools: {', '.join(result['tools_used'])}")
    console.print()

    if output == "table":
        from rich.table import Table

        from ..branding import resolve_theme, severity_label
        from ..config import SettingsStore

        settings = SettingsStore()
        theme = resolve_theme(settings.get("color_theme"))
        ftable = Table(title="Findings", header_style="bold", border_style="dim")
        ftable.add_column("Severity", width=10)
        ftable.add_column("Pass", width=14)
        ftable.add_column("Tool", width=14)
        ftable.add_column("Detail", style="white")
        for f in result["all_findings"][:30]:
            sev = f.get("severity", "info")
            ftable.add_row(
                severity_label(theme, sev),
                f.get("pass", "—"),
                f.get("tool", "—"),
                str(f.get("detail", f.get("description", "")))[:80],
            )
        if len(result["all_findings"]) > 30:
            ftable.add_row(
                "", "", f"[dim]... and {len(result['all_findings']) - 30} more[/dim]", ""
            )
        console.print(ftable)


def _resolve_key(provider: str) -> str:
    """Resolve API key from credential store → env."""
    from ..providers import resolve_api_key

    env_var = _PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    if not os.environ.get(env_var):
        cs = _get_creds()
        if cs:
            try:
                key = cs.retrieve(provider, "api_key")
                if key:
                    os.environ[env_var] = key
            except Exception:
                logger.debug("API key not in credential store for provider %s", provider)
    val = resolve_api_key(provider, env_var) or ""
    if val:
        os.environ[env_var] = val
    return val


def _store_key(provider: str, key: str) -> None:
    """Store API key in CredentialStore and environment."""
    env_var = _PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    os.environ[env_var] = key
    cs = _get_creds()
    if cs:
        try:
            cs.store(provider, key, "api_key")
        except Exception:
            logger.warning("Failed to store API key for provider %s", provider, exc_info=True)


def _delete_key(provider: str) -> None:
    """Delete API key from CredentialStore and environment."""
    env_var = _PROVIDER_ENV_MAP.get(provider, f"{provider.upper()}_API_KEY")
    os.environ.pop(env_var, None)
    cs = _get_creds()
    if cs:
        try:
            cs.delete(provider, "api_key")
        except Exception:
            logger.warning("Failed to delete API key for provider %s", provider, exc_info=True)


def _get_engine(mode: str = "integrated") -> ExecutionEngine:
    """Build an ExecutionEngine with API keys from config/credentials."""
    engine_config: dict = {}
    if os.getenv("SIYARIX_FAST_DISCOVERY", "0") == "1":
        engine_config["fast_discovery"] = True
    openai_key = _resolve_key("openai")
    gemini_key = _resolve_key("gemini")
    anthropic_key = _resolve_key("anthropic")
    groq_key = _resolve_key("groq")
    together_key = _resolve_key("together")
    openrouter_key = _resolve_key("openrouter")
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
# Ensure ~/.siyarix/bin is on PATH (onboarding installs binaries there)
# ---------------------------------------------------------------------------
_siyarix_bin = str(Path.home() / ".siyarix" / "bin")
if _siyarix_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _siyarix_bin + os.pathsep + os.environ.get("PATH", "")

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
    force: bool = typer.Option(
        False, "--force", "-f", help="Re-run wizard even if already configured"
    ),
    _skip_requirements: bool = typer.Option(
        False, "--skip-requirements", help="Skip requirements check"
    ),
    express: bool = typer.Option(
        False, "--express", "-q", help="Express setup — sensible defaults in seconds"
    ),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", "-y", help="Non-interactive setup with auto-detected defaults"
    ),
) -> None:
    """Initialize Siyarix — interactive setup wizard.

    Runs the full onboarding wizard: ethics pledge, requirements check,
    provider setup, mode and persona configuration.
    """
    home_dir = get_config_dir()
    marker = home_dir / ".initialized"
    if marker.exists() and not force:
        console.print("[green]\u2713 Siyarix is already initialized.[/green]")
        console.print("  Run [cyan]siyarix init --force[/cyan] to re-run the wizard.")
        return

    from siyarix.config import SettingsStore
    from siyarix.onboarding import OnboardingWizard

    settings = SettingsStore()
    wizard = OnboardingWizard(
        settings=settings,
        express=express,
        non_interactive=non_interactive,
    )
    run_async(wizard.run())


def _run_batch_lines(
    lines: list[str],
    mode: str = "integrated",
    offline_mode: str | None = None,
) -> None:
    """Execute a list of command lines through the chat REPL handler.

    When *offline_mode* is set, runs all natural-language commands through
    the registry planner instead of hardcoding a handful of canned responses.
    """
    from ..chat import SiyarixChat

    chat = SiyarixChat(mode=mode)
    is_offline = offline_mode == "offline" or mode == "offline"

    # Show mode indicator for non-interactive mode
    if is_offline:
        console.print("[yellow]⚡ Offline mode active — using heuristic planning[/yellow]")
    else:
        console.print(f"[dim]Mode: {mode}[/dim]")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        console.print(f"[bold]{'[OFFLINE]' if is_offline else ''} > {line}[/bold]")
        if line.startswith("/"):
            asyncio.run(chat._handle_slash(line))
        else:
            try:
                if is_offline:
                    asyncio.run(chat._execute_instruction(line))
                else:
                    chat._session.add_message("user", line)
                    asyncio.run(chat._execute_instruction(line))
            except Exception as e:
                console.print(f"[dim]Error processing command: {e}[/dim]")
        console.print()


def _show_version() -> None:
    from ..branding import resolve_version

    ver = resolve_version()
    console.print(f"[bold cyan]Siyarix[/bold cyan] [green]v{ver}[/green]")
    console.print(f"Platform: {sys.platform}  Python: {sys.version.split()[0]}")


async def _run_onboarding() -> None:
    """Run the first-run onboarding wizard."""
    from siyarix.config import SettingsStore
    from siyarix.onboarding import OnboardingWizard

    settings = SettingsStore()
    wizard = OnboardingWizard(settings=settings)
    completed = await wizard.run()
    if completed:
        console.print("[green]Setup complete! Restarting...[/green]")
    else:
        console.print("[yellow]Setup exited. Run 'siyarix init' to restart.[/yellow]")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    config_file: str = typer.Option(
        None, "--config", "-c", help="Path to custom config file (TOML/JSON/YAML)"
    ),
    batch: str = typer.Option(None, "--batch", "-b", help="Path to batch script file to execute"),
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Execution mode: autonomous|integrated|offline|registry",
    ),
    target: str = typer.Option("", "--target", "-t", help="Set initial target for the session"),
    session: str = typer.Option("", "--session", help="Resume a previous session by ID"),
    resume: bool = typer.Option(False, "--resume", help="Resume an existing session"),
    version: bool = typer.Option(False, "--version", help="Show version information"),
) -> None:
    """Siyarix CLI — unified entry point.

    Usage:
      siyarix <command> [options]    — Direct command execution
      echo "<cmd>" | siyarix         — Pipe commands via stdin
      siyarix                        — Launch interactive chat
    """
    global _active_theme

    if version:
        _show_version()
        raise typer.Exit()

    if config_file:
        resolved = Path(config_file).expanduser().resolve()
        if resolved.is_file():
            # Point the settings loader at this file for this process only.
            # Do NOT rewrite SIYARIX_CONFIG_DIR — that would make subsequent
            # lookups invent a sibling settings.toml and ignore the selection.
            os.environ["SIYARIX_CONFIG"] = str(resolved)
            try:
                config.reload(resolved)  # module-level SettingsStore singleton
            except Exception as exc:
                console.print(f"[red]Failed to load config {resolved}: {exc}[/red]")
                raise typer.Exit(1)
            _active_theme = str(config.get("color_theme") or "default")
            console.print(f"[dim]Loaded config: {resolved}[/dim]")
        else:
            console.print(f"[red]Config file not found: {resolved}[/red]")
            raise typer.Exit(1)

    mode_val: Any = mode
    if mode_val is None:
        try:
            mode = str(config.get("default_mode") or "integrated")
        except Exception:
            mode = "integrated"

    # --batch file mode (file-based, non-interactive)
    if batch:
        resolved = Path(batch).expanduser().resolve()
        if resolved.exists():
            script_lines = resolved.read_text(encoding="utf-8").splitlines()
            console.print(
                f"[dim]Executing batch script: {resolved} ({len(script_lines)} commands)[/dim]"
            )
            _run_batch_lines(script_lines, mode=mode, offline_mode=mode)
        else:
            console.print(f"[red]Batch script not found: {resolved}[/red]")
            raise typer.Exit(1)
        return

    # Pipe from stdin: echo "scan 10.0.0.1" | siyarix
    if _IS_STDIN_PIPE and ctx.invoked_subcommand is None:
        lines = [line for line in sys.stdin if line.strip()]
        if lines:
            _run_batch_lines([line.strip() for line in lines], mode=mode, offline_mode=mode)
        return

    # No subcommand: check onboarding regardless of TTY
    if ctx.invoked_subcommand is None:
        try:
            from siyarix.bootstrap import INITIALIZED_MARKER
            from siyarix.config import SettingsStore

            needs_onboarding = not INITIALIZED_MARKER.exists() or not SettingsStore().get(
                "onboarding_complete"
            )
        except Exception:
            logger.debug("Onboarding check failed, assuming fresh install", exc_info=True)
            needs_onboarding = True

        if needs_onboarding:
            if _IS_TTY:
                import asyncio

                asyncio.run(_run_onboarding())
            else:
                console.print(
                    "[yellow]Siyarix needs initial setup. Run [cyan]siyarix init[/cyan] to start the setup wizard.[/yellow]"
                )
            return

        # TTY: launch interactive chat
        if _IS_TTY:
            if mode and mode.lower() in ("offline", "registry"):
                console.print(
                    "[yellow]⚡ Starting in offline mode — heuristic planning only[/yellow]"
                )
            start_chat(
                mode=mode, target=target, session_id=session or None, resume=resume or bool(session)
            )


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
    store = CommandProfileStore()
    intents = sorted(CROSS_PLATFORM_COMMANDS.keys())
    options = [f"intent: {i}" for i in intents]
    saved = store.list_credentials()
    options += [f"saved: {p.name} -> {p.command}" for p in saved]

    # Non-TTY mode: print palette and exit
    if not sys.stdin.isatty():
        console.print("[bold]Available palette commands:[/bold]")
        for o in options:
            console.print(f"  {o}")
        return

    try:
        from prompt_toolkit import prompt as _ptk_prompt
        from prompt_toolkit.completion import WordCompleter as _WordCompleter

        PTK = True
    except Exception as exc:
        import logging

        logging.getLogger(__name__).debug("prompt_toolkit not available: %s", exc)
        PTK = False

    if PTK:
        choice = _ptk_prompt(
            "Select or search: ", completer=_WordCompleter(options, ignore_case=True)
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


@profile_app.command("list")
def profile_list_alias() -> None:
    """List saved command profiles (alias for list-cmds)."""
    profile_list_cmds()


@profile_app.command("rm-cmd")
def profile_rm_cmd(name: str = typer.Argument(..., help="Profile name to remove")) -> None:
    """Remove a saved command profile."""
    store = CommandProfileStore()
    ok = store.delete(name)
    if ok:
        console.print(f"[green]✓ Removed {name}[/green]")
    else:
        console.print(f"[red]Profile not found: {name}[/red]")


from .audit_cmds import audit_app

app.add_typer(audit_app, name="audit")

from .config_cmds import config_app

app.add_typer(config_app, name="config")

completions_app = typer.Typer(help="🏁 Shell completions")
app.add_typer(completions_app, name="completions")


@app.command("completion", hidden=True)
def _completion_alias(
    shell: str = typer.Argument("bash", help="Shell (bash, zsh, fish, powershell)"),
) -> None:
    """Alias for 'completions'. Use 'siyarix completions' (plural) instead."""
    # Clean up old broken line from .bashrc / .zshrc so user stops seeing this
    import re as _re

    for rc_name in (".bashrc", ".zshrc", ".config/fish/config.fish"):
        rc = Path.home() / rc_name
        if rc.is_file():
            try:
                text = rc.read_text(encoding="utf-8")
                cleaned = _re.sub(
                    r'\neval "\$\(siyarix? completion \w+\)".*',
                    "",
                    text,
                )
                if cleaned != text:
                    rc.write_text(cleaned, encoding="utf-8")
            except OSError:
                logger.warning(
                    "Failed to clean up broken completion line in %s", rc_name, exc_info=True
                )

    # Write to stderr so eval "$(siyarix completion bash)" doesn't choke on the output
    print(
        "'siyarix completion' (singular) is deprecated. "
        f"Use 'siyarix completions install {shell}' instead.",
        file=sys.stderr,
    )
    print(
        f'Or run: eval "$(_SIYARIX_COMPLETE=source_{shell} siyarix)"',
        file=sys.stderr,
    )


theme_app = typer.Typer(help="🎨 Theme customization")
app.add_typer(theme_app, name="theme")


@theme_app.command("list")
def theme_list() -> None:
    """List available color themes."""
    themes = available_themes()
    active = resolve_theme(config.get("color_theme") or _active_theme)
    table = Table(title="Available Color Themes", header_style="bold cyan")
    table.add_column("Theme", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("CLI Command", style="white")
    table.add_column("REPL Command", style="dim")
    for t in themes:
        is_active = t == active
        status = "[bold green]✓ (active)[/bold green]" if is_active else ""
        table.add_row(t, status, f"siyarix theme set {t}", f"/theme set {t}")
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

tool_registry_app = typer.Typer(help="🛠 Tool discovery & registry")
app.add_typer(tool_registry_app, name="tool-registry")


@cache_app.command("status")
def cache_status() -> None:
    """Show cache statistics."""
    from ..cache_manager import cache_manager

    stats = cache_manager.stats()
    size_mb = stats.get("total_size_bytes", 0) / (1024 * 1024)
    total_entries = stats.get("total_entries", 0)
    hit_rate = stats.get("hit_rate", 0.0)
    domains = stats.get("domains", [])
    domain_str = ", ".join(domains) if domains else "None"

    table = Table(title="Cache Storage & Performance", header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total Cached Entries", str(total_entries))
    table.add_row("Cache Storage Size", f"{size_mb:.2f} MB")
    table.add_row("Cache Hit Rate", f"{hit_rate:.1%}")
    table.add_row("Cached Domains", domain_str)
    console.print(table)


@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached data."""
    from ..cache_manager import cache_manager

    count = cache_manager.clear()
    console.print(f"[green]Cache cleared: {count} entries[/green]")


from .tools_cmds import tools_app

app.add_typer(tools_app, name="tools")
app.add_typer(tools_app, name="tool")

app.add_typer(plugins_app, name="plugins")
app.add_typer(plugins_app, name="plugin")


@tool_registry_app.command("providers")
def list_providers() -> None:
    """List configured model providers (order of preference)."""
    from ..providers.manager import ProviderManager

    pm = ProviderManager.get_instance()
    providers = pm.list_providers()
    if not providers:
        console.print("[dim]No providers registered[/dim]")
        return

    table = Table(title="Configured Model Providers", header_style="bold cyan")
    table.add_column("Provider", style="cyan")
    table.add_column("Display Name", style="white")
    table.add_column("Configured", style="green")
    for name in providers:
        profile = pm.get_profile(name)
        display = profile.display_name if profile else name.capitalize()
        has_key = bool(pm.get_api_key(name))
        status = "[green]✓[/green]" if has_key else "[dim]✗[/dim]"
        table.add_row(name, display, status)
    console.print(table)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_theme: str = config.get("color_theme") or "default"


# ---------------------------------------------------------------------------
# Premium: Main entry with enhanced output
# ---------------------------------------------------------------------------
@app.command()
def scan(
    ctx: typer.Context,
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, URLs, or @file.txt"),
    tool: str = typer.Option("", "--tool", "-t", help="Specific tool to use"),
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Execution mode: autonomous|integrated|offline|registry",
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output: table|json|yaml|csv|html|quiet"
    ),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans (1 = sequential per-target; "
            "default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to database"),
    _notify: bool = typer.Option(False, "--notify", "-n", help="Send notification on completion"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    profile: str = typer.Option("", "--profile", help="Use specific profile"),
) -> None:
    """Run security scans against one or more targets.

    Supports @targets.txt multi-target mode. Prefix a file path with @ to load targets.
    With 2+ targets, --parallel runs independent per-target scans concurrently.

    Examples:
      siyarix scan 192.168.1.1
      siyarix scan 10.0.0.0/24 --tool nmap --mode registry
      siyarix scan @targets.txt --parallel 5
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    mode_val: Any = mode
    if mode_val is None:
        parent_params = ctx.parent.params if ctx.parent else {}
        mode = str(parent_params.get("mode", "integrated"))

    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(config.get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))

    result = _execute_scan_core(
        targets,
        tool=tool,
        mode=mode,
        output=output,
        timeout=timeout,
        save=save,
        dry_run=dry_run,
        no_banner=no_banner,
        profile=profile,
        parallel=parallel_workers,
        notify=_notify,
    )
    if result is not None and not getattr(result, "success", True):
        raise typer.Exit(1)


def _build_scan_instruction(target: str, *, tool: str = "", nmap_args: str = "") -> str:
    """Build a natural-language scan instruction for a single target."""
    instruction = f"scan {target}"
    if nmap_args:
        instruction += f" flags {nmap_args}"
    if tool:
        instruction += f" with {tool}"
    return instruction


async def _execute_targets_parallel(
    targets: list[str],
    *,
    mode: str,
    tool: str = "",
    nmap_args: str = "",
    parallel: int = 3,
    dry_run: bool = False,
    persist: bool = False,
) -> EngineResult:
    """Run one engine.execute per target with bounded concurrency; merge results."""
    workers = max(1, min(int(parallel), len(targets), 32))
    sem = asyncio.Semaphore(workers)
    console.print(
        f"[dim]Scanning {len(targets)} targets with {workers} parallel workers[/dim]"
    )

    async def _one(target: str) -> EngineResult:
        instruction = _build_scan_instruction(target, tool=tool, nmap_args=nmap_args)
        engine = _get_engine(mode)
        async with sem:
            try:
                return await engine.execute(
                    instruction,
                    interactive=False,
                    dry_run=dry_run,
                    persist=persist,
                )
            except Exception as exc:
                logger.exception("Parallel scan failed for target %s", target)
                return EngineResult(
                    success=False,
                    summary=f"{target}: failed ({exc})",
                    error_message=str(exc),
                )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Parallel scan[/bold cyan]"),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            f"0/{len(targets)} done · 0 ok · 0 fail", total=len(targets)
        )
        completed = 0
        ok_count = 0
        fail_count = 0
        in_flight: set[str] = set()
        lock = asyncio.Lock()

        async def _tracked(target: str) -> EngineResult:
            nonlocal completed, ok_count, fail_count
            async with lock:
                in_flight.add(target)
                active = ", ".join(sorted(in_flight)[:3])
                if len(in_flight) > 3:
                    active += f" +{len(in_flight) - 3}"
                progress.update(
                    task_id,
                    description=(
                        f"{completed}/{len(targets)} done · {ok_count} ok · "
                        f"{fail_count} fail · now: {active or '—'}"
                    ),
                )
            result = await _one(target)
            async with lock:
                in_flight.discard(target)
                completed += 1
                if result.success:
                    ok_count += 1
                else:
                    fail_count += 1
                progress.update(
                    task_id,
                    advance=1,
                    description=(
                        f"{completed}/{len(targets)} done · {ok_count} ok · "
                        f"{fail_count} fail"
                    ),
                )
            return result

        raw_results = await asyncio.gather(
            *[_tracked(t) for t in targets],
            return_exceptions=True,
        )

    merged = EngineResult(success=True, summary="")
    summaries: list[str] = []
    for target, raw in zip(targets, raw_results, strict=True):
        if isinstance(raw, BaseException):
            merged.success = False
            msg = f"{target}: error ({raw})"
            summaries.append(msg)
            merged.error_message = (
                f"{merged.error_message}; {msg}" if merged.error_message else msg
            )
            continue
        for finding in raw.all_findings or []:
            if isinstance(finding, dict):
                tagged = dict(finding)
                tagged.setdefault("target", target)
                tagged.setdefault("scan_target", target)
                merged.all_findings.append(tagged)
            else:
                # Best-effort tag object findings for multi-target rollups.
                try:
                    if getattr(finding, "target", None) in (None, ""):
                        setattr(finding, "target", target)
                    if getattr(finding, "scan_target", None) in (None, ""):
                        setattr(finding, "scan_target", target)
                except Exception:
                    pass
                merged.all_findings.append(finding)
        merged.step_results.extend(raw.step_results or [])
        merged.duration_ms += float(raw.duration_ms or 0.0)
        merged.retries_performed += int(raw.retries_performed or 0)
        if raw.raw_output:
            merged.raw_output = (
                f"{merged.raw_output}\n{raw.raw_output}" if merged.raw_output else raw.raw_output
            )
        if not raw.success:
            merged.success = False
        if raw.error_message:
            merged.error_message = (
                f"{merged.error_message}; {raw.error_message}"
                if merged.error_message
                else raw.error_message
            )
        summaries.append(raw.summary or f"{target}: done")

    preview = "; ".join(summaries[:8])
    if len(summaries) > 8:
        preview += "…"
    ok_n = sum(
        1
        for raw in raw_results
        if not isinstance(raw, BaseException) and getattr(raw, "success", False)
    )
    fail_n = len(targets) - ok_n
    findings_n = len(merged.all_findings or [])
    status = "ok" if merged.success else "partial/fail"
    merged.summary = (
        f"Parallel scan of {len(targets)} targets ({status}; "
        f"{ok_n} ok / {fail_n} fail; {findings_n} findings): {preview}"
    )
    style = "green" if merged.success else "yellow"
    console.print(
        f"[{style}]Parallel scan complete:[/{style}] "
        f"{ok_n} ok · {fail_n} fail · {findings_n} findings · "
        f"{merged.duration_ms:.0f} ms"
    )
    return merged


def _execute_scan_core(
    targets: list[str],
    tool: str = "",
    mode: str = "integrated",
    output: str = "table",
    timeout: int = 300,
    save: bool = False,
    dry_run: bool = False,
    no_banner: bool = False,
    profile: str = "",
    parallel: int = 3,
    notify: bool = False,
    nmap_args: str = "",
) -> Any:
    """Core scan execution logic (shared between scan and presets)."""
    _ = timeout, no_banner, profile  # reserved for preset/future CLI wiring
    expanded_targets: list[str] = []
    for t in targets:
        if t.startswith("@"):
            target_file = Path(t[1:])
            if target_file.exists():
                lines = [
                    line.strip()
                    for line in target_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                expanded_targets.extend(lines)
                console.print(f"[dim]Loaded {len(lines)} targets from {target_file}[/dim]")
            else:
                console.print(f"[red]Target file not found: {target_file}[/red]")
                raise typer.Exit(3)
        else:
            expanded_targets.append(t)
    if not expanded_targets:
        console.print("[red]No targets specified. Use siyarix scan <target> or @file.txt[/red]")
        raise typer.Exit(1)
    for target in expanded_targets:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)
    valid_outputs = ("table", "json", "yaml", "csv", "html", "quiet")
    output = output.lower()
    if output not in valid_outputs:
        console.print(
            f"[red]Invalid output format '{output}'. Valid: {', '.join(valid_outputs)}[/red]"
        )
        raise typer.Exit(1)
    instruction = _build_scan_instruction(
        " ".join(expanded_targets), tool=tool, nmap_args=nmap_args
    )
    audit.log(
        event_type=AuditEventType.SCAN_START,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="started",
        target=",".join(expanded_targets),
        details={
            "tool": tool,
            "mode": mode,
            "targets": expanded_targets,
            "parallel": parallel,
        },
    )
    if len(expanded_targets) > 1:
        # Always one engine.execute per target (parallel workers or sequential).
        # Avoids the old join-all-targets single instruction that lost per-host tagging.
        result = run_async(
            _execute_targets_parallel(
                expanded_targets,
                mode=mode,
                tool=tool,
                nmap_args=nmap_args,
                parallel=parallel,
                dry_run=dry_run,
                persist=save,
            )
        )
    else:
        engine = _get_engine(mode)
        result = run_async(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )
    if dry_run:
        console.print("[yellow]Dry run complete — no commands executed.[/yellow]")
        return result
    summary_text = str(getattr(result, "summary", None) or "")
    if output != "quiet" and len(expanded_targets) > 1 and parallel > 1 and summary_text:
        console.print(Panel(summary_text, title="Parallel Scan Summary", border_style="cyan"))
    if output == "quiet":
        pass
    elif result.all_findings:
        if output in ("json", "yaml", "csv", "html"):
            try:
                from ..output import OutputEngine

                output_engine = OutputEngine(output_format=output)

                def _as_dict(finding: Any) -> dict[str, Any]:
                    if isinstance(finding, dict):
                        return finding
                    if hasattr(finding, "to_dict"):
                        return finding.to_dict()
                    try:
                        return vars(finding)
                    except TypeError:
                        return {"value": finding}

                findings_dicts = [_as_dict(f) for f in result.all_findings]
                if output == "json":
                    output_engine.print_json(findings_dicts)
                elif output == "yaml":
                    output_engine.print_yaml(findings_dicts)
                elif output == "csv":
                    output_engine.print_csv(findings_dicts)
                elif output == "html":
                    if hasattr(output_engine, "print_html"):
                        output_engine.print_html(findings_dicts)
                    else:
                        output_engine.print_json(findings_dicts)
            except ImportError:
                _display_findings_table(result.all_findings)
        else:
            _display_findings_table(result.all_findings)
    audit.log(
        event_type=AuditEventType.SCAN_COMPLETE,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="success" if result.success else "failed",
        target=",".join(expanded_targets),
        details={"summary": result.summary, "findings": len(result.all_findings)},
    )
    if notify:
        try:
            from ..notifications import NotificationDispatcher

            dispatcher = NotificationDispatcher()
            status_text = "completed successfully" if result.success else "failed"
            findings_count = len(result.all_findings) if hasattr(result, "all_findings") else 0
            msg = (
                f"🛡️ **Siyarix Scan {status_text}**\n\n"
                f"**Targets:** {', '.join(expanded_targets)}\n"
                f"**Mode:** {mode}\n"
                f"**Findings:** {findings_count}\n"
            )
            run_async(dispatcher.dispatch(msg))
        except Exception as notify_exc:
            logger.debug("Failed to dispatch scan notification: %s", notify_exc)
    return result


@app.command(name="scan-quick", hidden=False)
def scan_quick(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans "
            "(default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Quick scan preset — fast port discovery (top 100 ports, no service detection).

    Supports ``@targets.txt`` and ``--parallel`` for multi-host campaigns.
    """
    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(config.get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))
    _execute_scan_core(
        targets,
        tool="nmap",
        mode=mode or "registry",
        output="table",
        timeout=120,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
        nmap_args="--top-ports 100",
        parallel=parallel_workers,
    )


@app.command(name="scan-full", hidden=False)
def scan_full(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    _parallel: int | None = typer.Option(
        None,
        "--parallel",
        "-p",
        help=(
            "Max concurrent workers for multi-target scans "
            "(default from settings default_parallel / SIYARIX_PARALLEL)"
        ),
        min=1,
        max=32,
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Full scan preset — all ports, service + OS detection, default scripts.

    Supports ``@targets.txt`` and ``--parallel`` for multi-host campaigns.
    """
    parallel_workers = _parallel
    if parallel_workers is None:
        try:
            parallel_workers = int(config.get("default_parallel") or 3)
        except (TypeError, ValueError):
            parallel_workers = 3
    parallel_workers = max(1, min(int(parallel_workers), 32))
    _execute_scan_core(
        targets,
        tool="nmap",
        mode=mode or "registry",
        output="table",
        timeout=600,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
        nmap_args="-p- -sV -O -sC",
        parallel=parallel_workers,
    )


@app.command(name="scan-deep", hidden=False)
def scan_deep(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or @file.txt"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to offline store"),
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """Deep scan preset — multi-pass OS detection, service fingerprinting, and vulnerability scanning.

    Runs 4 progressive passes: discovery → fingerprint → vulnerability → enumeration.
    """
    expanded_targets: list[str] = []
    for t in targets:
        if t.startswith("@"):
            target_file = Path(t[1:])
            if target_file.exists():
                lines = [
                    line.strip()
                    for line in target_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                expanded_targets.extend(lines)
                console.print(f"[dim]Loaded {len(lines)} targets from {target_file}[/dim]")
            else:
                console.print(f"[red]Target file not found: {target_file}[/red]")
                raise typer.Exit(3)
        else:
            expanded_targets.append(t)

    for target in expanded_targets:
        console.print(f"\n[bold cyan]Starting deep scan of {target}...[/bold cyan]")
        _execute_deep_scan(target, output=output, save=save)


@app.command(name="scan-web", hidden=False)
def scan_web(
    targets: list[str] = typer.Argument(..., help="Target URLs or domains"),
    mode: str = typer.Option(None, "--mode", "-m", help="Execution mode"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
) -> None:
    """Web scan preset — HTTP service enumeration (whatweb, nikto, nuclei)."""
    tool = "whatweb+nikto+nuclei"
    updated_targets = [f"http://{t}" if "://" not in t else t for t in targets]
    _execute_scan_core(
        updated_targets,
        tool=tool,
        mode=mode or "registry",
        output="table",
        timeout=300,
        save=False,
        dry_run=dry_run,
        no_banner=True,
        profile="",
    )


@app.command()
def discover(
    target: str = typer.Argument(help="Target network or host"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep discovery (OS, services, vulns)"),
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

    if deep:
        engine = _make_deep_scan_engine()
        result = run_async(engine.scan(target, persist=True))

        if export:
            import json

            Path(export).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            console.print(f"[dim]Deep scan results exported to {export}[/dim]")

        severity_counts = result.get("severity_summary", {})
        console.print(f"\n[bold cyan]Deep discovery complete for {target}[/bold cyan]")
        console.print(f"  Total findings: {result.get('total_findings', 0)}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count:
                console.print(f"    {sev}: {count}")
        return

    instruction = f"scan and discover all services on {target}"
    scan_engine = _get_engine("integrated")
    result = run_async(scan_engine.execute(instruction, interactive=True))

    if export and result.all_findings:
        import json

        Path(export).write_text(json.dumps(result.all_findings, indent=2), encoding="utf-8")
        console.print(f"[dim]Findings exported to {export}[/dim]")


@app.command()
def run(
    ctx: typer.Context,
    command: str | None = typer.Argument(
        None, help="Natural language command or tool name (optional with --resume)"
    ),
    target: str = typer.Option("", "--target", "-t", help="Target for the command"),
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Execution mode: autonomous|integrated|offline|registry",
    ),
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

    mode_val: Any = mode
    if mode_val is None:
        parent_params = ctx.parent.params if ctx.parent else {}
        mode = str(parent_params.get("mode", "integrated"))

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
        resume_result = run_async(engine.resume(resolved_id, interactive=True))
        if resume_result is not None and not getattr(resume_result, "success", True):
            raise typer.Exit(1)
        return

    if not command:
        console.print(
            "[red]Missing command. Pass an instruction, or use --resume <id|latest>.[/red]"
        )
        raise typer.Exit(2)

    instruction = command
    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)
        instruction += f" on {target}"

    route = intent_router.route(instruction)
    route.mode = mode if mode != "integrated" else route.mode
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

        pipe_res = run_async(pipeline.execute(steps, step_executor))
        result = PipelineExecutionResult(
            success=pipe_res.success, all_findings=pipe_res.all_findings
        )
        if save and result.all_findings:
            try:
                from ..offline_store import OfflineStore

                store = OfflineStore()
                store.save_scan(instruction, result.all_findings, mode=route.mode)
            except Exception:
                logger.warning("Failed to persist scan results", exc_info=True)
    else:
        engine = _get_engine(route.mode)
        result = run_async(
            engine.execute(instruction, interactive=True, dry_run=dry_run, persist=save)
        )

    # Display results
    if result.success:
        if result.all_findings:
            _display_findings_table(result.all_findings)
        else:
            console.print("\n[green]Execution completed successfully.[/green]")
    else:
        error_msg = (
            getattr(result, "error_message", "Unknown error")
            if hasattr(result, "error_message")
            else "Unknown error"
        )
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
    if not result.success:
        raise typer.Exit(1)


@app.command()
def agent(
    goal: str = typer.Argument(help="The goal for the autonomous agent to achieve"),
    target: str = typer.Option("", "--target", "-t", help="Target host/IP/URL"),
    max_iterations: int = typer.Option(10, "--max-iter", "-n", help="Maximum agent iterations"),
    mode: str = typer.Option("autonomous", "--mode", "-m", help="Execution mode"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable stealth mode"),
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

    from ..core import AgentCore, AgentGoal, AgentMode

    mode_map = {
        "offline": AgentMode.REGISTRY,
        "autonomous": AgentMode.AUTONOMOUS,
        "integrated": AgentMode.HYBRID,
    }
    agent = AgentCore(mode=mode_map.get(mode, AgentMode.HYBRID))

    settings = SettingsStore()
    if stealth or settings.get("stealth_mode"):
        agent.stealth.enable("medium")

    async def _run_agent() -> None:
        await agent.start()
        try:
            agent_goal = AgentGoal(description=goal, target=target)
            await agent.execute_goal(agent_goal)
        finally:
            await agent.shutdown()

    run_async(_run_agent())


# ---------------------------------------------------------------------------
# Health & Metrics
# ---------------------------------------------------------------------------


@app.command("health")
def health_check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """Run system health checks."""
    status = run_async(get_health().check_all())
    if output == "json":
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
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json|prometheus"),
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
            Path(export).write_text(data, encoding="utf-8")
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
    store = None
    try:
        from ..offline_store import OfflineStore

        store = OfflineStore()
    except ModuleNotFoundError:
        console.print("[yellow]Offline store not available — skipping finding check[/yellow]")

    health = run_async(get_health().check_all())

    if health.state.value == "unhealthy":
        console.print("[red]Health check failed: UNHEALTHY[/red]")
        raise typer.Exit(2)

    if health.state.value == "degraded" and not allow_degraded:
        console.print("[yellow]Health check is DEGRADED (use --allow-degraded to pass).[/yellow]")
        raise typer.Exit(2)

    if store:
        critical = store.search_findings(severity="critical", limit=1)
        if critical:
            console.print("[red]Critical findings detected. Failing gate.[/red]")
            raise typer.Exit(3)

    console.print("[green]✓ CI gate passed[/green]")


@app.command("production-check")
@app.command("doctor")
def production_check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit nonzero when any check is warn/fail"
    ),
) -> None:
    """Production readiness checklist (security gates, offline posture, config).

    Alias: ``siyarix doctor``.
    """
    from .production_check import run_production_check

    run_production_check(output=output, strict=strict, console=console, config=config)


# Audit commands live in ``siyarix.cli.audit_cmds`` (registered above).
# Security sub-commands are defined in security_commands.py.


# ---------------------------------------------------------------------------
# Tool registry commands (real implementation)
# ---------------------------------------------------------------------------
@tool_registry_app.command("list")
def tool_registry_list(
    category: str = typer.Option("", "--category", "-c", help="Filter by category"),
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Force re-discovery"),
    _fast: bool = typer.Option(False, "--fast", help="Skip version probes for speed"),
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
        console.print("[yellow]No tools found. Install security tools and run again.[/yellow]")
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
    output_path: str = typer.Argument(..., help="Path to save the tool metadata JSON"),
) -> None:
    """Regenerate the tool metadata file by scanning all binaries on PATH."""
    reg = make_tool_registry()
    count = reg.update_metadata(Path(output_path))
    console.print(f"[green]Successfully updated metadata: {count} tools recorded.[/green]")


# ---------------------------------------------------------------------------
# Auth commands — wire API keys to the engine
# ---------------------------------------------------------------------------
@auth_app.command("set-key")
def auth_set_key(
    provider: str = typer.Argument(help="Provider: openai | gemini | anthropic | custom"),
    api_key: str = typer.Option(..., "--key", "-k", help="API key value", hide_input=True),
) -> None:
    """Store an API key for a model provider.

    Examples:
      siyarix auth set-key openai --key sk-...
      siyarix auth set-key gemini --key AIz...
      siyarix auth set-key anthropic --key sk-ant-...
    """
    _store_key(provider, api_key)
    console.print(f"[green]✓ API key stored for provider: {provider}[/green]")
    console.print("[dim]Key is stored in the encrypted CredentialStore.[/dim]")


@auth_app.command("show")
def auth_show() -> None:
    """Show configured API key providers."""
    try:
        from siyarix.providers import ProviderManager

        pm = ProviderManager.get_instance()
        providers = pm.list_providers()
    except Exception:
        providers = ["openai", "gemini", "anthropic", "groq", "openrouter"]

    table = Table(title="Configured API Keys", show_header=True, header_style="bold green")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source")

    for prov in providers:
        from siyarix.providers import get_provider_env_var

        env_key = get_provider_env_var(prov)
        from_env = bool(os.getenv(env_key))
        cs = _get_creds()
        from_creds = bool(cs.retrieve(prov, "api_key")) if cs else False
        if from_env:
            status, source = "✓ Set", "Environment variable"
        elif from_creds:
            status, source = "✓ Set", "CredentialStore"
        else:
            status, source = "✗ Not set", "—"
        table.add_row(prov, status, source)

    console.print(table)


# ---------------------------------------------------------------------------
# Shell completions
# ---------------------------------------------------------------------------
@completions_app.command("install")
def completions_install(
    shell: str = typer.Argument(default="", help="Shell: bash | zsh | fish | powershell"),
) -> None:
    """Install shell completions for Siyarix.

    Examples:
      siyarix completions install bash
      siyarix completions install powershell
    """
    if not shell:
        shell = os.getenv("SHELL", "")
        if shell:
            shell = os.path.basename(shell).lower()
        elif platform.system().lower() == "windows":
            # Detect PowerShell Core first, then Windows PowerShell, then cmd
            if shutil.which("pwsh"):
                shell = "powershell"
            elif shutil.which("powershell"):
                shell = "powershell"
            else:
                shell = "powershell"  # best default on Windows
        else:
            # Unix fallback: detect from PATH
            for sh in ("pwsh", "bash", "zsh", "fish", "sh"):
                if shutil.which(sh):
                    shell = sh
                    break
            shell = shell or "bash"

    shell = shell.lower()
    comp_dir = get_config_dir() / "completions"
    comp_dir.mkdir(parents=True, exist_ok=True)

    completions_map = {
        "bash": (
            Path("~/.bashrc").expanduser(),
            comp_dir / "siyarix.bash",
            f"source {comp_dir / 'siyarix.bash'}",
        ),
        "zsh": (
            Path("~/.zshrc").expanduser(),
            comp_dir / "siyarix.zsh",
            f"source {comp_dir / 'siyarix.zsh'}",
        ),
        "fish": (
            Path("~/.config/fish/config.fish").expanduser(),
            Path("~/.config/fish/completions/siyarix.fish").expanduser(),
            f"source {comp_dir / 'siyarix.fish'}",
        ),
        "powershell": (
            Path.home() / ".config" / "powershell" / "profile.ps1",
            comp_dir / "siyarix.powershell",
            "$env:_SIYARIX_COMPLETE='source_powershell'; siyarix | Out-String | Invoke-Expression",
        ),
        "pwsh": (
            Path.home() / ".config" / "powershell" / "profile.ps1",
            comp_dir / "siyarix.powershell",
            "$env:_SIYARIX_COMPLETE='source_powershell'; siyarix | Out-String | Invoke-Expression",
        ),
    }

    if shell not in completions_map:
        console.print(f"[red]Unsupported shell: {shell}. Choose: bash, zsh, fish, powershell[/red]")
        raise typer.Exit(1)

    rc_file, comp_file, source_line = completions_map[shell]

    # Generate static completion file using Click's real completion classes
    try:
        _generate_completion(shell, comp_file)
        console.print(f"[green]\u2713 Completion script generated: {comp_file}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Could not generate completions: {exc}[/yellow]")
        console.print("[dim]Fallback: adding eval line (runs Python on terminal open)[/dim]")
        source_line = f'eval "$(_SIYARIX_COMPLETE=source_{shell} siyarix)"'

    # Add source line to rc file
    if rc_file.exists():
        text = rc_file.read_text(encoding="utf-8")
        # Clean up old eval lines
        import re as _re

        cleaned = _re.sub(r"\n# Siyarix completions\n.*?\n", "", text)
        if source_line not in cleaned:
            rc_file.write_text(f"{cleaned}\n# Siyarix completions\n{source_line}\n")
            console.print(f"[green]\u2713 Source line added to {rc_file}[/green]")
        else:
            console.print(f"[dim]Completions already configured in {rc_file}[/dim]")
    else:
        rc_file.parent.mkdir(parents=True, exist_ok=True)
        rc_file.write_text(f"# Siyarix completions\n{source_line}\n")
        console.print(f"[green]\u2713 Created {rc_file}[/green]")

    console.print(f"[dim]Restart your shell or run: source {rc_file}[/dim]")


# ---------------------------------------------------------------------------
# Config commands — professional configuration suite
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Report command
# ---------------------------------------------------------------------------
@app.command("report")
def generate_report(
    output: str = typer.Option(None, "--output", "-o", help="Output path for the report"),
    fmt: str = typer.Option("html", "--format", "-f", help="Format: html|markdown|json|sarif"),
) -> None:
    """Generate a security assessment report from the knowledge graph."""
    from ..core import AgentCore, AgentMode

    try:
        from ..report import ReportEngine, ReportFormat
    except ImportError:
        console.print("[red]Report engine not available in this build.[/red]")
        raise typer.Exit(1)

    core = AgentCore(mode=AgentMode.REGISTRY)

    async def _run() -> None:
        await core.start()
        try:
            engine = ReportEngine()
            report = engine.build_report_from_kg(core._knowledge_graph)
            fmt_map = {
                "html": ReportFormat.HTML,
                "markdown": ReportFormat.MARKDOWN,
                "json": ReportFormat.JSON,
                "sarif": ReportFormat.SARIF,
            }
            out_path = engine.save(
                report, Path(output or "siyarix_report"), fmt_map.get(fmt, ReportFormat.HTML)
            )
            console.print(f"[bold green]Report generated successfully:[/bold green] {out_path}")
        finally:
            await core.shutdown()

    import asyncio

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Compliance commands
# ---------------------------------------------------------------------------
compliance_app = typer.Typer(help="Compliance evidence collection and assessment.")
app.add_typer(compliance_app, name="compliance")


@compliance_app.command("run")
def compliance_run(
    framework: str = typer.Argument(..., help="Compliance framework (e.g., SOC2, NIST, GDPR)"),
    target: str = typer.Argument(..., help="Target to assess"),
) -> None:
    """Run a compliance assessment."""
    import asyncio

    from siyarix.compliance import ComplianceEngine

    engine = ComplianceEngine()

    async def _run() -> None:
        console.print(
            f"[cyan]Starting {framework} compliance mapping for {target}...[/cyan]\n"
            "[yellow]Note: checks are a control-mapping scaffold. "
            "NOT_EVALUATED means insufficient automated evidence — not a pass.[/yellow]"
        )
        try:
            report = await engine.run_assessment(framework, target)
            table = Table(
                title=f"Compliance Assessment: {framework.upper()} ({target})",
                header_style="bold cyan",
            )
            table.add_column("Control ID", style="cyan", no_wrap=True)
            table.add_column("Status", justify="center")
            table.add_column("Details", style="white")
            for res in report.results:
                status_color = (
                    "green" if res.status == "PASS" else "red" if res.status == "FAIL" else "yellow"
                )
                table.add_row(
                    res.check_id,
                    f"[{status_color}]{res.status}[/{status_color}]",
                    res.message,
                )
            console.print(table)
            summary = report.summary()
            uneval = summary.get("NOT_EVALUATED", 0)
            fails = summary.get("FAIL", 0)
            console.print(
                f"[cyan]Evidence written to {report.evidence_path}[/cyan]\n"
                f"[dim]summary: PASS={summary.get('PASS', 0)} "
                f"FAIL={fails} NOT_EVALUATED={uneval}[/dim]"
            )
            if fails:
                console.print("[red]One or more local probes FAILED.[/red]")
                raise typer.Exit(2)
            if uneval:
                console.print(
                    "[yellow]Assessment incomplete: NOT_EVALUATED controls remain "
                    "(scaffold — not an attestation).[/yellow]"
                )
                raise typer.Exit(3)
            console.print("[green]All evaluated local probes passed.[/green]")
        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]Assessment failed: {e}[/red]")
            raise typer.Exit(1)

    asyncio.run(_run())


@compliance_app.command("list")
@compliance_app.command("frameworks")
def compliance_list() -> None:
    """List supported compliance frameworks and their controls."""
    from siyarix.compliance import ComplianceEngine, FRAMEWORK_METADATA

    table = Table(title="Supported Compliance Frameworks", header_style="bold cyan")
    table.add_column("Framework", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Governing Body", style="dim")
    table.add_column("Controls / Check IDs", style="green")
    for fw, checks in ComplianceEngine.FRAMEWORKS.items():
        meta = FRAMEWORK_METADATA.get(fw, {})
        table.add_row(
            fw,
            meta.get("name", fw),
            meta.get("governing_body", "—"),
            ", ".join(checks),
        )
    console.print(table)


@compliance_app.command("reports")
def compliance_reports() -> None:
    """List previously generated compliance assessment reports."""
    from siyarix.compliance import ComplianceEngine

    engine = ComplianceEngine()
    reports = engine.list_reports()
    if not reports:
        console.print("[dim]No compliance reports found.[/dim]")
        return

    table = Table(title="Compliance Evidence Reports", header_style="bold cyan")
    table.add_column("Framework", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Checks", justify="right")
    table.add_column("Evidence Path", style="dim")
    for r in reports:
        table.add_row(
            r["framework"],
            r["target"],
            str(r["checks_count"]),
            r["evidence_path"],
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Playbook commands
# ---------------------------------------------------------------------------
playbook_app = typer.Typer(help="Manage and run YAML playbooks.")
app.add_typer(playbook_app, name="playbook")


def _builtin_playbook_dir() -> Path:
    """Directory of playbooks shipped inside the installed package."""
    return Path(__file__).resolve().parents[1] / "data" / "playbooks"


def _resolve_playbook_path(path: str, dir_path: str | None = None) -> Path | None:
    """Resolve a playbook from an explicit path, cwd, or built-in package data."""
    candidate = Path(path)
    if candidate.exists():
        return candidate
    search_roots = []
    if dir_path:
        search_roots.append(Path(dir_path))
    search_roots.extend([Path("playbooks"), _builtin_playbook_dir()])
    names = [path, f"{path}.yaml", f"{path}.yml"]
    for root in search_roots:
        for name in names:
            hit = root / name
            if hit.exists():
                return hit
    return None


def _iter_playbook_files(dir_path: str | None = None) -> list[Path]:
    """List playbooks from an explicit dir, else cwd + built-in package data."""
    roots: list[Path] = []
    if dir_path and dir_path != "playbooks":
        roots.append(Path(dir_path))
    else:
        roots.extend([Path("playbooks"), _builtin_playbook_dir()])
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in ("*.yaml", "*.yml"):
            for f in sorted(root.glob(pattern)):
                if f.name not in seen:
                    files.append(f)
                    seen.add(f.name)
    return files


@playbook_app.command("run")
def playbook_run(
    path: str = typer.Argument(..., help="Path to playbook YAML file"),
    var: list[str] = typer.Option([], "--var", help="Variables in key=value format"),
) -> None:
    """Run a YAML playbook."""
    import asyncio

    from siyarix.core import AgentCore
    from siyarix.playbook import PlaybookEngine
    from siyarix.workflow import WorkflowEngine

    variables = {}
    for v in var:
        if "=" in v:
            k, val = v.split("=", 1)
            variables[k] = val

    p = _resolve_playbook_path(path)
    if p is None:
        console.print(f"[red]Playbook '{path}' not found (checked cwd and built-in package).[/red]")
        raise typer.Exit(1)

    engine = PlaybookEngine(WorkflowEngine())
    core = AgentCore()

    async def _run() -> None:
        await core.start()
        try:
            await engine.execute(p, variables, executor=core)
        finally:
            await core.shutdown()

    asyncio.run(_run())


@playbook_app.command("list")
def playbook_list(
    dir_path: str = typer.Option(
        "playbooks",
        "--dir",
        "-d",
        help="Directory containing playbooks (also searches built-in package data)",
    ),
) -> None:
    """List available playbooks."""
    files = _iter_playbook_files(dir_path)
    if not files:
        if dir_path and dir_path != "playbooks" and not Path(dir_path).is_dir():
            console.print(f"[yellow]Directory '{dir_path}' not found.[/yellow]")
        else:
            console.print(
                f"[yellow]No playbooks found in '{dir_path}' or built-in package data.[/yellow]"
            )
        return

    import yaml

    table = Table(title="Available Playbooks", header_style="bold cyan")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Description", style="dim")
    table.add_column("Steps", justify="right", style="green")
    table.add_column("Source", style="dim")

    builtin = _builtin_playbook_dir()
    for f in files:
        name = f.stem
        desc = "—"
        steps_count = "—"
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                name = data.get("name", f.stem)
                desc = data.get("description", "—")
                steps_count = str(len(data.get("steps", [])))
        except Exception:
            pass
        source = "builtin" if builtin in f.parents or f.parent == builtin else str(f.parent)
        table.add_row(f.name, name, desc[:60], steps_count, source)

    console.print(table)


@playbook_app.command("show")
@playbook_app.command("info")
def playbook_show(
    name: str = typer.Argument(..., help="Playbook name or path to YAML file"),
    dir_path: str = typer.Option("playbooks", "--dir", "-d", help="Directory containing playbooks"),
) -> None:
    """Show detailed structure and execution DAG of a playbook."""
    import yaml

    p = _resolve_playbook_path(name, dir_path)
    if p is None or not p.is_file():
        console.print(f"[red]Playbook '{name}' not found.[/red]")
        raise typer.Exit(1)

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Playbook must be a YAML dictionary")
    except Exception as exc:
        console.print(f"[red]Failed to load playbook: {exc}[/red]")
        raise typer.Exit(1)

    title = data.get("name", p.stem)
    desc = data.get("description", "No description provided.")
    vars_dict = data.get("vars", {})
    vars_summary = ", ".join(f"{k}={v}" for k, v in vars_dict.items()) if vars_dict else "None"

    panel_text = (
        f"[bold cyan]Name:[/bold cyan]        {title}\n"
        f"[bold]File:[/bold]        {p}\n"
        f"[bold]Description:[/bold] {desc}\n"
        f"[bold]Variables:[/bold]   {vars_summary}"
    )
    console.print(
        Panel.fit(panel_text, title="[bold cyan]Playbook Info[/bold cyan]", border_style="cyan")
    )

    steps = data.get("steps", [])
    if steps:
        step_table = Table(title="Execution Steps (DAG)", header_style="bold cyan")
        step_table.add_column("Step ID", style="cyan", no_wrap=True)
        step_table.add_column("Type", style="yellow")
        step_table.add_column("Tool / Role", style="white")
        step_table.add_column("Depends On", style="dim")
        step_table.add_column("Description", style="white")
        step_table.add_column("Timeout (s)", justify="right", style="green")

        for s in steps:
            s_type = s.get("type", "tool")
            tool_role = s.get("role") if s_type == "agent" else s.get("tool", "—")
            deps = ", ".join(s.get("depends_on", [])) or "—"
            step_table.add_row(
                str(s.get("id", "—")),
                str(s_type),
                str(tool_role),
                deps,
                str(s.get("description", "—"))[:50],
                str(s.get("timeout", 60.0)),
            )
        console.print(step_table)


@playbook_app.command("validate")
def playbook_validate(
    path: str = typer.Argument(..., help="Path to playbook YAML file"),
) -> None:
    """Validate a YAML playbook."""
    from siyarix.playbook import PlaybookEngine
    from siyarix.workflow import WorkflowEngine

    p = _resolve_playbook_path(path)
    if p is None:
        console.print(f"[red]Playbook '{path}' not found.[/red]")
        raise typer.Exit(1)

    engine = PlaybookEngine(WorkflowEngine())
    try:
        engine.load(p)
        console.print(f"[green]Playbook '{p}' is valid.[/green]")
    except Exception as e:
        console.print(f"[red]Playbook validation failed: {e}[/red]")
        raise typer.Exit(1)


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
