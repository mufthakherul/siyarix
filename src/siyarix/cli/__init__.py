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
import logging
import os
from typing import Any

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
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .. import __version__
from ..async_utils import run_async
from ..branding import resolve_theme, severity_label
from ..chat import start_chat
from ..compat import ExecutionEngine, ExecutionMode, SessionKernel
from ..config import SettingsStore, get_config_dir
from ..core.router import IntentRouter
from ..logging_config import configure_logging
from ..registry_factory import make_tool_registry
from ..security_commands import security_app
from .credentials import resolve_key
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

intent_router = IntentRouter()
session_kernel = SessionKernel()


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


def _get_engine(mode: str = "integrated") -> ExecutionEngine:
    """Build an ExecutionEngine with API keys from config/credentials."""
    engine_config: dict = {}
    if os.getenv("SIYARIX_FAST_DISCOVERY", "0") == "1":
        engine_config["fast_discovery"] = True
    openai_key = resolve_key("openai")
    gemini_key = resolve_key("gemini")
    anthropic_key = resolve_key("anthropic")
    groq_key = resolve_key("groq")
    together_key = resolve_key("together")
    openrouter_key = resolve_key("openrouter")
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


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_theme: str = config.get("color_theme") or "default"

# ---------------------------------------------------------------------------
# Sub-command groups & extracted command modules (ARCH-01 / ENG-01)
# ---------------------------------------------------------------------------
app.add_typer(security_app, name="security")

from .auth_cmds import auth_app  # noqa: E402
from .audit_cmds import audit_app  # noqa: E402
from .cache_cmds import cache_app  # noqa: E402
from .completions_cmds import (  # noqa: E402
    _generate_completion as _generate_completion,  # re-exported for onboarding
    register_completions,
)
from .config_cmds import config_app  # noqa: E402
from .profile_cmds import register_profile_commands  # noqa: E402
from .registry_cmds import bind_registry, tool_registry_app  # noqa: E402
from .theme_cmds import bind_theme_sync, theme_app  # noqa: E402
from .tools_cmds import tools_app  # noqa: E402

app.add_typer(auth_app, name="auth")
register_profile_commands(app)
app.add_typer(audit_app, name="audit")
app.add_typer(config_app, name="config")
register_completions(app)


def _sync_active_theme(name: str) -> None:
    global _active_theme
    _active_theme = name


bind_theme_sync(_sync_active_theme)
app.add_typer(theme_app, name="theme")
app.add_typer(cache_app, name="cache")
bind_registry(registry)
app.add_typer(tool_registry_app, name="tool-registry")
app.add_typer(tools_app, name="tools")
app.add_typer(tools_app, name="tool")
app.add_typer(plugins_app, name="plugins")
app.add_typer(plugins_app, name="plugin")

# Scan commands live in ``siyarix.cli.scan_cmds`` (ARCH-01).
from .scan_cmds import register_scan_commands  # noqa: E402

register_scan_commands(
    app,
    console=console,
    config=config,
    get_engine=_get_engine,
    display_findings_table=_display_findings_table,
    execute_deep_scan_fn=_execute_deep_scan,
    ci_mode=bool(_CI_MODE),
    active_theme=_active_theme,
)

from .agent_cmds import register_agent_commands  # noqa: E402

register_agent_commands(
    app,
    console=console,
    get_engine=_get_engine,
    make_deep_scan_engine=_make_deep_scan_engine,
    display_findings_table=_display_findings_table,
    intent_router=intent_router,
    session_kernel=session_kernel,
    ci_mode=bool(_CI_MODE),
    active_theme=_active_theme,
)

from .ops_cmds import register_ops_commands  # noqa: E402

register_ops_commands(app, console=console, config=config)


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

    asyncio.run(_run())


# Compliance + playbook commands live in dedicated modules (ARCH-01).
from .compliance_cmds import compliance_app  # noqa: E402
from .playbook_cmds import playbook_app  # noqa: E402

app.add_typer(compliance_app, name="compliance")
app.add_typer(playbook_app, name="playbook")


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
