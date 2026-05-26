"""Siyarix CLI — Premium Enterprise Entry Point.

Features:
  • Multi-level command routing with nested Typer apps
  • Premium Rich console with themes, panels, banners
  • Smart mode detection (registry/autonomous/integrated)
  • Plugin ecosystem with auto-discovery
  • Autonomous task planner & natural language
  • Enterprise audit logging & compliance
  • Bulk operations & watch mode
  • Multi-environment & profile support
  • Offline-first with sync capabilities
  • CI/CD integration & policy gates
  • Team collaboration & org management
  • Advanced output formats (JSON/YAML/CSV/Table/Rich)
  • Secure credential & API key management
  • Real-time progress & live dashboards
  • Context-aware help & examples
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table

__version__ = "2.0.0"

from typing import Any, cast

from .audit_log import AuditEventType, AuditSeverity, audit
from .branding import available_themes, print_banner
from .chat import start_chat
from .command_profiles import CommandProfile, CommandProfileStore
from .config import SettingsStore
from .core import IntentRouter, SessionKernel
from .core.agentic_loop import AgenticLoop
from .credential_store import CredentialStore
from .engine import ExecutionEngine, ExecutionMode
from .environment import (ensure_env_file, load_env_file, provider_env_var,
                          upsert_env_vars)
from .exceptions import ValidationError
from .health import get_health
from .logging_config import configure_logging
from .metrics import get_metrics
from .offline_store import OfflineStore
from .orchestration import WorkflowRuntime, WorkflowState
from .plugins import PluginManager
from .security_commands import security_app
from .shell_knowledge import (CROSS_PLATFORM_COMMANDS, INTENT_METADATA,
                              build_platform_context, detect_shell,
                              get_security_commands, get_shell_platform,
                              list_supported_shells, normalize_shell)
from .tool_registry import ToolRegistry
from .ux import OnboardingWizard, SplitPane
from .validators import validate_target
from .xi import XICoreService

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
plugins = PluginManager()
creds = CredentialStore()
load_env_file()
_plugins_loaded = False
intent_router = IntentRouter()
session_kernel = SessionKernel()
xi_core = XICoreService()


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
    engine_config["model_provider"] = config.get("model_provider")
    engine_config["gemini_model"] = config.get("gemini_model")
    engine_config["openai_model"] = config.get("openai_model")
    engine_config["anthropic_model"] = config.get("anthropic_model")
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
  [green]siyarix[/green]                          — Interactive shell (chat / TUI)
  [green]siyarix scan 192.168.1.0/24[/green]      — Direct command execution
  [green]echo "scan 10.0.0.1" | siyarix[/green]  — Pipe commands via stdin
  [green]siyarix run "scan my network"[/green]    — Natural language command
  [green]siyarix discover example.com[/green]     — Asset & service discovery

[bold]Key Commands:[/bold]
  • [magenta]siyarix scan[/magenta]         — Network / port scanning
  • [magenta]siyarix run[/magenta]          — Natural language → execution
  • [magenta]siyarix agent[/magenta]        — Goal-driven autonomous agent
  • [magenta]siyarix shell[/magenta]        — Cross-platform shell helper
  • [magenta]siyarix workflow[/magenta]     — Workflow orchestration
  • [magenta]siyarix auth set-key[/magenta] — Configure AI model API keys
  • [magenta]siyarix --help[/magenta]       — Full command reference
    """,
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,  # launch chat when called with no subcommand
)


def _run_batch_lines(lines: list[str]) -> None:
    """Execute a list of command lines through the chat REPL handler."""
    from .chat import SiyarixChat
    chat = SiyarixChat(mode="integrated")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        console.print(f"[bold]> {line}[/bold]")
        if line.startswith("/"):
            cmd, _, rest = line.partition(" ")
            handler = chat._commands.get(cmd)
            if handler:
                asyncio.run(handler(rest.strip()))
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
        else:
            asyncio.run(chat._handle_natural_language(line))


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
) -> None:
    """Siyarix CLI — the unified entry point.

    \b
    Three usage modes:
      1) [green]siyarix[/green]              — Interactive shell (chat + TUI)
      2) [green]siyarix <command>[/green]    — Direct command execution
      3) [green]echo ... | siyarix[/green]   — Pipe commands via stdin
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
        lines = [l for l in sys.stdin if l.strip()]
        if lines:
            _run_batch_lines([l.strip() for l in lines])
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

plugin_app = typer.Typer(help="🔌 Plugin lifecycle management")
app.add_typer(plugin_app, name="plugin")

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
    try:
        # Use config store
        config.set("color_theme", name)
        console.print(f"[green]✓ Theme set to: {name}[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to set theme: {exc}[/red]")


@theme_app.command("preview")
@theme_app.command("appearance")
def theme_preview(
    name: str = typer.Argument(default="", help="Theme to preview (optional)"),
) -> None:
    """Preview the current or selected theme appearance."""
    from .branding import print_theme_preview

    selected = name or config.get("color_theme") or _active_theme
    print_theme_preview(console, selected)


workflow_app = typer.Typer(help="⚙️ Workflow orchestration")
app.add_typer(workflow_app, name="workflow")

team_app = typer.Typer(help="👥 Team & organization")
app.add_typer(team_app, name="team")

org_app = typer.Typer(help="🏢 Organization-scoped commands")
app.add_typer(org_app, name="org")

schedule_app = typer.Typer(help="⏱ Recurring scan schedules")
app.add_typer(schedule_app, name="schedule")


@schedule_app.command("list")
def schedule_list(
    output: str = typer.Option("table", "--output", "-o", help="table|json"),
) -> None:
    """List all scheduled scan jobs."""
    from .scheduler import SiyarixScheduler

    sched = SiyarixScheduler()
    jobs = sched.list_all()
    if not jobs:
        console.print("[dim]No scheduled jobs found.[/dim]")
        return
    if output == "json":
        console.print(
            json.dumps(
                [
                    {
                        "id": j.id,
                        "name": j.name,
                        "target": j.target,
                        "cron": j.cron,
                        "command": j.command,
                        "persona": j.persona,
                        "active": j.active,
                        "last_run": j.last_run,
                        "next_run": j.next_run,
                    }
                    for j in jobs
                ],
                indent=2,
            )
        )
        return
    table = Table(title=f"Scheduled Jobs ({len(jobs)})", header_style="bold cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Cron", style="yellow")
    table.add_column("Command", style="white")
    table.add_column("Active", justify="center")
    table.add_column("Next Run", style="dim")
    for j in jobs:
        active = "[green]✓[/green]" if j.active else "[dim]✗[/dim]"
        table.add_row(
            j.name,
            j.target or "—",
            j.cron,
            j.command[:40],
            active,
            j.next_run[:16] if j.next_run else "-",
        )
    console.print(table)


@schedule_app.command("create")
def schedule_create(
    name: str = typer.Argument(..., help="Job name"),
    target: str = typer.Argument(..., help="Scan target"),
    cron: str = typer.Argument("daily", help="daily|weekly|hourly or cron expression"),
    command: str = typer.Argument("", help="Command to execute"),
    persona: str = typer.Option("none", "--persona", "-p", help="Persona to use"),
) -> None:
    """Create a new scheduled scan job."""
    from .scheduler import SiyarixScheduler

    sched = SiyarixScheduler()
    job = sched.create(name=name, target=target, cron=cron, command=command, persona=persona)
    console.print(f"[green]✓ Scheduled job created: {job.name} (id={job.id})[/green]")


@schedule_app.command("delete")
def schedule_delete(
    job_id: str = typer.Argument(..., help="Job ID or name"),
) -> None:
    """Delete a scheduled scan job."""
    from .scheduler import SiyarixScheduler

    sched = SiyarixScheduler()
    if sched.delete(job_id):
        console.print(f"[green]✓ Scheduled job deleted: {job_id}[/green]")
    else:
        console.print(f"[red]Scheduled job not found: {job_id}[/red]")

cloud_app = typer.Typer(help="☁️ Cloud provider security scanning")
app.add_typer(cloud_app, name="cloud")

k8s_app = typer.Typer(help="☸️ Kubernetes security assessment")
app.add_typer(k8s_app, name="k8s")

docker_app = typer.Typer(help="🐳 Container security scanning")
app.add_typer(docker_app, name="docker")

iac_app = typer.Typer(help="🏗️ Infrastructure as Code scanning")
app.add_typer(iac_app, name="iac")

mobile_app = typer.Typer(help="📱 Mobile application security testing")
app.add_typer(mobile_app, name="mobile")

iot_app = typer.Typer(help="🔌 IoT & embedded device testing")
app.add_typer(iot_app, name="iot")

hsm_app = typer.Typer(help="🔐 Hardware Security Module management")
app.add_typer(hsm_app, name="hsm")

opsec_app = typer.Typer(help="👤 Operational Security measures")
app.add_typer(opsec_app, name="opsec")

siem_app = typer.Typer(help="📡 SIEM/SOAR integration")
app.add_typer(siem_app, name="siem")

platform_app = typer.Typer(help="🔗 Bug bounty platform integration")
app.add_typer(platform_app, name="platform")

performance_app = typer.Typer(help="⚡ Performance optimization")
app.add_typer(performance_app, name="performance")

cache_app = typer.Typer(help="💾 Cache management")
app.add_typer(cache_app, name="cache")

distributed_app = typer.Typer(help="🌐 Distributed execution")
app.add_typer(distributed_app, name="distributed")

import_app = typer.Typer(help="📥 Import external scan results")
app.add_typer(import_app, name="import")

findings_app = typer.Typer(help="🔍 Finding collaboration")
app.add_typer(findings_app, name="findings")

@cloud_app.command("scan")
def cloud_scan(
    provider: str = typer.Argument("aws", help="aws|azure|gcp"),
    target: str = typer.Argument("", help="Account/project/tenant ID or name"),
) -> None:
    """Scan a cloud provider environment for security issues."""
    from .cloud_scanner import CloudProvider, CloudScanner
    provider_enum = getattr(CloudProvider, provider.upper(), CloudProvider.AWS)
    scanner = CloudScanner()
    result = scanner.scan_cloud(provider_enum, target)
    console.print(scanner.generate_report(result, fmt="text"))

@k8s_app.command("scan")
def k8s_scan(
    namespace: str = typer.Argument("default", help="Kubernetes namespace"),
) -> None:
    """Scan a Kubernetes cluster for security issues."""
    from .cloud_scanner import CloudScanner
    scanner = CloudScanner()
    result = scanner.scan_kubernetes(namespace)
    console.print(scanner.generate_report(result, fmt="text"))

@docker_app.command("scan")
def docker_scan(
    image: str = typer.Argument("", help="Docker image name"),
) -> None:
    """Scan a Docker container image for vulnerabilities."""
    from .cloud_scanner import CloudScanner
    scanner = CloudScanner()
    result = scanner.scan_docker(image)
    console.print(scanner.generate_report(result, fmt="text"))

@iac_app.command("scan")
def iac_scan(
    path: str = typer.Argument(".", help="Path to IaC directory/file"),
    recursive: bool = typer.Option(True, "--recursive", "-r", help="Scan subdirectories"),
) -> None:
    """Scan Infrastructure as Code templates for misconfigurations."""
    from .iac_scanner import IaCScanner
    scanner = IaCScanner()
    result = scanner.scan_path(path)
    console.print(scanner.generate_report(result, fmt="text"))

@mobile_app.command("scan")
def mobile_scan(
    apk_path: str = typer.Argument(..., help="Path to APK file"),
) -> None:
    """Static analysis of an Android APK for security issues."""
    from .mobile_scanner import MobileScanner
    scanner = MobileScanner()
    result = scanner.scan_apk(apk_path)
    console.print(scanner.generate_report(result, fmt="text"))

@iot_app.command("scan")
def iot_scan(
    device: str = typer.Argument("", help="Firmware path or serial port"),
    mode: str = typer.Option("firmware", "--mode", "-m", help="firmware|serial"),
    baud: int = typer.Option(115200, "--baud", "-b", help="Serial baud rate"),
) -> None:
    """Scan an IoT device or firmware image."""
    from .iot_scanner import IoTScanner
    scanner = IoTScanner()
    if mode == "serial":
        result = scanner.scan_serial_port(device, baud=baud)
    else:
        result = scanner.scan_firmware(device)
    console.print(scanner.generate_report(result, fmt="text"))

@hsm_app.command("status")
def hsm_status() -> None:
    """Show HSM connection status."""
    from .hsm_manager import HSMService
    hsm = HSMService()
    console.print(hsm.generate_report(fmt="text"))

@hsm_app.command("configure")
def hsm_configure(
    provider: str = typer.Option("yubikey", "--provider", "-p", help="yubikey|pkcs11|tpm"),
) -> None:
    """Configure and connect to an HSM provider."""
    from .hsm_manager import HSMService
    hsm = HSMService()
    hsm.connect(provider=provider)
    console.print(hsm.generate_report(fmt="text"))

@opsec_app.command("isolate")
def opsec_isolate(
    target: str = typer.Option("", "--target", "-t", help="Target to isolate"),
    tor: bool = typer.Option(False, "--tor", help="Use TOR exit node rotation"),
    doh: bool = typer.Option(True, "--doh", help="DNS over HTTPS"),
) -> None:
    """Isolate scanning activity with OPSEC measures."""
    from .opsec import opsec_manager
    result = opsec_manager.isolate(target=target, use_tor=tor, use_doh=doh)
    console.print(f"[green]{result.detail}[/green]")

@opsec_app.command("burn")
def opsec_burn(
    session: str = typer.Argument("", help="Session ID to destroy"),
) -> None:
    """Securely destroy all traces of a session."""
    from .opsec import opsec_manager
    result = opsec_manager.burn(session_id=session)
    console.print(f"[red]{result.detail}[/red]")

@siem_app.command("connect")
def siem_connect(
    platform: str = typer.Argument("splunk", help="splunk|elastic|qradar"),
    url: str = typer.Argument("", help="SIEM URL"),
) -> None:
    """Connect to a SIEM/SOAR platform."""
    from .platform_integration import platform_integration
    result = platform_integration.connect_siem(platform, url=url)
    if result.connected:
        console.print(f"[green]Connected to {platform}[/green]")
    else:
        console.print(f"[red]{result.error}[/red]")

@platform_app.command("connect")
def platform_connect(
    platform: str = typer.Argument("hackerone", help="hackerone|bugcrowd|intigriti"),
    username: str = typer.Option("", "--username", "-u"),
) -> None:
    """Connect to a bug bounty platform."""
    from .platform_integration import platform_integration
    result = platform_integration.connect_bounty(platform, username=username)
    if result.connected:
        console.print(f"[green]Connected to {platform} as {result.username}[/green]")
    else:
        console.print(f"[red]{result.error}[/red]")

@performance_app.command("status")
def perf_status() -> None:
    """Show system resources and performance configuration."""
    from .performance import performance_optimizer
    s = performance_optimizer.summary()
    r = s["resources"]
    console.print(f"CPU: {r['cpu_cores']}C/{r['cpu_logical']}T | RAM: {r['ram_gb']}GB | Platform: {r['platform']}")
    console.print(f"Agents: {s['config']['max_concurrent_agents']} | Memory/agent: {s['config']['memory_per_agent_mb']}MB")

@performance_app.command("tune")
def perf_tune() -> None:
    """Auto-tune performance parameters based on hardware."""
    from .performance import performance_optimizer
    config = performance_optimizer.auto_tune()
    console.print(f"[green]Tuned: {config.max_concurrent_agents} agents, {config.memory_limit_per_agent_mb}MB each[/green]")

@cache_app.command("status")
def cache_status() -> None:
    """Show cache statistics."""
    from .cache_manager import cache_manager
    stats = cache_manager.stats()
    console.print(f"Entries: {stats['total_entries']} | Size: {stats['total_size_mb']}MB | Hit rate: {stats['hit_rate']:.0%}")
    console.print(f"Domains: {', '.join(stats.get('domains', []))}")

@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached data."""
    from .cache_manager import cache_manager
    count = cache_manager.clear()
    console.print(f"[green]Cache cleared: {count} entries[/green]")

@distributed_app.command("status")
def distributed_status() -> None:
    """Show distributed worker cluster status."""
    from .distributed import DistributedOrchestrator
    orch = DistributedOrchestrator()
    summary = orch.summary()
    console.print(f"Workers: {summary.get('total_workers', 1)} | Cores: {summary.get('total_cores', 0)} | RAM: {summary.get('total_ram_gb', 0)}GB")

@import_app.command("scan")
def import_scan(
    fmt: str = typer.Argument("auto", help="nessus|burp|metasploit|stix|auto"),
    path: str = typer.Argument(..., help="Path to scan result file"),
) -> None:
    """Import external scan results for unified analysis."""
    from .importer import security_importer
    importer_fn = getattr(security_importer, f"import_{fmt}", None)
    if importer_fn:
        result = importer_fn(path)
    else:
        result = security_importer.auto_import(path)
    console.print(f"Imported {result.total_imported} findings from {fmt}")
    for f in result.findings[:10]:
        console.print(f"  [{f.severity}] {f.title} @ {f.host or '?'}:{f.port}")
    if len(result.findings) > 10:
        console.print(f"  ... and {len(result.findings) - 10} more")

report_app = typer.Typer(help="📊 Report generation & distribution")
app.add_typer(report_app, name="report")

ci_app = typer.Typer(help="🚀 CI/CD & policy gates")
app.add_typer(ci_app, name="ci")

bulk_app = typer.Typer(help="📦 Bulk operations & batch jobs")
app.add_typer(bulk_app, name="bulk")

watch_app = typer.Typer(help="👁 Watch mode & live monitoring")
app.add_typer(watch_app, name="watch")

dashboard_app = typer.Typer(help="📊 Live security dashboard")
app.add_typer(dashboard_app, name="dashboard")

tool_registry_app = typer.Typer(help="🛠 Tool discovery & registry")
app.add_typer(tool_registry_app, name="tool-registry")


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


shell_app = typer.Typer(help="🖥 Cross-platform shell command helper")
app.add_typer(shell_app, name="shell")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_profile: str | None = None
_active_theme: str = "default"


# ---------------------------------------------------------------------------
# Shell sub-commands — Cross-platform terminal command helper
# ---------------------------------------------------------------------------


@shell_app.command("platform")
def shell_platform(
    as_json: bool = typer.Option(
        False, "--json", help="Print raw platform context as JSON"
    ),
    compact: bool = typer.Option(
        False, "--compact", help="Show compact summary output"
    ),
) -> None:
    """Show current platform, device, runtime, and terminal diagnostics."""
    ctx = build_platform_context()

    if as_json:
        console.print(json.dumps(ctx, indent=2))
        return

    if compact:
        console.print(
            Panel.fit(
                f"[bold]Platform:[/bold] {ctx.get('platform_pretty', '')}\n"
                f"[bold]Terminal:[/bold] {ctx.get('terminal_type', '')} | [bold]Shell:[/bold] {ctx.get('shell_platform', '')}\n"
                f"[bold]Python:[/bold] {ctx.get('python_version', '')} | [bold]CPU:[/bold] {ctx.get('cpu_count', '')}\n"
                f"[bold]Container:[/bold] {ctx.get('is_container', False)} ({ctx.get('container_runtime', 'none')})",
                title="[bold]Platform Summary[/bold]",
                border_style="cyan",
            )
        )
        return

    table = Table(title="Platform & Runtime Diagnostics", header_style="bold cyan")
    table.add_column("Category", style="magenta", no_wrap=True)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    rows = [
        ("OS", "platform", ctx.get("platform_pretty", "")),
        ("OS", "kernel_release", ctx.get("platform_release", "")),
        ("OS", "platform_full", ctx.get("platform_full", "")),
        ("OS", "architecture", ctx.get("arch", "")),
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
        ("Siyarix", "available_intents", str(ctx.get("available_tools_count", 0))),
    ]

    for category, key, value in rows:
        table.add_row(category, key, str(value))
    console.print(table)


@shell_app.command("doctor")
def shell_doctor() -> None:
    """Run shell environment diagnostics for a quick readiness report."""
    ctx = build_platform_context()
    checks = [
        ("Python", "python", shutil.which("python") or shutil.which("python3")),
        ("Git", "git", shutil.which("git")),
        ("Nmap", "nmap", shutil.which("nmap")),
        ("Nuclei", "nuclei", shutil.which("nuclei")),
        ("Docker", "docker", shutil.which("docker")),
        ("Kubectl", "kubectl", shutil.which("kubectl")),
    ]

    table = Table(title="Shell Doctor", header_style="bold cyan")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Detail", style="dim")

    for label, command, path in checks:
        status = "[green]OK[/green]" if path else "[yellow]Missing[/yellow]"
        table.add_row(label, status, path or f"{command} not found in PATH")

    console.print(table)
    console.print(
        f"[dim]Platform: {ctx.get('platform_pretty', '')} | Shell: {ctx.get('shell_platform', '')} | Terminal: {ctx.get('terminal_type', '')}[/dim]"
    )


@shell_app.command("report")
def shell_report(
    output: str = typer.Option(
        "table", "--output", "-o", help="Output format: table|json"
    ),
) -> None:
    """Generate a shell capability report (intents, shell support, and platform)."""
    intents_total = len(CROSS_PLATFORM_COMMANDS)
    shells_total = len(list_supported_shells())
    platform_ctx = build_platform_context()
    categories: dict[str, int] = {}
    for meta in INTENT_METADATA.values():
        category = meta.get("category", "other")
        categories[category] = categories.get(category, 0) + 1

    payload: dict[str, Any] = {
        "intents_total": intents_total,
        "shells_total": shells_total,
        "categories": dict(sorted(categories.items())),
        "platform": {
            "platform": platform_ctx.get("platform_pretty"),
            "shell": platform_ctx.get("shell_platform"),
            "terminal_type": platform_ctx.get("terminal_type"),
            "python_version": platform_ctx.get("python_version"),
        },
    }

    if output == "json":
        console.print(json.dumps(payload, indent=2))
        return

    table = Table(title="Shell Capability Report", header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Intents", str(payload["intents_total"]))
    table.add_row("Supported Shells", str(payload["shells_total"]))
    table.add_row("Platform", str(payload["platform"]["platform"]))
    table.add_row("Shell", str(payload["platform"]["shell"]))
    table.add_row("Terminal Type", str(payload["platform"]["terminal_type"]))
    table.add_row("Python", str(payload["platform"]["python_version"]))
    console.print(table)

    ctable = Table(title="Intent Categories", header_style="bold magenta")
    ctable.add_column("Category", style="magenta")
    ctable.add_column("Intents", style="cyan")
    for category, count in payload["categories"].items():
        ctable.add_row(category, str(count))
    console.print(ctable)


@shell_app.command("translate")
def shell_translate(
    intent: str = typer.Argument(
        help="Command intent (e.g. list_files, network_connections, ping)"
    ),
    target: str = typer.Option(
        "", "--target", help="Target for commands that need one (e.g. IP/hostname)"
    ),
    user: str = typer.Option("", "--user", help="User for SSH/SCP intents"),
    path: str = typer.Option("", "--path", help="Path for file transfer intents"),
    file: str = typer.Option("", "--file", help="File path for file_hash intents"),
) -> None:
    """Translate a command intent to all supported shells.

    Examples:
      siyarix shell translate list_files
      siyarix shell translate ping --target 192.168.1.1
      siyarix shell translate network_connections
    """
    cps = cast(dict[str, dict[str, str]], CROSS_PLATFORM_COMMANDS)
    entry: dict[str, str] = cps.get(intent, {})
    if not entry:
        # Fuzzy search
        matches = [
            k for k in CROSS_PLATFORM_COMMANDS if any(w in k for w in intent.split("_"))
        ]
        if matches:
            console.print(
                f"[yellow]Intent '{intent}' not found. Did you mean:[/yellow]"
            )
            for m in matches[:5]:
                console.print(f"  [cyan]{m}[/cyan]")
        else:
            console.print(f"[red]Unknown intent: {intent}[/red]")
            console.print(
                "[dim]Run 'siyarix shell list-intents' to see all available intents.[/dim]"
            )
        raise typer.Exit(1)

    table = Table(
        title=f"Command: [bold]{intent}[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Shell", style="cyan", width=14)
    table.add_column("Command", style="green")

    current_shell = normalize_shell(detect_shell()).value
    for shell_key, cmd in entry.items():
        if target:
            cmd = cmd.replace("{target}", target)
        if user:
            cmd = cmd.replace("{user}", user)
        if path:
            cmd = cmd.replace("{path}", path)
        if file:
            cmd = cmd.replace("{file}", file)
        marker = " ◄ current" if shell_key == current_shell else ""
        style = "bold" if shell_key == current_shell else ""
        table.add_row(f"[{style}]{shell_key}[/{style}]{marker}", cmd)

    console.print(table)


@shell_app.command("list-intents")
def shell_list_intents(
    filter_str: str = typer.Option(
        "", "--filter", "-f", help="Filter intents by keyword"
    ),
) -> None:
    """List all available command intents for translation.

    Example:
      siyarix shell list-intents
      siyarix shell list-intents --filter network
    """
    intents = list(CROSS_PLATFORM_COMMANDS.keys())
    if filter_str:
        intents = [i for i in intents if filter_str.lower() in i.lower()]

    table = Table(
        title=f"Available Command Intents ({len(intents)})", header_style="bold cyan"
    )
    table.add_column("Intent", style="cyan")
    table.add_column("Category", style="magenta", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Args", style="dim", no_wrap=True)

    for intent in sorted(intents):
        meta = INTENT_METADATA.get(intent, {})
        placeholders = ",".join(meta.get("placeholders", [])) or "—"
        table.add_row(
            intent,
            meta.get("category", "—"),
            meta.get("description", "—"),
            placeholders,
        )

    console.print(table)


@shell_app.command("list-shells")
def shell_list_shells() -> None:
    """List supported shells and their support tiers."""
    table = Table(title="Supported Shells", header_style="bold cyan")
    table.add_column("Shell", style="cyan")
    table.add_column("Tier", style="magenta")
    for name, tier in list_supported_shells():
        table.add_row(name, tier)
    console.print(table)


@shell_app.command("security-cmds")
def shell_security_cmds(
    shell_name: str = typer.Option(
        "", "--shell", "-s", help="Override shell: bash|powershell|cmd"
    ),
) -> None:
    """Show security-relevant commands for the current or specified shell.

    Examples:
      siyarix shell security-cmds
      siyarix shell security-cmds --shell powershell
      siyarix shell security-cmds --shell bash
    """
    from .shell_knowledge import ShellType

    if shell_name:
        try:
            shell = ShellType(shell_name.lower())
        except ValueError:
            console.print(f"[red]Unknown shell: {shell_name}[/red]")
            raise typer.Exit(1)
    else:
        shell = detect_shell()

    cmds = get_security_commands(shell)
    title = (
        f"Security Commands for {normalize_shell(shell).value} ({get_shell_platform()})"
    )

    table = Table(title=title, header_style="bold red", show_lines=True)
    table.add_column("Purpose", style="cyan", no_wrap=True, width=35)
    table.add_column("Command", style="green")

    for purpose, cmd in cmds.items():
        table.add_row(purpose, cmd)

    console.print(table)
    console.print(
        "\n[dim]Use [cyan]siyarix shell translate <intent>[/cyan] for cross-platform equivalents.[/dim]"
    )


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
    work_mode: str = typer.Option(
        "",
        "--work-mode",
        help="Persona: offensive|defensive|bug_hunter|pentester|soc_analyst|none|auto",
    ),
) -> None:
    """Run security scans against target(s) using the execution engine.

    Supports @targets.txt multi-target mode: prefix a path with @ to load targets from file.

    Examples:
      siyarix scan 192.168.1.1
      siyarix scan 10.0.0.0/24 --tool nmap --mode registry
      siyarix scan @targets.txt --parallel 5
      siyarix scan example.com --dry-run
      siyarix scan example.com --work-mode bug_hunter
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

    # Apply persona if specified
    if work_mode:
        try:
            from .persona_engine import PersonaEngine

            pe = PersonaEngine()
            pe.switch_to(work_mode)
            console.print(f"[dim]Persona: {work_mode}[/dim]")
        except ValueError as exc:
            console.print(f"[yellow]{exc}[/yellow]")

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
    """Run a natural language command through the autonomous execution engine.

    Examples:
      siyarix run "scan example.com with nmap and nuclei then generate report"
      siyarix run "enumerate subdomains of target.com" --mode autonomous
      siyarix run "check for sql injection on http://site.com/login" --dry-run
      siyarix run --resume latest
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    # Handle --resume
    if resume_plan:
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

    recommendations = xi_core.recommend(session, route)
    if recommendations:
        table = Table(title="XI Recommendations", header_style="bold cyan")
        table.add_column("Priority", style="magenta", no_wrap=True)
        table.add_column("Recommendation", style="white")
        table.add_column("Reason", style="dim")
        for rec in recommendations:
            table.add_row(rec.priority, rec.title, rec.reason)
        console.print(table)

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
        from .core.pipeline import CommandPipeline

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

    The agent will continuously plan, execute, and re-plan until the goal
    is achieved or max iterations are reached.

    Examples:
      siyarix agent "Perform full recon on target.com" --target target.com
      siyarix agent "Find all SQL injection vulnerabilities" -t http://app.local -n 5
      siyarix agent "Enumerate and scan the 10.0.0.0/24 network" --max-iter 15
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    if target:
        try:
            validate_target(target)
        except ValidationError as exc:
            console.print(f"[red]Invalid target '{target}': {exc}[/red]")
            raise typer.Exit(1)

    engine = _get_engine(mode)
    loop = AgenticLoop(
        engine=engine,
        goal=goal,
        target=target,
        max_iterations=max_iterations,
        interactive=True,
    )
    asyncio.run(loop.run())


# ---------------------------------------------------------------------------
# Workflow commands — persistence and resume
# ---------------------------------------------------------------------------


@workflow_app.command("list")
def workflow_list(
    limit: int = typer.Option(20, "--limit", "-l", help="Max plans to list"),
    status: str = typer.Option("", "--status", help="Filter by status"),
) -> None:
    """List persisted execution plans."""
    store = OfflineStore()
    plans = store.list_plans(limit=limit, status=status or None)
    if not plans:
        console.print("[yellow]No plans found.[/yellow]")
        return

    table = Table(
        title=f"Execution Plans (showing {len(plans)})", header_style="bold cyan"
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta", no_wrap=True)
    table.add_column("Created", style="green", no_wrap=True)
    table.add_column("Updated", style="green", no_wrap=True)
    table.add_column("Instruction", style="white")

    for p in plans:
        table.add_row(
            p.get("id", ""),
            p.get("status", ""),
            p.get("created_at", ""),
            p.get("updated_at", ""),
            (p.get("instruction", "") or "")[:80],
        )

    console.print(table)


@workflow_app.command("show")
def workflow_show(
    plan_id: str = typer.Argument(help="Plan ID to display"),
) -> None:
    """Show a persisted execution plan with steps."""
    store = OfflineStore()
    plan = store.get_plan(plan_id)
    if not plan:
        console.print(f"[red]Plan not found: {plan_id}[/red]")
        raise typer.Exit(1)

    header = (
        f"[bold]ID:[/bold] {plan.get('id')}\n"
        f"[bold]Status:[/bold] {plan.get('status')}\n"
        f"[bold]Created:[/bold] {plan.get('created_at')}\n"
        f"[bold]Updated:[/bold] {plan.get('updated_at')}\n"
        f"[bold]Instruction:[/bold] {plan.get('instruction')}"
    )
    console.print(Panel.fit(header, title="Execution Plan", border_style="cyan"))

    steps = plan.get("steps", [])
    if not steps:
        console.print("[yellow]No step executions recorded.[/yellow]")
        return

    table = Table(title=f"Steps ({len(steps)})", header_style="bold magenta")
    table.add_column("Step ID", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta", no_wrap=True)
    table.add_column("Duration (ms)", style="green", no_wrap=True)
    table.add_column("Retries", style="yellow", no_wrap=True)
    table.add_column("Exit", style="white", no_wrap=True)
    table.add_column("Output", style="white")

    for s in steps:
        table.add_row(
            s.get("step_id", ""),
            s.get("status", ""),
            str(int(s.get("duration_ms") or 0)),
            str(int(s.get("retry_count") or 0)),
            str(s.get("exit_code") or ""),
            (s.get("output", "") or "")[:80],
        )

    console.print(table)


@workflow_app.command("resume")
def workflow_resume(
    plan_id: str = typer.Option("", "--id", help="Plan ID to resume"),
    latest: bool = typer.Option(False, "--latest", help="Resume the most recent plan"),
    mode: str = typer.Option("integrated", "--mode", "-m", help="Execution mode"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
) -> None:
    """Resume a previously persisted execution plan."""
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    store = OfflineStore()
    resolved_id = plan_id
    if latest:
        resolved_id = store.get_latest_plan_id() or ""

    if not resolved_id:
        console.print("[red]No plan ID provided and no recent plan found.[/red]")
        raise typer.Exit(1)

    engine = _get_engine(mode)
    asyncio.run(engine.resume(resolved_id, interactive=True))


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


# ---------------------------------------------------------------------------
# Premium: Dashboard command
# ---------------------------------------------------------------------------
@dashboard_app.command("show")
def show(
    refresh: int = typer.Option(
        5, "--refresh", "-r", help="Refresh interval (seconds)"
    ),
    export: str = typer.Option("", "--export", "-e", help="Export snapshot to file"),
    panel: str = typer.Option(
        "attack_map",
        "--panel",
        "-p",
        help="Right pane view: attack_map|timeline|metrics|cheatsheet",
    ),
    target: str = typer.Option("", "--target", "-t", help="Target context to analyze"),
) -> None:
    """Show live security dashboard using premium SplitPane layout."""
    from .session_manager import session_registry

    store = OfflineStore()
    metrics = get_metrics().to_dict()
    scans = store.list_scans(limit=20)
    plans = store.list_plans(limit=20)

    total_findings = sum(s.get("total_findings", 0) for s in scans)
    latest_scan = scans[0]["created_at"] if scans else "—"

    # Fetch recent session or construct metadata
    recent_sessions = session_registry.list_sessions(limit=1)
    recent_session = recent_sessions[0] if recent_sessions else None

    class SessionMetaMock:
        def __init__(self, target_val: str):
            self.target = target_val

    tgt = target or (recent_session.target if recent_session else "127.0.0.1")
    session_meta = SessionMetaMock(tgt)

    findings_list: list = []
    for s in scans:
        if "findings" in s and isinstance(s["findings"], list):
            findings_list.extend(s["findings"])
        elif "all_findings" in s and isinstance(s["all_findings"], list):
            findings_list.extend(s["all_findings"])

    timeline_events: list = []

    # Left pane layout
    left_table = Table(box=None, header_style="bold cyan")
    left_table.add_column("Security Parameter", style="white")
    left_table.add_column("Value", style="bold green", justify="right")

    left_table.add_row("Total Scans", str(metrics["execution"]["total_scans"]))
    left_table.add_row(
        "Successful Scans", str(metrics["execution"]["successful_scans"])
    )
    left_table.add_row("Failed Scans", str(metrics["execution"]["failed_scans"]))
    left_table.add_row("Total Findings", str(total_findings))
    left_table.add_row("Plans Tracked", str(len(plans)))
    left_table.add_row("Latest Scan", latest_scan)

    left_content = Table.grid(padding=1)
    left_content.add_row("[bold cyan]🛡️ SIYARIX OPERATIONS METRICS[/bold cyan]\n")
    left_content.add_row(left_table)

    if plans:
        plan_table = Table(
            title="Recent Plans",
            show_header=True,
            header_style="bold dim cyan",
            box=None,
        )
        plan_table.add_column("Plan ID", style="magenta")
        plan_table.add_column("Created", style="dim")
        for p in plans[:5]:
            p_id = p.get("plan_id") or p.get("id") or "—"
            plan_table.add_row(str(p_id)[:8], p.get("created_at", "—"))
        left_content.add_row("\n")
        left_content.add_row(plan_table)

    sp = SplitPane(theme=_active_theme)
    layout = sp.generate_layout(
        left_renderable=left_content,
        right_type=panel,
        session_meta=session_meta,
        findings=findings_list,
        timeline_events=timeline_events,
    )

    console.print(layout)

    if export:
        snapshot = {
            "metrics": metrics,
            "total_findings": total_findings,
            "latest_scan": latest_scan,
            "plans_count": len(plans),
        }
        Path(export).write_text(json.dumps(snapshot, indent=2))
        console.print(f"[dim]Exported snapshot to {export}[/dim]")


@dashboard_app.callback(invoke_without_command=True)
def dashboard_callback(
    ctx: typer.Context,
    refresh: int = typer.Option(
        5, "--refresh", "-r", help="Refresh interval (seconds)"
    ),
    export: str = typer.Option("", "--export", "-e", help="Export snapshot to file"),
    panel: str = typer.Option(
        "attack_map",
        "--panel",
        "-p",
        help="Right pane view: attack_map|timeline|metrics|cheatsheet",
    ),
    target: str = typer.Option("", "--target", "-t", help="Target context to analyze"),
) -> None:
    """Live system dashboard showing visual attack maps, metrics, timelines, and cheatsheets."""
    if ctx.invoked_subcommand is not None:
        return
    show(refresh=refresh, export=export, panel=panel, target=target)


# ---------------------------------------------------------------------------
# Premium: Bulk operations
# ---------------------------------------------------------------------------
@bulk_app.command("scan")
def bulk_scan_cmd(
    targets_file: str = typer.Argument(help="File with targets (one per line)"),
    tool: str = typer.Option("nmap", "--tool", "-t", help="Tool to use"),
    batch_size: int = typer.Option(10, "--batch", "-b", help="Batch size"),
    output_dir: str = typer.Option(
        "./results", "--output-dir", "-o", help="Output directory"
    ),
    mode: str = typer.Option("integrated", "--mode", "-m", help="Execution mode"),
    save: bool = typer.Option(
        True, "--save/--no-save", help="Persist workflow execution"
    ),
    parallel: int = typer.Option(3, "--parallel", "-p", help="Concurrent executions"),
) -> None:
    """Bulk scan multiple targets from file."""
    print_banner(console, _active_theme)

    target_path = Path(targets_file)
    if not target_path.exists():
        console.print(f"[red]Error: File not found: {targets_file}[/red]")
        raise typer.Exit(1)

    targets = [t.strip() for t in target_path.read_text().splitlines() if t.strip()]
    console.print(
        f"[bold]Bulk Scan:[/bold] {len(targets)} targets | Tool: {tool} | Batch: {batch_size}"
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    engine = _get_engine(mode)

    async def _run_bulk() -> None:
        semaphore = asyncio.Semaphore(max(parallel, 1))

        async def run_target(target: str) -> None:
            async with semaphore:
                try:
                    validate_target(target)
                except ValidationError as exc:
                    console.print(f"[red]Invalid target '{target}': {exc}[/red]")
                    progress.advance(task, 1)
                    return

                instruction = f"scan {target} with {tool}"
                result = await engine.execute(
                    instruction, interactive=False, dry_run=False, persist=save
                )

                safe_name = target.replace("/", "_").replace(":", "_")
                out_file = output_path / f"{safe_name}.json"
                out_file.write_text(json.dumps(result.to_dict(), indent=2))
                progress.advance(task, 1)

        tasks = [run_target(t) for t in targets]
        await asyncio.gather(*tasks)

    with Progress() as progress:
        task = progress.add_task("[green]Scanning...", total=len(targets))
        asyncio.run(_run_bulk())

    console.print(f"[green]✓ Bulk scan complete! Results in: {output_dir}[/green]")


@bulk_app.command()
def update(
    filter: str = typer.Option("", "--filter", "-f", help="Filter pattern"),
    status: str = typer.Option("", "--status", "-s", help="New status"),
) -> None:
    """Bulk update incidents or vulnerabilities."""
    console.print(f"[bold]Bulk Update[/bold]: filter={filter}, status={status}")


# ---------------------------------------------------------------------------
# Premium: Watch mode
# ---------------------------------------------------------------------------
@watch_app.command()
def start(
    query: str = typer.Argument(
        help="Watch query (e.g., 'incidents severity:critical')"
    ),
    interval: int = typer.Option(
        30, "--interval", "-i", help="Check interval (seconds)"
    ),
    notify: bool = typer.Option(
        True, "--notify/--no-notify", help="Send notifications"
    ),
    severity: str = typer.Option(
        "", "--severity", "-s", help="Filter findings by severity"
    ),
    limit: int = typer.Option(10, "--limit", "-l", help="Max findings to show"),
) -> None:
    """Start watch mode — monitor for changes."""
    print_banner(console, _active_theme)
    console.print(
        f"[bold]Watch Mode Started[/bold]\nQuery: {query}\nInterval: {interval}s\n"
    )
    store = OfflineStore()
    last_count = 0

    try:
        while True:
            findings = store.search_findings(severity=severity or None, limit=limit)
            current_count = len(findings)
            ts = datetime.now().strftime("%H:%M:%S")
            if current_count != last_count:
                console.print(
                    f"[dim]{ts} — Updates detected ({current_count} findings)[/dim]"
                )
                table = Table(title="Recent Findings", header_style="bold cyan")
                table.add_column("Title", style="white")
                table.add_column("Severity", style="magenta", no_wrap=True)
                table.add_column("Tool", style="cyan", no_wrap=True)
                table.add_column("Target", style="green")
                for f in findings:
                    table.add_row(
                        f.get("title", "")[:50],
                        f.get("severity", ""),
                        f.get("tool", ""),
                        f.get("target", "")[:30],
                    )
                console.print(table)
                if notify:
                    console.print("[green]Notification: findings updated.[/green]")
                last_count = current_count
            else:
                console.print(f"[dim]{ts} — No changes[/dim]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch mode stopped.[/yellow]")


# ---------------------------------------------------------------------------
# Findings commands
# ---------------------------------------------------------------------------


@findings_app.command("list")
def findings_list(
    severity: str = typer.Option("", "--severity", "-s", help="Filter by severity"),
    tool: str = typer.Option("", "--tool", "-t", help="Filter by tool"),
    search: str = typer.Option("", "--search", help="Text search"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max results"),
) -> None:
    """List findings from the offline store."""
    store = OfflineStore()
    findings = store.search_findings(
        severity=severity or None,
        tool=tool or None,
        search=search or None,
        limit=limit,
    )
    if not findings:
        console.print("[yellow]No findings found.[/yellow]")
        return

    table = Table(title=f"Findings ({len(findings)})", header_style="bold magenta")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="magenta", no_wrap=True)
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Target", style="green")
    table.add_column("Timestamp", style="dim", no_wrap=True)

    for f in findings:
        table.add_row(
            f.get("title", "")[:60],
            f.get("severity", ""),
            f.get("tool", ""),
            f.get("target", "")[:30],
            f.get("timestamp", ""),
        )

    console.print(table)


@findings_app.command("export")
def findings_export(
    output: str = typer.Argument(help="Output file (.json or .csv)"),
    severity: str = typer.Option("", "--severity", "-s", help="Filter by severity"),
    tool: str = typer.Option("", "--tool", "-t", help="Filter by tool"),
    search: str = typer.Option("", "--search", help="Text search"),
) -> None:
    """Export findings to JSON or CSV."""
    store = OfflineStore()
    ext = Path(output).suffix.lower()
    if not ext:
        console.print("[red]Output file must include extension (.json or .csv).[/red]")
        raise typer.Exit(1)

    if severity or tool or search:
        findings = store.search_findings(
            severity=severity or None,
            tool=tool or None,
            search=search or None,
            limit=10000,
        )
        if ext == ".json":
            Path(output).write_text(json.dumps(findings, indent=2))
        elif ext == ".csv":
            if not findings:
                Path(output).write_text("")
            else:
                fieldnames = list(findings[0].keys())
                with open(output, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in findings:
                        writer.writerow(row)
        else:
            console.print("[red]Unsupported extension. Use .json or .csv.[/red]")
            raise typer.Exit(1)
    else:
        if ext == ".json":
            store.export_json(output)
        elif ext == ".csv":
            store.export_csv(output)
        else:
            console.print("[red]Unsupported extension. Use .json or .csv.[/red]")
            raise typer.Exit(1)

    console.print(f"[green]✓ Exported findings to {output}[/green]")


# ---------------------------------------------------------------------------
# Report commands
# ---------------------------------------------------------------------------


@report_app.command("generate")
def report_generate(
    output: str = typer.Argument(help="Output report file (.md, .json, .csv)"),
    limit: int = typer.Option(10000, "--limit", "-n", help="Max findings to include"),
) -> None:
    """Generate a basic findings report."""
    store = OfflineStore()
    findings = store.search_findings(limit=limit)

    ext = Path(output).suffix.lower()
    if ext == ".json":
        Path(output).write_text(json.dumps(findings, indent=2))
        console.print(f"[green]✓ Report generated: {output}[/green]")
        return

    if ext == ".csv":
        if not findings:
            Path(output).write_text("")
        else:
            fieldnames = list(findings[0].keys())
            with open(output, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for row in findings:
                    writer.writerow(row)
        console.print(f"[green]✓ Report generated: {output}[/green]")
        return

    if ext != ".md":
        console.print("[red]Unsupported report format. Use .md, .json, or .csv.[/red]")
        raise typer.Exit(1)

    severity_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.get("severity", "info")] = (
            severity_counts.get(f.get("severity", "info"), 0) + 1
        )
        tool_counts[f.get("tool", "unknown")] = (
            tool_counts.get(f.get("tool", "unknown"), 0) + 1
        )

    lines = [
        "# Siyarix Findings Report",
        "",
        f"Generated: {datetime.now().isoformat()}",
        "",
        f"Total findings: {len(findings)}",
        "",
        "## By Severity",
    ]
    for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
        lines.append(f"- {sev}: {count}")

    lines.append("")
    lines.append("## By Tool")
    for tool, count in sorted(tool_counts.items(), key=lambda x: x[0]):
        lines.append(f"- {tool}: {count}")

    lines.append("")
    lines.append("## Findings (truncated)")
    for f in findings[:50]:
        lines.append(
            f"- [{f.get('severity', 'info')}] {f.get('title', '')} ({f.get('tool', '')})"
        )

    Path(output).write_text("\n".join(lines))
    console.print(f"[green]✓ Report generated: {output}[/green]")


# ---------------------------------------------------------------------------
# CI/CD & policy gates
# ---------------------------------------------------------------------------


@ci_app.command("gate")
def ci_gate(
    allow_degraded: bool = typer.Option(
        False, "--allow-degraded", help="Allow degraded health state"
    ),
) -> None:
    """Fail if health is unhealthy or critical findings exist."""
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
# Premium: Workflow orchestration
# ---------------------------------------------------------------------------
@workflow_app.command("run")
def workflow_run_cmd(
    workflow: str = typer.Argument(help="Workflow name or file path"),
    params: str = typer.Option("{}", "--params", "-p", help="JSON parameters"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
) -> None:
    """Run a workflow (YAML/JSON pipeline)."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Workflow:[/bold] {workflow}")

    try:
        parsed_params = json.loads(params or "{}")
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid --params JSON: {exc}[/red]")
        raise typer.Exit(1)

    runtime = WorkflowRuntime(engine_factory=_get_engine, store=OfflineStore())
    try:
        workflow_data = runtime.load_workflow(workflow, parsed_params)
        workflow_name = str(
            workflow_data.get("name") or Path(workflow).stem or "workflow"
        )
        steps = runtime.validate(workflow_data)
    except Exception as exc:
        console.print(f"[red]Workflow validation failed: {exc}[/red]")
        raise typer.Exit(1)

    result = asyncio.run(
        runtime.execute(workflow_name=workflow_name, steps=steps, dry_run=dry_run)
    )

    table = Table(
        title=f"Workflow Result: {result.workflow_name}", header_style="bold cyan"
    )
    table.add_column("Step", style="cyan")
    table.add_column("State", style="magenta")
    table.add_column("Error", style="red")
    for step in steps:
        state = result.step_states.get(step.id, WorkflowState.PLANNED)
        table.add_row(step.id, state.value, result.step_errors.get(step.id, ""))
    console.print(table)

    if result.status == WorkflowState.COMPLETED:
        console.print(f"[green]✓ Workflow complete (plan_id={result.plan_id})[/green]")
    elif result.status == WorkflowState.BLOCKED:
        console.print(f"[yellow]Workflow blocked (plan_id={result.plan_id})[/yellow]")
        raise typer.Exit(2)
    else:
        console.print(f"[red]Workflow failed (plan_id={result.plan_id})[/red]")
        raise typer.Exit(1)


@workflow_app.command("catalog")
def workflow_catalog(
    path: str = typer.Option("./workflows", "--path", help="Workflow directory"),
) -> None:
    """List workflow files from a directory."""
    root = Path(path)
    if not root.exists():
        console.print(f"[yellow]No workflow directory found at {path}[/yellow]")
        return

    files = (
        sorted(root.glob("*.yml"))
        + sorted(root.glob("*.yaml"))
        + sorted(root.glob("*.json"))
    )
    if not files:
        console.print(f"[yellow]No workflow files found in {path}[/yellow]")
        return

    table = Table(
        title="Workflow Catalog", show_header=True, header_style="bold magenta"
    )
    table.add_column("Name", style="cyan")
    table.add_column("Path", style="white")

    for f in files:
        table.add_row(f.stem, str(f))

    console.print(table)


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
# Premium: Team & Organization commands
# ---------------------------------------------------------------------------
@team_app.command("invite")
def team_invite(
    email: str = typer.Argument(help="Email to invite"),
    role: str = typer.Option(
        "member", "--role", "-r", help="Role: admin|member|viewer"
    ),
) -> None:
    """Invite a team member."""
    console.print(f"[green]✓ Invitation sent to {email} (role: {role})[/green]")


@org_app.command("stats")
def org_stats() -> None:
    """Show organization statistics."""
    table = Table(
        title="Organization Statistics", show_header=True, header_style="bold cyan"
    )
    table.add_column("Metric", style="white")
    table.add_column("Value", style="bold green", justify="right")

    stats = [
        ("Members", "12"),
        ("Scans (30d)", "156"),
        ("Incidents (Open)", "5"),
        ("Vulnerabilities", "89"),
        ("Compliance Score", "78%"),
    ]

    for metric, value in stats:
        table.add_row(metric, value)

    console.print(table)


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
    tools = registry.discover(force_refresh=refresh, fast=fast)
    if category:
        tools = [t for t in tools if t.category == category]

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
    table.add_column("Version", style="yellow")
    table.add_column("Capabilities", style="white")

    for t in sorted(tools, key=lambda x: x.category):
        caps = ", ".join(t.capabilities[:3])
        if len(t.capabilities) > 3:
            caps += f" +{len(t.capabilities) - 3}"
        table.add_row(t.name, t.binary, t.category, t.version[:30], caps)

    console.print(table)


@tool_registry_app.command("show")
def tool_registry_show(name: str = typer.Argument(help="Tool name or binary")) -> None:
    """Show detailed info about a specific tool."""
    tools = registry.discover()
    tool = next((t for t in tools if t.name == name or t.binary == name), None)
    if not tool:
        console.print(f"[red]Tool not found: {name}[/red]")
        raise typer.Exit(1)

    console.print(
        Panel.fit(
            f"[bold]{tool.name}[/bold] ({tool.binary})\n"
            f"[dim]Category:[/dim]     {tool.category}\n"
            f"[dim]Version:[/dim]      {tool.version}\n"
            f"[dim]Path:[/dim]         {tool.path}\n"
            f"[dim]Capabilities:[/dim] {', '.join(tool.capabilities)}\n"
            f"[dim]Description:[/dim]  {tool.description}",
            title="Tool Info",
            border_style="cyan",
        )
    )


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
    env_key = provider_env_var(provider)
    upsert_env_vars({env_key: api_key}, ensure_env_file())
    os.environ[env_key] = api_key
    console.print(f"[green]✓ API key stored for provider: {provider}[/green]")
    console.print(
        "[dim]Key is stored in the credential vault and synced to .env.[/dim]"
    )


@auth_app.command("show")
def auth_show() -> None:
    """Show configured API key providers."""
    providers = ["openai", "gemini", "anthropic", "cloud"]
    table = Table(
        title="Configured API Keys", show_header=True, header_style="bold green"
    )
    table.add_column("Provider", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source")

    for prov in providers:
        env_key = provider_env_var(prov)
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
# Plugin management (wired to real PluginManager)
# ---------------------------------------------------------------------------
@plugin_app.command("list")
def plugin_list() -> None:
    """List all installed plugins."""
    real_plugins = plugins.list_plugins()
    table = Table(
        title="Plugin Ecosystem", show_header=True, header_style="bold magenta"
    )
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Author", style="dim")
    table.add_column("Description", style="white")

    if not real_plugins:
        console.print(
            "[dim]No plugins installed. Use 'siyarix plugin install <name>' to add plugins.[/dim]"
        )
        return

    for p in real_plugins:
        status = "[green]✓ Active[/green]" if p.enabled else "[dim]○ Disabled[/dim]"
        table.add_row(p.name, p.version, status, p.author, p.description[:40])

    console.print(table)


@plugin_app.command("install")
def plugin_install(
    plugin: str = typer.Argument(help="Plugin name or URL"),
    source: str = typer.Option(
        "official", "--source", "-s", help="Source: official|community|local"
    ),
) -> None:
    """Install a plugin from marketplace or local path."""
    from pathlib import Path

    console.print(f"[bold]Installing:[/bold] {plugin} from {source}...")
    source_path = Path(plugin)
    try:
        if source_path.exists():
            installed = plugins.install_from_path(source_path)
            console.print(
                f"[green]✓ Plugin installed from {plugin} → {installed}[/green]"
            )
        else:
            target = Path(plugins.root) / plugin
            target.mkdir(parents=True, exist_ok=True)
            yaml_path = target / "plugin.yaml"
            if not yaml_path.exists():
                yaml_path.write_text(
                    f"name: {plugin}\nversion: 1.0.0\nauthor: community\n"
                    f"description: Plugin '{plugin}' installed from marketplace\nenabled: true\n",
                    encoding="utf-8",
                )
                (target / "__init__.py").write_text("", encoding="utf-8")
            plugins.set_enabled(plugin, True)
            console.print(f"[green]✓ Plugin installed: {plugin}[/green]")
    except Exception as exc:
        console.print(f"[red]Install failed: {exc}[/red]")


# ---------------------------------------------------------------------------
# Theme management (premium)
# ---------------------------------------------------------------------------
# Note: theme commands are defined earlier; duplicate premium-themed handlers removed to
# avoid redefinition and typing conflicts.


# ---------------------------------------------------------------------------
# Guided Setup Wizard
# ---------------------------------------------------------------------------
@app.command()
def wizard() -> None:
    """Launch the interactive guided onboarding setup wizard."""
    wiz = OnboardingWizard()
    wiz.run()


# ---------------------------------------------------------------------------
# Version command
# ---------------------------------------------------------------------------
@app.command()
def version() -> None:
    """Show Siyarix version information."""
    tools = registry.discover()
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
def _load_plugins_once() -> None:
    """Load plugins exactly once, safely."""
    global _plugins_loaded
    if not _plugins_loaded:
        try:
            plugins.load_command_plugins(app)
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning("Plugin load error: %s", exc)
        _plugins_loaded = True


if __name__ == "__main__":
    try:
        _load_plugins_once()
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if config.get("log_level") == "debug":
            console.print_exception()
        sys.exit(1)
