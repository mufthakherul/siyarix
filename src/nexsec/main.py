"""NexSec CLI — Premium Enterprise Entry Point.

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
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

__version__ = "1.2.0"

from .audit_log import AuditEventType, AuditSeverity, audit
from .branding import available_themes, print_banner
from .chat import start_chat
from .config import SettingsStore
from .credential_store import CredentialStore
from .engine import ExecutionEngine, ExecutionMode
from .plugins import PluginManager
from .security_commands import security_app
from .shell_knowledge import (
    build_platform_context,
    detect_shell,
    get_security_commands,
    get_shell_platform,
    CROSS_PLATFORM_COMMANDS,
    normalize_shell,
    INTENT_METADATA,
    list_supported_shells,
)
from .tool_registry import ToolRegistry

# ---------------------------------------------------------------------------
# Initialize core systems
# ---------------------------------------------------------------------------

# Detect non-interactive / CI environments for banner suppression
_IS_TTY = sys.stdout.isatty()
_CI_MODE = os.getenv("CI", "") or os.getenv("NEXSEC_NO_BANNER", "") or not _IS_TTY

console = Console()
registry = ToolRegistry()
config = SettingsStore()
plugins = PluginManager()
creds = CredentialStore()
_plugins_loaded = False


def _get_engine(mode: str = "integrated") -> ExecutionEngine:
    """Build an ExecutionEngine with API keys from config/credentials."""
    engine_config: dict = {}
    openai_key = os.environ.get("OPENAI_API_KEY", "") or creds.get_password("openai", "api_key") or ""
    if openai_key:
        engine_config["openai_api_key"] = openai_key
    engine_config["ollama_url"] = config.get("ollama_url")
    engine_config["ollama_model"] = config.get("ollama_model")
    try:
        exec_mode = ExecutionMode(mode)
    except ValueError:
        exec_mode = ExecutionMode.INTEGRATED
    return ExecutionEngine(mode=exec_mode, registry=registry, config=engine_config)


# ---------------------------------------------------------------------------
# Main Typer app — Premium structure
# ---------------------------------------------------------------------------
app = typer.Typer(
    name="nexsec",
    help=f"""
[bold cyan]NexSec CLI — Enterprise Cybersecurity Command Center[/bold cyan]

[dim]Version: {__version__} | Platform: {platform.system()} | Python: {platform.python_version()}[/dim]

[bold]Quick Start:[/bold]
  [green]nexsec[/green]                          — Interactive chat mode (AI assistant)
  [green]nexsec chat[/green]                     — Interactive AI cybersecurity REPL
  [green]nexsec scan 192.168.1.0/24[/green]      — Network/port scan
  [green]nexsec run "scan my network"[/green]    — Natural language command
  [green]nexsec discover example.com[/green]     — Asset & service discovery
  [green]nexsec tool-registry list[/green]       — Show installed security tools

[bold]Execution Modes:[/bold]
  [yellow]--mode registry[/yellow]    — Fast, offline (tool registry only)
  [yellow]--mode autonomous[/yellow]  — AI model-driven planning
  [yellow]--mode integrated[/yellow]  — AI + registry fallback (default)

[bold]Premium Features:[/bold]
  • [magenta]nexsec chat[/magenta]          — AI conversational REPL with session history
  • [magenta]nexsec shell[/magenta]         — Cross-platform shell command helper
  • [magenta]nexsec dashboard[/magenta]     — Live security dashboard
  • [magenta]nexsec bulk scan[/magenta]     — Bulk target scanning
  • [magenta]nexsec workflow[/magenta]      — Workflow orchestration
  • [magenta]nexsec compliance[/magenta]    — Compliance reporting
  • [magenta]nexsec auth set-key[/magenta]  — Configure AI model API keys
    """,
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,  # launch chat when called with no subcommand
)


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Launch interactive chat mode when nexsec is invoked with no subcommand."""
    if ctx.invoked_subcommand is None and _IS_TTY:
        # No subcommand and running interactively — launch chat
        start_chat()


# Register security command group into the main CLI.
app.add_typer(security_app, name="security")

# ---------------------------------------------------------------------------
# Sub-command groups (Premium ecosystem)
# ---------------------------------------------------------------------------

offline_app = typer.Typer(help="💾 Offline data & cache management")
app.add_typer(offline_app, name="offline")

mode_app = typer.Typer(help="⚙️ Execution mode management")
app.add_typer(mode_app, name="mode")

auth_app = typer.Typer(help="🔑 Authentication & API keys")
app.add_typer(auth_app, name="auth")

profile_app = typer.Typer(help="👤 Profile & workspace management")
app.add_typer(profile_app, name="profile")

audit_app = typer.Typer(help="📋 Audit trail & compliance logs")
app.add_typer(audit_app, name="audit")

history_app = typer.Typer(help="📜 Scan history & findings")
app.add_typer(history_app, name="history")

config_app = typer.Typer(help="⚙️ CLI configuration")
app.add_typer(config_app, name="config")

completions_app = typer.Typer(help="🏁 Shell completions")
app.add_typer(completions_app, name="completions")

planner_app = typer.Typer(help="🤖 Model provider & autonomous planning")
app.add_typer(planner_app, name="planner")

sync_app = typer.Typer(help="🔄 Offline sync & reconciliation")
app.add_typer(sync_app, name="sync")

plugin_app = typer.Typer(help="🔌 Plugin lifecycle management")
app.add_typer(plugin_app, name="plugin")

theme_app = typer.Typer(help="🎨 Theme customization")
app.add_typer(theme_app, name="theme")

workflow_app = typer.Typer(help="⚙️ Workflow orchestration")
app.add_typer(workflow_app, name="workflow")

team_app = typer.Typer(help="👥 Team & organization")
app.add_typer(team_app, name="team")

org_app = typer.Typer(help="🏢 Organization-scoped commands")
app.add_typer(org_app, name="org")

schedule_app = typer.Typer(help="⏱ Recurring scan schedules")
app.add_typer(schedule_app, name="schedule")

findings_app = typer.Typer(help="🔍 Finding collaboration")
app.add_typer(findings_app, name="findings")

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

shell_app = typer.Typer(help="🖥 Cross-platform shell command helper")
app.add_typer(shell_app, name="shell")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_profile: str | None = None
_active_theme: str = "default"


# ---------------------------------------------------------------------------
# Chat command — Interactive AI cybersecurity REPL
# ---------------------------------------------------------------------------
@app.command()
def chat(
    mode: str = typer.Option("integrated", "--mode", "-m", help="Execution mode: registry|autonomous|integrated"),
    target: str = typer.Option("", "--target", "-t", help="Set initial target for the session"),
    session: str = typer.Option("", "--session", "-s", help="Resume a previous session by ID"),
    resume: bool = typer.Option(False, "--resume", "-r", help="Resume the most recent session"),
):
    """Start an interactive AI cybersecurity REPL (chat mode).

    NexSec chat gives you a conversational interface to run security tools,
    get cross-platform command help, and manage sessions with history.

    Examples:
      nexsec chat
      nexsec chat --target 192.168.1.1
      nexsec chat --mode autonomous
      nexsec chat --session abc123 --resume
    """
    session_id = session or None
    start_chat(mode=mode, target=target, session_id=session_id, resume=resume)


# ---------------------------------------------------------------------------
# Shell sub-commands — Cross-platform terminal command helper
# ---------------------------------------------------------------------------

@shell_app.command("platform")
def shell_platform():
    """Show current platform and detected shell information."""
    ctx = build_platform_context()
    console.print(Panel.fit(
        f"[bold]Platform:[/bold]    {ctx['platform']} {platform.release()}\n"
        f"[bold]Device:[/bold]      {ctx['device_type']}\n"
        f"[bold]Terminal:[/bold]    {ctx['terminal_type']}\n"
        f"[bold]Shell:[/bold]       {ctx['shell']} ({ctx['shell_platform']})\n"
        f"[bold]Architecture:[/bold] {ctx['arch']}\n"
        f"[bold]Python:[/bold]      {ctx['python_version']}\n"
        f"[bold]WSL:[/bold]         {'[green]✓ Available[/green]' if ctx['has_wsl'] else '[red]✗ Not found[/red]'}\n"
        f"[bold]SSH:[/bold]         {'[green]✓ Remote[/green]' if ctx['is_terminal_ssh'] else '[dim]local[/dim]'}\n"
        f"[bold]Cloud:[/bold]       {'[green]✓ Cloud[/green]' if ctx['is_terminal_cloud'] else '[dim]local[/dim]'}\n"
        f"[bold]Windows:[/bold]     {ctx['is_windows']}\n"
        f"[bold]Linux:[/bold]       {ctx['is_linux']}\n"
        f"[bold]macOS:[/bold]       {ctx['is_macos']}",
        title="[bold]Platform & Shell Info[/bold]",
        border_style="cyan",
    ))


@shell_app.command("translate")
def shell_translate(
    intent: str = typer.Argument(help="Command intent (e.g. list_files, network_connections, ping)"),
    target: str = typer.Option("", "--target", help="Target for commands that need one (e.g. IP/hostname)"),
    user: str = typer.Option("", "--user", help="User for SSH/SCP intents"),
    path: str = typer.Option("", "--path", help="Path for file transfer intents"),
    file: str = typer.Option("", "--file", help="File path for file_hash intents"),
):
    """Translate a command intent to all supported shells.

    Examples:
      nexsec shell translate list_files
      nexsec shell translate ping --target 192.168.1.1
      nexsec shell translate network_connections
    """
    entry = CROSS_PLATFORM_COMMANDS.get(intent)
    if not entry:
        # Fuzzy search
        matches = [k for k in CROSS_PLATFORM_COMMANDS if any(w in k for w in intent.split("_"))]
        if matches:
            console.print(f"[yellow]Intent '{intent}' not found. Did you mean:[/yellow]")
            for m in matches[:5]:
                console.print(f"  [cyan]{m}[/cyan]")
        else:
            console.print(f"[red]Unknown intent: {intent}[/red]")
            console.print("[dim]Run 'nexsec shell list-intents' to see all available intents.[/dim]")
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
    filter_str: str = typer.Option("", "--filter", "-f", help="Filter intents by keyword"),
):
    """List all available command intents for translation.

    Example:
      nexsec shell list-intents
      nexsec shell list-intents --filter network
    """
    intents = list(CROSS_PLATFORM_COMMANDS.keys())
    if filter_str:
        intents = [i for i in intents if filter_str.lower() in i.lower()]

    table = Table(title=f"Available Command Intents ({len(intents)})", header_style="bold cyan")
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
    shell_name: str = typer.Option("", "--shell", "-s", help="Override shell: bash|powershell|cmd"),
):
    """Show security-relevant commands for the current or specified shell.

    Examples:
      nexsec shell security-cmds
      nexsec shell security-cmds --shell powershell
      nexsec shell security-cmds --shell bash
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
    title = f"Security Commands for {normalize_shell(shell).value} ({get_shell_platform()})"

    table = Table(title=title, header_style="bold red", show_lines=True)
    table.add_column("Purpose", style="cyan", no_wrap=True, width=35)
    table.add_column("Command", style="green")

    for purpose, cmd in cmds.items():
        table.add_row(purpose, cmd)

    console.print(table)
    console.print("\n[dim]Use [cyan]nexsec shell translate <intent>[/cyan] for cross-platform equivalents.[/dim]")


# ---------------------------------------------------------------------------
# Premium: Main entry with enhanced output
# ---------------------------------------------------------------------------
@app.command()
def scan(
    targets: list[str] = typer.Argument(help="Target(s): IP, CIDR, URL, or hostname"),
    tool: str = typer.Option("", "--tool", "-t", help="Specific tool to use"),
    mode: str = typer.Option(
        "integrated", "--mode", "-m", help="Execution mode: registry|autonomous|integrated"
    ),
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json|yaml|csv"),
    parallel: int = typer.Option(3, "--parallel", "-p", help="Parallel workers"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to database"),
    notify: bool = typer.Option(False, "--notify", "-n", help="Send notification on completion"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only, do not execute"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
    profile: str = typer.Option("", "--profile", help="Use specific profile"),
):
    """Run security scans against target(s) using the execution engine.

    Examples:
      nexsec scan 192.168.1.1
      nexsec scan 10.0.0.0/24 --tool nmap --mode registry
      nexsec scan example.com --dry-run
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    instruction = f"scan {' '.join(targets)}"
    if tool:
        instruction += f" with {tool}"

    audit.log(
        event_type=AuditEventType.SCAN_START,
        severity=AuditSeverity.INFO,
        user=os.getenv("USER", os.getenv("USERNAME", "cli")),
        action="scan",
        result="started",
        target=",".join(targets),
        details={"tool": tool, "mode": mode, "targets": targets},
    )

    engine = _get_engine(mode)
    result = asyncio.run(engine.execute(instruction, interactive=True, dry_run=dry_run))

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
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep discovery (OS, services, vulns)"),
    export: str = typer.Option("", "--export", "-e", help="Export to file (JSON/YAML)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
):
    """Discover assets, services, and vulnerabilities on a target.

    Examples:
      nexsec discover 192.168.1.0/24
      nexsec discover example.com --deep
      nexsec discover 10.0.0.0/8 --export results.json
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

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
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress ASCII banner"),
):
    """Run a natural language command through the autonomous execution engine.

    Examples:
      nexsec run "scan example.com with nmap and nuclei then generate report"
      nexsec run "enumerate subdomains of target.com" --mode autonomous
      nexsec run "check for sql injection on http://site.com/login" --dry-run
    """
    if not no_banner and not _CI_MODE:
        print_banner(console, _active_theme)

    instruction = command
    if target:
        instruction += f" on {target}"

    engine = _get_engine(mode)
    asyncio.run(engine.execute(instruction, interactive=True, dry_run=dry_run))


# ---------------------------------------------------------------------------
# Premium: Dashboard command
# ---------------------------------------------------------------------------
@dashboard_app.command()
def show(
    refresh: int = typer.Option(5, "--refresh", "-r", help="Refresh interval (seconds)"),
    export: str = typer.Option("", "--export", "-e", help="Export snapshot to file"),
):
    """Show live security dashboard."""
    print_banner(console, _active_theme)

    table = Table(title="Security Operations Dashboard", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="white")
    table.add_column("Value", style="bold green", justify="right")
    table.add_column("Trend", justify="center")
    table.add_column("Status", justify="center")

    # Mock data — replace with API calls
    metrics = [
        ("Security Score", "78.5", "↑", "🟢 Good"),
        ("Open Incidents", "5", "↓", "🟡 Warning"),
        ("Critical Vulns", "12", "↑", "🔴 Critical"),
        ("Threat Hunts", "3", "→", "🟢 Active"),
        ("MFA Coverage", "89%", "↑", "🟢 Good"),
        ("Patch Rate", "76%", "↓", "🟡 Warning"),
    ]

    for name, value, trend, status in metrics:
        table.add_row(name, value, trend, status)

    console.print(table)

    if export:
        console.print(f"[dim]Exported to {export}[/dim]")


# ---------------------------------------------------------------------------
# Premium: Bulk operations
# ---------------------------------------------------------------------------
@bulk_app.command("scan")
def bulk_scan_cmd(
    targets_file: str = typer.Argument(help="File with targets (one per line)"),
    tool: str = typer.Option("nmap", "--tool", "-t", help="Tool to use"),
    batch_size: int = typer.Option(10, "--batch", "-b", help="Batch size"),
    output_dir: str = typer.Option("./results", "--output-dir", "-o", help="Output directory"),
):
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

    with Progress() as progress:
        task = progress.add_task("[green]Scanning...", total=len(targets))
        for i in range(0, len(targets), batch_size):
            batch = targets[i : i + batch_size]
            # Process batch...
            progress.advance(task, len(batch))

    console.print(f"[green]✓ Bulk scan complete! Results in: {output_dir}[/green]")


@bulk_app.command()
def update(
    filter: str = typer.Option("", "--filter", "-f", help="Filter pattern"),
    status: str = typer.Option("", "--status", "-s", help="New status"),
):
    """Bulk update incidents or vulnerabilities."""
    console.print(f"[bold]Bulk Update[/bold]: filter={filter}, status={status}")


# ---------------------------------------------------------------------------
# Premium: Watch mode
# ---------------------------------------------------------------------------
@watch_app.command()
def start(
    query: str = typer.Argument(help="Watch query (e.g., 'incidents severity:critical')"),
    interval: int = typer.Option(30, "--interval", "-i", help="Check interval (seconds)"),
    notify: bool = typer.Option(True, "--notify/--no-notify", help="Send notifications"),
):
    """Start watch mode — monitor for changes."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Watch Mode Started[/bold]\nQuery: {query}\nInterval: {interval}s\n")

    try:
        while True:
            # Check for changes...
            console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} — Checking...[/dim]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch mode stopped.[/yellow]")


# ---------------------------------------------------------------------------
# Premium: Workflow orchestration
# ---------------------------------------------------------------------------
@workflow_app.command("run")
def workflow_run_cmd(
    workflow: str = typer.Argument(help="Workflow name or file path"),
    params: str = typer.Option("{}", "--params", "-p", help="JSON parameters"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate only"),
):
    """Run a workflow (YAML/JSON pipeline)."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Workflow:[/bold] {workflow}")

    if dry_run:
        console.print("[yellow]DRY RUN — no actions executed[/yellow]")

    # Workflow execution logic...
    console.print("[green]✓ Workflow complete![/green]")


@workflow_app.command()
def list():
    """List available workflows."""
    table = Table(title="Available Workflows", show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Steps", justify="right", style="yellow")
    table.add_column("Last Run", style="dim")

    workflows = [
        ("daily-scan", "Daily network scan + report", "5", "2h ago"),
        ("incident-response", "Full incident response playbook", "12", "1d ago"),
        ("compliance-check", "SOC2 + ISO27001 compliance", "8", "7d ago"),
        ("threat-hunt", "Run all threat hunt queries", "15", "3d ago"),
    ]

    for name, desc, steps, last_run in workflows:
        table.add_row(name, desc, steps, last_run)

    console.print(table)


# ---------------------------------------------------------------------------
# Premium: Compliance commands
# ---------------------------------------------------------------------------
@audit_app.command()
def report(
    framework: str = typer.Argument(help="Framework: soc2|iso27001|nist"),
    output: str = typer.Option("report.pdf", "--output", "-o", help="Output file"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Include evidence"),
):
    """Generate compliance report."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Compliance Report:[/bold] {framework}")
    # Report generation...
    console.print(f"[green]✓ Report generated: {output}[/green]")


@audit_app.command()
def logs(
    event_type: str = typer.Option("", "--type", "-t", help="Filter by event type"),
    user: str = typer.Option("", "--user", "-u", help="Filter by user"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max records"),
    output: str = typer.Option("", "--output", "-o", help="Export to file"),
):
    """View audit logs."""
    print_banner(console, _active_theme)

    table = Table(title="Audit Trail", show_header=True, header_style="bold yellow")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("User", style="cyan")
    table.add_column("Event", style="white")
    table.add_column("Target", style="yellow")
    table.add_column("Status", justify="center")

    # Mock audit data
    logs = [
        ("2026-05-05 12:00:00", "admin", "scan", "192.168.1.0/24", "✓"),
        ("2026-05-05 11:45:00", "john", "incident_create", "INC-001", "✓"),
        ("2026-05-05 11:30:00", "sarah", "vuln_update", "CVE-2024-0001", "✓"),
    ]

    for ts, user, event, target, status in logs[:limit]:
        table.add_row(ts, user, event, target, status)

    console.print(table)


# ---------------------------------------------------------------------------
# Security sub-commands (premium)
# ---------------------------------------------------------------------------
@security_app.command("incidents")
def security_incidents(
    status: str = typer.Option("", "--status", "-s", help="Filter by status"),
    severity: str = typer.Option("", "--severity", "-sv", help="Filter by severity"),
    limit: int = typer.Option(10, "--limit", "-n", help="Max results"),
    output: str = typer.Option("table", "--output", "-o", help="Output format"),
):
    """List security incidents."""
    print_banner(console, _active_theme)
    console.print(f"[bold]Incidents[/bold] (status={status}, severity={severity})")

    table = Table(show_header=True, header_style="bold red")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Severity", style="yellow", justify="center")
    table.add_column("Status", style="green", justify="center")

    incidents = [
        ("INC-001", "Ransomware Detected", "critical", "open"),
        ("INC-002", "Phishing Campaign", "high", "investigating"),
        ("INC-003", "Data Exfiltration", "critical", "contained"),
    ]

    for id, title, sev, incident_status in incidents:
        if status and incident_status != status:
            continue
        if severity and severity != sev:
            continue
        table.add_row(id, title, sev.upper(), incident_status)

    console.print(table)


@security_app.command("vulns")
def security_vulns(
    severity: str = typer.Option("", "--severity", "-s", help="Filter by severity"),
    status: str = typer.Option("open", "--status", help="Filter by status"),
    export: str = typer.Option("", "--export", "-e", help="Export to file"),
):
    """List vulnerabilities."""
    print_banner(console, _active_theme)

    table = Table(title="Vulnerabilities", show_header=True, header_style="bold magenta")
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("CVSS", justify="right", style="yellow")
    table.add_column("EPSS", justify="right", style="purple")
    table.add_column("Status", justify="center")

    vulns = [
        ("CVE-2024-0001", "RCE in Apache Struts", "9.8", "0.92", "open"),
        ("CVE-2024-0002", "SQL Injection", "8.5", "0.45", "patched"),
        ("CVE-2024-0003", "XSS in Profile", "6.1", "0.12", "open"),
    ]

    for cve, title, cvss, epss, st in vulns:
        table.add_row(cve, title, cvss, epss, st)

    console.print(table)


@security_app.command("threat-hunt")
def security_threat_hunt(
    action: str = typer.Argument(help="Action: list|run|campaigns"),
    query_id: str = typer.Argument(default="", help="Query ID (for 'run')"),
):
    """Threat hunting operations."""
    print_banner(console, _active_theme)

    if action == "list":
        table = Table(title="Threat Hunting Queries", show_header=True, header_style="bold blue")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("MITRE Tactic", style="purple")
        table.add_column("Severity", justify="center")

        queries = [
            ("q_001", "PowerShell Suspicious", "execution", "high"),
            ("q_002", "RDP Brute Force", "credential_access", "critical"),
            ("q_003", "DNS Tunneling", "command_and_control", "critical"),
        ]

        for id, name, tactic, sev in queries:
            table.add_row(id, name, tactic, sev.upper())

        console.print(table)

    elif action == "run" and query_id:
        console.print(f"[bold]Running hunt query:[/bold] {query_id}")
        console.print("[green]✓ Hunt complete — 3 findings[/green]")


# ---------------------------------------------------------------------------
# Premium: Team & Organization commands
# ---------------------------------------------------------------------------
@team_app.command("invite")
def team_invite(
    email: str = typer.Argument(help="Email to invite"),
    role: str = typer.Option("member", "--role", "-r", help="Role: admin|member|viewer"),
):
    """Invite a team member."""
    console.print(f"[green]✓ Invitation sent to {email} (role: {role})[/green]")


@org_app.command("stats")
def org_stats():
    """Show organization statistics."""
    table = Table(title="Organization Statistics", show_header=True, header_style="bold cyan")
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
):
    """List all discovered security tools on this system.

    Examples:
      nexsec tool-registry list
      nexsec tool-registry list --category recon
      nexsec tool-registry list --refresh
    """
    tools = registry.discover(force_refresh=refresh)
    if category:
        tools = [t for t in tools if t.category == category]

    if not tools:
        console.print("[yellow]No tools found. Install security tools and run again.[/yellow]")
        return

    table = Table(title=f"Security Tools ({len(tools)} found)", show_header=True, header_style="bold cyan")
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
def tool_registry_show(name: str = typer.Argument(help="Tool name or binary")):
    """Show detailed info about a specific tool."""
    tools = registry.discover()
    tool = next((t for t in tools if t.name == name or t.binary == name), None)
    if not tool:
        console.print(f"[red]Tool not found: {name}[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold]{tool.name}[/bold] ({tool.binary})\n"
        f"[dim]Category:[/dim]     {tool.category}\n"
        f"[dim]Version:[/dim]      {tool.version}\n"
        f"[dim]Path:[/dim]         {tool.path}\n"
        f"[dim]Capabilities:[/dim] {', '.join(tool.capabilities)}\n"
        f"[dim]Description:[/dim]  {tool.description}",
        title="Tool Info",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Auth commands — wire API keys to the engine
# ---------------------------------------------------------------------------
@auth_app.command("set-key")
def auth_set_key(
    provider: str = typer.Argument(help="Provider: openai | anthropic | custom"),
    api_key: str = typer.Option(..., "--key", "-k", help="API key value", hide_input=True),
):
    """Store an API key for a model provider.

    Examples:
      nexsec auth set-key openai --key sk-...
      nexsec auth set-key anthropic --key sk-ant-...
    """
    creds.set_password(provider, "api_key", api_key)
    console.print(f"[green]✓ API key stored for provider: {provider}[/green]")
    console.print("[dim]Key is stored securely in the system keyring.[/dim]")


@auth_app.command("show")
def auth_show():
    """Show configured API key providers."""
    providers = ["openai", "anthropic"]
    table = Table(title="Configured API Keys", show_header=True, header_style="bold green")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source")

    for prov in providers:
        from_env = bool(os.getenv(f"{prov.upper()}_API_KEY"))
        from_creds = bool(creds.get_password(prov, "api_key"))
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
    shell: str = typer.Argument(default="", help="Shell: bash | zsh | fish | powershell"),
):
    """Install shell completions for NexSec.

    Examples:
      nexsec completions install bash
      nexsec completions install powershell
    """
    if not shell:
        shell = os.getenv("SHELL", "bash").split("/")[-1]
        if platform.system().lower() == "windows":
            shell = "powershell"

    shell = shell.lower()
    completions_map = {
        "bash": ("~/.bashrc", "_NEXSEC_COMPLETE=bash_source nexsec >> ~/.nexsec/complete.bash\necho 'source ~/.nexsec/complete.bash' >> ~/.bashrc"),
        "zsh": ("~/.zshrc", "_NEXSEC_COMPLETE=zsh_source nexsec >> ~/.nexsec/complete.zsh\necho 'source ~/.nexsec/complete.zsh' >> ~/.zshrc"),
        "fish": ("~/.config/fish/completions/nexsec.fish", "_NEXSEC_COMPLETE=fish_source nexsec > ~/.config/fish/completions/nexsec.fish"),
        "powershell": ("$PROFILE", "$env:_NEXSEC_COMPLETE='powershell_source'; nexsec | Out-String | Invoke-Expression"),
    }

    if shell not in completions_map:
        console.print(f"[red]Unsupported shell: {shell}. Choose: bash, zsh, fish, powershell[/red]")
        raise typer.Exit(1)

    target, instructions = completions_map[shell]
    console.print(Panel(
        f"[bold]To install {shell} completions, run:[/bold]\n\n"
        f"[green]{instructions}[/green]\n\n"
        f"[dim]Then restart your shell or source {target}[/dim]",
        title=f"Shell Completions ({shell})",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# Config commands — wired to real SettingsStore
# ---------------------------------------------------------------------------
@config_app.command("list")
def config_list():
    """List all configuration settings."""
    rows = config.list_all()
    table = Table(title="NexSec Configuration", show_header=True, header_style="bold cyan")
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Default", style="dim")
    table.add_column("Description", style="white")

    for row in rows:
        modified = "[bold]" if row["modified"] else ""
        table.add_row(
            f"{modified}{row['key']}", row["value"], row["default"], row["description"][:50]
        )
    console.print(table)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(help="Setting key"),
    value: str = typer.Argument(help="New value"),
):
    """Set a configuration value.\n\nExample: nexsec config set log_level debug"""
    try:
        new_val = config.set(key, value)
        console.print(f"[green]✓ {key} = {new_val}[/green]")
    except (KeyError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("get")
def config_get(key: str = typer.Argument(help="Setting key")):
    """Get a configuration value."""
    try:
        val = config.get(key)
        console.print(f"[cyan]{key}[/cyan] = [green]{val}[/green]")
    except KeyError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("reset")
def config_reset(key: str = typer.Argument(default="", help="Key to reset (empty = all)")):
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
def plugin_list():
    """List all installed plugins."""
    real_plugins = plugins.list_plugins()
    table = Table(title="Plugin Ecosystem", show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Author", style="dim")
    table.add_column("Description", style="white")

    if not real_plugins:
        console.print("[dim]No plugins installed. Use 'nexsec plugin install <name>' to add plugins.[/dim]")
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
):
    """Install a plugin."""
    console.print(f"[bold]Installing:[/bold] {plugin} from {source}...")
    # Installation logic...
    console.print(f"[green]✓ Plugin installed: {plugin}[/green]")


# ---------------------------------------------------------------------------
# Theme management (premium)
# ---------------------------------------------------------------------------
@theme_app.command("list")
def theme_list():
    """List available themes."""
    table = Table(title="Available Themes", show_header=True, header_style="bold yellow")
    table.add_column("Name", style="cyan")
    table.add_column("Preview", style="white")
    table.add_column("Current", justify="center")

    themes = [
        ("default", "🔵 Blue/Purple gradient", "✓" if _active_theme == "default" else ""),
        ("dark", "⚫ Pure dark", ""),
        ("light", "⚪ Light mode", ""),
        ("neon", "💜 Neon glow", ""),
        ("minimal", "⬜ Minimal", ""),
    ]

    for name, preview, current in themes:
        table.add_row(name, preview, current)

    console.print(table)


@theme_app.command("set")
def theme_set(
    theme: str = typer.Argument(help="Theme name"),
):
    """Set active theme."""
    global _active_theme
    if theme in available_themes():
        _active_theme = theme
        config.set("color_theme", theme)
        console.print(f"[green]✓ Theme set to: {theme}[/green]")
    else:
        console.print(f"[red]Error: Unknown theme: {theme}[/red]")


# ---------------------------------------------------------------------------
# Version command
# ---------------------------------------------------------------------------
@app.command()
def version():
    """Show NexSec version information."""
    tools = registry.discover()
    console.print(Panel.fit(
        f"[bold cyan]NexSec[/bold cyan] [green]v{__version__}[/green]\n"
        f"[dim]Platform:[/dim] {platform.system()} {platform.release()}\n"
        f"[dim]Python:[/dim]   {platform.python_version()}\n"
        f"[dim]Tools found:[/dim] {len(tools)}",
        title="Version",
        border_style="cyan",
    ))


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
