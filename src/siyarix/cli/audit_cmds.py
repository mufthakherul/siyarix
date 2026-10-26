# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit trail CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from siyarix.audit_log import audit
from siyarix.branding import print_banner, resolve_theme

console = Console()

audit_app = typer.Typer(help="📋 Audit trail & compliance logs")


@audit_app.command()
def report(
    framework: str = typer.Argument(help="Framework: soc2|iso27001|nist"),
    output: str = typer.Option("report.md", "--output", "-o", help="Output file"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Include evidence"),
    days: int = typer.Option(30, "--days", help="Number of days to include"),
) -> None:
    """Generate compliance report."""
    print_banner(console, resolve_theme(None))
    console.print(f"[bold]Compliance Report:[/bold] {framework}")

    ext = Path(output).suffix.lower()
    if ext in {".json", ".csv"}:
        fmt = ext.lstrip(".")
        audit.export(export_format=fmt, filepath=output, days=days)
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
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
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
            f"- {evt.get('timestamp')} | {evt.get('user')} | "
            f"{evt.get('event_type')} | {evt.get('target')}"
        )

    if detailed and events:
        lines.append("")
        lines.append("## Event Details")
        for evt in events[-20:]:
            lines.append(json.dumps(evt, indent=2))

    Path(output).write_text("\n".join(lines), encoding="utf-8")
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
    if output:
        ext = Path(output).suffix.lower()
        if ext not in {".json", ".csv"}:
            console.print("[red]Unsupported export format. Use .json or .csv.[/red]")
            raise typer.Exit(1)
        audit.export(export_format=ext.lstrip("."), filepath=output, days=days)
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


@audit_app.command("show")
@audit_app.command("list")
def audit_show(
    event_type: str = typer.Option("", "--type", "-t", help="Filter by event type"),
    user: str = typer.Option("", "--user", "-u", help="Filter by user"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max records"),
    output: str = typer.Option("", "--output", "-o", help="Export to file"),
    severity: str = typer.Option("", "--severity", help="Filter by severity"),
    days: int = typer.Option(30, "--days", help="Number of days to include"),
) -> None:
    """Show audit logs (alias for logs)."""
    logs(
        event_type=event_type,
        user=user,
        limit=limit,
        output=output,
        severity=severity,
        days=days,
    )


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify audit log chain integrity."""
    result = audit.verify_chain()
    if result.get("valid"):
        console.print("[green]✓ Audit chain integrity verified[/green]")
    else:
        console.print(f"[red]Chain integrity failed at {result.get('broken_at')}[/red]")
