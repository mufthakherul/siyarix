# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compliance CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

console = Console()

compliance_app = typer.Typer(help="Compliance evidence collection and assessment.")


@compliance_app.command("run")
def compliance_run(
    framework: str = typer.Argument(..., help="Compliance framework (e.g., SOC2, NIST, GDPR)"),
    target: str = typer.Argument(..., help="Target to assess"),
) -> None:
    """Run a compliance assessment."""
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
    from siyarix.compliance import FRAMEWORK_METADATA, ComplianceEngine

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
