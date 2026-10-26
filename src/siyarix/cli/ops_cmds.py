# SPDX-License-Identifier: AGPL-3.0-or-later
"""Health / metrics / CI / doctor CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from siyarix.async_utils import run_async
from siyarix.health import get_health
from siyarix.metrics import get_metrics

# Bound at register time from the CLI god-module.
_console: Console | None = None
_config: Any = None


def _c() -> Console:
    assert _console is not None
    return _console


def health_check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
) -> None:
    """Run system health checks."""
    status = run_async(get_health().check_all())
    if output == "json":
        _c().print(json.dumps(status.to_dict(), indent=2))
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

    _c().print(table)


def metrics_show(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json|prometheus"),
    export: str = typer.Option("", "--export", "-e", help="Export metrics to file"),
) -> None:
    """Show metrics from the current session."""
    metrics = get_metrics()

    if output == "prometheus":
        data = metrics.to_prometheus()
    elif output == "json":
        data = json.dumps(metrics.to_dict(), indent=2)
    else:
        data = None

    if data:
        _c().print(data)
        if export:
            Path(export).write_text(data, encoding="utf-8")
        return

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

    _c().print(table)


def ci_gate(
    allow_degraded: bool = typer.Option(
        False, "--allow-degraded", help="Pass even if health is degraded"
    ),
) -> None:
    """CI gate — verify system health and critical findings before deployment."""
    store = None
    try:
        from siyarix.offline_store import OfflineStore

        store = OfflineStore()
    except ModuleNotFoundError:
        _c().print("[yellow]Offline store not available — skipping finding check[/yellow]")

    health = run_async(get_health().check_all())

    if health.state.value == "unhealthy":
        _c().print("[red]Health check failed: UNHEALTHY[/red]")
        raise typer.Exit(2)

    if health.state.value == "degraded" and not allow_degraded:
        _c().print("[yellow]Health check is DEGRADED (use --allow-degraded to pass).[/yellow]")
        raise typer.Exit(2)

    if store:
        critical = store.search_findings(severity="critical", limit=1)
        if critical:
            _c().print("[red]Critical findings detected. Failing gate.[/red]")
            raise typer.Exit(3)

    _c().print("[green]✓ CI gate passed[/green]")


def production_check(
    output: str = typer.Option("table", "--output", "-o", help="Output: table|json"),
    strict: bool = typer.Option(False, "--strict", help="Exit nonzero when any check is warn/fail"),
) -> None:
    """Production readiness checklist (security gates, offline posture, config).

    Alias: ``siyarix doctor``.
    """
    from siyarix.cli.production_check import run_production_check

    run_production_check(output=output, strict=strict, console=_c(), config=_config)


def register_ops_commands(app: typer.Typer, *, console: Console, config: Any) -> None:
    """Attach health / metrics / ci-gate / doctor commands to *app*."""
    global _console, _config
    _console = console
    _config = config

    app.command(name="health")(health_check)
    app.command(name="metrics")(metrics_show)
    app.command(name="ci-gate")(ci_gate)
    app.command(name="production-check")(production_check)
    app.command(name="doctor")(production_check)
