# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cache management CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

console = Console()

cache_app = typer.Typer(help="💾 Cache management")


@cache_app.command("status")
def cache_status() -> None:
    """Show cache statistics."""
    from siyarix.cache_manager import cache_manager

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
    from siyarix.cache_manager import cache_manager

    count = cache_manager.clear()
    console.print(f"[green]Cache cleared: {count} entries[/green]")
