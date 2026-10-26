# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool-registry CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from siyarix.registry_factory import make_tool_registry

console = Console()

tool_registry_app = typer.Typer(help="🛠 Tool discovery & registry")

_registry: Any = None


def bind_registry(registry: Any) -> None:
    """Inject the process-wide tool registry used by list commands."""
    global _registry
    _registry = registry


def _reg() -> Any:
    if _registry is not None:
        return _registry
    return make_tool_registry()


@tool_registry_app.command("providers")
def list_providers() -> None:
    """List configured model providers (order of preference)."""
    from siyarix.providers.manager import ProviderManager

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
    registry = _reg()
    registry.discover_from_path()
    from siyarix.registry import ToolCategory as TC

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
