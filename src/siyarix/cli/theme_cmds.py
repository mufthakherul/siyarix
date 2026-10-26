# SPDX-License-Identifier: AGPL-3.0-or-later
"""Theme customization CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

from collections.abc import Callable

import typer
from rich.console import Console
from rich.table import Table

from siyarix.branding import available_themes, resolve_theme
from siyarix.config import SettingsStore

console = Console()
config = SettingsStore()

theme_app = typer.Typer(help="🎨 Theme customization")

# Optional sync hook so the CLI god-module can keep its in-process theme cache fresh.
_on_theme_set: Callable[[str], None] | None = None


def bind_theme_sync(on_set: Callable[[str], None]) -> None:
    """Register a callback invoked when ``theme set`` succeeds."""
    global _on_theme_set
    _on_theme_set = on_set


@theme_app.command("list")
def theme_list() -> None:
    """List available color themes."""
    themes = available_themes()
    active = resolve_theme(config.get("color_theme") or "default")
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
    try:
        config.set("color_theme", name)
        if _on_theme_set is not None:
            _on_theme_set(name)
        console.print(f"[green]Theme set to: {name}[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to set theme: {exc}[/red]")


@theme_app.command("preview")
@theme_app.command("appearance")
def theme_preview(
    name: str = typer.Argument(default="", help="Theme to preview (optional)"),
) -> None:
    """Preview the current or selected theme appearance."""
    from siyarix.branding import print_theme_preview

    selected = name or config.get("color_theme") or "default"
    print_theme_preview(console, selected)
