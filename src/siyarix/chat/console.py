"""Shared Rich Console instance for the Chat REPL.

Provides a feature-rich console with Markdown rendering, syntax highlighting,
severity-styled reporting, table/panel helpers, and a live status indicator.
"""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.status import Status
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.box import ROUNDED, HEAVY, MINIMAL, SIMPLE
from typing import Any

console = Console(highlight=True)

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold bright_red on #1a0000",
    "high": "bold red",
    "medium": "bright_yellow",
    "low": "bright_blue",
    "info": "cyan",
    "success": "bold bright_green",
    "warning": "bold bright_yellow",
    "debug": "dim white",
}

_MODE_BORDER_COLORS: dict[str, str] = {
    "autonomous": "magenta",
    "integrated": "cyan",
    "offline": "yellow",
    "registry": "yellow",
    "stealth": "red",
    "verbose": "green",
    "quiet": "bright_black",
    "redteam": "bold red",
    "blueteam": "bold blue",
    "compliance": "yellow",
    "audit": "magenta",
    "expert": "cyan",
    "beginner": "green",
    "interactive": "cyan",
    "batch": "magenta",
}


def mode_border(mode: str) -> str:
    return _MODE_BORDER_COLORS.get(mode, "cyan")


def severity_style(severity: str) -> str:
    return _SEVERITY_STYLES.get(severity.lower(), "white")


def print_severity(severity: str, text: str) -> None:
    console.print(f"[{severity_style(severity)}]{text}[/{severity_style(severity)}]")


def print_error(text: str) -> None:
    console.print(f"[bold red]✗ {text}[/bold red]")


def print_warning(text: str) -> None:
    console.print(f"[bold yellow]⚠ {text}[/bold yellow]")


def print_info(text: str) -> None:
    console.print(f"[cyan]ℹ {text}[/cyan]")


def print_success(text: str) -> None:
    console.print(f"[bold green]✓ {text}[/bold green]")


def panel_response(
    text: str,
    mode: str = "integrated",
    title: str = "◆ Siyarix",
    syntax_theme: str = "monokai",
) -> Panel:
    border = mode_border(mode)
    return Panel(
        Markdown(text, code_theme=syntax_theme),
        title=f"[bold {border}]{title}[/bold {border}]",
        border_style=border,
        padding=(0, 2),
        box=ROUNDED,
    )


def table_from_dicts(
    rows: list[dict[str, Any]],
    title: str = "",
    header_style: str = "bold cyan",
    show_header: bool = True,
) -> Table:
    if not rows:
        return Table(title=title)
    table = Table(title=title, header_style=header_style, show_header=show_header, box=SIMPLE)
    for key in rows[0]:
        table.add_column(key.replace("_", " ").title(), style="white", no_wrap=(len(rows) < 50))
    for row in rows:
        table.add_row(*[str(row.get(k, "")) for k in rows[0]])
    return table


def tree_from_dict(data: dict[str, Any], name: str = "root") -> Tree:
    tree = Tree(f"[bold]{name}[/bold]")
    for key, value in data.items():
        if isinstance(value, dict):
            subtree = tree.add(f"[cyan]{key}[/cyan]")
            for k, v in value.items():
                subtree.append(f"[white]{k}[/white]: [dim]{v}[/dim]")
        elif isinstance(value, list):
            subtree = tree.add(f"[cyan]{key}[/cyan] ([dim]{len(value)} items[/dim])")
            for item in value[:20]:
                subtree.append(str(item)[:80])
            if len(value) > 20:
                subtree.append(f"[dim]... and {len(value) - 20} more[/dim]")
        else:
            tree.append(f"[cyan]{key}[/cyan]: [white]{value}[/white]")
    return tree


def status_spinner(text: str = "Working...") -> Status:
    return console.status(f"[bold cyan]{text}[/bold cyan]", spinner="dots")


def progress_bar(description: str = "Processing") -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


__all__ = [
    "console",
    "mode_border",
    "severity_style",
    "print_severity",
    "print_error",
    "print_warning",
    "print_info",
    "print_success",
    "panel_response",
    "table_from_dicts",
    "tree_from_dict",
    "status_spinner",
    "progress_bar",
    "ROUNDED",
    "HEAVY",
    "MINIMAL",
    "SIMPLE",
]
