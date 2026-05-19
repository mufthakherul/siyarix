"""CLI branding and severity style helpers (CA-7.1)."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import logging

logger = logging.getLogger(__name__)

_THEME_ALIASES = {
    "monokai": "neon",
    "solarized": "dark",
}

_SEVERITY_STYLES: dict[str, dict[str, str]] = {
    "system": {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    },
    "default": {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    },
    "dark": {
        "critical": "bold red",
        "high": "bright_red",
        "medium": "bright_yellow",
        "low": "bright_cyan",
        "info": "bright_black",
    },
    "light": {
        "critical": "bold red",
        "high": "red",
        "medium": "magenta",
        "low": "blue",
        "info": "black",
    },
    "minimal": {
        "critical": "",
        "high": "",
        "medium": "",
        "low": "",
        "info": "",
    },
    "neon": {
        "critical": "bold bright_magenta",
        "high": "bright_red",
        "medium": "bright_yellow",
        "low": "bright_green",
        "info": "bright_cyan",
    },
}

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_BANNER = r"""
    ▟█████▙      ▟████▙     ▟█████▙   ███▙  ▟███   ███    ▟█████▙     ▟█████▙    ▟███████▙   ███       ███
   ███▀  ▀▀     ███▀  ▀██   ███▀  ▀▀   ████▙▟████   ███   ███▀  ▀▀    ███▀  ▀▀    ███▀▀▀▀▀▀   ███       ███
   ███          ███    ███  ▀█████▙    ███▀███▀██   ███   ███         ▀█████▙     ███████▙    ███       ███
   ███▄  ▄▄     ███▄  ▄██   ▄▄  ▀███   ███ ▀█▀ ██   ███   ███▄  ▄▄    ▄▄  ▀███    ███▄▄▄▄▄▄   ███▄▄▄▄▄  ███▄▄▄▄▄
    ▀█████▀      ▀████▀     ▀█████▀    ███     ██   ███    ▀█████▀    ▀█████▀     ▀███████▀   ▀███████  ▀███████

                             🆂 🅴 🅲 🆄 🆁 🅸 🆃 🆈   🅰 🅶 🅴 🅽 🆃   🅲 🅻 🅸
"""


def resolve_theme(theme_name: str | None) -> str:
    if not theme_name:
        return "default"
    raw = theme_name.strip().lower()
    mapped = _THEME_ALIASES.get(raw, raw)
    return mapped if mapped in _SEVERITY_STYLES else "default"


def canonical_theme(theme_name: str | None) -> str | None:
    """Resolve theme aliases and return canonical theme name, else None."""
    if not theme_name:
        return None
    raw = theme_name.strip().lower()
    mapped = _THEME_ALIASES.get(raw, raw)
    return mapped if mapped in _SEVERITY_STYLES else None


def available_themes() -> list[str]:
    return sorted(_SEVERITY_STYLES.keys())


def _sample_command(theme: str) -> str:
    if resolve_theme(theme) == "minimal":
        return "siyarix scan 10.0.0.5 --mode registry"
    return "siyarix scan 10.0.0.5 --mode integrated"


def severity_style(theme: str, severity: str) -> str:
    safe_theme = resolve_theme(theme)
    return _SEVERITY_STYLES[safe_theme].get(severity.lower(), "")


def severity_label(theme: str, severity: str) -> str:
    sev = severity.lower()
    icon = _SEVERITY_ICONS.get(sev, "⚪")
    text = sev.upper()
    style = severity_style(theme, sev)
    safe_theme = resolve_theme(theme)
    if safe_theme == "minimal":
        return text
    if style:
        return f"{icon} [{style}]{text}[/{style}]"
    return f"{icon} {text}"


def print_banner(
    console: Console, theme: str, subtitle: str = "Enterprise Security Operations Platform"
) -> None:
    safe_theme = resolve_theme(theme)
    color = "cyan"
    accent = "bright_white"

    if safe_theme == "neon":
        color = "bright_magenta"
        accent = "bright_cyan"
    elif safe_theme == "dark":
        color = "bright_blue"
        accent = "bright_white"
    elif safe_theme == "light":
        color = "blue"
        accent = "black"
    elif safe_theme == "minimal":
        color = "white"
        accent = "white"

    try:
        from importlib.metadata import version as _pkg_version

        _ver = _pkg_version("siyarix")
    except Exception as exc:
        logger.debug("Failed to resolve package version: %s", exc)
        _ver = "1.2.0"

    console.print(
        Panel.fit(
            f"[{color}]{_BANNER}[/{color}]\n[bold {accent}]{subtitle}[/bold {accent}]",
            title="[bold]SIYARIX[/bold]",
            subtitle=f"[dim]v{_ver}[/dim]",
            border_style=color,
            padding=(1, 4),
        )
    )


def print_theme_preview(console: Console, theme: str) -> None:
    """Render a compact appearance preview for the selected theme."""
    safe_theme = resolve_theme(theme)
    console.print(
        Panel.fit(
            f"[bold]Theme:[/bold] {safe_theme}\n"
            f"[bold]Title:[/bold] [cyan]NexSec[/cyan]\n"
            f"[bold]Text:[/bold] This is a sample paragraph to evaluate readability.\n"
            f"[bold]Shell:[/bold] [green]{_sample_command(safe_theme)}[/green]\n"
            f"[bold]Status:[/bold] {severity_label(safe_theme, 'info')} {severity_label(safe_theme, 'low')} "
            f"{severity_label(safe_theme, 'medium')} {severity_label(safe_theme, 'high')} {severity_label(safe_theme, 'critical')}",
            title="Appearance Preview",
            border_style="cyan" if safe_theme != "minimal" else "white",
        )
    )

    table = Table(title="UI Surface Samples", header_style="bold cyan")
    table.add_column("Surface", style="cyan")
    table.add_column("Example", style="white")
    table.add_row("Banner", "SIYARIX CLI")
    table.add_row("Prompt", "siyarix> scan 10.0.0.5")
    table.add_row("Command", _sample_command(safe_theme))
    table.add_row("Info", severity_label(safe_theme, "info"))
    table.add_row("Warning", severity_label(safe_theme, "medium"))
    table.add_row("Error", severity_label(safe_theme, "critical"))
    table.add_row("Markdown", "# Heading\n\n- bullet\n- list")
    console.print(table)
