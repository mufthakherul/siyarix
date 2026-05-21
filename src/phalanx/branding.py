"""Phalanx Branding — Premium Design System.

Seven curated themes, rich banner, severity styles, mode dispatcher display,
and design token helpers for a consistent terminal UX.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Theme aliases (backwards compat)
# ---------------------------------------------------------------------------
_THEME_ALIASES: dict[str, str] = {
    "monokai": "synthwave",
    "solarized": "arctic",
    "cyberpunk": "cyber-noir",
    "hacker": "matrix",
    "red": "bloodmoon",
    "blue": "arctic",
    "gold": "goldenrod",
    "dark": "cyber-noir",
    "light": "arctic",
    "neon": "synthwave",
    "minimal": "eclipse",
    "system": "cyber-noir",
}

# ---------------------------------------------------------------------------
# Severity severity_styles — one per theme
# ---------------------------------------------------------------------------
_SEVERITY_STYLES: dict[str, dict[str, str]] = {
    # ── Cyber Noir ── (default: dark blue-grey with electric cyan accents)
    "cyber-noir": {
        "critical": "bold bright_red",
        "high": "bold red",
        "medium": "bright_yellow",
        "low": "bright_cyan",
        "info": "bright_black",
        "accent": "bright_cyan",
        "primary": "cyan",
        "muted": "bright_black",
        "success": "bright_green",
        "border": "cyan",
    },
    # ── Matrix ── (bright green on black, classic terminal hacker)
    "matrix": {
        "critical": "bold bright_red",
        "high": "bold red",
        "medium": "bright_yellow",
        "low": "bright_green",
        "info": "green",
        "accent": "bright_green",
        "primary": "green",
        "muted": "dark_green",
        "success": "bright_green",
        "border": "green",
    },
    # ── Bloodmoon ── (red and black, aggressive offensive ops aesthetic)
    "bloodmoon": {
        "critical": "bold bright_red",
        "high": "bright_red",
        "medium": "red",
        "low": "dark_orange",
        "info": "bright_black",
        "accent": "bright_red",
        "primary": "red",
        "muted": "bright_black",
        "success": "dark_orange",
        "border": "red",
    },
    # ── Arctic ── (cool blue-white, clean enterprise / light mode)
    "arctic": {
        "critical": "bold red",
        "high": "red",
        "medium": "dark_orange",
        "low": "blue",
        "info": "bright_black",
        "accent": "bright_blue",
        "primary": "blue",
        "muted": "grey70",
        "success": "green",
        "border": "bright_blue",
    },
    # ── Goldenrod ── (gold and amber, premium warm-tone SOC aesthetic)
    "goldenrod": {
        "critical": "bold bright_red",
        "high": "red",
        "medium": "bright_yellow",
        "low": "yellow",
        "info": "bright_black",
        "accent": "bright_yellow",
        "primary": "yellow",
        "muted": "dark_orange",
        "success": "bright_green",
        "border": "yellow",
    },
    # ── Eclipse ── (clean monochrome, minimal distraction, CI-safe)
    "eclipse": {
        "critical": "bold",
        "high": "bold",
        "medium": "",
        "low": "",
        "info": "dim",
        "accent": "bold",
        "primary": "white",
        "muted": "dim",
        "success": "bold",
        "border": "white",
    },
    # ── Synthwave ── (purple/pink neon, cyberpunk retro)
    "synthwave": {
        "critical": "bold bright_magenta",
        "high": "bright_red",
        "medium": "bright_yellow",
        "low": "bright_cyan",
        "info": "magenta",
        "accent": "bright_magenta",
        "primary": "magenta",
        "muted": "purple4",
        "success": "bright_cyan",
        "border": "bright_magenta",
    },
}

# The canonical default theme
_DEFAULT_THEME = "cyber-noir"

# ---------------------------------------------------------------------------
# Severity icons
# ---------------------------------------------------------------------------
_SEVERITY_ICONS: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "success": "✅",
    "warning": "⚠️ ",
    "finding": "🔍",
}

# ---------------------------------------------------------------------------
# Premium ASCII banner — Phalanx v2
# ---------------------------------------------------------------------------
_BANNER = r"""
    ▟█████▙      ▟████▙     ▟█████▙   ███▙  ▟███   ███    ▟█████▙     ▟█████▙    ▟███████▙   ███       ███
   ███▀  ▀▀     ███▀  ▀██   ███▀  ▀▀   ████▙▟████   ███   ███▀  ▀▀    ███▀  ▀▀    ███▀▀▀▀▀▀   ███       ███
   ███          ███    ███  ▀█████▙    ███▀███▀██   ███   ███         ▀█████▙     ███████▙    ███       ███
   ███▄  ▄▄     ███▄  ▄██   ▄▄  ▀███   ███ ▀█▀ ██   ███   ███▄  ▄▄    ▄▄  ▀███    ███▄▄▄▄▄▄   ███▄▄▄▄▄  ███▄▄▄▄▄
    ▀█████▀      ▀████▀     ▀█████▀    ███     ██   ███    ▀█████▀    ▀█████▀     ▀███████▀   ▀███████  ▀███████

                             🆂 🅴 🅲 🆄 🆁 🅸 🆃 🆈   🅰 🅶 🅴 🅽 🆃   🅲 🅻 🅸
"""

# ---------------------------------------------------------------------------
# Mode dispatcher table data
# ---------------------------------------------------------------------------
_MODES: list[dict[str, str]] = [
    {
        "num": "1",
        "key": "[1]",
        "name": "Interactive Shell",
        "cmd": "phalanx",
        "shortcut": "/1",
        "desc": "AI-powered interactive REPL (default)",
    },
    {
        "num": "2",
        "key": "[2]",
        "name": "AI Conversational",
        "cmd": "phalanx chat",
        "shortcut": "/2",
        "desc": "Multi-turn AI cyber assistant",
    },
    {
        "num": "3",
        "key": "[3]",
        "name": "Direct Command",
        "cmd": 'phalanx run "scan target.com"',
        "shortcut": "/3",
        "desc": "One-shot NL command execution",
    },
    {
        "num": "4",
        "key": "[4]",
        "name": "Autonomous Agent",
        "cmd": 'phalanx agent --goal "..."',
        "shortcut": "/4",
        "desc": "Goal-driven autonomous operation",
    },
    {
        "num": "5",
        "key": "[5]",
        "name": "Workflow Automation",
        "cmd": "phalanx workflow run pentest.yaml",
        "shortcut": "/5",
        "desc": "YAML DAG workflow execution",
    },
    {
        "num": "6",
        "key": "[6]",
        "name": "TUI Dashboard",
        "cmd": "phalanx dashboard",
        "shortcut": "/6",
        "desc": "Live security operations dashboard",
    },
    {
        "num": "7",
        "key": "[7]",
        "name": "Guided Wizard",
        "cmd": "phalanx wizard",
        "shortcut": "/7",
        "desc": "Step-by-step guided operations",
    },
    {
        "num": "8",
        "key": "[8]",
        "name": "Team Collaboration",
        "cmd": "phalanx team --session ops-room-1",
        "shortcut": "/8",
        "desc": "Shared real-time session",
    },
    {
        "num": "9",
        "key": "[9]",
        "name": "Headless API",
        "cmd": "phalanx serve --port 8080",
        "shortcut": "/9",
        "desc": "REST/WebSocket API server",
    },
]


# ---------------------------------------------------------------------------
# Theme resolution helpers
# ---------------------------------------------------------------------------


def resolve_theme(theme_name: str | None) -> str:
    """Resolve a theme name (including aliases) to a canonical theme key."""
    if not theme_name:
        return _DEFAULT_THEME
    raw = theme_name.strip().lower()
    mapped = _THEME_ALIASES.get(raw, raw)
    return mapped if mapped in _SEVERITY_STYLES else _DEFAULT_THEME


def canonical_theme(theme_name: str | None) -> str | None:
    """Resolve theme aliases and return canonical name, else None."""
    if not theme_name:
        return None
    raw = theme_name.strip().lower()
    mapped = _THEME_ALIASES.get(raw, raw)
    return mapped if mapped in _SEVERITY_STYLES else None


def available_themes() -> list[str]:
    """Return all available theme names, sorted."""
    return sorted(_SEVERITY_STYLES.keys())


def design_token(theme: str, token: str) -> str:
    """Get a design token (accent, primary, muted, border, success) for a theme."""
    safe = resolve_theme(theme)
    return _SEVERITY_STYLES[safe].get(token, "")


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def severity_style(theme: str, severity: str) -> str:
    """Return Rich style string for a severity level in the given theme."""
    safe_theme = resolve_theme(theme)
    return _SEVERITY_STYLES[safe_theme].get(severity.lower(), "")


def severity_label(theme: str, severity: str) -> str:
    """Return a formatted severity label with icon and Rich markup."""
    sev = severity.lower()
    icon = _SEVERITY_ICONS.get(sev, "⚪")
    text = sev.upper()
    style = severity_style(theme, sev)
    safe_theme = resolve_theme(theme)
    if safe_theme == "eclipse":
        return text
    if style:
        return f"{icon} [{style}]{text}[/{style}]"
    return f"{icon} {text}"


# ---------------------------------------------------------------------------
# Banner printer
# ---------------------------------------------------------------------------


def print_banner(
    console: Console,
    theme: str,
    subtitle: str = "Enterprise Cybersecurity Operations Platform",
) -> None:
    """Print the Phalanx premium banner to the console."""
    safe_theme = resolve_theme(theme)
    style_map = _SEVERITY_STYLES[safe_theme]
    color = style_map.get("primary", "cyan")
    accent = style_map.get("accent", "bright_white")
    border = style_map.get("border", "cyan")

    try:
        from importlib.metadata import version as _pkg_version

        _ver = _pkg_version("phalanx")
    except Exception as exc:
        logger.debug("Failed to resolve package version: %s", exc)
        _ver = "2.0.0"

    import platform as _platform

    platform_tag = _platform.system()
    python_tag = _platform.python_version()

    console.print(
        Panel.fit(
            f"[{color}]{_BANNER}[/{color}]\n"
            f"[bold {accent}]{subtitle}[/bold {accent}]\n"
            f"[dim]v{_ver} · {platform_tag} · Python {python_tag} · Theme: {safe_theme}[/dim]",
            title="[bold]NEXSEC[/bold]",
            subtitle=f"[dim]AI-Native Cyber Operations · v{_ver}[/dim]",
            border_style=border,
            padding=(1, 4),
        )
    )


# ---------------------------------------------------------------------------
# Mode dispatcher display
# ---------------------------------------------------------------------------


def print_mode_dispatcher(console: Console, theme: str, active_mode_num: str = "1") -> None:
    """Print the Phalanx Mode Dispatcher table."""
    safe_theme = resolve_theme(theme)
    styles = _SEVERITY_STYLES[safe_theme]
    primary = styles.get("primary", "cyan")
    accent = styles.get("accent", "bright_cyan")
    muted = styles.get("muted", "bright_black")
    border = styles.get("border", "cyan")

    table = Table(
        show_header=True,
        header_style=f"bold {primary}",
        border_style=border,
        title=f"[bold {accent}]⚡ NEXSEC MODE DISPATCHER[/bold {accent}]",
        title_justify="center",
        padding=(0, 1),
    )
    table.add_column("Key", style="bold", width=5, justify="center")
    table.add_column("Mode", width=22)
    table.add_column("Command", style="green")
    table.add_column("Description", style=f"{muted}")

    for mode in _MODES:
        is_active = mode["num"] == active_mode_num
        key_str = f"[bold {accent}]{mode['key']}[/bold {accent}]" if is_active else f"[{muted}]{mode['key']}[/{muted}]"
        name_str = (
            f"[bold {accent}]▶ {mode['name']}[/bold {accent}]"
            if is_active
            else f"[{primary}]{mode['name']}[/{primary}]"
        )
        table.add_row(key_str, name_str, mode["cmd"], mode["desc"])

    console.print(table)
    console.print(
        f"[{muted}]  Switch with /1–/9 inside chat · Current: [bold]{active_mode_num}[/bold][/{muted}]"
    )


# ---------------------------------------------------------------------------
# Theme preview
# ---------------------------------------------------------------------------


def _sample_command(theme: str) -> str:
    if resolve_theme(theme) == "eclipse":
        return "phalanx scan 10.0.0.5 --mode registry"
    return "phalanx scan 10.0.0.5 --mode integrated"


def print_theme_preview(console: Console, theme: str) -> None:
    """Render a compact appearance preview for the selected theme."""
    safe_theme = resolve_theme(theme)
    styles = _SEVERITY_STYLES[safe_theme]
    border = styles.get("border", "cyan")
    accent = styles.get("accent", "bright_cyan")
    primary = styles.get("primary", "cyan")

    console.print(
        Panel.fit(
            f"[bold]Theme:[/bold] [{accent}]{safe_theme}[/{accent}]\n"
            f"[bold]Accent:[/bold] [{accent}]■■■[/{accent}]  "
            f"[bold]Primary:[/bold] [{primary}]■■■[/{primary}]  "
            f"[bold]Border:[/bold] [{border}]■■■[/{border}]\n"
            f"[bold]Sample:[/bold] [green]{_sample_command(safe_theme)}[/green]\n"
            f"[bold]Severities:[/bold]  "
            + "  ".join(severity_label(safe_theme, s) for s in ("info", "low", "medium", "high", "critical")),
            title=f"[bold {accent}]Theme Preview — {safe_theme}[/bold {accent}]",
            border_style=border,
        )
    )

    table = Table(title="UI Surface Samples", header_style=f"bold {primary}", border_style=border)
    table.add_column("Surface", style=primary)
    table.add_column("Example", style="white")
    table.add_row("Banner", "NEXSEC CLI v2.0")
    table.add_row("Prompt", "phalanx> scan 10.0.0.5")
    table.add_row("Command", _sample_command(safe_theme))
    table.add_row("Info", severity_label(safe_theme, "info"))
    table.add_row("Warning", severity_label(safe_theme, "medium"))
    table.add_row("Error", severity_label(safe_theme, "critical"))
    table.add_row("Success", severity_label(safe_theme, "success"))
    console.print(table)


# ---------------------------------------------------------------------------
# Compact mode switcher bar (for prompt display)
# ---------------------------------------------------------------------------


def render_mode_bar(theme: str, active_mode_num: str = "1") -> Text:
    """Render a compact single-line mode switcher bar as a Rich Text object."""
    safe_theme = resolve_theme(theme)
    styles = _SEVERITY_STYLES[safe_theme]
    accent = styles.get("accent", "bright_cyan")
    muted = styles.get("muted", "bright_black")

    text = Text()
    for i, mode in enumerate(_MODES):
        is_active = mode["num"] == active_mode_num
        label = f"[{mode['num']}]{mode['name'].split()[0]}"
        if is_active:
            text.append(f" {label} ", style=f"bold {accent}")
        else:
            text.append(f" {label} ", style=muted)
        if i < len(_MODES) - 1:
            text.append("·", style=muted)
    return text
