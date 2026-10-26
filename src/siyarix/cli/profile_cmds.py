# SPDX-License-Identifier: AGPL-3.0-or-later
"""Profile / palette / render-cmd CLI (extracted from the CLI god-module)."""

from __future__ import annotations

import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from siyarix.chat import CROSS_PLATFORM_COMMANDS, CommandProfile, CommandProfileStore

console = Console()

profile_app = typer.Typer(help="👤 Profile & workspace management")


@profile_app.command("save-cmd")
def profile_save_cmd(
    name: str = typer.Argument(..., help="Profile name"),
    command: str = typer.Argument(..., help="Command to save"),
) -> None:
    """Save a reusable command profile."""
    store = CommandProfileStore()
    p = CommandProfile(name=name, command=command)
    store.save(p)
    console.print(f"[green]✓ Saved command profile: {name}[/green]")


@profile_app.command("list-cmds")
def profile_list_cmds() -> None:
    """List saved command profiles."""
    store = CommandProfileStore()
    rows = store.list_credentials()
    if not rows:
        console.print("[dim]No saved command profiles.[/dim]")
        return
    table = Table(title="Saved Command Profiles", header_style="bold cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Command", style="white")
    table.add_column("Created", style="dim")
    for p in rows:
        table.add_row(p.name, p.command, p.created_at or "")
    console.print(table)


@profile_app.command("list")
def profile_list_alias() -> None:
    """List saved command profiles (alias for list-cmds)."""
    profile_list_cmds()


@profile_app.command("rm-cmd")
def profile_rm_cmd(name: str = typer.Argument(..., help="Profile name to remove")) -> None:
    """Remove a saved command profile."""
    store = CommandProfileStore()
    ok = store.delete(name)
    if ok:
        console.print(f"[green]✓ Removed {name}[/green]")
    else:
        console.print(f"[red]Profile not found: {name}[/red]")


def palette() -> None:
    """Open an interactive command palette (uses prompt_toolkit if installed)."""
    store = CommandProfileStore()
    intents = sorted(CROSS_PLATFORM_COMMANDS.keys())
    options = [f"intent: {i}" for i in intents]
    saved = store.list_credentials()
    options += [f"saved: {p.name} -> {p.command}" for p in saved]

    # Non-TTY mode: print palette and exit
    if not sys.stdin.isatty():
        console.print("[bold]Available palette commands:[/bold]")
        for o in options:
            console.print(f"  {o}")
        return

    try:
        from prompt_toolkit import prompt as _ptk_prompt
        from prompt_toolkit.completion import WordCompleter as _WordCompleter

        PTK = True
    except Exception as exc:
        import logging

        logging.getLogger(__name__).debug("prompt_toolkit not available: %s", exc)
        PTK = False

    if PTK:
        choice = _ptk_prompt(
            "Select or search: ", completer=_WordCompleter(options, ignore_case=True)
        ).strip()
    else:
        for i, o in enumerate(options[:200], 1):
            console.print(f"{i}. {o}")
        sel = Prompt.ask("Select # or type text to filter", default="").strip()
        if sel.isdigit():
            idx = int(sel) - 1
            if 0 <= idx < len(options):
                choice = options[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        else:
            matches = [o for o in options if sel.lower() in o.lower()]
            if not matches:
                console.print("[dim]No matches[/dim]")
                return
            choice = matches[0]

    console.print(f"Selected: {choice}")


def render_cmd(
    name: str = typer.Argument(..., help="Saved command profile name"),
    kv: list[str] = typer.Argument(None),
) -> None:
    """Render a saved command profile using provided key=value pairs.

    Example: siyarix render-cmd quick-nmap target=10.0.0.1 flags='-Pn'
    """
    store = CommandProfileStore()
    p = store.get(name)
    if not p:
        console.print(f"[red]Profile not found: {name}[/red]")
        raise typer.Exit(1)

    params: dict[str, str] = {}
    for item in kv or []:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k] = v

    rendered = store.render(p.command, params)
    console.print(Panel.fit(rendered, title=f"Rendered: {name}", border_style="cyan"))


def register_profile_commands(app: typer.Typer) -> None:
    """Attach profile group plus top-level palette / render-cmd commands."""
    app.add_typer(profile_app, name="profile")
    app.command()(palette)
    app.command(name="render-cmd")(render_cmd)
