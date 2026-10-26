# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI configuration commands (extracted from the CLI god-module)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from siyarix.config import SettingsStore, get_config_dir

console = Console()
config = SettingsStore()

config_app = typer.Typer(help="⚙️ CLI configuration")
config_profile_app = typer.Typer(help="Manage environment configuration profiles")
config_app.add_typer(config_profile_app, name="profile")

@config_app.command("list")
def config_list(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    reveal_secrets: bool = typer.Option(
        False, "--reveal-secrets", "--reveal", help="Reveal sensitive tokens/keys"
    ),
    modified_only: bool = typer.Option(
        False, "--modified-only", "-m", help="Show only values modified from defaults"
    ),
    as_json: bool = typer.Option(False, "--json", help="Output in JSON format"),
) -> None:
    """List all configuration settings."""
    rows = config.list_all(
        category=category, reveal_secrets=reveal_secrets, modified_only=modified_only
    )
    if as_json:
        out = {r["key"]: r["raw_value"] for r in rows}
        print(json.dumps(out, indent=2))
        return

    active_prof = config.get_active_profile()
    table = Table(
        title=f"Siyarix Configuration (Profile: [bold cyan]{active_prof}[/bold cyan])",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Default", style="dim")
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="white")

    for row in rows:
        modified = "[bold yellow]* [/bold yellow]" if row["modified"] else "  "
        table.add_row(
            f"{modified}{row['key']}",
            row["value"],
            row["default"],
            row["category"],
            row["description"][:50],
        )
    console.print(table)


@config_app.command("show")
def config_show(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    reveal_secrets: bool = typer.Option(
        False, "--reveal-secrets", "--reveal", help="Reveal sensitive tokens/keys"
    ),
    modified_only: bool = typer.Option(
        False, "--modified-only", "-m", help="Show only values modified from defaults"
    ),
    as_json: bool = typer.Option(False, "--json", help="Output in JSON format"),
) -> None:
    """Show all configuration settings (alias for list)."""
    config_list(
        category=category,
        reveal_secrets=reveal_secrets,
        modified_only=modified_only,
        as_json=as_json,
    )


@config_app.command("set")
def config_set(
    key: str = typer.Argument(help="Setting key or dot-notation path"),
    value: str = typer.Argument(help="New value"),
    allow_custom: bool = typer.Option(
        True, "--allow-custom/--no-custom", help="Allow setting arbitrary custom keys"
    ),
    type_: str | None = typer.Option(
        None, "--type", "-t", help="Target type: str|int|bool|float|list|json"
    ),
) -> None:
    """Set a configuration value.\n\nExample: siyarix config set log_level debug"""
    try:
        new_val = config.set(key, value, allow_custom=allow_custom, target_type=type_)
        console.print(f"[green]✓ {key} = {new_val}[/green]")
        if key in ("log_level", "appearance.log_level"):
            from siyarix.logging_config import configure_logging

            configure_logging(str(new_val))
    except (KeyError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("add")
def config_add(
    key: str = typer.Argument(help="Custom setting key (e.g. plugins.webhook_url)"),
    value: str = typer.Argument(help="Setting value"),
    type_: str | None = typer.Option(
        None, "--type", "-t", help="Value type: str|int|bool|float|list|json"
    ),
    description: str = typer.Option("", "--desc", "-d", help="Description for this setting"),
) -> None:
    """Add a custom configuration setting."""
    try:
        new_val = config.add(key, value, value_type=type_, description=description)
        console.print(f"[green]✓ Added setting {key} = {new_val}[/green]")
    except Exception as exc:
        console.print(f"[red]Error adding setting: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("unset")
def config_unset(key: str = typer.Argument(help="Setting key to unset or revert")) -> None:
    """Unset a custom setting or revert an existing setting to factory default."""
    try:
        existed = config.unset(key)
        if existed:
            console.print(f"[green]✓ Unset '{key}' (reverted to default / removed).[/green]")
        else:
            console.print(f"[yellow]Setting '{key}' was not set.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("remove", hidden=True)
def config_remove(key: str = typer.Argument(help="Setting key to remove")) -> None:
    """Remove a custom setting (alias for unset)."""
    config_unset(key)


@config_app.command("delete", hidden=True)
def config_delete(key: str = typer.Argument(help="Setting key to delete")) -> None:
    """Delete a custom setting (alias for unset)."""
    config_unset(key)


@config_app.command("get")
def config_get(
    key: str = typer.Argument(help="Setting key or dot-notation path"),
    reveal: bool = typer.Option(False, "--reveal", "-r", help="Reveal sensitive secret"),
) -> None:
    """Get a configuration value."""
    try:
        from ..config import mask_value

        val = config.get(key)
        display_val = val if reveal else mask_value(key, val)
        console.print(f"[cyan]{key}[/cyan] = [green]{display_val}[/green]")
    except KeyError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("reset")
def config_reset(key: str = typer.Argument(default="", help="Key to reset (empty = all)")) -> None:
    """Reset a setting (or all settings) to defaults."""
    try:
        config.reset(key or None)
        target = key if key else "all settings"
        console.print(f"[green]✓ Reset {target} to defaults.[/green]")
    except KeyError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("diff")
def config_diff(
    against: str = typer.Option(
        "defaults",
        "--against",
        "-a",
        help="Compare against: defaults | profile:<name> | backup:<name>",
    ),
) -> None:
    """Show differences between current configuration and target (defaults/profile/backup)."""
    try:
        entries = config.diff(against=against)
        if not entries:
            console.print(f"[green]✓ No differences found against {against}.[/green]")
            return

        table = Table(
            title=f"Configuration Diff (against {against})",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Status", style="bold")
        table.add_column("Key", style="cyan")
        table.add_column("Current Value", style="green")
        table.add_column("Target Value", style="dim")

        for e in entries:
            status_style = "[yellow]MODIFIED[/yellow]"
            if e.status == "added":
                status_style = "[green]ADDED[/green]"
            elif e.status == "removed":
                status_style = "[red]REMOVED[/red]"

            table.add_row(
                status_style,
                e.key,
                str(e.current_value) if e.current_value is not None else "[dim]None[/dim]",
                str(e.target_value) if e.target_value is not None else "[dim]None[/dim]",
            )
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error computing diff: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("validate")
def config_validate() -> None:
    """Run configuration health check and validate all values."""
    issues = config.validate()
    if not issues:
        console.print(
            "[bold green]✓ Configuration is healthy and valid! No issues detected.[/bold green]"
        )
        return

    table = Table(title="Configuration Health Check", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Key", style="cyan")
    table.add_column("Current Value", style="yellow")
    table.add_column("Message", style="white")

    has_errors = False
    for issue in issues:
        if issue.severity == "error":
            has_errors = True
            sev = "[bold red]ERROR[/bold red]"
        else:
            sev = "[bold yellow]WARNING[/bold yellow]"
        table.add_row(sev, issue.key, str(issue.current_value), issue.message)

    console.print(table)
    if has_errors:
        raise typer.Exit(1)


@config_app.command("check", hidden=True)
def config_check() -> None:
    """Alias for validate."""
    config_validate()


@config_app.command("edit")
def config_edit() -> None:
    """Open settings file in your default text editor."""
    console.print(f"[cyan]Opening {config._path} in editor...[/cyan]")
    config.edit()
    console.print("[green]✓ Configuration reloaded.[/green]")


@config_app.command("path")
def config_path() -> None:
    """Display paths for active configuration, profiles, and backups."""
    from ..config import get_config_dir, get_settings_file

    cfg_dir = get_config_dir()
    settings_file = get_settings_file()
    active_prof = config.get_active_profile()

    console.print(
        Panel(
            f"[bold]Active Settings:[/bold] {settings_file}\n"
            f"[bold]Active Profile:[/bold]  [cyan]{active_prof}[/cyan]\n"
            f"[bold]Config Directory:[/bold] {cfg_dir}\n"
            f"[bold]Profiles Dir:[/bold]    {cfg_dir / 'profiles'}\n"
            f"[bold]Backups Dir:[/bold]     {cfg_dir / 'backups'}",
            title="⚙️ Configuration Paths",
            border_style="cyan",
        )
    )


@config_app.command("export")
def config_export(
    format: str = typer.Option("toml", "--format", "-f", help="Export format: toml | json | yaml"),
    output: str | None = typer.Option(None, "--output", "-o", help="File to write export to"),
    reveal_secrets: bool = typer.Option(False, "--reveal-secrets", help="Include unmasked secrets"),
    custom_only: bool = typer.Option(
        False, "--custom-only", help="Export only modified or custom keys"
    ),
) -> None:
    """Export configuration to TOML, JSON, or YAML."""
    try:
        content = config.export_config(
            format=format, reveal_secrets=reveal_secrets, custom_only=custom_only
        )
        if output:
            out_p = Path(output)
            out_p.write_text(content, encoding="utf-8")
            console.print(f"[green]✓ Configuration exported to {out_p}[/green]")
        else:
            print(content)
    except Exception as exc:
        console.print(f"[red]Export failed: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("import")
def config_import(
    file_path: str = typer.Argument(help="Path to TOML, JSON, or YAML config file to import"),
    merge: bool = typer.Option(
        True, "--merge/--replace", help="Merge into existing config or replace"
    ),
) -> None:
    """Import configuration from a file."""
    try:
        count = config.import_config(file_path, merge=merge)
        action = "Merged" if merge else "Replaced"
        console.print(f"[green]✓ {action} {count} configuration settings from {file_path}[/green]")
    except Exception as exc:
        console.print(f"[red]Import failed: {exc}[/red]")
        raise typer.Exit(1)


@config_app.command("backup")
def config_backup() -> None:
    """Create a manual backup of current settings."""
    bk = config.backup()
    if bk:
        console.print(f"[green]✓ Backup created successfully: {bk.name}[/green]")
    else:
        console.print("[red]Backup failed or configuration file does not exist.[/red]")
        raise typer.Exit(1)


@config_app.command("backups")
def config_backups() -> None:
    """List all available timestamped backups."""
    backups = config.list_backups()
    if not backups:
        console.print("[dim]No configuration backups found.[/dim]")
        return

    table = Table(title="Configuration Backups", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim")
    table.add_column("Backup Name", style="cyan")
    table.add_column("Timestamp (UTC)", style="white")
    table.add_column("Keys", style="green")
    table.add_column("Size", style="dim")

    for idx, b in enumerate(backups):
        table.add_row(str(idx), b.name, b.timestamp, str(b.key_count), f"{b.size_bytes} B")
    console.print(table)


@config_app.command("restore")
def config_restore(
    backup_id: str = typer.Argument(default="", help="Backup filename or index (empty = latest)"),
) -> None:
    """Restore configuration from a backup."""
    target: str | int = backup_id
    if backup_id.isdigit():
        target = int(backup_id)
    elif not backup_id:
        target = 0

    restored = config.restore_backup(target)
    if restored:
        console.print("[green]✓ Configuration successfully restored from backup.[/green]")
    else:
        console.print(
            "[red]Backup restore failed. Verify the backup identifier using 'siyarix config backups'.[/red]"
        )
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Profile sub-app under 'siyarix config profile'
# ---------------------------------------------------------------------------


@config_profile_app.command("list")
def profile_list() -> None:
    """List all configuration profiles."""
    profs = config.list_profiles()
    table = Table(title="Configuration Profiles", show_header=True, header_style="bold cyan")
    table.add_column("Active", style="bold green", justify="center")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    for p in profs:
        active_mark = "[bold green]✓[/bold green]" if p.is_active else ""
        table.add_row(active_mark, p.name, p.description)
    console.print(table)


@config_profile_app.command("current")
def profile_current() -> None:
    """Show the currently active profile."""
    console.print(f"Active profile: [bold cyan]{config.get_active_profile()}[/bold cyan]")


@config_profile_app.command("switch")
def profile_switch(
    name: str = typer.Argument(
        help="Profile to switch to (e.g. ctf, stealth, offline, cloud, default)"
    ),
) -> None:
    """Switch the active configuration profile."""
    try:
        config.switch_profile(name)
        console.print(
            f"[green]✓ Switched active profile to '[bold cyan]{name}[/bold cyan]'.[/green]"
        )
    except Exception as exc:
        console.print(f"[red]Failed to switch profile: {exc}[/red]")
        raise typer.Exit(1)


@config_profile_app.command("create")
def profile_create(
    name: str = typer.Argument(help="New profile name"),
    from_profile: str | None = typer.Option(
        None, "--from", "-f", help="Source profile to copy from"
    ),
) -> None:
    """Create a new configuration profile."""
    try:
        config.create_profile(name, from_profile=from_profile)
        src = f" based on '{from_profile}'" if from_profile else ""
        console.print(f"[green]✓ Profile '{name}' created successfully{src}.[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to create profile: {exc}[/red]")
        raise typer.Exit(1)


@config_profile_app.command("delete")
def profile_delete(name: str = typer.Argument(help="Profile name to delete")) -> None:
    """Delete a configuration profile."""
    try:
        config.delete_profile(name)
        console.print(f"[green]✓ Profile '{name}' deleted.[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to delete profile: {exc}[/red]")
        raise typer.Exit(1)
