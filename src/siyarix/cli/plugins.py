# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI subcommands for managing Siyarix plugins."""

from __future__ import annotations

import logging
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from siyarix.plugins.manager import PluginManager
from siyarix.plugins.models import PluginStatus

logger = logging.getLogger(__name__)
console = Console()

plugins_app = typer.Typer(
    name="plugin",
    help="Enterprise plugin management (list, search, install, uninstall, update, info).",
    no_args_is_help=True,
)


@plugins_app.command("list")
def list_plugins() -> None:
    """List all installed plugins and their registered capabilities."""
    mgr = PluginManager.get_instance()
    plugins = mgr.list_plugins()

    if not plugins:
        console.print("[dim]No plugins installed.[/dim]")
        console.print(f"[dim]Plugins directory: {mgr.plugins_dir}[/dim]")
        console.print("[cyan]Discover plugins using: [bold]siyarix plugin search[/bold][/cyan]")
        return

    table = Table(
        title=f"Installed Plugins ({len(plugins)})",
        header_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Name", style="bold white")
    table.add_column("Version", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Registered Tools", style="green")
    table.add_column("Description", style="dim")

    for p in plugins:
        m = p.manifest
        if p.status == PluginStatus.ACTIVE:
            status_str = "[bold green]ACTIVE[/bold green]"
        elif p.status == PluginStatus.DISABLED:
            status_str = "[yellow]DISABLED[/yellow]"
        else:
            status_str = "[bold red]ERROR[/bold red]"

        risk_val = m.risk_level.value if hasattr(m.risk_level, "value") else str(m.risk_level)
        risk_style = (
            "bold red"
            if risk_val in ("high", "critical")
            else "yellow"
            if risk_val == "medium"
            else "green"
        )
        risk_str = f"[{risk_style}]{risk_val.upper()}[/{risk_style}]"

        cat_val = m.category.value if hasattr(m.category, "value") else str(m.category)
        tools_str = ", ".join(p.registered_tools) if p.registered_tools else "[dim]none[/dim]"
        desc = (m.description[:45] + "...") if len(m.description) > 48 else m.description

        table.add_row(
            m.name,
            m.version,
            cat_val,
            status_str,
            risk_str,
            tools_str,
            desc,
        )

    console.print(table)
    console.print(f"[dim]Plugins directory: {mgr.plugins_dir}[/dim]")


@plugins_app.command("search")
def search_plugins(
    query: str = typer.Argument("", help="Search query (name, category, tag, or description)"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag"),
) -> None:
    """Search the remote Siyarix plugin registry."""
    mgr = PluginManager.get_instance()
    with console.status("[cyan]Searching plugin registry...[/cyan]", spinner="dots"):
        results = mgr.search(query=query, category=category, tag=tag)

    if not results:
        console.print(f"[yellow]No plugins found matching query '{query}'.[/yellow]")
        return

    table = Table(
        title=f"Plugin Registry Results ({len(results)})",
        header_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Name", style="bold white")
    table.add_column("Version", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Risk", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Description")

    for item in results:
        name = item.get("name", "")
        ver = item.get("version", "1.0.0")
        cat = item.get("category", "utility")
        risk = item.get("risk_level", "safe")
        is_installed = item.get("installed", False)
        desc = item.get("description", "")

        risk_style = (
            "bold red"
            if risk in ("high", "critical")
            else "yellow"
            if risk == "medium"
            else "green"
        )
        status_str = (
            "[bold green]INSTALLED[/bold green]" if is_installed else "[dim]AVAILABLE[/dim]"
        )

        table.add_row(
            name,
            ver,
            cat,
            f"[{risk_style}]{risk.upper()}[/{risk_style}]",
            status_str,
            desc,
        )

    console.print(table)
    console.print("[dim]Install any plugin with: [bold]siyarix plugin install <name>[/bold][/dim]")


@plugins_app.command("install")
def install_plugin(
    target: str = typer.Argument(..., help="Plugin name from registry, Git URL, or local path"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing installation"),
) -> None:
    """Install a plugin from the registry, Git repository, or local path."""
    mgr = PluginManager.get_instance()
    console.print(f"[cyan]Installing plugin: [bold]{target}[/bold]...[/cyan]")

    try:
        meta = mgr.install(target, force=force)
        tools = ", ".join(meta.registered_tools) if meta.registered_tools else "none"
        console.print(
            f"[bold green]✓ Successfully installed plugin '{meta.manifest.name}' (v{meta.manifest.version})![/bold green]"
        )
        if meta.registered_tools:
            console.print(f"[green]Registered tools: [bold]{tools}[/bold][/green]")
        console.print(f"[dim]Path: {meta.path}[/dim]")
    except Exception as e:
        console.print(f"[bold red]✗ Installation failed:[/bold red] {e}")
        raise typer.Exit(1)


@plugins_app.command("uninstall")
def uninstall_plugin(
    name: str = typer.Argument(..., help="Name of plugin to uninstall"),
) -> None:
    """Uninstall a plugin and remove its registered tools."""
    mgr = PluginManager.get_instance()
    if mgr.uninstall(name):
        console.print(f"[bold green]✓ Plugin '{name}' successfully uninstalled.[/bold green]")
    else:
        console.print(f"[yellow]Plugin '{name}' not found or could not be removed.[/yellow]")
        raise typer.Exit(1)


@plugins_app.command("update")
def update_plugins(
    name: Optional[str] = typer.Argument(
        None, help="Specific plugin name to update (or all if omitted)"
    ),
) -> None:
    """Update one or all installed plugins to latest versions."""
    mgr = PluginManager.get_instance()
    with console.status("[cyan]Updating plugins...[/cyan]", spinner="dots"):
        updated = mgr.update(name)

    if updated:
        console.print(
            f"[bold green]✓ Updated {len(updated)} plugin(s): {', '.join(updated)}[/bold green]"
        )
    else:
        console.print("[green]All plugins are already up to date.[/green]")


@plugins_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Name of installed plugin"),
) -> None:
    """Inspect detailed runtime metadata and capabilities of an installed plugin."""
    mgr = PluginManager.get_instance()
    try:
        info_data = mgr.info(name)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    status_color = (
        "green"
        if info_data["status"] == "active"
        else "yellow"
        if info_data["status"] == "disabled"
        else "red"
    )
    tools = ", ".join(info_data["registered_tools"]) if info_data["registered_tools"] else "None"
    deps = ", ".join(info_data["dependencies"]) if info_data["dependencies"] else "None"
    tags = ", ".join(info_data["tags"]) if info_data["tags"] else "None"

    body = f"""[bold white]Name:[/bold white] {info_data["name"]} (v{info_data["version"]})
[bold white]Status:[/bold white] [{status_color}]{info_data["status"].upper()}[/{status_color}]
[bold white]Category:[/bold white] {info_data["category"]}
[bold white]Risk Level:[/bold white] {info_data["risk_level"]}
[bold white]Author:[/bold white] {info_data["author"] or "Unknown"}
[bold white]License:[/bold white] {info_data["license"]}
[bold white]Description:[/bold white] {info_data["description"]}
[bold white]Registered Tools:[/bold white] [green]{tools}[/green]
[bold white]Tags:[/bold white] {tags}
[bold white]Dependencies:[/bold white] {deps}
[bold white]Location:[/bold white] [dim]{info_data["path"]}[/dim]"""

    if info_data.get("error_message"):
        body += f"\n[bold red]Error Message:[/bold red] {info_data['error_message']}"

    console.print(Panel(body, title=f"Plugin: {info_data['name']}", border_style="cyan"))


@plugins_app.command("enable")
def enable_plugin(
    name: str = typer.Argument(..., help="Name of plugin to enable"),
) -> None:
    """Enable a disabled plugin."""
    mgr = PluginManager.get_instance()
    if mgr.enable(name):
        console.print(f"[bold green]✓ Plugin '{name}' enabled.[/bold green]")
    else:
        console.print(f"[bold red]✗ Failed to enable plugin '{name}'.[/bold red]")
        raise typer.Exit(1)


@plugins_app.command("disable")
def disable_plugin(
    name: str = typer.Argument(..., help="Name of plugin to disable"),
) -> None:
    """Disable an active plugin without uninstalling it."""
    mgr = PluginManager.get_instance()
    if mgr.disable(name):
        console.print(f"[yellow]✓ Plugin '{name}' disabled.[/yellow]")
    else:
        console.print(f"[bold red]✗ Failed to disable plugin '{name}'.[/bold red]")
        raise typer.Exit(1)


@plugins_app.command("reload")
def reload_plugins() -> None:
    """Reload all active plugins from disk."""
    mgr = PluginManager.get_instance()
    with console.status("[cyan]Reloading plugins...[/cyan]", spinner="dots"):
        count = mgr.load_all()
    console.print(f"[bold green]✓ Successfully reloaded {count} plugin(s).[/bold green]")


@plugins_app.command("create")
def create_plugin(
    name: str = typer.Argument(..., help="Name of new plugin to scaffold"),
    category: str = typer.Option("recon", "--category", "-c", help="Tool category for plugin"),
) -> None:
    """Scaffold a new enterprise plugin directory with template manifest and code."""
    mgr = PluginManager.get_instance()
    try:
        path = mgr.create(name=name, category=category)
        console.print(
            f"[bold green]✓ Created plugin template at: [white]{path}[/white][/bold green]"
        )
        console.print(
            f"[dim]Edit {path / 'plugin.py'} to implement your custom tools and logic.[/dim]"
        )
    except Exception as e:
        console.print(f"[bold red]✗ Failed to create plugin:[/bold red] {e}")
        raise typer.Exit(1)
