# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security tool management CLI (extracted from the CLI god-module)."""

from __future__ import annotations

import json
import shutil
from typing import Any, Optional

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

console = Console()

tools_app = typer.Typer(help="🛠️ Security tool management: install, uninstall, modify, list, search")


_TOOL_PRESETS: dict[str, list[str]] = {
    "recon": ["nmap", "masscan", "subfinder", "httpx", "dig", "whois"],
    "web": ["nikto", "sqlmap", "ffuf", "gobuster", "nuclei", "wafw00f"],
    "network": ["nmap", "wireshark", "tcpdump", "aircrack-ng"],
    "pentester": [
        "nmap",
        "sqlmap",
        "hydra",
        "metasploit",
        "ffuf",
        "hashcat",
        "john",
        "exiftool",
        "yara",
    ],
    "devsecops": ["semgrep", "bandit", "trufflehog", "checkov"],
}


def _get_all_tools_merged() -> dict[str, dict[str, Any]]:
    """Merge cyber_tools.json with custom tools from ToolConfigManager."""
    from ..tool_config import ToolConfigManager
    from ..tool_version import _load_db

    db = dict(_load_db())
    cfg_mgr = ToolConfigManager.get_instance()
    for name, ctool in cfg_mgr.list_custom_tools().items():
        db[name] = {
            "name": name,
            "binary": ctool.binary,
            "description": ctool.description,
            "category": ctool.category,
            "risk_level": ctool.risk_level,
            "custom": True,
            "enabled": ctool.enabled,
            "personas": ["custom"],
            "aliases": [],
        }
    return db


@tools_app.command("list")
def tools_list(
    installed_only: bool = typer.Option(
        False, "--installed", "-i", help="Show only installed tools"
    ),
    missing_only: bool = typer.Option(False, "--missing", "-m", help="Show only missing tools"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    persona: Optional[str] = typer.Option(None, "--persona", "-p", help="Filter by persona"),
    risk: Optional[str] = typer.Option(None, "--risk", "-r", help="Filter by risk level"),
    json_out: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List security tools with installation status and customizations."""
    from ..tool_config import ToolConfigManager
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller()
    cfg_mgr = ToolConfigManager.get_instance()
    all_tools = _get_all_tools_merged()

    results: list[dict[str, Any]] = []
    for name, data in sorted(all_tools.items()):
        is_inst = installer.is_installed(name)
        if installed_only and not is_inst:
            continue
        if missing_only and is_inst:
            continue
        cat = str(data.get("category", "utility")).lower()
        if category and category.lower() not in cat:
            continue
        rsk = str(data.get("risk_level", "safe")).lower()
        if risk and risk.lower() != rsk:
            continue
        personas = [p.lower() for p in data.get("personas", [])]
        if persona and persona.lower() not in personas:
            continue

        override = cfg_mgr.get_override(name)
        is_custom = bool(data.get("custom", False))
        is_enabled = cfg_mgr.is_tool_enabled(name)
        status_label = "Default"
        if not is_enabled:
            status_label = "Disabled"
        elif is_custom:
            status_label = "Custom"
        elif override:
            status_label = "Modified"

        desc = " ".join(str(data.get("description", "")).split())
        results.append(
            {
                "name": name,
                "installed": is_inst,
                "category": cat,
                "risk_level": rsk,
                "status": status_label,
                "description": desc,
            }
        )

    if json_out:
        print(json.dumps(results, indent=2))
        return

    table = Table(
        title=f"Security Tools ({len(results)} matches)",
        header_style="bold cyan",
    )
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Installed", justify="center")
    table.add_column("Category", style="magenta")
    table.add_column("Risk", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Description", style="white")

    for item in results:
        inst_badge = "[green]✓ Yes[/green]" if item["installed"] else "[dim]✗ No[/dim]"
        status_str = {
            "Disabled": "[yellow]Disabled[/yellow]",
            "Custom": "[magenta]Custom[/magenta]",
            "Modified": "[cyan]Modified[/cyan]",
            "Default": "[dim]Default[/dim]",
        }.get(item["status"], item["status"])

        risk_color = {
            "safe": "green",
            "low": "blue",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }.get(item["risk_level"], "white")
        risk_badge = f"[{risk_color}]{item['risk_level'].upper()}[/{risk_color}]"

        table.add_row(
            item["name"],
            inst_badge,
            item["category"],
            risk_badge,
            status_str,
            item["description"][:50] + ("..." if len(item["description"]) > 50 else ""),
        )

    console.print(table)


@tools_app.command("search")
def tools_search(
    query: str = typer.Argument(..., help="Search keyword (name, description, tag, alias)"),
    json_out: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Search tools database by keyword."""
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller()
    all_tools = _get_all_tools_merged()
    q = query.lower()

    matches: list[dict[str, Any]] = []
    for name, data in sorted(all_tools.items()):
        name_match = q in name.lower()
        desc_match = q in data.get("description", "").lower()
        alias_match = any(q in str(a).lower() for a in data.get("aliases", []))
        cat_match = q in str(data.get("category", "")).lower()

        if name_match or desc_match or alias_match or cat_match:
            desc = " ".join(str(data.get("description", "")).split())
            matches.append(
                {
                    "name": name,
                    "installed": installer.is_installed(name),
                    "category": data.get("category", "utility"),
                    "risk_level": data.get("risk_level", "safe"),
                    "description": desc,
                }
            )

    if json_out:
        print(json.dumps(matches, indent=2))
        return

    if not matches:
        console.print(f"[yellow]No tools matching '{query}' found.[/yellow]")
        return

    table = Table(
        title=f"Tool Search Results for '{query}' ({len(matches)} found)",
        header_style="bold cyan",
    )
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Installed", justify="center")
    table.add_column("Category", style="magenta")
    table.add_column("Risk", justify="center")
    table.add_column("Description", style="white")

    for item in matches:
        inst_badge = "[green]✓ Yes[/green]" if item["installed"] else "[dim]✗ No[/dim]"
        table.add_row(
            item["name"],
            inst_badge,
            item["category"],
            item["risk_level"],
            item["description"][:60],
        )

    console.print(table)


@tools_app.command("info")
def tools_info(tool: str = typer.Argument(..., help="Name of tool to inspect")) -> None:
    """Inspect detailed tool metadata, installation recipes, and configuration."""
    from ..tool_config import ToolConfigManager
    from ..tool_installer import ToolInstaller
    from ..tool_version import get_tool_metadata

    installer = ToolInstaller()
    cfg_mgr = ToolConfigManager.get_instance()

    meta = get_tool_metadata(tool)
    custom = cfg_mgr.get_custom_tool(tool)
    override = cfg_mgr.get_override(tool)
    is_installed = installer.is_installed(tool)
    recipe = installer.get_install_recipe(tool)

    table = Table(title=f"Tool Specification: [bold cyan]{tool}[/bold cyan]", show_header=False)
    table.add_column("Property", style="cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row(
        "Installed Status",
        "[green]✓ Installed[/green]" if is_installed else "[red]✗ Not Installed[/red]",
    )
    which_bin = shutil.which(tool)
    table.add_row("System PATH Binary", which_bin or "[dim]None[/dim]")

    if custom:
        table.add_row("Tool Type", "[magenta]Custom User Tool[/magenta]")
        table.add_row("Custom Binary", custom.binary)
        table.add_row("Description", custom.description)
        table.add_row("Category", custom.category)
        table.add_row("Risk Level", custom.risk_level)
        table.add_row("Timeout", f"{custom.timeout}s")
        table.add_row("Enabled", "[green]Yes[/green]" if custom.enabled else "[yellow]No[/yellow]")
    elif meta:
        table.add_row("Description", meta.get("description", "N/A"))
        table.add_row("Category", meta.get("category", "utility"))
        table.add_row("Risk Level", meta.get("risk_level", "safe"))
        aliases = ", ".join(meta.get("aliases", []))
        if aliases:
            table.add_row("Aliases", aliases)
        personas = ", ".join(meta.get("personas", []))
        if personas:
            table.add_row("Personas", personas)

    if override:
        table.add_row("Custom Override", "[cyan]Active[/cyan]")
        if override.binary_path:
            table.add_row("Override Binary", override.binary_path)
        if override.default_args:
            table.add_row("Default Flags", " ".join(override.default_args))
        if override.timeout:
            table.add_row("Override Timeout", f"{override.timeout}s")
        table.add_row(
            "Enabled", "[green]Yes[/green]" if override.enabled else "[yellow]Disabled[/yellow]"
        )

    table.add_row("Detected Package Manager", recipe.get("pm", "unknown"))
    table.add_row("Package Name", recipe.get("package", tool))
    table.add_row("Install Command", " ".join(recipe.get("install_cmd", [])))
    table.add_row("Uninstall Command", " ".join(recipe.get("uninstall_cmd", [])))

    all_recipes = recipe.get("all_recipes", {})
    if all_recipes:
        recipe_list = [f"{k}: {v}" for k, v in all_recipes.items()]
        table.add_row("Known Packages", ", ".join(recipe_list))

    console.print(table)


@tools_app.command("install")
def tools_install(
    tools: Optional[list[str]] = typer.Argument(None, help="Tool(s) to install"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    method: Optional[str] = typer.Option(
        None,
        "--method",
        "-m",
        help="Installer method (winget, choco, scoop, apt, pacman, brew, pkg, pip, go)",
    ),
    preset: Optional[str] = typer.Option(
        None, "--preset", "-p", help="Install tool preset: recon|web|network|pentester|devsecops"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Preview install command without executing"
    ),
) -> None:
    """Install one or more tools across supported package managers."""
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller(console=console)
    target_tools = list(tools or [])
    if preset:
        preset_key = preset.lower()
        if preset_key not in _TOOL_PRESETS:
            valid = ", ".join(_TOOL_PRESETS.keys())
            console.print(f"[red]Unknown preset '{preset}'. Valid: {valid}[/red]")
            return
        target_tools.extend(_TOOL_PRESETS[preset_key])

    if not target_tools:
        console.print("[yellow]Please specify tool name(s) or use --preset.[/yellow]")
        return

    # Deduplicate while preserving order
    unique_tools = list(dict.fromkeys(target_tools))

    if dry_run:
        console.print(
            f"[bold cyan]Dry Run: Installation Plan for {len(unique_tools)} tool(s)[/bold cyan]"
        )
        for t in unique_tools:
            rec = installer.get_install_recipe(t)
            status = "[green]Installed[/green]" if rec["installed"] else "[dim]Not installed[/dim]"
            console.print(
                f"  • [cyan]{t}[/cyan] ({status}) via [magenta]{rec['method']}[/magenta]:"
            )
            console.print(f"    Command: [white]{' '.join(rec['install_cmd'])}[/white]")
        return

    if not yes:
        count = len(unique_tools)
        if not Confirm.ask(f"Proceed with installing {count} tool(s)?", default=True):
            console.print("[dim]Installation aborted by user.[/dim]")
            return

    results = []
    for t in unique_tools:
        res = installer.install(t, method=method)
        results.append(res)

    success_count = sum(1 for r in results if r.success)
    console.print(
        f"\n[bold green]Installation finished: {success_count}/{len(results)} succeeded.[/bold green]"
    )


@tools_app.command("uninstall")
def tools_uninstall(
    tools: list[str] = typer.Argument(..., help="Tool(s) to uninstall"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    purge: bool = typer.Option(
        False, "--purge", help="Remove all configuration and cache files if supported"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Preview uninstall command without executing"
    ),
) -> None:
    """Uninstall one or more tools."""
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller(console=console)

    if dry_run:
        console.print(
            f"[bold cyan]Dry Run: Uninstallation Plan for {len(tools)} tool(s)[/bold cyan]"
        )
        for t in tools:
            rec = installer.get_install_recipe(t)
            console.print(f"  • [cyan]{t}[/cyan] via [magenta]{rec['method']}[/magenta]:")
            console.print(f"    Command: [white]{' '.join(rec['uninstall_cmd'])}[/white]")
        return

    if not yes:
        if not Confirm.ask(
            f"Are you sure you want to uninstall {len(tools)} tool(s)?", default=False
        ):
            console.print("[dim]Uninstallation aborted by user.[/dim]")
            return

    results = []
    for t in tools:
        res = installer.uninstall(t, purge=purge)
        results.append(res)

    success_count = sum(1 for r in results if r.success)
    console.print(
        f"\n[bold green]Uninstallation finished: {success_count}/{len(results)} removed.[/bold green]"
    )


@tools_app.command("update")
def tools_update(
    tools: Optional[list[str]] = typer.Argument(None, help="Specific tool(s) to update"),
    all_tools: bool = typer.Option(
        False, "--all", "-a", help="Update all installed security tools"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Update installed tools to their latest upstream versions."""
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller(console=console)
    target_tools = list(tools or [])

    if all_tools:
        all_db = _get_all_tools_merged()
        target_tools = [name for name in all_db if installer.is_installed(name)]

    if not target_tools:
        console.print("[yellow]No tools specified to update. Use tool names or --all.[/yellow]")
        return

    if not yes:
        if not Confirm.ask(f"Update {len(target_tools)} tool(s)?", default=True):
            console.print("[dim]Update aborted by user.[/dim]")
            return

    for t in target_tools:
        installer.update(t)


@tools_app.command("modify")
def tools_modify(
    tool: str = typer.Argument(..., help="Tool name to modify"),
    binary: Optional[str] = typer.Option(
        None, "--binary", "-b", help="Custom executable binary path"
    ),
    risk: Optional[str] = typer.Option(
        None, "--risk", "-r", help="Override risk level: safe|low|medium|high|critical"
    ),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Override category"),
    timeout: Optional[int] = typer.Option(
        None, "--timeout", "-t", help="Execution timeout in seconds"
    ),
    default_args: Optional[str] = typer.Option(
        None, "--default-args", help="Arguments to always include (space separated)"
    ),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="Custom tool description"
    ),
) -> None:
    """Modify configuration, binary location, default flags, or risk level for a tool."""
    import shlex
    from ..tool_config import ToolConfigManager

    cfg_mgr = ToolConfigManager.get_instance()
    updates: dict[str, Any] = {}
    if binary is not None:
        updates["binary_path"] = binary
    if risk is not None:
        updates["risk_level"] = risk.lower()
    if category is not None:
        updates["category"] = category.lower()
    if timeout is not None:
        updates["timeout"] = timeout
    if default_args is not None:
        updates["default_args"] = shlex.split(default_args)
    if description is not None:
        updates["description"] = description

    if not updates:
        console.print("[yellow]No modification flags provided. See --help.[/yellow]")
        return

    cfg_mgr.set_override(tool, **updates)
    console.print(f"[green]✓ Successfully updated configuration for [cyan]{tool}[/cyan].[/green]")


@tools_app.command("enable")
def tools_enable(tool: str = typer.Argument(..., help="Tool name to enable")) -> None:
    """Enable a previously disabled tool."""
    from ..tool_config import ToolConfigManager

    cfg_mgr = ToolConfigManager.get_instance()
    cfg_mgr.enable_tool(tool)
    console.print(f"[green]✓ Tool [cyan]{tool}[/cyan] is now enabled.[/green]")


@tools_app.command("disable")
def tools_disable(tool: str = typer.Argument(..., help="Tool name to disable")) -> None:
    """Disable a tool from execution and recommendations."""
    from ..tool_config import ToolConfigManager

    cfg_mgr = ToolConfigManager.get_instance()
    cfg_mgr.disable_tool(tool)
    console.print(f"[yellow]✓ Tool [cyan]{tool}[/cyan] is now disabled.[/yellow]")


@tools_app.command("reset")
def tools_reset(
    tool: Optional[str] = typer.Argument(
        None, help="Tool name to reset (omit to reset all modifications)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Reset tool modifications back to defaults."""
    from ..tool_config import ToolConfigManager

    if not yes:
        target = f"modifications for '{tool}'" if tool else "ALL tool modifications"
        if not Confirm.ask(f"Are you sure you want to reset {target}?", default=False):
            console.print("[dim]Reset aborted.[/dim]")
            return

    cfg_mgr = ToolConfigManager.get_instance()
    cfg_mgr.reset(tool)
    if tool:
        console.print(f"[green]✓ Modifications for [cyan]{tool}[/cyan] reset to default.[/green]")
    else:
        console.print("[green]✓ All tool modifications reset to defaults.[/green]")


@tools_app.command("add-custom")
def tools_add_custom(
    name: str = typer.Argument(..., help="Unique tool identifier"),
    binary: str = typer.Option(..., "--binary", "-b", help="Path to executable binary or script"),
    description: str = typer.Option("", "--description", "-d", help="Tool description"),
    category: str = typer.Option("utility", "--category", "-c", help="Tool category"),
    risk: str = typer.Option(
        "safe", "--risk", "-r", help="Risk level: safe|low|medium|high|critical"
    ),
    default_args: Optional[str] = typer.Option(
        None, "--default-args", help="Default arguments (space separated)"
    ),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Execution timeout in seconds"),
) -> None:
    """Register a new custom script or tool in Siyarix."""
    import shlex
    from ..tool_config import CustomToolDefinition, ToolConfigManager

    cfg_mgr = ToolConfigManager.get_instance()
    parsed_args = shlex.split(default_args) if default_args else []
    custom = CustomToolDefinition(
        name=name,
        binary=binary,
        description=description,
        category=category.lower(),
        risk_level=risk.lower(),
        default_args=parsed_args,
        timeout=timeout,
    )
    cfg_mgr.add_custom_tool(custom)
    console.print(f"[green]✓ Custom tool [cyan]{name}[/cyan] successfully registered![/green]")


@tools_app.command("remove-custom")
def tools_remove_custom(
    name: str = typer.Argument(..., help="Custom tool name to remove"),
) -> None:
    """Remove a previously registered custom tool."""
    from ..tool_config import ToolConfigManager

    cfg_mgr = ToolConfigManager.get_instance()
    if cfg_mgr.remove_custom_tool(name):
        console.print(f"[green]✓ Custom tool [cyan]{name}[/cyan] removed.[/green]")
    else:
        console.print(f"[yellow]Custom tool '{name}' not found.[/yellow]")


@tools_app.command("check")
def tools_check(
    tools: Optional[list[str]] = typer.Argument(
        None, help="Specific tools to check (default: all installed)"
    ),
) -> None:
    """Check health and verify executability of tools."""
    from ..tool_installer import ToolInstaller

    installer = ToolInstaller()
    all_db = _get_all_tools_merged()
    check_list = tools or [k for k in all_db if installer.is_installed(k)]

    table = Table(title="Tool Health & Verification", header_style="bold cyan")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Location", style="dim")

    for t in check_list:
        is_inst = installer.is_installed(t)
        loc = shutil.which(t) or "[dim]N/A[/dim]"
        status = "[green]✓ Ready[/green]" if is_inst else "[red]✗ Missing[/red]"
        table.add_row(t, status, str(loc))

    console.print(table)
