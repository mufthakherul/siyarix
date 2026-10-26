# SPDX-License-Identifier: AGPL-3.0-or-later
"""Playbook CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

playbook_app = typer.Typer(help="Manage and run YAML playbooks.")


def _builtin_playbook_dir() -> Path:
    """Directory of playbooks shipped inside the installed package."""
    return Path(__file__).resolve().parents[1] / "data" / "playbooks"


def _resolve_playbook_path(path: str, dir_path: str | None = None) -> Path | None:
    """Resolve a playbook from an explicit path, cwd, or built-in package data."""
    candidate = Path(path)
    if candidate.exists():
        return candidate
    search_roots = []
    if dir_path:
        search_roots.append(Path(dir_path))
    search_roots.extend([Path("playbooks"), _builtin_playbook_dir()])
    names = [path, f"{path}.yaml", f"{path}.yml"]
    for root in search_roots:
        for name in names:
            hit = root / name
            if hit.exists():
                return hit
    return None


def _iter_playbook_files(dir_path: str | None = None) -> list[Path]:
    """List playbooks from an explicit dir, else cwd + built-in package data."""
    roots: list[Path] = []
    if dir_path and dir_path != "playbooks":
        roots.append(Path(dir_path))
    else:
        roots.extend([Path("playbooks"), _builtin_playbook_dir()])
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in ("*.yaml", "*.yml"):
            for f in sorted(root.glob(pattern)):
                if f.name not in seen:
                    files.append(f)
                    seen.add(f.name)
    return files


@playbook_app.command("run")
def playbook_run(
    path: str = typer.Argument(..., help="Path to playbook YAML file"),
    var: list[str] = typer.Option([], "--var", help="Variables in key=value format"),
) -> None:
    """Run a YAML playbook."""
    from siyarix.core import AgentCore
    from siyarix.playbook import PlaybookEngine
    from siyarix.workflow import WorkflowEngine

    variables = {}
    for v in var:
        if "=" in v:
            k, val = v.split("=", 1)
            variables[k] = val

    p = _resolve_playbook_path(path)
    if p is None:
        console.print(f"[red]Playbook '{path}' not found (checked cwd and built-in package).[/red]")
        raise typer.Exit(1)

    engine = PlaybookEngine(WorkflowEngine())
    core = AgentCore()

    async def _run() -> None:
        await core.start()
        try:
            await engine.execute(p, variables, executor=core)
        finally:
            await core.shutdown()

    asyncio.run(_run())


@playbook_app.command("list")
def playbook_list(
    dir_path: str = typer.Option(
        "playbooks",
        "--dir",
        "-d",
        help="Directory containing playbooks (also searches built-in package data)",
    ),
) -> None:
    """List available playbooks."""
    files = _iter_playbook_files(dir_path)
    if not files:
        if dir_path and dir_path != "playbooks" and not Path(dir_path).is_dir():
            console.print(f"[yellow]Directory '{dir_path}' not found.[/yellow]")
        else:
            console.print(
                f"[yellow]No playbooks found in '{dir_path}' or built-in package data.[/yellow]"
            )
        return

    import yaml

    table = Table(title="Available Playbooks", header_style="bold cyan")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Description", style="dim")
    table.add_column("Steps", justify="right", style="green")
    table.add_column("Source", style="dim")

    builtin = _builtin_playbook_dir()
    for f in files:
        name = f.stem
        desc = "—"
        steps_count = "—"
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                name = data.get("name", f.stem)
                desc = data.get("description", "—")
                steps_count = str(len(data.get("steps", [])))
        except Exception:
            pass
        source = "builtin" if builtin in f.parents or f.parent == builtin else str(f.parent)
        table.add_row(f.name, name, desc[:60], steps_count, source)

    console.print(table)


@playbook_app.command("show")
@playbook_app.command("info")
def playbook_show(
    name: str = typer.Argument(..., help="Playbook name or path to YAML file"),
    dir_path: str = typer.Option("playbooks", "--dir", "-d", help="Directory containing playbooks"),
) -> None:
    """Show detailed structure and execution DAG of a playbook."""
    import yaml

    p = _resolve_playbook_path(name, dir_path)
    if p is None or not p.is_file():
        console.print(f"[red]Playbook '{name}' not found.[/red]")
        raise typer.Exit(1)

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Playbook must be a YAML dictionary")
    except Exception as exc:
        console.print(f"[red]Failed to load playbook: {exc}[/red]")
        raise typer.Exit(1)

    title = data.get("name", p.stem)
    desc = data.get("description", "No description provided.")
    vars_dict = data.get("vars", {})
    vars_summary = ", ".join(f"{k}={v}" for k, v in vars_dict.items()) if vars_dict else "None"

    panel_text = (
        f"[bold cyan]Name:[/bold cyan]        {title}\n"
        f"[bold]File:[/bold]        {p}\n"
        f"[bold]Description:[/bold] {desc}\n"
        f"[bold]Variables:[/bold]   {vars_summary}"
    )
    console.print(
        Panel.fit(panel_text, title="[bold cyan]Playbook Info[/bold cyan]", border_style="cyan")
    )

    steps = data.get("steps", [])
    if steps:
        step_table = Table(title="Execution Steps (DAG)", header_style="bold cyan")
        step_table.add_column("Step ID", style="cyan", no_wrap=True)
        step_table.add_column("Type", style="yellow")
        step_table.add_column("Tool / Role", style="white")
        step_table.add_column("Depends On", style="dim")
        step_table.add_column("Description", style="white")
        step_table.add_column("Timeout (s)", justify="right", style="green")

        for s in steps:
            s_type = s.get("type", "tool")
            tool_role = s.get("role") if s_type == "agent" else s.get("tool", "—")
            deps = ", ".join(s.get("depends_on", [])) or "—"
            step_table.add_row(
                str(s.get("id", "—")),
                str(s_type),
                str(tool_role),
                deps,
                str(s.get("description", "—"))[:50],
                str(s.get("timeout", 60.0)),
            )
        console.print(step_table)


@playbook_app.command("validate")
def playbook_validate(
    path: str = typer.Argument(..., help="Path to playbook YAML file"),
) -> None:
    """Validate a YAML playbook."""
    from siyarix.playbook import PlaybookEngine
    from siyarix.workflow import WorkflowEngine

    p = _resolve_playbook_path(path)
    if p is None:
        console.print(f"[red]Playbook '{path}' not found.[/red]")
        raise typer.Exit(1)

    engine = PlaybookEngine(WorkflowEngine())
    try:
        engine.load(p)
        console.print(f"[green]Playbook '{p}' is valid.[/green]")
    except Exception as e:
        console.print(f"[red]Playbook validation failed: {e}[/red]")
        raise typer.Exit(1)
