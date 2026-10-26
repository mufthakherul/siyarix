# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shell completion CLI commands (extracted from the CLI god-module)."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console

from siyarix.config import get_config_dir

logger = logging.getLogger(__name__)
console = Console()

completions_app = typer.Typer(help="🏁 Shell completions")

_root_app: typer.Typer | None = None


def _generate_completion(shell: str, output_path: Path) -> bool:
    """Generate a static shell completion script. Returns True on success."""
    assert _root_app is not None
    _SHELL_MAP = {
        "bash": "BashComplete",
        "zsh": "ZshComplete",
        "fish": "FishComplete",
    }
    if shell not in _SHELL_MAP:
        return False

    import click.shell_completion as _sc

    comp_cls = _sc._available_shells.get(shell)
    if comp_cls is None:
        return False

    from typer.main import get_command as _get_command

    cmd = _get_command(_root_app)
    comp = comp_cls(cmd, {}, "siyarix", "_SIYARIX_COMPLETE")  # type: ignore[arg-type]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(comp.source())
    return True


def _completion_alias(
    shell: str = typer.Argument("bash", help="Shell (bash, zsh, fish, powershell)"),
) -> None:
    """Alias for 'completions'. Use 'siyarix completions' (plural) instead."""
    import re as _re

    for rc_name in (".bashrc", ".zshrc", ".config/fish/config.fish"):
        rc = Path.home() / rc_name
        if rc.is_file():
            try:
                text = rc.read_text(encoding="utf-8")
                cleaned = _re.sub(
                    r'\neval "\$\(siyarix? completion \w+\)".*',
                    "",
                    text,
                )
                if cleaned != text:
                    rc.write_text(cleaned, encoding="utf-8")
            except OSError:
                logger.warning(
                    "Failed to clean up broken completion line in %s", rc_name, exc_info=True
                )

    print(
        "'siyarix completion' (singular) is deprecated. "
        f"Use 'siyarix completions install {shell}' instead.",
        file=sys.stderr,
    )
    print(
        f'Or run: eval "$(_SIYARIX_COMPLETE=source_{shell} siyarix)"',
        file=sys.stderr,
    )


@completions_app.command("install")
def completions_install(
    shell: str = typer.Argument(default="", help="Shell: bash | zsh | fish | powershell"),
) -> None:
    """Install shell completions for Siyarix.

    Examples:
      siyarix completions install bash
      siyarix completions install powershell
    """
    if not shell:
        shell = os.getenv("SHELL", "")
        if shell:
            shell = os.path.basename(shell).lower()
        elif platform.system().lower() == "windows":
            if shutil.which("pwsh"):
                shell = "powershell"
            elif shutil.which("powershell"):
                shell = "powershell"
            else:
                shell = "powershell"
        else:
            for sh in ("pwsh", "bash", "zsh", "fish", "sh"):
                if shutil.which(sh):
                    shell = sh
                    break
            shell = shell or "bash"

    shell = shell.lower()
    comp_dir = get_config_dir() / "completions"
    comp_dir.mkdir(parents=True, exist_ok=True)

    completions_map = {
        "bash": (
            Path("~/.bashrc").expanduser(),
            comp_dir / "siyarix.bash",
            f"source {comp_dir / 'siyarix.bash'}",
        ),
        "zsh": (
            Path("~/.zshrc").expanduser(),
            comp_dir / "siyarix.zsh",
            f"source {comp_dir / 'siyarix.zsh'}",
        ),
        "fish": (
            Path("~/.config/fish/config.fish").expanduser(),
            Path("~/.config/fish/completions/siyarix.fish").expanduser(),
            f"source {comp_dir / 'siyarix.fish'}",
        ),
        "powershell": (
            Path.home() / ".config" / "powershell" / "profile.ps1",
            comp_dir / "siyarix.powershell",
            "$env:_SIYARIX_COMPLETE='source_powershell'; siyarix | Out-String | Invoke-Expression",
        ),
        "pwsh": (
            Path.home() / ".config" / "powershell" / "profile.ps1",
            comp_dir / "siyarix.powershell",
            "$env:_SIYARIX_COMPLETE='source_powershell'; siyarix | Out-String | Invoke-Expression",
        ),
    }

    if shell not in completions_map:
        console.print(f"[red]Unsupported shell: {shell}. Choose: bash, zsh, fish, powershell[/red]")
        raise typer.Exit(1)

    rc_file, comp_file, source_line = completions_map[shell]

    try:
        _generate_completion(shell, comp_file)
        console.print(f"[green]\u2713 Completion script generated: {comp_file}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Could not generate completions: {exc}[/yellow]")
        console.print("[dim]Fallback: adding eval line (runs Python on terminal open)[/dim]")
        source_line = f'eval "$(_SIYARIX_COMPLETE=source_{shell} siyarix)"'

    if rc_file.exists():
        text = rc_file.read_text(encoding="utf-8")
        import re as _re

        cleaned = _re.sub(r"\n# Siyarix completions\n.*?\n", "", text)
        if source_line not in cleaned:
            rc_file.write_text(f"{cleaned}\n# Siyarix completions\n{source_line}\n")
            console.print(f"[green]\u2713 Source line added to {rc_file}[/green]")
        else:
            console.print(f"[dim]Completions already configured in {rc_file}[/dim]")
    else:
        rc_file.parent.mkdir(parents=True, exist_ok=True)
        rc_file.write_text(f"# Siyarix completions\n{source_line}\n")
        console.print(f"[green]\u2713 Created {rc_file}[/green]")

    console.print(f"[dim]Restart your shell or run: source {rc_file}[/dim]")


def register_completions(app: typer.Typer) -> None:
    """Attach completions group and deprecated singular alias to *app*."""
    global _root_app
    _root_app = app
    app.add_typer(completions_app, name="completions")
    app.command(name="completion", hidden=True)(_completion_alias)
