"""
Shell-injection review loop for suspicious commands.
Provides interactive EDIT / RUN / STEP / CANCEL prompts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax

console = Console()
logger = logging.getLogger(__name__)


class ReviewDecision:
    EDIT = "edit"
    RUN = "run"
    STEP = "step"
    CANCEL = "cancel"


@dataclass
class ReviewResult:
    decision: str  # edit | run | step | cancel
    edited_command: str = ""


def review_command(original: str, tool: str, reason: str) -> ReviewResult:
    """Interactive review loop for potentially dangerous commands."""
    console.print(
        Panel(
            f"[bold yellow]Command Review Required[/bold yellow]\n"
            f"[bold]Tool:[/bold] {tool}\n"
            f"[bold]Reason:[/bold] {reason}\n"
            f"{Syntax(original, 'bash', theme='monokai')}",
            title="Shell Injection Review",
            border_style="yellow",
        )
    )

    while True:
        choice = Prompt.ask(
            "[yellow]Review command[/yellow]",
            choices=["edit", "run", "step", "cancel"],
            default="edit",
        )

        if choice == "edit":
            edited = Prompt.ask("Edit command", default=original)
            return ReviewResult(decision=ReviewDecision.EDIT, edited_command=edited)

        if choice == "run":
            return ReviewResult(decision=ReviewDecision.RUN, edited_command=original)

        if choice == "step":
            return ReviewResult(decision=ReviewDecision.STEP, edited_command=original)

        if choice == "cancel":
            return ReviewResult(decision=ReviewDecision.CANCEL)


def review_and_confirm(original: str, tool: str, reason: str) -> str | None:
    """Simplify: returns edited command or None if cancelled."""
    result = review_command(original, tool, reason)
    if result.decision == ReviewDecision.CANCEL:
        return None
    if result.decision == ReviewDecision.EDIT:
        return result.edited_command
    return original


__all__ = ["ReviewResult", "review_command", "review_and_confirm", "ReviewDecision"]
