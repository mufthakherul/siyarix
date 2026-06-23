# SPDX-License-Identifier: AGPL-3.0-or-later

"""Interactive review loop for LLM-generated shell commands.
Provides EDIT / RUN / STEP / CANCEL prompts before execution.
Auto-approves in non-TTY/CI mode to prevent blocking.

Integration points
------------------
- ``executor.py``              — ``_get_review_and_confirm()`` imports ``review_and_confirm``
- ``executor_autonomous.py``   — ``_review_commands()`` imports ``review_and_confirm``
- ``registry.py``              — permission-gate review imports ``review_and_confirm``
- ``chat/handlers.py``         — ``/review`` slash command toggles the ``command_review`` setting
                                  which gates whether the executor calls this module.
"""

from __future__ import annotations

import logging
import sys
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
    decision: str
    edited_command: str = ""


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def review_command(original: str, tool: str, reason: str) -> ReviewResult:
    """Interactive review loop for potentially dangerous commands.
    Auto-approves in non-TTY/CI mode.
    """
    if not _is_interactive():
        logger.info("Non-TTY mode: auto-approving command: %s", original[:80])
        return ReviewResult(decision=ReviewDecision.RUN, edited_command=original)

    from rich.console import Group
    from rich.text import Text

    syntax = Syntax(original, "bash", theme="monokai")
    console.print(
        Panel(
            Group(
                Text(f"Tool: {tool}", style="bold"),
                Text(f"Reason: {reason}", style="bold"),
                Text(""),
                syntax,
            ),
            title="Command Execution Review",
            border_style="yellow",
        ),
    )

    while True:
        choice = Prompt.ask(
            "[yellow]Review command[/yellow]",
            choices=["edit", "run", "step", "cancel"],
            default="run",
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
    """Simplify: returns edited command or None if cancelled.
    Auto-approves in non-TTY/CI mode to prevent blocking.
    """
    if not _is_interactive():
        logger.info("Non-TTY mode: auto-approving command for tool=%s", tool)
        return original

    result = review_command(original, tool, reason)
    if result.decision == ReviewDecision.CANCEL:
        return None
    if result.decision == ReviewDecision.EDIT:
        return result.edited_command
    return original


__all__ = ["ReviewDecision", "ReviewResult", "review_and_confirm", "review_command"]
