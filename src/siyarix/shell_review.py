# SPDX-License-Identifier: AGPL-3.0-or-later

"""Interactive review loop for LLM-generated shell commands.

Provides EDIT / RUN / STEP / CANCEL prompts before execution.

**Fails closed.**  A command only reaches this module because the permission gate decided a human
must look at it.  Auto-approving under a pipe, in CI or from cron therefore silently deleted the
control exactly where nobody was watching, so a non-interactive session now REFUSES.  The single
escape hatch is ``SIYARIX_PREAUTHORIZED=1``: opt-in, loudly logged, and audited on every use.

Integration points
------------------
- ``executor.py``              — ``_get_review_and_confirm()`` imports ``review_and_confirm``
- ``executor_autonomous.py``   — ``_review_commands()`` imports ``review_and_confirm``
- ``executor_registry.py``     — plan execution goes through BaseExecutor permission checks
- ``registry.py``              — permission-gate review imports ``review_and_confirm``
- ``chat/handlers.py``         — ``/review`` slash command toggles the ``command_review`` setting
                                  which gates whether the executor calls this module.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax

console = Console()
logger = logging.getLogger(__name__)

PREAUTHORIZED_ENV_VAR = "SIYARIX_PREAUTHORIZED"

_NON_TTY_GUIDANCE = (
    "No terminal is attached, so the required human review cannot be shown. "
    f"Set {PREAUTHORIZED_ENV_VAR}=1 to pre-authorize non-interactive execution, "
    "or run Siyarix from an interactive shell."
)


def review_refusal_message(reason: str = "") -> str:
    """Human-facing denial text when ``review_and_confirm`` returns ``None``.

    Distinguishes a real interactive cancel from a non-TTY fail-closed refusal
    so operators are not told "Cancelled by user" when no prompt was shown.
    """
    if not _is_interactive():
        return _NON_TTY_GUIDANCE
    if reason:
        return f"Cancelled by user: {reason}"
    return "Cancelled by user"


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


def is_interactive() -> bool:
    """True when a human can actually answer a prompt on this session."""
    return _is_interactive()


def is_preauthorized() -> bool:
    """True when the operator opted in to non-interactive execution of gated commands."""
    return os.environ.get(PREAUTHORIZED_ENV_VAR, "0").strip().lower() in ("1", "true", "yes", "on")


def _audit_non_interactive(command: str, tool: str, reason: str, *, approved: bool) -> None:
    """Log and audit a review that no human saw, in either direction."""
    from .audit_log import AuditEventType, AuditSeverity, log_event

    if approved:
        logger.warning(
            "%s=1: approving command without human review (tool=%s reason=%s): %s",
            PREAUTHORIZED_ENV_VAR,
            tool,
            reason,
            command[:200],
        )
        try:
            log_event(
                event_type=AuditEventType.SECURITY_APPROVAL,
                severity=AuditSeverity.HIGH,
                user="shell_review",
                action="Pre-authorized non-interactive execution",
                result="granted",
                details={
                    "tool": tool,
                    "command": command[:500],
                    "reason": f"pre-authorized (non-interactive): {reason}",
                },
            )
        except Exception as exc:  # pragma: no cover - audit must never block control flow
            logger.debug("Audit log unavailable for pre-authorization: %s", exc)
    else:
        logger.warning(
            "Refusing command that requires review (tool=%s reason=%s): %s. %s",
            tool,
            reason,
            command[:200],
            _NON_TTY_GUIDANCE,
        )
        try:
            log_event(
                event_type=AuditEventType.SECURITY_DENIAL,
                severity=AuditSeverity.MEDIUM,
                user="shell_review",
                action="Non-interactive review refused",
                result="denied",
                details={
                    "tool": tool,
                    "command": command[:500],
                    "reason": f"non-interactive review refused: {reason}",
                },
            )
        except Exception as exc:  # pragma: no cover
            logger.debug("Audit log unavailable for review refusal: %s", exc)


def review_command(original: str, tool: str, reason: str) -> ReviewResult:
    """Interactive review loop for potentially dangerous commands.

    Returns ``CANCEL`` when no terminal is attached, unless ``SIYARIX_PREAUTHORIZED=1`` is set.
    """
    if not _is_interactive():
        if is_preauthorized():
            _audit_non_interactive(original, tool, reason, approved=True)
            return ReviewResult(decision=ReviewDecision.RUN, edited_command=original)
        _audit_non_interactive(original, tool, reason, approved=False)
        return ReviewResult(decision=ReviewDecision.CANCEL)

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
        # Default to cancel so Enter never auto-approves a gated command.
        choice = Prompt.ask(
            "[yellow]Review command[/yellow]",
            choices=["edit", "run", "step", "cancel"],
            default="cancel",
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
    """Return the approved command text, or ``None`` when execution is refused.

    Returns ``None`` in a non-interactive session unless ``SIYARIX_PREAUTHORIZED=1`` is set.
    """
    if not _is_interactive():
        if is_preauthorized():
            _audit_non_interactive(original, tool, reason, approved=True)
            return original
        _audit_non_interactive(original, tool, reason, approved=False)
        return None

    result = review_command(original, tool, reason)
    if result.decision == ReviewDecision.CANCEL:
        return None
    if result.decision == ReviewDecision.EDIT:
        return result.edited_command
    return original


__all__ = [
    "PREAUTHORIZED_ENV_VAR",
    "ReviewDecision",
    "ReviewResult",
    "is_interactive",
    "is_preauthorized",
    "review_and_confirm",
    "review_command",
    "review_refusal_message",
]
