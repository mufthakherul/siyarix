# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unified Mode Dispatcher for Siyarix v1.0.0.

Detects the optimal interaction mode based on CLI context, environment variables,
TTY availability, and user preferences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LaunchContext:
    """CLI and environment context used to determine execution mode."""

    args: list[str] = field(default_factory=list)
    is_headless: bool = False
    is_interactive: bool = True
    has_goal_flag: bool = False
    goal: str = ""
    has_workflow: bool = False
    workflow_path: str = ""
    is_dashboard_request: bool = False
    instruction: str = ""
    is_team_session: bool = False
    team_session_id: str = ""
    is_wizard_request: bool = False
    user_skill_level: str = "intermediate"


class BaseMode:
    """Base class for all nine interaction modes."""

    def __init__(self, ctx: LaunchContext) -> None:
        self.ctx = ctx

    def name(self) -> str:
        """Return canonical name of the mode."""
        return self.__class__.__name__

    def execute(self) -> Any:
        """Run execution logic for this mode."""
        raise NotImplementedError("Modes must implement execute()")


class InteractiveShellMode(BaseMode):
    """Mode 1: Interactive Shell — standard CLI execution."""

    def execute(self) -> str:
        return "interactive_shell"


class AIConversationalMode(BaseMode):
    """Mode 2: AI Conversational — multi-turn chat assistant."""

    def execute(self) -> str:
        return "ai_conversational"


class DirectCommandMode(BaseMode):
    """Mode 3: Direct Command — natural language one-shot execution."""

    def execute(self) -> str:
        return "direct_command"


class AutonomousAgentMode(BaseMode):
    """Mode 4: Autonomous Agent — goal-driven reasoning loop."""

    def execute(self) -> str:
        return "autonomous_agent"


class WorkflowAutomationMode(BaseMode):
    """Mode 5: Workflow Automation — execution of a DAG pipeline file."""

    def execute(self) -> str:
        return "workflow_automation"


class TUIDashboardMode(BaseMode):
    """Mode 6: TUI Dashboard — live security console."""

    def execute(self) -> str:
        return "tui_dashboard"


class GuidedWizardMode(BaseMode):
    """Mode 7: Guided Wizard — step-by-step onboarding setup."""

    def execute(self) -> str:
        return "guided_wizard"


class TeamCollaborationMode(BaseMode):
    """Mode 8: Team Collaboration — shared operation session room."""

    def execute(self) -> str:
        return "team_collaboration"


class HeadlessAPIMode(BaseMode):
    """Mode 9: Headless API — REST / WebSocket server."""

    def execute(self) -> str:
        return "headless_api"


class ModeDispatcher:
    """Determines and dispatches to the correct execution mode based on context."""

    def dispatch(self, ctx: LaunchContext) -> BaseMode:
        """Resolve the optimal mode based on context priority."""
        if ctx.is_headless:
            return HeadlessAPIMode(ctx)
        if ctx.is_wizard_request:
            return GuidedWizardMode(ctx)
        if ctx.has_goal_flag:
            return AutonomousAgentMode(ctx)
        if ctx.has_workflow:
            return WorkflowAutomationMode(ctx)
        if ctx.is_dashboard_request:
            return TUIDashboardMode(ctx)
        if ctx.is_team_session:
            return TeamCollaborationMode(ctx)
        if ctx.instruction:
            return DirectCommandMode(ctx)

        # Look for explicit 'chat' in args
        if len(ctx.args) > 0 and ctx.args[0] == "chat":
            return AIConversationalMode(ctx)

        return InteractiveShellMode(ctx)
