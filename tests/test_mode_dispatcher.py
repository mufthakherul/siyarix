# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for core/mode_dispatcher.py — ModeDispatcher (71 stmts, ~59% covered)."""

from __future__ import annotations


import pytest

from siyarix.core.mode_dispatcher import (
    AIConversationalMode,
    AutonomousAgentMode,
    BaseMode,
    DirectCommandMode,
    GuidedWizardMode,
    HeadlessAPIMode,
    InteractiveShellMode,
    LaunchContext,
    ModeDispatcher,
    TeamCollaborationMode,
    TUIDashboardMode,
    WorkflowAutomationMode,
)


class TestLaunchContext:
    def test_defaults(self):
        ctx = LaunchContext()
        assert ctx.args == []
        assert ctx.is_headless is False
        assert ctx.is_interactive is True
        assert ctx.goal == ""
        assert ctx.instruction == ""

    def test_with_values(self):
        ctx = LaunchContext(
            args=["chat"],
            is_headless=False,
            is_interactive=True,
            has_goal_flag=True,
            goal="scan network",
            instruction="scan 10.0.0.1",
        )
        assert ctx.args == ["chat"]
        assert ctx.has_goal_flag is True
        assert ctx.goal == "scan network"

    def test_all_fields_set(self):
        ctx = LaunchContext(
            args=["run"],
            is_headless=True,
            is_interactive=False,
            has_goal_flag=False,
            goal="",
            has_workflow=True,
            workflow_path="/tmp/workflow.yaml",
            is_dashboard_request=True,
            instruction="status",
            is_team_session=True,
            team_session_id="team_1",
            is_wizard_request=True,
            user_skill_level="expert",
        )
        assert ctx.is_headless is True
        assert ctx.is_dashboard_request is True
        assert ctx.user_skill_level == "expert"


class TestBaseMode:
    def test_name(self):
        ctx = LaunchContext()
        mode = BaseMode(ctx)
        assert mode.name() == "BaseMode"

    def test_execute_raises(self):
        ctx = LaunchContext()
        mode = BaseMode(ctx)
        with pytest.raises(NotImplementedError):
            mode.execute()


class TestConcreteModes:
    @pytest.fixture
    def ctx(self):
        return LaunchContext()

    def test_interactive_shell(self, ctx):
        mode = InteractiveShellMode(ctx)
        assert mode.name() == "InteractiveShellMode"
        assert mode.execute() == "interactive_shell"

    def test_ai_conversational(self, ctx):
        mode = AIConversationalMode(ctx)
        assert mode.execute() == "ai_conversational"

    def test_direct_command(self, ctx):
        mode = DirectCommandMode(ctx)
        assert mode.execute() == "direct_command"

    def test_autonomous_agent(self, ctx):
        mode = AutonomousAgentMode(ctx)
        assert mode.execute() == "autonomous_agent"

    def test_workflow_automation(self, ctx):
        mode = WorkflowAutomationMode(ctx)
        assert mode.execute() == "workflow_automation"

    def test_tui_dashboard(self, ctx):
        mode = TUIDashboardMode(ctx)
        assert mode.execute() == "tui_dashboard"

    def test_guided_wizard(self, ctx):
        mode = GuidedWizardMode(ctx)
        assert mode.execute() == "guided_wizard"

    def test_team_collaboration(self, ctx):
        mode = TeamCollaborationMode(ctx)
        assert mode.execute() == "team_collaboration"

    def test_headless_api(self, ctx):
        mode = HeadlessAPIMode(ctx)
        assert mode.execute() == "headless_api"


class TestModeDispatcher:
    @pytest.fixture
    def dispatcher(self):
        return ModeDispatcher()

    def test_dispatch_headless(self, dispatcher):
        ctx = LaunchContext(is_headless=True)
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, HeadlessAPIMode)

    def test_dispatch_wizard(self, dispatcher):
        ctx = LaunchContext(is_wizard_request=True)
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, GuidedWizardMode)

    def test_dispatch_goal(self, dispatcher):
        ctx = LaunchContext(has_goal_flag=True, goal="scan")
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, AutonomousAgentMode)

    def test_dispatch_workflow(self, dispatcher):
        ctx = LaunchContext(has_workflow=True, workflow_path="wf.yaml")
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, WorkflowAutomationMode)

    def test_dispatch_dashboard(self, dispatcher):
        ctx = LaunchContext(is_dashboard_request=True)
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, TUIDashboardMode)

    def test_dispatch_team_session(self, dispatcher):
        ctx = LaunchContext(is_team_session=True, team_session_id="sess_1")
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, TeamCollaborationMode)

    def test_dispatch_instruction(self, dispatcher):
        ctx = LaunchContext(instruction="scan 10.0.0.1")
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, DirectCommandMode)

    def test_dispatch_chat_arg(self, dispatcher):
        ctx = LaunchContext(args=["chat"])
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, AIConversationalMode)

    def test_dispatch_default_interactive(self, dispatcher):
        ctx = LaunchContext()
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, InteractiveShellMode)

    def test_dispatch_priority_order(self, dispatcher):
        # headless has highest priority
        ctx = LaunchContext(
            is_headless=True,
            is_wizard_request=True,
            has_goal_flag=True,
            has_workflow=True,
            is_dashboard_request=True,
            is_team_session=True,
            instruction="test",
        )
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, HeadlessAPIMode)

    def test_dispatch_empty_args_no_chat(self, dispatcher):
        ctx = LaunchContext(args=["not_chat"])
        mode = dispatcher.dispatch(ctx)
        assert isinstance(mode, InteractiveShellMode)

    def test_dispatcher_stores_context(self, dispatcher):
        ctx = LaunchContext(is_headless=True)
        mode = dispatcher.dispatch(ctx)
        assert mode.ctx is ctx
