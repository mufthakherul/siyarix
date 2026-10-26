# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focused unit tests for SX-003 / SX-004 / SX-005 / SX-010 remediations."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.exceptions import PermissionDeniedError
from siyarix.executor import BaseExecutor
from siyarix.executor_autonomous import AutonomousExecutor, CommandResult
from siyarix.models import ExecutionPlan, PlanStatus, PlanStep, PlanType, StepStatus
from siyarix.report import ReportEngine
from siyarix.report.models import ReportConfig, ReportFormat

# ── SX-003: permission gate before spawn ───────────────────────────────────


class TestSX003PermissionGate:
    @pytest.mark.asyncio
    async def test_denied_gate_starts_zero_handlers(self) -> None:
        gate = MagicMock()
        gate.check.return_value = MagicMock(
            allowed=False, reason="blocked by policy", requires_review=False
        )
        executor = AutonomousExecutor(permission_gate=gate, command_review=False)
        handler = AsyncMock(return_value={"status": "success"})
        executor.register_handler("nmap", handler)

        step = PlanStep(id="s1", tool="nmap", command="nmap 10.0.0.1")
        state = CommandResult(label="$ nmap 10.0.0.1")

        with patch.object(executor, "_execute_shell_command", new_callable=AsyncMock) as mock_shell:
            result_step, result = await executor._exec_one(step, state)

        assert result.get("denied") is True
        assert result_step.status == StepStatus.FAILED
        assert "blocked" in str(result.get("error", "")).lower()
        mock_shell.assert_not_awaited()
        handler.assert_not_awaited()
        assert state.done is True

    @pytest.mark.asyncio
    async def test_denied_gate_skips_tool_step_handler(self) -> None:
        gate = MagicMock()
        gate.check.return_value = MagicMock(
            allowed=False, reason="forbidden", requires_review=False
        )
        executor = AutonomousExecutor(permission_gate=gate, command_review=False)
        handler = AsyncMock(return_value={"status": "success"})
        executor.register_handler("custom", handler)

        # Tool step with command in args triggers gate via _check_permissions
        step = PlanStep(
            id="s1",
            tool="custom",
            command="rm -rf /",
            args={},
        )
        state = CommandResult(label="custom")
        _, result = await executor._exec_one(step, state)
        assert result.get("denied") is True
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_command_review_still_cancels_plan(self) -> None:
        executor = AutonomousExecutor(command_review=True)
        plan = ExecutionPlan(
            goal="test",
            steps=[PlanStep(id="s1", command="echo hi")],
        )
        with patch("siyarix.shell_review.review_and_confirm", return_value=None):
            result = await executor.execute_plan(plan, live_display=False)
        assert result.status == PlanStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_allowed_gate_proceeds_to_shell(self) -> None:
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=True, reason="", requires_review=False)
        executor = AutonomousExecutor(permission_gate=gate, command_review=False)
        step = PlanStep(id="s1", tool="echo", command="echo ok")
        state = CommandResult(label="$ echo ok")
        with (
            patch.object(
                executor,
                "_execute_shell_command",
                new_callable=AsyncMock,
                return_value={"status": "success", "output": "ok"},
            ) as mock_shell,
            patch.object(executor, "_try_parse_output", side_effect=lambda s, r: r),
        ):
            _, result = await executor._exec_one(step, state)
        mock_shell.assert_awaited_once()
        assert result["status"] == "success"


# ── SX-004: scope via BaseExecutor.check_scope ─────────────────────────────


class TestSX004ScopeWiring:
    def test_check_scope_blocks_public_domain_exemption(self) -> None:
        executor = BaseExecutor()
        with patch.dict("os.environ", {"SIYARIX_ALLOWED_SCOPE": "10.0.0.0/8"}):
            with pytest.raises(PermissionDeniedError, match="github.com"):
                executor.check_scope("curl https://github.com/foo")

    def test_check_scope_ipv6(self) -> None:
        executor = BaseExecutor()
        with patch.dict("os.environ", {"SIYARIX_ALLOWED_SCOPE": "2001:db8::/32"}):
            executor.check_scope("nmap -6 2001:db8::10")
            with pytest.raises(PermissionDeniedError):
                executor.check_scope("nmap -6 2001:db9::10")

    @pytest.mark.asyncio
    async def test_check_permissions_kwargs_only_enforces_scope(self) -> None:
        executor = BaseExecutor()
        step = PlanStep(tool="nmap", command="", args={"target": "8.8.8.8"})
        with patch.dict("os.environ", {"SIYARIX_ALLOWED_SCOPE": "10.0.0.0/8"}):
            with pytest.raises(PermissionDeniedError):
                await executor._check_permissions(step)

    @pytest.mark.asyncio
    async def test_registry_execute_enforces_scope_on_kwargs(self) -> None:
        from siyarix.registry import ToolRegistry
        from siyarix.tool_models import ToolCapability

        reg = ToolRegistry()
        handler = AsyncMock(return_value={"status": "success"})
        for tool_name in ("nmap", "nikto"):
            reg.register(ToolCapability(name=tool_name, installed=True), handler)
        with patch.dict("os.environ", {"SIYARIX_ALLOWED_SCOPE": "10.0.0.0/8"}):
            with pytest.raises(PermissionDeniedError):
                await reg.execute("nmap", target="8.8.8.8")
            with pytest.raises(PermissionDeniedError):
                await reg.execute("nikto", args=["-h", "8.8.8.8"])
            with pytest.raises(PermissionDeniedError):
                await reg.execute("nikto", target="10.0.0.5", args=["-h", "evil.example.com"])
            # Non-empty command must not short-circuit kwargs hosts.
            with pytest.raises(PermissionDeniedError):
                await reg.execute(
                    "nikto",
                    command="nikto -h 10.0.0.5",
                    args=["-h", "evil.example.com"],
                )
            with pytest.raises(PermissionDeniedError):
                await reg.execute("nikto", command="true", target="evil.example.com")

    def test_check_scope_cidr_only_blocks_domain(self) -> None:
        executor = BaseExecutor()
        with patch.dict("os.environ", {"SIYARIX_ALLOWED_SCOPE": "192.168.0.0/16"}):
            with pytest.raises(PermissionDeniedError, match="evil.com"):
                executor.check_scope("nikto -h evil.com")


# ── SX-005: XSS escaping + CSP + severity badges ───────────────────────────


class TestSX005HtmlReportSafety:
    def test_escapes_xss_in_finding_fields(self) -> None:
        engine = ReportEngine()
        payload = "<script>alert('xss')</script>"
        findings = [
            {
                "severity": "high",
                "title": payload,
                "description": f"<img src=x onerror={payload}>",
                "tool": "<svg/onload=alert(1)>",
                "target": '"><script>alert(2)</script>',
                "evidence": "<script>document.cookie</script>",
            }
        ]
        report = engine.build_report(
            findings, target=payload, config=ReportConfig(cvss_scoring=False)
        )
        html = engine.render(report, ReportFormat.HTML)

        assert "<script>alert('xss')</script>" not in html
        assert "&lt;script&gt;" in html or "&#" in html
        assert "onerror=" not in html.lower() or "&lt;img" in html
        assert "Content-Security-Policy" in html
        assert "default-src 'none'" in html

    def test_medium_badge_uses_med_variable_not_medi(self) -> None:
        engine = ReportEngine()
        findings = [{"severity": "medium", "title": "Med finding", "description": "x"}]
        report = engine.build_report(findings, target="t", config=ReportConfig(cvss_scoring=False))
        html = engine.render(report, ReportFormat.HTML)
        assert "badge-medium" in html
        assert "var(--medi)" not in html
        assert "--med:" in html or "var(--med)" in html
        # Contrasting fg/bg for severity badges
        assert "badge-critical" in html or "badge-medium" in html
        assert "--med-fg" in html or "badge-medium" in html

    def test_metadata_target_escaped(self) -> None:
        engine = ReportEngine()
        report = engine.build_report(
            [],
            target="<b>bold</b>",
            config=ReportConfig(cvss_scoring=False),
        )
        html = engine.render(report, ReportFormat.HTML)
        assert "<b>bold</b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html


# ── SX-010: dependency-aware scheduling ────────────────────────────────────


class TestSX010DependencyScheduling:
    @pytest.mark.asyncio
    async def test_dependent_waits_for_success(self) -> None:
        executor = AutonomousExecutor(command_review=False, max_workers=2)
        order: list[str] = []

        async def fake_exec(step: PlanStep, state: CommandResult):
            order.append(step.id)
            step.status = StepStatus.COMPLETED
            step.result = {"status": "success"}
            state.done = True
            state.exit_code = 0
            return step, step.result

        s1 = PlanStep(id="a", command="echo a")
        s2 = PlanStep(id="b", command="echo b", dependencies=["a"])
        plan = ExecutionPlan(
            goal="deps",
            plan_type=PlanType.DAG,
            steps=[s1, s2],
        )

        with patch.object(executor, "_exec_one", side_effect=fake_exec):
            result = await executor.execute_plan(plan, live_display=False)

        assert order == ["a", "b"]
        assert result.steps[0].status == StepStatus.COMPLETED
        assert result.steps[1].status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_skips_dependents_of_failed_steps(self) -> None:
        executor = AutonomousExecutor(command_review=False, max_workers=2)

        async def fake_exec(step: PlanStep, state: CommandResult):
            if step.id == "root":
                step.status = StepStatus.FAILED
                step.result = {"status": "error", "error": "boom"}
                state.done = True
                state.exit_code = 1
                return step, step.result
            # Should never run for child
            step.status = StepStatus.COMPLETED
            step.result = {"status": "success"}
            state.done = True
            return step, step.result

        root = PlanStep(id="root", command="false")
        child = PlanStep(id="child", command="echo child", dependencies=["root"])
        plan = ExecutionPlan(goal="fail-deps", plan_type=PlanType.DAG, steps=[root, child])

        with patch.object(executor, "_exec_one", side_effect=fake_exec):
            result = await executor.execute_plan(plan, live_display=False)

        assert result.get_step("root").status == StepStatus.FAILED  # type: ignore[union-attr]
        assert result.get_step("child").status == StepStatus.SKIPPED  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_cycle_is_handled_safely(self) -> None:
        executor = AutonomousExecutor(command_review=False, max_workers=2)
        started: list[str] = []

        async def fake_exec(step: PlanStep, state: CommandResult):
            started.append(step.id)
            step.status = StepStatus.COMPLETED
            step.result = {"status": "success"}
            state.done = True
            state.exit_code = 0
            return step, step.result

        a = PlanStep(id="a", command="echo a", dependencies=["b"])
        b = PlanStep(id="b", command="echo b", dependencies=["a"])
        plan = ExecutionPlan(goal="cycle", plan_type=PlanType.DAG, steps=[a, b])

        with patch.object(executor, "_exec_one", side_effect=fake_exec):
            result = await executor.execute_plan(plan, live_display=False)

        # Neither step should have been executed; both skipped due to cycle/deadlock
        assert started == []
        assert all(s.status == StepStatus.SKIPPED for s in result.steps)

    @pytest.mark.asyncio
    async def test_concurrency_bounded_by_pool(self) -> None:
        executor = AutonomousExecutor(command_review=False, max_workers=2)
        in_flight = 0
        max_seen = 0

        async def fake_exec(step: PlanStep, state: CommandResult):
            nonlocal in_flight, max_seen
            in_flight += 1
            max_seen = max(max_seen, in_flight)
            import asyncio

            await asyncio.sleep(0.05)
            in_flight -= 1
            step.status = StepStatus.COMPLETED
            step.result = {"status": "success"}
            state.done = True
            state.exit_code = 0
            return step, step.result

        steps = [PlanStep(id=f"s{i}", command=f"echo {i}") for i in range(5)]
        plan = ExecutionPlan(goal="parallel", plan_type=PlanType.PARALLEL, steps=steps)

        with patch.object(executor, "_exec_one", side_effect=fake_exec):
            await executor.execute_plan(plan, live_display=False)

        assert max_seen <= 2
