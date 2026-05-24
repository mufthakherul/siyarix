"""ToolExecutor: encapsulates execution logic for plan steps.

This class isolates tool/shell execution so ExecutionEngine can delegate
and ToolExecutor can be unit-tested with injected run_tool function.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from rich.console import Console

from .executor import run_tool_complete
from .metrics import get_metrics
from .notifications import notification_center
from .security_hardening import redactor

from .engine_types import StepResult, StepStatus
from .planner import ExecutionStep, StepType

console = Console()


class ToolExecutor:
    def __init__(
        self,
        resolver: Any,
        discovered_tools: list[Any],
        graph: Any,
        run_tool_fn: Callable[..., Any] | None = None,
    ) -> None:
        self._resolver = resolver
        self._discovered_tools = discovered_tools
        self._graph = graph
        self._run_tool = run_tool_fn or run_tool_complete

    async def execute_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        start = time.monotonic()

        try:
            if step.step_type == StepType.TOOL_RUN:
                return await self._run_tool_step(step)
            elif step.step_type == StepType.SHELL_CMD:
                return await self._run_shell_step(step, interactive)
            elif step.step_type == StepType.ANALYSIS:
                return await self._run_analysis_step(step)
            elif step.step_type == StepType.REPORT:
                return self._run_report_step(step)
            elif step.step_type == StepType.PARALLEL_GROUP:
                return await self._run_parallel_step(step, interactive)
            else:
                return StepResult(
                    step_id=step.id,
                    status=StepStatus.SKIPPED,
                    output=f"Unsupported step type: {step.step_type}",
                )
        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                error=str(exc),
                duration_ms=duration,
            )

    async def _run_tool_step(self, step: ExecutionStep) -> StepResult:
        tool_name = step.tool or ""
        start = time.monotonic()

        # Handle __all__ case
        if tool_name == "__all__":
            findings = []
            outputs = []
            metrics = get_metrics()
            for tool_info in self._discovered_tools:
                args = list(step.args)
                if step.target:
                    args.append(step.target)
                result = await self._run_tool(tool_info.path, args, step.timeout)
                outputs.append(f"--- {tool_info.name} ---\n{result.stdout}")
                # TODO: parse findings and ingest into graph
                metrics.record_tool_execution(
                    tool_name=tool_info.name,
                    duration=0.0,
                    successful=True,
                    findings_count=0,
                )
            duration = (time.monotonic() - start) * 1000
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output="\n".join(outputs),
                duration_ms=duration,
                findings=findings,
            )

        # Resolve tool
        resolved = self._resolver.resolve(step.tool or "", step.args)
        if not resolved.is_safe:
            return StepResult(step_id=step.id, status=StepStatus.BLOCKED, error=f"Blocked: {'; '.join(resolved.warnings)}")

        args = list(step.args)
        if step.target:
            args.append(step.target)

        result = await self._run_tool(resolved.path, args, step.timeout)
        duration = (time.monotonic() - start) * 1000

        # Redact output
        safe_output = redactor.redact(result.stdout)
        safe_error = redactor.redact(result.stderr) if result.exit_code != 0 else ""

        # Parse findings using available parsers
        findings = []
        try:
            from .parsers import GobusterParser, NiktoParser, NmapParser, NucleiParser

            parsers = {
                "nmap": NmapParser(),
                "nikto": NiktoParser(),
                "nuclei": NucleiParser(),
                "gobuster": GobusterParser(),
            }
            parser = parsers.get(tool_name)
            if parser:
                try:
                    findings = parser.parse(result.stdout)
                except Exception:
                    findings = []
        except Exception:
            findings = []

        # Ingest findings into graph and emit notifications
        for f in findings:
            try:
                if self._graph is not None and hasattr(self._graph, "ingest_finding"):
                    self._graph.ingest_finding(f, tool=tool_name)
            except Exception:
                pass
            try:
                notification_center.finding(
                    tool=tool_name,
                    severity=f.get("severity", "info"),
                    description=f.get("description", str(f)),
                    target=step.target or "",
                )
            except Exception:
                pass

        # Record metrics
        get_metrics().record_tool_execution(
            tool_name=tool_name,
            duration=duration / 1000,
            successful=result.exit_code == 0,
            findings_count=len(findings),
        )

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if result.exit_code == 0 else StepStatus.FAILED,
            output=safe_output,
            error=safe_error,
            duration_ms=duration,
            findings=findings,
        )

    async def _run_shell_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        command = step.command or ""
        if not command:
            return StepResult(step_id=step.id, status=StepStatus.SKIPPED, output="No command specified")

        parts = command.split()
        base_cmd = parts[0]
        args = parts[1:] + list(step.args)
        if step.target:
            args.append(step.target)

        resolved = self._resolver.resolve(base_cmd, args)
        if not resolved.is_safe:
            return StepResult(step_id=step.id, status=StepStatus.BLOCKED, error=f"Blocked: {'; '.join(resolved.warnings)}")

        result = await self._run_tool(resolved.path, resolved.args, step.timeout)
        duration = (time.monotonic() - start) * 1000

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if result.exit_code == 0 else StepStatus.FAILED,
            output=redactor.redact(result.stdout),
            error=redactor.redact(result.stderr) if result.exit_code != 0 else "",
            duration_ms=duration,
        )

    async def _run_analysis_step(self, step: ExecutionStep) -> StepResult:
        # Minimal analysis implementation — returns summary
        context_outputs = []
        for dep_id in step.depends_on:
            # engine populates completed steps; ToolExecutor doesn't access them here
            pass
        return StepResult(step_id=step.id, status=StepStatus.SUCCESS, output="Analysis placeholder", metadata={"type": "analysis"})

    def _run_report_step(self, step: ExecutionStep) -> StepResult:
        fmt = step.metadata.get("format", "text")
        return StepResult(step_id=step.id, status=StepStatus.SUCCESS, output=f"Report generation ({fmt})")

    async def _run_parallel_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        sub_steps = step.metadata.get("steps", [])
        if not sub_steps:
            return StepResult(step_id=step.id, status=StepStatus.SKIPPED, output="No sub-steps")

        semaphore = asyncio.Semaphore(step.metadata.get("max_concurrent", 3))

        async def run_bounded(s: ExecutionStep) -> StepResult:
            async with semaphore:
                return await self.execute_step(s, interactive)

        tasks = [run_bounded(s) for s in sub_steps]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        outputs = []
        errors = []
        findings = []

        for r in results:
            if isinstance(r, Exception):
                errors.append(str(r))
            elif isinstance(r, StepResult):
                if r.output:
                    outputs.append(r.output)
                if r.error:
                    errors.append(r.error)
                findings.extend(r.findings)

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if not errors else StepStatus.FAILED,
            output="\n".join(outputs) if outputs else "Parallel execution completed",
            error="; ".join(errors) if errors else "",
            findings=findings,
        )


__all__ = ["ToolExecutor"]
