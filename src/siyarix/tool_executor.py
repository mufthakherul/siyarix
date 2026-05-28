# SPDX-License-Identifier: AGPL-3.0-or-later

"""ToolExecutor: encapsulates execution logic for plan steps.

This class isolates tool/shell execution so ExecutionEngine can delegate
and ToolExecutor can be unit-tested with injected run_tool function.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from rich.console import Console

from .engine_types import StepResult, StepStatus
from .executor import run_tool_complete
from .metrics import get_metrics
from .planner import ExecutionStep, StepType
from .security_hardening import redactor

logger = logging.getLogger(__name__)

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

    async def execute_step(
        self, step: ExecutionStep, interactive: bool = False
    ) -> StepResult:
        start = time.monotonic()

        try:
            if step.step_type == StepType.TOOL_RUN:
                return await self._run_tool_step(step)
            elif step.step_type == StepType.SHELL_CMD:
                return await self._run_shell_step(step, interactive)
            elif step.step_type == StepType.ANALYSIS:
                return await self._run_analysis_step(step)
            elif step.step_type == StepType.REPORT:
                return await self._run_report_step(step)
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

        if tool_name == "__all__":
            findings: list = []
            outputs: list = []
            metrics = get_metrics()
            for tool_info in self._discovered_tools:
                tool_start = time.monotonic()
                args = list(step.args)
                if step.target:
                    args.append(step.target)
                result = await self._run_tool(tool_info.path, args, step.timeout)
                tool_duration = time.monotonic() - tool_start
                outputs.append(f"--- {tool_info.name} ---\n{result.stdout}")
                tool_findings = self._parse_output(tool_info.name, result.stdout)
                findings.extend(tool_findings)
                metrics.record_tool_execution(
                    tool_name=tool_info.name,
                    duration=tool_duration,
                    successful=result.exit_code == 0,
                    findings_count=len(tool_findings),
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
            return StepResult(
                step_id=step.id,
                status=StepStatus.BLOCKED,
                error=f"Blocked: {'; '.join(resolved.warnings)}",
            )

        args = list(step.args)
        if step.target:
            args.append(step.target)

        result = await self._run_tool(resolved.path, args, step.timeout)
        duration = (time.monotonic() - start) * 1000

        # Redact output
        safe_output = redactor.redact(result.stdout)
        safe_error = redactor.redact(result.stderr) if result.exit_code != 0 else ""

        findings = self._parse_output(tool_name, result.stdout)

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

    async def _run_shell_step(
        self, step: ExecutionStep, interactive: bool
    ) -> StepResult:
        command = step.command or ""
        if not command:
            return StepResult(
                step_id=step.id,
                status=StepStatus.SKIPPED,
                output="No command specified",
            )

        parts = command.split()
        base_cmd = parts[0]
        args = parts[1:] + list(step.args)
        if step.target:
            args.append(step.target)

        resolved = self._resolver.resolve(base_cmd, args)
        if not resolved.is_safe:
            return StepResult(
                step_id=step.id,
                status=StepStatus.BLOCKED,
                error=f"Blocked: {'; '.join(resolved.warnings)}",
            )

        start_time = time.monotonic()
        result = await self._run_tool(resolved.path, resolved.args, step.timeout)
        duration = (time.monotonic() - start_time) * 1000

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if result.exit_code == 0 else StepStatus.FAILED,
            output=redactor.redact(result.stdout),
            error=redactor.redact(result.stderr) if result.exit_code != 0 else "",
            duration_ms=duration,
        )

    def _parse_output(self, tool_name: str, output: str) -> list[dict[str, Any]]:
        """Parse tool output using registered parsers."""
        try:
            from .parsers import (
                Parser, AircrackParser, AmassParser, BettercapParser,
                BurpsuiteParser, EttercapParser, FfufParser,
                GobusterParser, HashcatParser, HydraParser,
                ImpacketParser, JohnParser, MasscanParser,
                MetasploitParser, NiktoParser, NmapParser,
                NucleiParser, ShodanParser, SqlmapParser,
                SubfinderParser, WpscanParser, ZaproxyParser,
            )

            parsers: dict[str, Parser] = {
                "aircrack-ng": AircrackParser(),
                "amass": AmassParser(),
                "bettercap": BettercapParser(),
                "burpsuite": BurpsuiteParser(),
                "ettercap": EttercapParser(),
                "ffuf": FfufParser(),
                "gobuster": GobusterParser(),
                "hashcat": HashcatParser(),
                "hydra": HydraParser(),
                "impacket": ImpacketParser(),
                "john": JohnParser(),
                "masscan": MasscanParser(),
                "metasploit": MetasploitParser(),
                "nikto": NiktoParser(),
                "nmap": NmapParser(),
                "nuclei": NucleiParser(),
                "shodan": ShodanParser(),
                "sqlmap": SqlmapParser(),
                "subfinder": SubfinderParser(),
                "wpscan": WpscanParser(),
                "zaproxy": ZaproxyParser(),
            }
            parser = parsers.get(tool_name)
            if parser:
                return parser.parse(output) or []
        except Exception as exc:
            logger.warning("Parser failed for %s: %s", tool_name, exc)
        return []

    async def _run_analysis_step(self, step: ExecutionStep) -> StepResult:
        try:
            from .report_engine import ReportEngine, ReportFormat

            engine = ReportEngine()
            report = engine.render(
                engine.build_report(findings=[], target=step.description or "Analysis"),
                fmt=ReportFormat.MARKDOWN,
            )
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output=report or "Analysis complete — no findings to summarize",
                metadata={"type": "analysis"},
            )
        except Exception as exc:
            logger.debug("Analysis via ReportEngine failed: %s", exc)
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output=f"Analysis requested: {step.description}",
                metadata={"type": "analysis"},
            )

    async def _run_report_step(self, step: ExecutionStep) -> StepResult:
        fmt = step.metadata.get("format", "text")
        try:
            from .report_engine import ReportEngine, ReportFormat

            engine = ReportEngine()
            report = engine.render(
                engine.build_report(findings=[], target=step.description or "Report"),
                fmt=ReportFormat.MARKDOWN if fmt == "markdown" else ReportFormat.HTML if fmt == "html" else ReportFormat.JSON if fmt == "json" else ReportFormat.MARKDOWN,
            )
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output=report or f"Report generated ({fmt})",
                metadata={"format": fmt},
            )
        except Exception as exc:
            logger.debug("Report via ReportEngine failed: %s", exc)
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output=f"Report generation ({fmt})",
                metadata={"format": fmt},
            )

    async def _run_parallel_step(
        self, step: ExecutionStep, interactive: bool
    ) -> StepResult:
        sub_steps = step.metadata.get("steps", [])
        if not sub_steps:
            return StepResult(
                step_id=step.id, status=StepStatus.SKIPPED, output="No sub-steps"
            )

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
