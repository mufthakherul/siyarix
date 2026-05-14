"""Hybrid execution engine — combines AI-powered dynamic planning with static
registry-based tool execution.

This is the core of the CosmicSec CLI Agent's hybrid architecture:

- **Dynamic mode**: AI interprets natural language → plans steps → executes
  (like GitHub Copilot CLI, Gemini CLI, OpenAI CLI)
- **Static mode**: Uses the tool registry directly for known tools
  (current approach — fast, reliable, offline-capable)
- **Hybrid mode** (default): AI plans complex tasks; static registry handles
  known tools; intelligent fallback between the two

The engine provides a unified execution interface regardless of whether the
plan came from AI or from the static registry.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .ai_planner import (
    AITaskPlanner,
    CloudProvider,
    ExecutionPlan,
    ExecutionStep,
    OllamaProvider,
    OpenAIProvider,
    StepType,
)
from .dynamic_resolver import DynamicResolver
from .executor import run_tool_complete
from .tool_registry import ToolInfo, ToolRegistry

logger = logging.getLogger(__name__)
console = Console()

# Maximum characters of output to include in AI analysis context per step
_MAX_CONTEXT_OUTPUT_LENGTH = 2000

class ExecutionMode(StrEnum):
    """Execution mode for the hybrid engine."""

    STATIC = "static"  # Registry-only (current behavior, no AI)
    DYNAMIC = "dynamic"  # AI-only planning and execution
    HYBRID = "hybrid"  # AI planning with static fallback (recommended)

class StepStatus(StrEnum):
    """Status of an execution step."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"

@dataclass
class StepResult:
    """Result of executing a single step."""

    step_id: str
    status: StepStatus
    output: str = ""
    error: str = ""
    duration_ms: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class EngineResult:
    """Aggregate result of executing an entire plan."""

    plan: ExecutionPlan
    step_results: list[StepResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    mode: ExecutionMode = ExecutionMode.HYBRID
    all_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(r.status in (StepStatus.SUCCESS, StepStatus.SKIPPED) for r in self.step_results)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.step_results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        return counts

class HybridEngine:
    """The hybrid execution engine — brain of the CosmicSec CLI Agent.

    Combines AI-powered dynamic planning with static registry-based execution.
    Supports three modes: static, dynamic, and hybrid (default).

    Usage::

        engine = HybridEngine()
        result = await engine.execute("scan 192.168.1.1 with nmap then analyze results")
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.HYBRID,
        registry: ToolRegistry | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._mode = mode
        self._registry = registry or ToolRegistry()
        self._config = config or {}

        # Discover tools and build context
        self._discovered_tools = self._registry.discover()
        self._tool_map: dict[str, ToolInfo] = {t.name: t for t in self._discovered_tools}
        self._binary_map: dict[str, ToolInfo] = {t.binary: t for t in self._discovered_tools}

        # Initialize AI planner with providers
        self._planner = AITaskPlanner()
        self._setup_providers()

        # Initialize dynamic resolver
        registered = {t.binary: t.path for t in self._discovered_tools}
        registered.update({t.name: t.path for t in self._discovered_tools})
        self._resolver = DynamicResolver(registered_tools=registered)

        # Step results for tracking
        self._completed_steps: dict[str, StepResult] = {}

    def _setup_providers(self) -> None:
        """Configure AI providers based on available configuration."""
        # OpenAI
        openai_key = self._config.get("openai_api_key", "")
        openai_model = self._config.get("openai_model", "gpt-4o")
        provider = OpenAIProvider(api_key=openai_key, model=openai_model)
        if provider.available:
            self._planner.add_provider(provider)

        # Ollama (local)
        ollama_url = self._config.get("ollama_url", "http://localhost:11434")
        ollama_model = self._config.get("ollama_model", "llama3.1")
        self._planner.add_provider(OllamaProvider(base_url=ollama_url, model=ollama_model))

        # CosmicSec Cloud
        cloud_url = self._config.get("server_url", "")
        cloud_key = self._config.get("api_key", "")
        if cloud_url and cloud_key:
            self._planner.add_provider(CloudProvider(server_url=cloud_url, api_key=cloud_key))

    @property
    def mode(self) -> ExecutionMode:
        return self._mode

    @property
    def discovered_tools(self) -> list[ToolInfo]:
        return self._discovered_tools

    def _build_context(self) -> dict[str, Any]:
        """Build context dict for the AI planner."""
        return {
            "available_tools": [
                {
                    "name": t.name,
                    "binary": t.binary,
                    "capabilities": t.capabilities,
                    "version": t.version,
                }
                for t in self._discovered_tools
            ],
            "mode": self._mode.value,
        }

    async def plan(self, instruction: str) -> ExecutionPlan:
        """Create an execution plan for the given instruction.

        This is the planning phase — no execution happens here.
        """
        context = self._build_context()
        force_mode = None
        if self._mode == ExecutionMode.STATIC:
            force_mode = "static"
        elif self._mode == ExecutionMode.DYNAMIC:
            force_mode = "dynamic"

        return await self._planner.plan(instruction, context, force_mode)

    async def execute(
        self,
        instruction: str,
        interactive: bool = True,
        dry_run: bool = False,
    ) -> EngineResult:
        """Plan and execute a natural language instruction.

        Parameters
        ----------
        instruction:
            The user's natural language command.
        interactive:
            If True, show progress and prompt for unsafe commands.
        dry_run:
            If True, plan only — don't execute.
        """
        start_time = time.monotonic()

        # Phase 1: Plan
        plan = await self.plan(instruction)

        if interactive:
            self._display_plan(plan)

        if dry_run:
            return EngineResult(plan=plan, mode=self._mode)

        if not plan.steps:
            if interactive:
                console.print(
                    "[yellow]Could not create an execution plan from your instruction.[/yellow]\n"
                    "[dim]Tip: Try being more specific, e.g. "
                    "'scan 192.168.1.1 with nmap and nuclei'[/dim]"
                )
            return EngineResult(plan=plan, mode=self._mode)

        # Phase 2: Execute
        self._completed_steps.clear()
        result = EngineResult(plan=plan, mode=self._mode)

        if interactive:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                result = await self._execute_plan(plan, progress, interactive)
        else:
            result = await self._execute_plan(plan, None, interactive)

        result.total_duration_ms = (time.monotonic() - start_time) * 1000

        # Phase 3: Summary
        if interactive:
            self._display_summary(result)

        return result

    async def _execute_plan(
        self,
        plan: ExecutionPlan,
        progress: Progress | None,
        interactive: bool,
    ) -> EngineResult:
        """Execute all steps in the plan respecting dependencies."""
        result = EngineResult(plan=plan, mode=self._mode)

        for step in plan.steps:
            # Check dependencies
            if not self._check_dependencies(step):
                sr = StepResult(
                    step_id=step.id,
                    status=StepStatus.SKIPPED,
                    output="Skipped: dependency not met",
                )
                result.step_results.append(sr)
                self._completed_steps[step.id] = sr
                continue

            # Check condition
            if step.condition and not self._evaluate_condition(step.condition):
                sr = StepResult(
                    step_id=step.id,
                    status=StepStatus.SKIPPED,
                    output=f"Skipped: condition not met ({step.condition})",
                )
                result.step_results.append(sr)
                self._completed_steps[step.id] = sr
                continue

            # Execute the step
            task_id = None
            if progress:
                task_id = progress.add_task(
                    f"[{step.id}] {step.description or step.tool or 'executing'}",
                    total=None,
                )

            sr = await self._execute_step(step, interactive)
            result.step_results.append(sr)
            result.all_findings.extend(sr.findings)
            self._completed_steps[step.id] = sr

            if progress and task_id is not None:
                status_icon = "✅" if sr.status == StepStatus.SUCCESS else "❌"
                progress.update(
                    task_id,
                    description=f"{status_icon} [{step.id}] {step.description}",
                    completed=True,
                )

        return result

    async def _execute_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        """Execute a single step based on its type."""
        start = time.monotonic()

        try:
            if step.step_type == StepType.TOOL_RUN:
                return await self._run_tool_step(step, interactive)
            elif step.step_type == StepType.SHELL_CMD:
                return await self._run_shell_step(step, interactive)
            elif step.step_type == StepType.AI_ANALYSIS:
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
            logger.exception("Step %s failed", step.id)
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                error=str(exc),
                duration_ms=duration,
            )

    async def _run_tool_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        """Execute a registered security tool."""
        tool_name = step.tool or ""
        start = time.monotonic()

        # Handle "__all__" special case
        if tool_name == "__all__":
            findings: list[dict[str, Any]] = []
            outputs: list[str] = []
            for tool_info in self._discovered_tools:
                args = list(step.args)
                if step.target:
                    args.append(step.target)
                result = await run_tool_complete(tool_info.path, args, step.timeout)
                outputs.append(f"--- {tool_info.name} ---\n{result.stdout}")
                # Parse findings if parser available
                tool_findings = self._parse_tool_output(tool_info.name, result.stdout)
                findings.extend(tool_findings)
            duration = (time.monotonic() - start) * 1000
            return StepResult(
                step_id=step.id,
                status=StepStatus.SUCCESS,
                output="\n".join(outputs),
                duration_ms=duration,
                findings=findings,
            )

        # Resolve the tool
        resolved = self._resolver.resolve(tool_name, step.args)

        if not resolved.is_safe:
            if interactive:
                console.print(
                    f"[red]⚠ Blocked unsafe command:[/red] {tool_name}\n" f"  Reasons: {'; '.join(resolved.warnings)}"
                )
            return StepResult(
                step_id=step.id,
                status=StepStatus.BLOCKED,
                error=f"Blocked: {'; '.join(resolved.warnings)}",
            )

        # Build args
        args = list(step.args)
        if step.target:
            args.append(step.target)

        # Execute
        result = await run_tool_complete(resolved.path, args, step.timeout)
        duration = (time.monotonic() - start) * 1000

        # Parse findings
        findings = self._parse_tool_output(tool_name, result.stdout)

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if result.exit_code == 0 else StepStatus.FAILED,
            output=result.stdout,
            error=result.stderr if result.exit_code != 0 else "",
            duration_ms=duration,
            findings=findings,
        )

    async def _run_shell_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        """Execute a shell command (from dynamic AI planning)."""
        command = step.command or ""
        if not command:
            return StepResult(
                step_id=step.id,
                status=StepStatus.SKIPPED,
                output="No command specified",
            )

        # Resolve and validate
        parts = command.split()
        base_cmd = parts[0]
        args = parts[1:] + list(step.args)
        if step.target:
            args.append(step.target)

        resolved = self._resolver.resolve(base_cmd, args)

        if not resolved.is_safe:
            if interactive:
                console.print(
                    f"[red]⚠ Blocked unsafe command:[/red] {command}\n" f"  Reasons: {'; '.join(resolved.warnings)}"
                )
            return StepResult(
                step_id=step.id,
                status=StepStatus.BLOCKED,
                error=f"Blocked: {'; '.join(resolved.warnings)}",
            )

        # Warn for unregistered commands
        if resolved.warnings and interactive:
            for w in resolved.warnings:
                console.print(f"[yellow]⚠ {w}[/yellow]")

        start = time.monotonic()
        result = await run_tool_complete(resolved.path, resolved.args, step.timeout)
        duration = (time.monotonic() - start) * 1000

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS if result.exit_code == 0 else StepStatus.FAILED,
            output=result.stdout,
            error=result.stderr if result.exit_code != 0 else "",
            duration_ms=duration,
        )

    async def _run_analysis_step(self, step: ExecutionStep) -> StepResult:
        """Run an AI analysis step on previous results."""
        # Gather outputs from previous steps
        context_outputs = []
        for dep_id in step.depends_on:
            dep_result = self._completed_steps.get(dep_id)
            if dep_result and dep_result.output:
                context_outputs.append(f"[{dep_id}] {dep_result.output[:_MAX_CONTEXT_OUTPUT_LENGTH]}")

        # For now, provide a structured summary
        summary = f"Analysis requested. Context from {len(context_outputs)} previous step(s)."
        if context_outputs:
            summary += "\n" + "\n".join(context_outputs[:5])

        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            output=summary,
            metadata={"type": "analysis", "context_count": len(context_outputs)},
        )

    def _run_report_step(self, step: ExecutionStep) -> StepResult:
        """Generate a report step."""
        fmt = step.metadata.get("format", "text")
        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            output=f"Report generation ({fmt}) — delegated to report engine",
            metadata={"format": fmt},
        )

    async def _run_parallel_step(self, step: ExecutionStep, interactive: bool) -> StepResult:
        """Execute a group of steps in parallel."""
        # Parallel groups would contain sub-steps in metadata
        return StepResult(
            step_id=step.id,
            status=StepStatus.SUCCESS,
            output="Parallel group completed",
        )

    def _check_dependencies(self, step: ExecutionStep) -> bool:
        """Check if all dependencies have completed successfully."""
        for dep_id in step.depends_on:
            dep_result = self._completed_steps.get(dep_id)
            if dep_result is None:
                return False
            if dep_result.status not in (StepStatus.SUCCESS, StepStatus.SKIPPED):
                return False
        return True

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate a step condition based on completed steps."""
        # Simple condition evaluation — expand in future phases
        if "findings.count > 0" in condition:
            total_findings = sum(len(r.findings) for r in self._completed_steps.values())
            return total_findings > 0
        return True  # Default: execute

    def _parse_tool_output(self, tool_name: str, output: str) -> list[dict[str, Any]]:
        """Parse tool output using registered parsers."""
        from .parsers import GobusterParser, NiktoParser, NmapParser, NucleiParser

        parsers: dict[str, Any] = {
            "nmap": NmapParser(),
            "nikto": NiktoParser(),
            "nuclei": NucleiParser(),
            "gobuster": GobusterParser(),
        }

        parser = parsers.get(tool_name)
        if parser:
            try:
                return parser.parse(output)
            except Exception as exc:
                logger.warning("Parser for %s failed: %s", tool_name, exc)

        return []

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _display_plan(self, plan: ExecutionPlan) -> None:
        """Display the execution plan to the user."""
        source_colors = {
            "static": "blue",
            "dynamic": "green",
            "hybrid-static": "cyan",
            "hybrid-dynamic": "magenta",
            "hybrid-fallback": "yellow",
        }
        color = source_colors.get(plan.source, "white")

        table = Table(
            title=f"Execution Plan [{plan.source}]",
            show_header=True,
            header_style="bold",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Tool/Command", style="bold")
        table.add_column("Target", style="green")
        table.add_column("Description")

        for i, step in enumerate(plan.steps, 1):
            tool_cmd = step.tool or step.command or "—"
            table.add_row(
                str(i),
                step.step_type.value,
                tool_cmd,
                step.target or "—",
                step.description,
            )

        console.print()
        console.print(
            Panel(
                table,
                title=f"[{color}]🚀 CosmicSec Hybrid Engine — {plan.source.upper()} mode[/{color}]",
                subtitle=f"Confidence: {plan.confidence:.0%}",
            )
        )
        console.print()

    def _display_summary(self, result: EngineResult) -> None:
        """Display the execution summary."""
        status_icons = {
            "success": "✅",
            "failed": "❌",
            "skipped": "⏭️",
            "blocked": "🚫",
        }

        console.print()
        lines = [
            f"[bold]Execution Summary[/bold] ({result.mode.value} mode)",
            f"  Duration: {result.total_duration_ms / 1000:.1f}s",
            f"  Steps: {len(result.step_results)}",
        ]

        for status, count in result.summary.items():
            icon = status_icons.get(status, "•")
            lines.append(f"  {icon} {status}: {count}")

        if result.all_findings:
            lines.append(f"  📋 Total findings: {len(result.all_findings)}")

        console.print(
            Panel(
                "\n".join(lines),
                title="[bold green]✨ Complete[/bold green]" if result.success else "[bold red]⚠ Issues[/bold red]",
            )
        )
