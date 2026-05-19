"""NexSec Command Pipeline System — Executing chained operations.

Supports piping operations with '|' or sequential steps with 'then'.
Context and findings accumulate across the execution chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..interpreter import RuleInterpreter, InterpretedTask, TaskCategory


@dataclass
class PipelineStep:
    """A single step in the execution pipeline."""

    step_id: str
    instruction: str
    interpreted_task: InterpretedTask | None = None
    continue_on_error: bool = True
    status: str = "pending"  # pending, running, completed, failed


@dataclass
class PipelineContext:
    """Accumulated context across all pipeline steps."""

    targets: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    accumulated_findings: list[dict[str, Any]] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)

    def update(self, result: dict[str, Any]) -> None:
        """Update context with result of a pipeline step."""
        if "targets" in result:
            for t in result["targets"]:
                if t not in self.targets:
                    self.targets.append(t)
        if "tools" in result:
            for tool in result["tools"]:
                if tool not in self.tools:
                    self.tools.append(tool)
        if "findings" in result:
            self.accumulated_findings.extend(result["findings"])
        if "variables" in result:
            self.variables.update(result["variables"])


@dataclass
class PipelineResult:
    """Final outcome of pipeline execution."""

    success: bool
    steps: list[PipelineStep]
    context: PipelineContext
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    error_message: str = ""


class CommandPipeline:
    """Parses and executes a chain of sequential operations."""

    def __init__(self) -> None:
        self._interpreter = RuleInterpreter()

    def parse(self, pipeline_str: str) -> list[PipelineStep]:
        """Parse natural language or piped command into sequential steps."""
        # Split on pipe '|' or explicit step separators like 'then', 'and then'
        steps_raw: list[str] = []
        if "|" in pipeline_str:
            steps_raw = [s.strip() for s in pipeline_str.split("|")]
        else:
            # Match variations of 'then', 'and then', 'next', 'followed by'
            pattern = r"\s+(?:then|and then|next|followed by)\s+"
            steps_raw = [s.strip() for s in re.split(pattern, pipeline_str, flags=re.IGNORECASE)]

        steps: list[PipelineStep] = []
        for i, raw_step in enumerate(steps_raw):
            if not raw_step:
                continue
            # Interpret task
            task = self._interpreter.interpret(raw_step)
            steps.append(
                PipelineStep(
                    step_id=f"step_{i + 1}",
                    instruction=raw_step,
                    interpreted_task=task,
                )
            )
        return steps

    async def execute(
        self,
        steps: list[PipelineStep],
        executor_func: Callable[[PipelineStep, PipelineContext], Any],
    ) -> PipelineResult:
        """Execute all steps sequentially using the provided runner function."""
        context = PipelineContext()
        success = True
        err_msg = ""

        for step in steps:
            step.status = "running"
            try:
                # Merge target context down to subsequent steps if they lack targets
                if step.interpreted_task and not step.interpreted_task.targets and context.targets:
                    step.interpreted_task.targets = list(context.targets)

                # Execute step
                result = await executor_func(step, context)
                step.status = "completed"

                if isinstance(result, dict):
                    context.update(result)
                    if result.get("status") == "failed":
                        step.status = "failed"
                        if not step.continue_on_error:
                            success = False
                            err_msg = result.get("error", "Step execution failed")
                            break
                elif hasattr(result, "is_success") and not result.is_success:
                    step.status = "failed"
                    if not step.continue_on_error:
                        success = False
                        err_msg = getattr(result, "error_message", "Step failed")
                        break

            except Exception as exc:
                step.status = "failed"
                if not step.continue_on_error:
                    success = False
                    err_msg = str(exc)
                    break

        return PipelineResult(
            success=success,
            steps=steps,
            context=context,
            all_findings=context.accumulated_findings,
            error_message=err_msg,
        )
