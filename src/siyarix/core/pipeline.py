# SPDX-License-Identifier: AGPL-3.0-or-later
"""Simple command pipeline for chaining instructions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine


@dataclass
class PipelineStep:
    instruction: str
    step_id: str = ""


@dataclass
class PipelineResult:
    success: bool = True
    all_findings: list[Any] = field(default_factory=list)
    steps_completed: int = 0
    steps_failed: int = 0


class CommandPipeline:
    """Parse and execute chained commands separated by | or then/and then."""

    def parse(self, instruction: str) -> list[PipelineStep]:
        steps: list[PipelineStep] = []
        if "|" in instruction:
            parts = [p.strip() for p in instruction.split("|") if p.strip()]
        elif " then " in instruction.lower():
            parts = [p.strip() for p in instruction.lower().split(" then ") if p.strip()]
        elif " and then " in instruction.lower():
            parts = [p.strip() for p in instruction.lower().split(" and then ") if p.strip()]
        elif " followed by " in instruction.lower():
            parts = [p.strip() for p in instruction.lower().split(" followed by ") if p.strip()]
        else:
            return [PipelineStep(instruction=instruction)]

        for i, part in enumerate(parts):
            steps.append(PipelineStep(instruction=part, step_id=f"pipe_{i}"))
        return steps

    async def execute(
        self,
        steps: list[PipelineStep],
        executor: Callable[[PipelineStep, Any], Coroutine[Any, Any, dict[str, Any]]],
        ctx: Any = None,
    ) -> PipelineResult:
        result = PipelineResult()
        for step in steps:
            try:
                res = await executor(step, ctx)
                if res.get("status") == "completed":
                    result.steps_completed += 1
                    result.all_findings.extend(res.get("findings", []))
                else:
                    result.steps_failed += 1
                    result.success = False
            except Exception:
                result.steps_failed += 1
                result.success = False
        return result
