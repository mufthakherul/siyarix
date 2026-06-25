# SPDX-License-Identifier: AGPL-3.0-or-later
"""Simple command pipeline for chaining instructions."""

from __future__ import annotations

import re
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
        elif re.search(r"\band\s+then\b", instruction, re.IGNORECASE):
            parts = [
                p.strip()
                for p in re.split(r"\band\s+then\b", instruction, flags=re.IGNORECASE)
                if p.strip()
            ]
        elif (
            re.search(r"\bthen\b", instruction, re.IGNORECASE)
            and "and then" not in instruction.lower()
        ):
            parts = [
                p.strip()
                for p in re.split(r"\bthen\b", instruction, flags=re.IGNORECASE)
                if p.strip()
            ]
        elif re.search(r"\bfollowed\s+by\b", instruction, re.IGNORECASE):
            parts = [
                p.strip()
                for p in re.split(r"\bfollowed\s+by\b", instruction, flags=re.IGNORECASE)
                if p.strip()
            ]
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
        previous_output: dict[str, Any] = {}
        for step in steps:
            try:
                enriched_ctx = {**(ctx or {}), "previous_output": previous_output}
                res = await executor(step, enriched_ctx)
                if res.get("status") == "completed":
                    result.steps_completed += 1
                    result.all_findings.extend(res.get("findings", []))
                    previous_output = {
                        "output": res.get("output", ""),
                        "findings": res.get("findings", []),
                        "step_id": step.step_id,
                    }
                else:
                    result.steps_failed += 1
                    result.success = False
            except Exception:
                result.steps_failed += 1
                result.success = False
        return result
