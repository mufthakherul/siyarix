# SPDX-License-Identifier: AGPL-3.0-or-later
"""Siyarix YAML Playbook Engine."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

from siyarix.models import ExecutionPlan, PlanStep, PlanType
from siyarix.workflow import WorkflowEngine

logger = logging.getLogger(__name__)

class PlaybookEngine:
    """Parses and executes YAML playbooks."""

    def __init__(self, workflow_engine: WorkflowEngine) -> None:
        self.workflow_engine = workflow_engine

    def load(self, path: str | Path) -> dict[str, Any]:
        """Load and validate a YAML playbook."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError("Playbook must be a YAML dictionary")
        if "steps" not in data:
            raise ValueError("Playbook missing 'steps' section")
        return data

    def _resolve_vars(self, text: str, context: dict[str, str]) -> str:
        """Resolve {{ var }} templates."""
        def replace(match: re.Match) -> str:
            var_name = match.group(1).strip()
            if var_name.startswith("env."):
                return os.environ.get(var_name[4:], "")
            return context.get(var_name, match.group(0))
        return re.sub(r"\{\{(.*?)\}\}", replace, text)

    def _resolve_dict(self, data: Any, context: dict[str, str]) -> Any:
        if isinstance(data, dict):
            return {k: self._resolve_dict(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._resolve_dict(v, context) for v in data]
        elif isinstance(data, str):
            return self._resolve_vars(data, context)
        return data

    def create_plan(self, data: dict[str, Any], variables: dict[str, str] | None = None) -> ExecutionPlan:
        """Convert a loaded playbook into an ExecutionPlan."""
        context = variables or {}
        if "vars" in data:
            for k, v in data["vars"].items():
                if k not in context:
                    if isinstance(v, str):
                        context[k] = self._resolve_vars(v, context)
                    else:
                        context[k] = str(v)

        steps: list[PlanStep] = []
        for step_data in data["steps"]:
            resolved_step = self._resolve_dict(step_data, context)
            step_id = resolved_step.get("id", f"step_{len(steps)+1}")
            step_type = resolved_step.get("type", "tool")
            tool = resolved_step.get("tool", "")
            args = resolved_step.get("args", {})
            depends_on = resolved_step.get("depends_on", [])

            if step_type == "agent":
                tool = "_subagent"
                args = {
                    "role": resolved_step.get("role", "assistant"),
                    "goal": resolved_step.get("goal", ""),
                }

            # Use JSON string for args to match planner output format if needed,
            # or pass the dict directly if tools support it.
            import json
            command = json.dumps(args)

            step = PlanStep(
                id=step_id,
                description=f"Run {tool} from playbook",
                tool=tool,
                command=command,
                dependencies=depends_on,
            )
            steps.append(step)

        return ExecutionPlan(
            plan_type=PlanType.DAG,
            steps=steps,
        )

    async def execute(self, path: str | Path, variables: dict[str, str] | None = None, executor: Any = None) -> Any:
        """Load and execute a playbook."""
        data = self.load(path)
        plan = self.create_plan(data, variables)
        nodes = [
            {
                "id": step.id,
                "name": step.description,
                "step_fn": step.tool,
                "args": {"command": step.command},
                "timeout": step.timeout,
            }
            for step in plan.steps
        ]
        edges = []
        for step in plan.steps:
            for dep in step.dependencies:
                edges.append({"source": dep, "target": step.id})
        workflow = self.workflow_engine.create_workflow(
            name=str(path),
            description="Playbook execution",
            nodes=nodes,
            edges=edges,
        )
        return await self.workflow_engine.run_workflow(workflow)
