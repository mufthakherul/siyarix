# SPDX-License-Identifier: AGPL-3.0-or-later
"""Siyarix YAML Playbook Engine."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

from siyarix.models import ExecutionPlan, PlanStep, PlanType
from siyarix.workflow import WorkflowEngine

logger = logging.getLogger(__name__)


# Exact allowlist for non-SIYARIX env keys + SIYARIX_ prefix for feature flags.
_ENV_ALLOWLIST_EXACT: frozenset[str] = frozenset(
    {
        "HOME",
        "USER",
        "SHELL",
        "LANG",
        "TZ",
        "PATH",
        "TERM",
        "HOSTNAME",
        "PWD",
        "LOGNAME",
        "CI",
    }
)
_ENV_PREFIX_ALLOW: frozenset[str] = frozenset({"SIYARIX_"})
# Block secret-bearing names even when they match the SIYARIX_ prefix.
_ENV_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential|webhook|"
    r"private[_-]?key|sudo|auth|bearer|cookie|session|authorization)"
)


def _env_var_allowed(env_key: str) -> bool:
    """Return True when *env_key* may be interpolated into a playbook."""
    if not env_key or _ENV_SECRET_RE.search(env_key):
        return False
    if env_key in _ENV_ALLOWLIST_EXACT:
        return True
    return any(env_key.startswith(prefix) for prefix in _ENV_PREFIX_ALLOW)


class PlaybookEngine:
    """Parses and executes YAML playbooks."""

    def __init__(self, workflow_engine: WorkflowEngine) -> None:
        self.workflow_engine = workflow_engine
        self._agent: Any = None

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
                env_key = var_name[4:]
                if not _env_var_allowed(env_key):
                    logger.warning("Blocked access to restricted env var: %s", env_key)
                    return "[REDACTED]"
                return os.environ.get(env_key, "")
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

    def create_plan(
        self, data: dict[str, Any], variables: dict[str, str] | None = None
    ) -> ExecutionPlan:
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
            step_id = resolved_step.get("id", f"step_{len(steps) + 1}")
            step_type = resolved_step.get("type", "tool")
            tool = resolved_step.get("tool", "")
            args = resolved_step.get("args", {})
            depends_on = resolved_step.get("depends_on", [])
            condition = resolved_step.get("if", None)
            retries = resolved_step.get("retries", 0)
            timeout = resolved_step.get("timeout", 600.0)

            if step_type == "agent":
                tool = "_subagent"
                args = {
                    "role": resolved_step.get("role", "assistant"),
                    "goal": resolved_step.get("goal", ""),
                }

            # Embed advanced execution metadata into args so the executor can access them
            if condition:
                args["_condition"] = condition
            if retries:
                args["_retries"] = retries

            # Keep structured args on the step; JSON in `command` is only a
            # transport for the workflow runner (never shelled).
            step_args = args if isinstance(args, dict) else {}
            step = PlanStep(
                id=step_id,
                description=resolved_step.get("description", f"Run {tool} from playbook"),
                tool=tool,
                args=dict(step_args),
                command=json.dumps(step_args),
                dependencies=depends_on,
                timeout=timeout,
            )
            steps.append(step)

        return ExecutionPlan(
            plan_type=PlanType.DAG,
            steps=steps,
        )

    def _parse_step_args(self, raw: str) -> dict[str, Any]:
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _ensure_tool_step_functions(self, tool_names: set[str]) -> None:
        """Register registry-backed (or agent-backed) step functions for playbook tools."""
        from siyarix.registry_factory import make_tool_registry

        registry = make_tool_registry()
        try:
            registry.discover_from_path()
            registry.scan_path()
        except Exception:
            logger.debug("Playbook tool discovery incomplete", exc_info=True)

        async def _run_registry_tool(ctx: dict[str, Any]) -> dict[str, Any]:
            tool = str(ctx.get("tool") or "").strip()
            if not tool:
                return {"status": "error", "error": "Playbook step missing tool name"}
            args = self._parse_step_args(str(ctx.get("command") or ""))
            exec_kwargs = {k: v for k, v in args.items() if not str(k).startswith("_")}
            try:
                result = await registry.execute(tool, **exec_kwargs)
                if isinstance(result, dict):
                    return result
                return {"status": "success", "output": result}
            except Exception as exc:
                logger.exception("Playbook tool %s failed", tool)
                return {"status": "error", "error": str(exc), "tool": tool}

        async def _run_subagent(ctx: dict[str, Any]) -> dict[str, Any]:
            args = self._parse_step_args(str(ctx.get("command") or ""))
            role = str(args.get("role") or "assistant")
            goal = str(args.get("goal") or "")
            if self._agent is None:
                return {
                    "status": "error",
                    "error": "Agent executor not provided for playbook agent steps",
                }
            try:
                result = await self._agent.execute_subagent(role, goal)
                findings = getattr(result, "findings", None) or []
                return {
                    "status": "success" if getattr(result, "success", False) else "error",
                    "output": getattr(result, "summary", "") or "",
                    "findings": findings,
                    "role": role,
                }
            except Exception as exc:
                logger.exception("Playbook subagent failed")
                return {"status": "error", "error": str(exc), "role": role}

        for name in tool_names:
            if not name:
                continue
            if name == "_subagent":
                self.workflow_engine.register_step(name, _run_subagent)
            else:
                self.workflow_engine.register_step(name, _run_registry_tool)

    async def execute(
        self, path: str | Path, variables: dict[str, str] | None = None, executor: Any = None
    ) -> Any:
        """Load and execute a playbook."""
        self._agent = executor
        data = self.load(path)
        plan = self.create_plan(data, variables)
        self._ensure_tool_step_functions({s.tool for s in plan.steps if s.tool})
        nodes = []
        for step in plan.steps:
            meta = self._parse_step_args(step.command or "")
            retries = int(meta.get("_retries") or 0)
            nodes.append(
                {
                    "id": step.id,
                    "name": step.description,
                    "step_fn": step.tool,
                    "args": {
                        "tool": step.tool,
                        "command": step.command,
                        "timeout": step.timeout,
                        "_condition": meta.get("_condition", ""),
                    },
                    "timeout": step.timeout,
                    "max_retries": max(0, retries),
                }
            )
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


__all__ = ["PlaybookEngine", "_env_var_allowed"]
