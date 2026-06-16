# SPDX-License-Identifier: AGPL-3.0-or-later
"""Autonomous planner — LLM-only goal decomposition without local heuristic fallback.

Sends tool schemas only on the first call of a session to conserve tokens.
The LLM is responsible for verifying tool availability, installing missing
tools, and constructing correct shell commands.
"""

from __future__ import annotations

import json
import logging
import platform as _platform
import re
import sys
from typing import Any

from .events import Event, EventType, emit_sync
from .models import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
)

logger = logging.getLogger(__name__)


class AutonomousPlanner:
    """LLM-driven planner with session-aware token optimisation.

    On the first call of a session, the full available tool list and
    platform context is sent to the LLM. Subsequent calls send only
    the compact context to reduce token consumption.

    The LLM is instructed to verify tools are installed before use
    and to install any missing tools autonomously.
    """

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._session_initialised: bool = False

    @property
    def session_initialised(self) -> bool:
        return self._session_initialised

    def mark_session_initialised(self) -> None:
        self._session_initialised = True

    def reset_session(self) -> None:
        self._session_initialised = False

    def _build_platform_context(self) -> str:
        _is_win = sys.platform == "win32"
        _shell_cmd = "cmd /c" if _is_win else "sh -c"
        lines = [
            f"Running on: {_platform.system()} {_platform.release()} ({_platform.machine()})",
            f"Shell: {_shell_cmd}",
        ]
        if _is_win:
            lines.extend(
                [
                    "IMPORTANT: This is a Windows system. Use Windows-compatible commands and paths.",
                    "  - nmap: use -sT (TCP connect) instead of -sS (SYN scan); omit -O (OS detection)",
                    "  - Use forward slashes or escaped backslashes in paths",
                    "  - For DNS queries, use nslookup instead of dig if dig is unavailable",
                    "  - List available tools with 'where' instead of 'which'",
                    "  - Standard security tools may need to be installed via winget/choco",
                ]
            )
        else:
            lines.extend(
                [
                    "Running on a Unix-like system (Linux/macOS). Standard Unix commands apply.",
                    "  - nmap -sS (SYN scan) requires root",
                ]
            )
        return "\n".join(lines)

    def _build_first_prompt(
        self,
        system_prompt: str | None,
        user_goal: str,
        platform_info: str,
        tool_schemas: list[dict] | None = None,
        available_tools: list[str] | None = None,
    ) -> str:
        if system_prompt:
            base = system_prompt
        else:
            base = """You are a senior red-team operator and penetration testing specialist with full access to every binary on this system. Construct exact shell commands.

Respond with ONLY valid JSON:
{
  "needs_tools": true or false,
  "reasoning": "Strategic rationale",
  "steps": [
    {
      "tool": "",
      "command": "exact shell command with all flags and arguments",
      "description": "What this does"
    }
  ]
}

- needs_tools=true for security operations, false for chat/explanation
- Always use the "command" field for raw shell execution
- Before running each command, verify the required tool is installed
- If a tool is missing, install it first (using winget, choco, apt, brew, pip, go, npm, or cargo as appropriate)
- Default to non-invasive techniques first
- Prefer accuracy over speed"""

        base += f"\n\n{platform_info}\n"

        if tool_schemas:
            lines = ["\nAvailable tools on this system:"]
            for t in tool_schemas:
                name = t.get("name", "")
                desc = t.get("description", "")
                tags = t.get("tags", [])
                cat = t.get("category", "")
                meta = f"  - {name}"
                if desc and desc != name:
                    meta += f": {desc}"
                if tags:
                    meta += f" [{', '.join(tags[:5])}]"
                if cat:
                    meta += f" ({cat})"
                lines.append(meta)
            base += "\n".join(lines)
        elif available_tools:
            lines = ["\nAvailable tools:"] + [f"  - {t}" for t in available_tools]
            base += "\n".join(lines)

        base += "\n\nUser request: " + user_goal
        return base

    def _build_subsequent_prompt(
        self,
        system_prompt: str | None,
        user_goal: str,
        platform_info: str,
        history: list[dict] | None = None,
    ) -> str:
        if system_prompt:
            base = system_prompt
        else:
            base = "Continue the previous session. Respond with ONLY valid JSON following the same structure as before."
        base += f"\n\n{platform_info}\n"
        if history:
            recent = history[-6:] if len(history) > 6 else history
            base += "\nRecent context:\n" + "\n".join(
                f"{m.get('role', 'unknown')}: {m.get('content', '')[:200]}" for m in recent
            )
        base += "\n\nUser request: " + user_goal
        return base

    async def plan(
        self,
        goal: str,
        system_prompt: str | None = None,
        platform: str | None = None,
        llm_call: Any = None,
        tool_schemas: list[dict] | None = None,
        available_tools: list[str] | None = None,
        history: list[dict] | None = None,
        is_first_call: bool | None = None,
    ) -> ExecutionPlan:
        """Generate a plan using the LLM.

        Parameters
        ----------
        goal:
            The user's request to plan for.
        system_prompt:
            Optional external system prompt. When provided the tools list
            and platform info are appended.
        platform:
            Optional pre-built platform context string.
        llm_call:
            Async callable ``(system_prompt, user_prompt, *, history, tools) → dict``
            returning the LLM response.
        tool_schemas:
            Full tool metadata objects for the first call.
        available_tools:
            Simple tool name list fallback if schemas not available.
        history:
            Conversation history for context.
        is_first_call:
            Override the session-based first-call detection.
        """
        if llm_call is None:
            msg = "AutonomousPlanner requires an llm_call function"
            raise RuntimeError(msg)

        effective_first = (
            is_first_call if is_first_call is not None else not self._session_initialised
        )
        platform_info = platform or self._build_platform_context()

        if effective_first:
            full_prompt = self._build_first_prompt(
                system_prompt,
                goal,
                platform_info,
                tool_schemas=tool_schemas,
                available_tools=available_tools,
            )
            logger.debug("AutonomousPlanner: first-call prompt (full context + tools)")
        else:
            full_prompt = self._build_subsequent_prompt(
                system_prompt,
                goal,
                platform_info,
                history=history,
            )
            logger.debug("AutonomousPlanner: subsequent-call prompt (compact)")

        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": "execute_plan",
                    "description": "Execute shell commands or system operations.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "needs_tools": {"type": "boolean"},
                            "reasoning": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "tool": {"type": "string"},
                                        "command": {"type": "string"},
                                        "description": {"type": "string"},
                                    },
                                    "required": ["tool", "command", "description"],
                                },
                            },
                        },
                        "required": ["needs_tools", "reasoning", "steps"],
                    },
                },
            }
        ]

        try:
            raw = await llm_call(full_prompt, goal, history=history, tools=openai_tools)
        except Exception as exc:
            raise RuntimeError(f"LLM planning call failed: {exc}") from exc

        if effective_first:
            self.mark_session_initialised()

        data = self._parse_llm_response(raw)

        if not isinstance(data, dict):
            return self.create_plan(
                goal=goal,
                context={"response": str(data) if data else "", "llm_planned": True},
            )

        if not data.get("needs_tools"):
            return self.create_plan(
                goal=goal,
                context={
                    "reasoning": data.get("reasoning", ""),
                    "response": data.get("response", ""),
                    "llm_planned": True,
                },
            )

        steps_raw = data.get("steps", [])
        steps: list[dict[str, Any]] = []
        for i, s in enumerate(steps_raw):
            if not isinstance(s, dict):
                steps.append(
                    {
                        "description": str(s) if s else f"LLM step {i + 1}",
                        "tool": "",
                        "command": str(s) if s else None,
                        "args": {},
                    }
                )
                continue
            steps.append(
                {
                    "description": s.get("description", f"LLM step {i + 1}"),
                    "tool": s.get("tool", ""),
                    "command": s.get("command"),
                    "args": s.get("args", {}),
                }
            )

        if not steps:
            return self.create_plan(
                goal=goal,
                context={
                    "reasoning": data.get("reasoning", ""),
                    "response": data.get("response", ""),
                    "llm_planned": True,
                },
            )

        return self.create_plan(
            goal=goal,
            steps=steps,
            context={
                "reasoning": data.get("reasoning", ""),
                "response": data.get("response", ""),
                "llm_planned": True,
            },
        )

    def _parse_llm_response(self, raw: Any) -> dict[str, Any] | None:
        tool_calls = raw.get("tool_calls") if isinstance(raw, dict) else None
        if tool_calls and len(tool_calls) > 0:
            func_args = tool_calls[0].function.arguments
            if isinstance(func_args, str):
                try:
                    return json.loads(func_args)
                except json.JSONDecodeError:
                    return None
            return func_args

        response = raw.get("content", "") if isinstance(raw, dict) else str(raw)
        cleaned = response.strip()
        cleaned = re.sub(r"^[\s]*```(?:json)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?\s*```\s*$", "", cleaned)
        cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None

    def create_plan(
        self,
        goal: str,
        plan_type: PlanType = PlanType.SEQUENTIAL,
        steps: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        plan_steps = []
        if steps:
            for i, step_def in enumerate(steps):
                plan_steps.append(
                    PlanStep(
                        id=step_def.get("id", f"step_{i:03d}"),
                        description=step_def.get("description", f"Step {i + 1}"),
                        tool=step_def.get("tool", ""),
                        args=step_def.get("args", {}),
                        command=step_def.get("command"),
                        dependencies=step_def.get("dependencies", []),
                        timeout=step_def.get("timeout", 300.0),
                    )
                )
        plan = ExecutionPlan(
            goal=goal,
            plan_type=plan_type,
            steps=plan_steps,
            context=context or {},
            status=PlanStatus.ACTIVE,
        )
        self._plans[plan.id] = plan
        emit_sync(
            Event(
                type=EventType.PLAN_CREATED,
                source="planner_autonomous",
                data={"plan_id": plan.id, "goal": goal, "steps": len(plan_steps)},
            )
        )
        return plan

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        return self._plans.get(plan_id)

    def list_plans(self, status: PlanStatus | None = None) -> list[ExecutionPlan]:
        plans = list(self._plans.values())
        if status:
            plans = [p for p in plans if p.status == status]
        return sorted(plans, key=lambda p: -p.created_at)

    def stats(self) -> dict[str, Any]:
        plans = list(self._plans.values())
        return {
            "total_plans": len(plans),
            "active": len([p for p in plans if p.status == PlanStatus.ACTIVE]),
            "completed": len([p for p in plans if p.status == PlanStatus.COMPLETED]),
            "session_initialised": self._session_initialised,
        }


__all__ = [
    "AutonomousPlanner",
]
