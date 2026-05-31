# SPDX-License-Identifier: AGPL-3.0-or-later
"""Advanced planning system with goal decomposition and workflow generation."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PlanStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"
    BLOCKED = "blocked"


class PlanType(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DAG = "dag"
    REACT = "react"
    ADAPTIVE = "adaptive"


@dataclass
class PlanStep:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 300.0
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        return self.status == StepStatus.PENDING

    @property
    def can_retry(self) -> bool:
        return self.retry_count < self.max_retries

    @property
    def is_terminal(self) -> bool:
        return self.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED)


@dataclass
class ExecutionPlan:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    goal: str = ""
    plan_type: PlanType = PlanType.SEQUENTIAL
    status: PlanStatus = PlanStatus.DRAFT
    steps: list[PlanStep] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def completed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    @property
    def failed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    @property
    def pending_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status in (StepStatus.PENDING, StepStatus.READY)]

    @property
    def is_complete(self) -> bool:
        return all(s.is_terminal for s in self.steps)

    @property
    def has_failures(self) -> bool:
        return any(s.status == StepStatus.FAILED for s in self.steps)

    @property
    def progress_pct(self) -> float:
        if not self.steps:
            return 100.0
        done = len(self.completed_steps) + len([s for s in self.steps if s.status == StepStatus.SKIPPED])
        return (done / len(self.steps)) * 100.0

    def get_step(self, step_id: str) -> PlanStep | None:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def get_ready_steps(self) -> list[PlanStep]:
        ready = []
        for step in self.steps:
            if step.status not in (StepStatus.PENDING, StepStatus.READY):
                continue
            deps_met = all(
                self.get_step(dep) is not None and self.get_step(dep).status == StepStatus.COMPLETED
                for dep in step.dependencies
            )
            if deps_met:
                step.status = StepStatus.READY
                ready.append(step)
        return ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "goal": self.goal, "type": self.plan_type.value,
            "status": self.status.value, "progress": self.progress_pct,
            "steps": [{"id": s.id, "description": s.description, "tool": s.tool, "status": s.status.value} for s in self.steps],
        }


class Planner:
    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._templates: dict[str, list[dict[str, Any]]] = {
            "recon_full": [
                {"description": "Port scan with nmap", "tool": "nmap", "args": {"flags": "-sV -sC -T4"}},
                {"description": "Web technology detection", "tool": "nuclei", "args": {"tags": "tech"}},
                {"description": "Directory brute force", "tool": "gobuster", "args": {"mode": "dir"}},
                {"description": "Subdomain enumeration", "tool": "subfinder", "args": {}},
            ],
            "web_audit": [
                {"description": "Nikto web server scan", "tool": "nikto", "args": {}},
                {"description": "Nuclei vulnerability scan", "tool": "nuclei", "args": {"severity": "medium,high,critical"}},
                {"description": "SQL injection test", "tool": "sqlmap", "args": {"batch": True}},
                {"description": "Directory enumeration", "tool": "ffuf", "args": {"wordlist": "common.txt"}},
            ],
            "brute_force": [
                {"description": "Service enumeration", "tool": "nmap", "args": {"flags": "-sV"}},
                {"description": "Credential brute force", "tool": "hydra", "args": {}},
            ],
            "wifi_audit": [
                {"description": "Capture WiFi traffic", "tool": "aircrack-ng", "args": {"mode": "capture"}},
                {"description": "WPA handshake crack", "tool": "aircrack-ng", "args": {"mode": "crack"}},
            ],
        }

    def create_plan(self, goal: str, plan_type: PlanType = PlanType.SEQUENTIAL,
                    steps: list[dict[str, Any]] | None = None,
                    context: dict[str, Any] | None = None) -> ExecutionPlan:
        plan_steps = []
        if steps:
            for i, step_def in enumerate(steps):
                plan_steps.append(PlanStep(
                    id=f"step_{i:03d}", description=step_def.get("description", f"Step {i+1}"),
                    tool=step_def.get("tool", ""), args=step_def.get("args", {}),
                    dependencies=step_def.get("dependencies", []),
                    timeout=step_def.get("timeout", 300.0),
                ))
        plan = ExecutionPlan(goal=goal, plan_type=plan_type, steps=plan_steps, context=context or {}, status=PlanStatus.ACTIVE)
        self._plans[plan.id] = plan
        return plan

    def create_from_template(self, template_name: str, target: str,
                             overrides: dict[str, Any] | None = None) -> ExecutionPlan:
        import re
        template = self._templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")
        url_match = re.search(r'https?://[^\s]+', target)
        host_match = re.search(r'\b(?:[\w-]+\.)+[a-z]{2,}\b', target.lower())
        clean_target = url_match.group(0) if url_match else (host_match.group(0) if host_match else target)
        steps = []
        for step_def in template:
            step = {**step_def, "args": {**step_def.get("args", {}), "target": clean_target}}
            if overrides:
                step["args"].update(overrides.get("args", {}))
            steps.append(step)
        return self.create_plan(goal=f"{template_name} on {clean_target}", steps=steps, context={"target": clean_target, "template": template_name})

    def decompose_goal(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        import re
        goal_lower = goal.lower()
        if any(kw in goal_lower for kw in ("brute", "crack", "password", "credential")):
            return self.create_from_template("brute_force", goal)
        if any(kw in goal_lower for kw in ("wifi", "wireless", "wpa")):
            return self.create_from_template("wifi_audit", goal)
        url_match = re.search(r'https?://[^\s]+', goal)
        host_match = re.search(r'\b(?:[\w-]+\.)+[a-z]{2,}\b', goal_lower)
        target = ""
        if url_match:
            target = url_match.group(0)
        elif host_match:
            target = host_match.group(0)
        tool_match = None
        if available_tools:
            for t in available_tools:
                if t.lower() in goal_lower:
                    tool_match = t
                    break
        if tool_match:
            return self.create_plan(goal=goal, steps=[{
                "description": f"Execute {tool_match} on {target}",
                "tool": tool_match,
                "args": {"target": target, "flags": "-sT -T4 --top-ports 100" if tool_match == "nmap" else ""},
            }])
        if target:
            return self.create_plan(goal=goal, steps=[
                {"description": "HTTP headers check", "tool": "curl", "args": {"target": target, "flags": "-sI"}},
                {"description": "Technology fingerprinting", "tool": "whatweb", "args": {"target": target}},
                {"description": "DNS enumeration", "tool": "dig", "args": {"target": target.replace("https://", "").replace("http://", "").split("/")[0]}},
            ])
        return self.create_plan(goal=goal, steps=[{"description": f"Execute: {goal}", "tool": "curl", "args": {"target": target, "flags": "-sI"}}])

    def adapt_plan(self, plan: ExecutionPlan, failed_step: PlanStep, error: str) -> ExecutionPlan:
        if failed_step.tool == "nmap" and "filtered" in error.lower():
            failed_step.args["flags"] = failed_step.args.get("flags", "") + " -Pn"
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        elif failed_step.tool in ("nikto", "nuclei") and "refused" in error.lower():
            idx = plan.steps.index(failed_step)
            plan.steps.insert(idx + 1, PlanStep(
                id=f"adapted_{idx}", description="Fallback scan", tool="nuclei",
                args={"target": failed_step.args.get("target", "")},
            ))
            failed_step.status = StepStatus.SKIPPED
        elif failed_step.tool in ("gobuster", "ffuf") and "404" in error:
            failed_step.args["extensions"] = "php,html,js,txt"
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        elif failed_step.can_retry:
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        else:
            failed_step.status = StepStatus.FAILED
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
        return {"total_plans": len(plans), "active": len([p for p in plans if p.status == PlanStatus.ACTIVE]),
                "completed": len([p for p in plans if p.status == PlanStatus.COMPLETED]),
                "templates": list(self._templates.keys())}
