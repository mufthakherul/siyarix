# SPDX-License-Identifier: AGPL-3.0-or-later
"""DAG-based workflow engine with conditional execution."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Coroutine

WorkflowStepFn = Callable[[dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]


class WorkflowStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowEdge:
    source: str
    target: str
    condition: str = ""


@dataclass
class WorkflowNode:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = ""
    step_fn: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 300.0

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            WorkflowStepStatus.COMPLETED,
            WorkflowStepStatus.FAILED,
            WorkflowStepStatus.SKIPPED,
        )


@dataclass
class Workflow:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = ""
    description: str = ""
    status: WorkflowStatus = WorkflowStatus.IDLE
    nodes: list[WorkflowNode] = field(default_factory=list)
    edges: list[WorkflowEdge] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    def get_node(self, node_id: str) -> WorkflowNode | None:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_ready_nodes(self) -> list[WorkflowNode]:
        ready = []
        for node in self.nodes:
            if node.status != WorkflowStepStatus.PENDING:
                continue
            incoming = [e for e in self.edges if e.target == node.id]
            if not incoming:
                ready.append(node)
                continue
            deps_met = True
            for e in incoming:
                src = self.get_node(e.source)
                if src is None or src.status != WorkflowStepStatus.COMPLETED:
                    deps_met = False
                    break
            if deps_met:
                ready.append(node)
        return ready

    @property
    def is_complete(self) -> bool:
        return all(n.is_terminal for n in self.nodes)

    @property
    def progress_pct(self) -> float:
        if not self.nodes:
            return 100.0
        return (len([n for n in self.nodes if n.is_terminal]) / len(self.nodes)) * 100.0


class WorkflowEngine:
    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._step_functions: dict[str, WorkflowStepFn] = {}
        self._semaphore = asyncio.Semaphore(4)

    def register_step(self, name: str, fn: WorkflowStepFn) -> None:
        self._step_functions[name] = fn

    def create_workflow(
        self,
        name: str,
        description: str = "",
        nodes: list[dict[str, Any]] | None = None,
        edges: list[dict[str, str]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Workflow:
        wf_nodes = [
            WorkflowNode(
                id=n.get("id", f"node_{i:03d}"),
                name=n.get("name", f"Step {i + 1}"),
                step_fn=n.get("step_fn", ""),
                args=n.get("args", {}),
                timeout=n.get("timeout", 300.0),
                max_retries=int(n.get("max_retries", 0) or 0),
            )
            for i, n in enumerate(nodes or [])
        ]
        wf_edges = [
            WorkflowEdge(source=e["source"], target=e["target"], condition=e.get("condition", ""))
            for e in (edges or [])
        ]
        workflow = Workflow(
            name=name,
            description=description,
            nodes=wf_nodes,
            edges=wf_edges,
            context=context or {},
        )
        self._workflows[workflow.id] = workflow
        return workflow

    async def run_workflow(self, workflow: Workflow) -> Workflow:
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = time.time()
        while not workflow.is_complete:
            if workflow.status == WorkflowStatus.CANCELLED:
                break
            ready = workflow.get_ready_nodes()
            if not ready:
                if any(n.status == WorkflowStepStatus.RUNNING for n in workflow.nodes):
                    await asyncio.sleep(0.1)
                    continue
                self._skip_blocked_dependents(workflow)
                if not workflow.get_ready_nodes() and not any(
                    n.status == WorkflowStepStatus.RUNNING for n in workflow.nodes
                ):
                    break
                continue
            await asyncio.gather(
                *[self._run_node(workflow, n) for n in ready], return_exceptions=True
            )
            self._skip_blocked_dependents(workflow)
        workflow.completed_at = time.time()
        if workflow.status != WorkflowStatus.CANCELLED:
            workflow.status = (
                WorkflowStatus.COMPLETED
                if all(n.status == WorkflowStepStatus.COMPLETED for n in workflow.nodes)
                else WorkflowStatus.FAILED
            )
        return workflow

    @staticmethod
    def _condition_passes(condition: str, context: dict[str, Any]) -> bool:
        """Fail-closed evaluation of simple playbook conditions (no eval)."""
        expr = (condition or "").strip()
        if not expr:
            return True
        lowered = expr.lower()
        if lowered in {"true", "always", "1", "yes"}:
            return True
        if lowered in {"false", "never", "0", "no"}:
            return False
        if "==" in expr:
            left, _, right = expr.partition("==")
            key = left.strip()
            expect = right.strip().strip("'\"")
            actual = context.get(key)
            if actual is None and key.startswith("env."):
                import os

                actual = os.environ.get(key[4:], "")
            return str(actual) == expect
        # Unknown expressions are fail-closed (skip step).
        return False

    async def _run_node(self, workflow: Workflow, node: WorkflowNode) -> None:
        node.status = WorkflowStepStatus.RUNNING
        step_fn = self._step_functions.get(node.step_fn)
        if not step_fn:
            node.status = WorkflowStepStatus.FAILED
            node.result = {"error": f"No step function: {node.step_fn}"}
            return

        merged_args = {**node.args, **workflow.context}
        condition = str(merged_args.get("_condition") or "")
        if condition and not self._condition_passes(condition, merged_args):
            node.status = WorkflowStepStatus.SKIPPED
            node.result = {"status": "skipped", "error": f"Condition not met: {condition}"}
            return

        attempts = max(1, int(node.max_retries) + 1)
        last_error: dict[str, Any] = {}
        for attempt in range(attempts):
            node.retry_count = attempt
            try:
                async with self._semaphore:
                    result = await asyncio.wait_for(
                        step_fn(merged_args), timeout=node.timeout
                    )
                    node.result = result if isinstance(result, dict) else {"output": result}
                    soft_status = str(node.result.get("status", "")).lower()
                    if soft_status in {"error", "failed", "failure"}:
                        last_error = node.result
                        if attempt + 1 < attempts:
                            continue
                        node.status = WorkflowStepStatus.FAILED
                        return
                    node.status = WorkflowStepStatus.COMPLETED
                    workflow.context[f"result_{node.id}"] = node.result
                    return
            except asyncio.TimeoutError:
                last_error = {"error": f"Timeout after {node.timeout}s"}
                if attempt + 1 < attempts:
                    continue
                node.status = WorkflowStepStatus.FAILED
                node.result = last_error
                return
            except Exception as e:
                last_error = {"error": str(e)}
                if attempt + 1 < attempts:
                    continue
                node.status = WorkflowStepStatus.FAILED
                node.result = last_error
                return
        node.status = WorkflowStepStatus.FAILED
        node.result = last_error or {"error": "exhausted retries"}

    def _skip_blocked_dependents(self, workflow: Workflow) -> None:
        """Mark PENDING nodes whose deps failed as SKIPPED so the DAG can finish."""
        changed = True
        while changed:
            changed = False
            for node in workflow.nodes:
                if node.status != WorkflowStepStatus.PENDING:
                    continue
                incoming = [e for e in workflow.edges if e.target == node.id]
                if not incoming:
                    continue
                if any(
                    (src := workflow.get_node(e.source)) is not None
                    and src.status
                    in (WorkflowStepStatus.FAILED, WorkflowStepStatus.SKIPPED)
                    for e in incoming
                ):
                    node.status = WorkflowStepStatus.SKIPPED
                    node.result = {"error": "Skipped due to failed dependency"}
                    changed = True

    def cancel_workflow(self, workflow_id: str) -> bool:
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False
        wf.status = WorkflowStatus.CANCELLED
        for node in wf.nodes:
            if not node.is_terminal:
                node.status = WorkflowStepStatus.SKIPPED
        return True

    def stats(self) -> dict[str, Any]:
        wfs = list(self._workflows.values())
        return {
            "total": len(wfs),
            "running": len([w for w in wfs if w.status == WorkflowStatus.RUNNING]),
            "completed": len([w for w in wfs if w.status == WorkflowStatus.COMPLETED]),
            "registered_steps": list(self._step_functions.keys()),
        }


__all__ = [
    "WorkflowStatus",
    "WorkflowStepStatus",
    "WorkflowEdge",
    "WorkflowNode",
    "Workflow",
    "WorkflowEngine",
]
