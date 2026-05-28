# SPDX-License-Identifier: AGPL-3.0-or-later

"""DAG-native workflow runtime for YAML/JSON execution plans."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from ..offline_store import OfflineStore

YAML_AVAILABLE = False
try:
    import yaml as _yaml

    YAML_AVAILABLE = True
except Exception:
    _yaml = None

yaml: Any = _yaml


class WorkflowState(StrEnum):
    """Workflow step lifecycle states."""

    PLANNED = "planned"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    BLOCKED = "blocked"
    RETRYING = "retrying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class WorkflowStepSpec:
    """Single workflow step."""

    id: str
    instruction: str
    mode: str = "integrated"
    depends_on: list[str] = field(default_factory=list)
    retries: int = 0
    timeout: int = 300
    persist: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowRunResult:
    """Aggregated workflow runtime output."""

    workflow_name: str
    plan_id: str
    status: WorkflowState
    step_states: dict[str, WorkflowState] = field(default_factory=dict)
    step_errors: dict[str, str] = field(default_factory=dict)
    step_results: dict[str, dict[str, Any]] = field(default_factory=dict)


class WorkflowRuntime:
    """Execute workflow files with DAG scheduling and resumable persistence."""

    def __init__(
        self,
        engine_factory: Callable[[str], Any],
        store: OfflineStore | None = None,
        max_concurrency: int = 3,
    ) -> None:
        self._engine_factory = engine_factory
        self._store = store or OfflineStore()
        self._max_concurrency = max(max_concurrency, 1)

    def load_workflow(
        self, workflow: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        params = params or {}
        if workflow.strip().startswith("{"):
            data = json.loads(workflow)
        else:
            path = Path(workflow)
            if path.exists():
                raw = path.read_text(encoding="utf-8")
                if path.suffix.lower() == ".json":
                    data = json.loads(raw)
                else:
                    if not YAML_AVAILABLE:
                        raise ValueError("PyYAML is required to load YAML workflows.")
                    data = yaml.safe_load(raw) or {}
            else:
                raise FileNotFoundError(f"Workflow not found: {workflow}")

        return self._apply_params(data, params)

    def _apply_params(
        self, data: dict[str, Any], params: dict[str, Any]
    ) -> dict[str, Any]:
        if not params:
            return data
        rendered = json.dumps(data)
        for key, value in params.items():
            rendered = rendered.replace("{{" + key + "}}", str(value))
        return json.loads(rendered)

    def validate(self, workflow: dict[str, Any]) -> list[WorkflowStepSpec]:
        steps_raw = workflow.get("steps")
        if not isinstance(steps_raw, list) or not steps_raw:
            raise ValueError("Workflow must contain a non-empty 'steps' array.")

        steps: list[WorkflowStepSpec] = []
        seen: set[str] = set()
        for row in steps_raw:
            if not isinstance(row, dict):
                raise ValueError("Each workflow step must be an object.")
            step_id = str(row.get("id") or "").strip()
            instruction = str(row.get("instruction") or "").strip()
            if not step_id or not instruction:
                raise ValueError("Each step requires non-empty 'id' and 'instruction'.")
            if step_id in seen:
                raise ValueError(f"Duplicate workflow step id: {step_id}")
            seen.add(step_id)
            steps.append(
                WorkflowStepSpec(
                    id=step_id,
                    instruction=instruction,
                    mode=str(row.get("mode") or "integrated"),
                    depends_on=list(row.get("depends_on") or []),
                    retries=int(row.get("retries") or 0),
                    timeout=int(row.get("timeout") or 300),
                    persist=bool(row.get("persist", True)),
                    metadata=dict(row.get("metadata") or {}),
                )
            )

        valid_ids = {s.id for s in steps}
        for s in steps:
            invalid = [d for d in s.depends_on if d not in valid_ids]
            if invalid:
                raise ValueError(f"Step '{s.id}' has unknown dependency IDs: {invalid}")

        return steps

    async def execute(
        self,
        workflow_name: str,
        steps: list[WorkflowStepSpec],
        *,
        dry_run: bool = False,
        resume_plan_id: str | None = None,
    ) -> WorkflowRunResult:
        plan_id = resume_plan_id or str(uuid.uuid4())
        self._store.save_plan(
            plan_id=plan_id,
            instruction=f"workflow:{workflow_name}",
            plan_json=json.dumps(
                {
                    "name": workflow_name,
                    "steps": [s.__dict__ for s in steps],
                }
            ),
            status=WorkflowState.PLANNED.value,
        )
        result = WorkflowRunResult(
            workflow_name=workflow_name, plan_id=plan_id, status=WorkflowState.QUEUED
        )
        for s in steps:
            result.step_states[s.id] = WorkflowState.PLANNED

        if dry_run:
            return result

        self._store.update_plan_status(plan_id, WorkflowState.RUNNING.value)
        semaphore = asyncio.Semaphore(self._max_concurrency)
        completed: set[str] = set()
        failed: set[str] = set()

        while len(completed | failed) < len(steps):
            ready = [
                s
                for s in steps
                if s.id not in completed
                and s.id not in failed
                and all(dep in completed for dep in s.depends_on)
            ]
            if not ready:
                result.status = WorkflowState.BLOCKED
                break

            async def run_step(
                spec: WorkflowStepSpec,
            ) -> tuple[str, bool, dict[str, Any], str]:
                async with semaphore:
                    result.step_states[spec.id] = WorkflowState.RUNNING
                    self._store.upsert_step_execution(
                        plan_id=plan_id,
                        step_id=spec.id,
                        status=WorkflowState.RUNNING.value,
                        output="",
                    )
                    tries = 0
                    last_err = ""
                    while tries <= spec.retries:
                        engine = self._engine_factory(spec.mode)
                        try:
                            exec_result = await engine.execute(
                                spec.instruction,
                                interactive=False,
                                persist=spec.persist,
                            )
                            payload = exec_result.to_dict()
                            if exec_result.success:
                                self._store.upsert_step_execution(
                                    plan_id=plan_id,
                                    step_id=spec.id,
                                    status=WorkflowState.COMPLETED.value,
                                    output=json.dumps(payload)[:5000],
                                    findings=exec_result.all_findings,
                                    duration_ms=exec_result.total_duration_ms,
                                )
                                return spec.id, True, payload, ""
                            last_err = "execution failed"
                        except Exception as exc:  # nosec B110
                            last_err = str(exc)
                        tries += 1
                        if tries <= spec.retries:
                            result.step_states[spec.id] = WorkflowState.RETRYING
                    self._store.upsert_step_execution(
                        plan_id=plan_id,
                        step_id=spec.id,
                        status=WorkflowState.FAILED.value,
                        output="",
                        error=last_err[:2000],
                    )
                    return spec.id, False, {}, last_err

            batch = await asyncio.gather(*(run_step(s) for s in ready))
            for step_id, ok, payload, error in batch:
                if ok:
                    completed.add(step_id)
                    result.step_states[step_id] = WorkflowState.COMPLETED
                    result.step_results[step_id] = payload
                else:
                    failed.add(step_id)
                    result.step_states[step_id] = WorkflowState.FAILED
                    result.step_errors[step_id] = error
                    for candidate in steps:
                        if (
                            step_id in candidate.depends_on
                            and candidate.id not in completed
                        ):
                            result.step_states[candidate.id] = WorkflowState.BLOCKED

        if failed:
            result.status = WorkflowState.FAILED
            self._store.update_plan_status(
                plan_id, WorkflowState.FAILED.value, completed=True
            )
        elif result.status == WorkflowState.BLOCKED:
            self._store.update_plan_status(plan_id, WorkflowState.BLOCKED.value)
        else:
            result.status = WorkflowState.COMPLETED
            self._store.update_plan_status(
                plan_id, WorkflowState.COMPLETED.value, completed=True
            )

        return result
