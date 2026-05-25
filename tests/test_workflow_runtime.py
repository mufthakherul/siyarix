import asyncio

import pytest
from siyarix.orchestration.workflow_runtime import WorkflowRuntime, WorkflowState
from siyarix.offline_store import OfflineStore
pytestmark = pytest.mark.workflow


class _FakeEngineResult:
    def __init__(self, success: bool = True) -> None:
        self.success = success
        self.all_findings: list[dict] = []
        self.total_duration_ms = 10.0
        self.plan_id = "fake-plan"
        self.retries_performed = 0

    def to_dict(self) -> dict:
        return {"success": self.success}


class _FakeEngine:
    async def execute(self, instruction: str, interactive: bool, persist: bool):  # noqa: ARG002
        if "fail" in instruction:
            return _FakeEngineResult(success=False)
        return _FakeEngineResult(success=True)


def _engine_factory(mode: str) -> _FakeEngine:  # noqa: ARG001
    return _FakeEngine()


def test_workflow_runtime_validate() -> None:
    runtime = WorkflowRuntime(engine_factory=_engine_factory, store=OfflineStore())
    steps = runtime.validate(
        {
            "name": "test-flow",
            "steps": [
                {"id": "s1", "instruction": "scan one"},
                {"id": "s2", "instruction": "scan two", "depends_on": ["s1"]},
            ],
        }
    )
    assert len(steps) == 2
    assert steps[1].depends_on == ["s1"]


def test_workflow_runtime_execute_success(tmp_path) -> None:
    runtime = WorkflowRuntime(
        engine_factory=_engine_factory,
        store=OfflineStore(db_path=tmp_path / "wf.db"),
    )
    steps = runtime.validate(
        {
            "name": "success-flow",
            "steps": [
                {"id": "s1", "instruction": "scan one"},
                {"id": "s2", "instruction": "scan two", "depends_on": ["s1"]},
            ],
        }
    )
    result = asyncio.run(runtime.execute("success-flow", steps))
    assert result.status == WorkflowState.COMPLETED
    assert result.step_states["s1"] == WorkflowState.COMPLETED
    assert result.step_states["s2"] == WorkflowState.COMPLETED


def test_workflow_runtime_execute_failure_blocks_dependents(tmp_path) -> None:
    runtime = WorkflowRuntime(
        engine_factory=_engine_factory,
        store=OfflineStore(db_path=tmp_path / "wf-fail.db"),
    )
    steps = runtime.validate(
        {
            "name": "failure-flow",
            "steps": [
                {"id": "s1", "instruction": "fail this step"},
                {"id": "s2", "instruction": "scan two", "depends_on": ["s1"]},
            ],
        }
    )
    result = asyncio.run(runtime.execute("failure-flow", steps))
    assert result.status == WorkflowState.FAILED
    assert result.step_states["s1"] == WorkflowState.FAILED
    assert result.step_states["s2"] == WorkflowState.BLOCKED
