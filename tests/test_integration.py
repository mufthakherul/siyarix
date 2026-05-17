"""Integration tests for workflow persistence and resume."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from siyarix.offline_store import OfflineStore


def _make_store(tmp_dir: str) -> OfflineStore:
    db_path = Path(tmp_dir) / "offline.db"
    return OfflineStore(db_path=db_path)


def test_workflow_persistence_roundtrip() -> None:
    with TemporaryDirectory() as tmp:
        store = _make_store(tmp)

        plan_id = "plan-123"
        plan_json = json.dumps({"steps": [], "source": "registry", "confidence": 0.5})
        store.save_plan(plan_id=plan_id, instruction="scan 127.0.0.1", plan_json=plan_json)

        store.upsert_step_execution(
            plan_id=plan_id,
            step_id="s1",
            status="success",
            output="ok",
            error="",
            findings=[{"title": "Test", "severity": "info"}],
            duration_ms=12.5,
            retry_count=1,
            exit_code=0,
        )

        plan = store.get_plan(plan_id)
        assert plan is not None
        assert plan["id"] == plan_id
        assert plan["instruction"] == "scan 127.0.0.1"
        assert plan["status"] == "planned"
        assert len(plan["steps"]) == 1

        step = plan["steps"][0]
        assert step["step_id"] == "s1"
        assert step["status"] == "success"
        assert step["retry_count"] == 1


def test_workflow_list_and_latest() -> None:
    with TemporaryDirectory() as tmp:
        store = _make_store(tmp)
        store.save_plan(
            plan_id="plan-a",
            instruction="scan host-a",
            plan_json=json.dumps({"steps": []}),
            status="planned",
        )
        store.save_plan(
            plan_id="plan-b",
            instruction="scan host-b",
            plan_json=json.dumps({"steps": []}),
            status="running",
        )

        plans = store.list_plans(limit=10)
        assert len(plans) == 2

        latest = store.get_latest_plan_id()
        assert latest in {"plan-a", "plan-b"}


def test_workflow_status_updates() -> None:
    with TemporaryDirectory() as tmp:
        store = _make_store(tmp)
        store.save_plan(
            plan_id="plan-status",
            instruction="scan status",
            plan_json=json.dumps({"steps": []}),
        )

        store.update_plan_status("plan-status", status="running")
        plan = store.get_plan("plan-status")
        assert plan["status"] == "running"

        store.update_plan_status("plan-status", status="completed", completed=True)
        plan = store.get_plan("plan-status")
        assert plan["status"] == "completed"
        assert plan["completed_at"] is not None
