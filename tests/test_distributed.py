# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for distributed task execution."""

import pytest

from siyarix.distributed import (DistributedOrchestrator, DistributedTask,
                                 TaskQueueBackend)

pytestmark = pytest.mark.distributed


class TestTaskQueueBackend:
    @pytest.mark.asyncio
    async def test_enqueue_dequeue_memory(self):
        backend = TaskQueueBackend()
        task = DistributedTask(task_type="scan", payload={"target": "10.0.0.1"})
        task_id = await backend.enqueue(task)
        assert task_id

        dequeued = await backend.dequeue("worker-1")
        assert dequeued is not None
        assert dequeued.task_type == "scan"

    @pytest.mark.asyncio
    async def test_complete_task(self):
        backend = TaskQueueBackend()
        task_id = await backend.enqueue(DistributedTask(task_type="test", payload={}))
        await backend.dequeue("worker-1")
        await backend.complete_task(task_id, {"result": "ok"})

        result = await backend.get_task(task_id)
        assert result is not None
        assert result.status == "completed"
        assert result.result == {"result": "ok"}

    @pytest.mark.asyncio
    async def test_empty_queue(self):
        backend = TaskQueueBackend()
        task = await backend.dequeue("worker-1")
        assert task is None

    @pytest.mark.asyncio
    async def test_register_worker(self):
        backend = TaskQueueBackend()
        await backend.register_worker("worker-1", {"tools": ["nmap", "nuclei"]})
        stats = backend.stats()
        assert stats["workers_registered"] == 1

    @pytest.mark.asyncio
    async def test_worker_heartbeat(self):
        backend = TaskQueueBackend()
        await backend.register_worker("worker-1")
        await backend.worker_heartbeat("worker-1")


class TestDistributedOrchestrator:
    @pytest.mark.asyncio
    async def test_dispatch_and_process(self):
        backend = TaskQueueBackend()
        orchestrator = DistributedOrchestrator(backend=backend)

        async def scan_handler(payload):
            return {"target": payload["target"], "status": "scanned"}

        orchestrator.register_handler("scan", scan_handler)
        task_id = await orchestrator.dispatch("scan", {"target": "10.0.0.1"})
        assert task_id

        processed = await orchestrator.process_next()
        assert processed is True

        task = await backend.get_task(task_id)
        assert task is not None
        assert task.status == "completed"

    @pytest.mark.asyncio
    async def test_no_handler_fails_gracefully(self):
        orchestrator = DistributedOrchestrator()
        task_id = await orchestrator.dispatch("unknown_type", {"data": "test"})
        processed = await orchestrator.process_next()
        assert processed is True

        task = await orchestrator.backend.get_task(task_id)
        assert task.status == "failed"

    @pytest.mark.asyncio
    async def test_handler_exception_handling(self):
        orchestrator = DistributedOrchestrator()

        async def failing_handler(payload):
            raise ValueError("Something went wrong")

        orchestrator.register_handler("fail", failing_handler)
        await orchestrator.dispatch("fail", {})
        processed = await orchestrator.process_next()
        assert processed is True

    @pytest.mark.asyncio
    async def test_process_loop(self):
        backend = TaskQueueBackend()
        orchestrator = DistributedOrchestrator(backend=backend)

        async def handler(payload):
            return {"processed": True}

        orchestrator.register_handler("task", handler)
        for i in range(5):
            await orchestrator.dispatch("task", {"id": i})

        count = await orchestrator.process_loop(max_iterations=10)
        assert count == 5
