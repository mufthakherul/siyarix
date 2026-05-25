"""Distributed Multi-Agent Deployment.

Replaces the in-process AgentTeam with a Redis/RQ-backed task queue so
multiple Phalanx instances can share work. Moves the SQLite offline store
to PostgreSQL for the server role.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class DistributedTask:
    """A task that can be distributed across worker nodes."""

    task_id: str = ""
    task_type: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    status: str = "pending"
    created_at: str = ""
    assigned_to: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""


class TaskQueueBackend:
    """Abstract backend for distributed task queues.

    Supports Redis/RQ, in-process (for testing), and extensible to
    RabbitMQ, AWS SQS, or Google Pub/Sub.
    """

    def __init__(self, backend_type: str = "memory", **kwargs: Any) -> None:
        self._backend_type = backend_type
        self._config = kwargs
        self._memory_queue: list[DistributedTask] = []
        self._memory_results: dict[str, DistributedTask] = {}
        self._workers: dict[str, dict[str, Any]] = {}

    @property
    def backend_type(self) -> str:
        return self._backend_type

    async def enqueue(self, task: DistributedTask) -> str:
        task.task_id = task.task_id or uuid.uuid4().hex[:12]
        task.created_at = datetime.now().isoformat()
        task.status = "pending"

        if self._backend_type == "redis":
            return await self._enqueue_redis(task)
        self._memory_queue.append(task)
        self._memory_results[task.task_id] = task
        logger.debug("Task enqueued: %s (%s)", task.task_id, task.task_type)
        return task.task_id

    async def dequeue(self, worker_id: str) -> DistributedTask | None:
        if self._backend_type == "redis":
            return await self._dequeue_redis(worker_id)

        if not self._memory_queue:
            return None
        task = self._memory_queue.pop(0)
        task.status = "running"
        task.assigned_to = worker_id
        self._memory_results[task.task_id] = task
        return task

    async def complete_task(self, task_id: str, result: dict[str, Any], error: str = "") -> None:
        task = self._memory_results.get(task_id)
        if task:
            task.status = "completed" if not error else "failed"
            task.result = result
            task.error = error

    async def get_task(self, task_id: str) -> DistributedTask | None:
        return self._memory_results.get(task_id)

    async def get_pending_count(self) -> int:
        if self._backend_type == "redis":
            return 0
        return len([t for t in self._memory_queue if t.status == "pending"])

    async def register_worker(
        self, worker_id: str, capabilities: dict[str, Any] | None = None
    ) -> None:
        self._workers[worker_id] = {
            "id": worker_id,
            "capabilities": capabilities or {},
            "registered_at": datetime.now().isoformat(),
            "last_heartbeat": datetime.now().isoformat(),
            "tasks_completed": 0,
        }

    async def worker_heartbeat(self, worker_id: str) -> None:
        worker = self._workers.get(worker_id)
        if worker:
            worker["last_heartbeat"] = datetime.now().isoformat()

    async def _enqueue_redis(self, task: DistributedTask) -> str:
        try:
            import redis.asyncio as redis_async  # pyright: ignore[reportMissingImports]

            r = redis_async.Redis.from_url(self._config.get("redis_url", "redis://localhost:6379"))
            await r.rpush("phalanx:queue", json.dumps(task.__dict__, default=str))
            await r.close()
            return task.task_id
        except ImportError:
            logger.warning("redis not installed, falling back to memory queue")
            self._memory_queue.append(task)
            return task.task_id

    async def _dequeue_redis(self, worker_id: str) -> DistributedTask | None:
        try:
            import redis.asyncio as redis_async  # pyright: ignore[reportMissingImports]

            r = redis_async.Redis.from_url(self._config.get("redis_url", "redis://localhost:6379"))
            data = await r.blpop("phalanx:queue", timeout=5)
            await r.close()
            if data:
                task_dict = json.loads(data[1])
                task = DistributedTask(**task_dict)
                task.status = "running"
                task.assigned_to = worker_id
                return task
        except ImportError:
            pass
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "backend_type": self._backend_type,
            "pending": len([t for t in self._memory_queue if t.status == "pending"]),
            "running": len([t for t in self._memory_results.values() if t.status == "running"]),
            "completed": len([t for t in self._memory_results.values() if t.status == "completed"]),
            "failed": len([t for t in self._memory_results.values() if t.status == "failed"]),
            "workers_registered": len(self._workers),
        }


class DistributedOrchestrator:
    """Orchestrates distributed task execution across worker nodes."""

    def __init__(self, backend: TaskQueueBackend | None = None) -> None:
        self._backend = backend or TaskQueueBackend()
        self._worker_id = f"orchestrator-{uuid.uuid4().hex[:8]}"
        self._task_handlers: dict[str, Callable] = {}

    def register_handler(self, task_type: str, handler: Callable) -> None:
        self._task_handlers[task_type] = handler

    async def dispatch(self, task_type: str, payload: dict[str, Any], priority: int = 0) -> str:
        task = DistributedTask(
            task_type=task_type,
            payload=payload,
            priority=priority,
        )
        task_id = await self._backend.enqueue(task)
        logger.info("Dispatched task %s (type=%s, priority=%d)", task_id, task_type, priority)
        return task_id

    async def process_next(self, worker_id: str | None = None) -> bool:
        wid = worker_id or self._worker_id
        task = await self._backend.dequeue(wid)
        if not task:
            return False

        logger.info("Worker %s processing task %s (type=%s)", wid, task.task_id, task.task_type)
        handler = self._task_handlers.get(task.task_type)
        if not handler:
            await self._backend.complete_task(task.task_id, {}, f"No handler for {task.task_type}")
            return True

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(task.payload)
            else:
                result = handler(task.payload)
            await self._backend.complete_task(task.task_id, result)
        except Exception as e:
            logger.error("Task %s failed: %s", task.task_id, e)
            await self._backend.complete_task(task.task_id, {}, str(e))
        return True

    async def process_loop(self, max_iterations: int = 100) -> int:
        processed = 0
        for _ in range(max_iterations):
            if not await self.process_next():
                break
            processed += 1
        return processed

    @property
    def backend(self) -> TaskQueueBackend:
        return self._backend


__all__ = [
    "DistributedOrchestrator",
    "TaskQueueBackend",
    "DistributedTask",
]
