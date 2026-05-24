"""Bounded asynchronous worker pool for running sub-agent tasks.

Provides a simple concurrency limiter with submit/close APIs suitable for
running tool-execution coroutines in the ExecutionEngine.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)


class AsyncWorkerPool:
    """A simple async worker pool that bounds concurrency with a semaphore.

    Usage:
        pool = AsyncWorkerPool(max_workers=5)
        result = await pool.submit(coro_func, *args)
        await pool.close()
    """

    def __init__(self, max_workers: int = 5) -> None:
        if max_workers <= 0:
            raise ValueError("max_workers must be > 0")
        self._sema = asyncio.Semaphore(max_workers)
        self._tasks: set[asyncio.Task] = set()
        self._closed = False

    async def submit(self, fn: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        if self._closed:
            raise RuntimeError("Pool is closed")

        async with self._sema:
            # Wrap execution in a task so it can be cancelled externally if needed
            task = asyncio.create_task(fn(*args, **kwargs))
            self._tasks.add(task)

            try:
                return await task
            finally:
                self._tasks.discard(task)

    async def close(self, timeout: float | None = None) -> None:
        """Cancel any running tasks and wait for them to finish.

        If `timeout` is provided, wait up to that many seconds for tasks to complete.
        """
        self._closed = True
        if not self._tasks:
            return

        for t in list(self._tasks):
            if not t.done():
                t.cancel()

        try:
            await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Worker pool shutdown timed out; some tasks did not finish")


__all__ = ["AsyncWorkerPool"]
