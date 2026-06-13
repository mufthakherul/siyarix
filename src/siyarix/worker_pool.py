# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded asynchronous worker pool for running sub-agent tasks.

Provides a simple concurrency limiter with ``submit`` / ``close`` APIs
suitable for running tool-execution coroutines in the ExecutionEngine.

The semaphore guards the *task execution itself* (not the submitter),
so the calling coroutine is released immediately after submission.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["AsyncWorkerPool"]


class AsyncWorkerPool:
    """Async worker pool that bounds concurrency with a semaphore.

    The semaphore is acquired **inside** the wrapper task so that the
    submitter is never blocked — only the actual execution of *fn* is
    gated by the concurrency limit.

    Usage::

        pool = AsyncWorkerPool(max_workers=5)
        result = await pool.submit(coro_func, *args)
        await pool.close()
    """

    def __init__(self, max_workers: int = 5, max_queue: int = 100) -> None:
        """Create a pool with at most *max_workers* concurrent tasks.

        Raises:
            ValueError: If *max_workers* is not positive.
        """
        if max_workers <= 0:
            raise ValueError("max_workers must be > 0")
        self._sema = asyncio.Semaphore(max_workers)
        self._queue_sema = asyncio.Semaphore(max_queue)
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closed = False

    async def submit(
        self, fn: Callable[..., Coroutine[Any, Any, Any]], *args: Any, **kwargs: Any
    ) -> asyncio.Task[Any]:
        """Submit *fn(\*args, \*\*kwargs)* for bounded execution.

        Returns an asyncio.Task representing the execution.

        Raises:
            RuntimeError: If the pool has been closed.
        """
        if self._closed:
            raise RuntimeError("Pool is closed")

        # Backpressure: Wait until there's room in the queue
        await self._queue_sema.acquire()

        async def _guarded() -> Any:
            """Acquire the semaphore around the actual work."""
            try:
                async with self._sema:
                    return await fn(*args, **kwargs)
            finally:
                self._queue_sema.release()

        task: asyncio.Task[Any] = asyncio.create_task(_guarded())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return task

    async def cancel_pending(self) -> None:
        """Cancel all unfinished tasks without closing the pool."""
        for t in list(self._tasks):
            if not t.done():
                t.cancel()

    async def close(self, timeout: float | None = None) -> None:
        """Cancel running tasks and wait for them to finish.

        Args:
            timeout: Max seconds to wait for tasks to complete.
                     ``None`` means wait indefinitely.

        The pool cannot be reused after ``close()``.
        """
        self._closed = True
        # Snapshot to avoid "Set changed size during iteration"
        snapshot = list(self._tasks)
        if not snapshot:
            return

        await self.cancel_pending()

        try:
            await asyncio.wait_for(
                asyncio.gather(*snapshot, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Worker pool shutdown timed out; some tasks did not finish")
        except Exception:
            logger.exception("Unexpected error during worker pool shutdown")
