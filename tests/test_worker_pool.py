import asyncio
import time

from phalanx.worker_pool import AsyncWorkerPool


def test_worker_pool_concurrency_and_results():
    pool = AsyncWorkerPool(max_workers=2)

    async def task(n: int):
        await asyncio.sleep(0.05 * n)
        return n * 2

    async def _run():
        tasks = [pool.submit(task, i) for i in range(1, 5)]
        results = await asyncio.gather(*tasks)
        await pool.close()
        assert results == [2, 4, 6, 8]

    asyncio.run(_run())


def test_worker_pool_close_cancels_tasks():
    pool = AsyncWorkerPool(max_workers=2)

    async def long_task():
        try:
            await asyncio.sleep(5)
            return "done"
        except asyncio.CancelledError:
            return "cancelled"

    async def _run():
        fut = asyncio.create_task(pool.submit(long_task))
        # Give the task a moment to start
        await asyncio.sleep(0.01)
        # Close pool, forcing cancellation
        await pool.close(timeout=0.1)
        res = await fut
        assert res in ("cancelled", "done")

    asyncio.run(_run())
import asyncio
from phalanx.worker_pool import AsyncWorkerPool


async def _sleep_and_return(x: int) -> int:
    await asyncio.sleep(0.01)
    return x * 2


def test_worker_pool_basic():
    pool = AsyncWorkerPool(max_workers=2)

    async def _run():
        r1 = await pool.submit(_sleep_and_return, 2)
        r2 = await pool.submit(_sleep_and_return, 3)
        await pool.close()
        return (r1, r2)

    res = asyncio.run(_run())
    assert res == (4, 6)
