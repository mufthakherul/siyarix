from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


def run_async(coro: Any) -> Any:
    """Safely run an async coroutine from a sync context.

    Handles the case where there's already a running event loop
    (e.g., in Jupyter, pytest-asyncio, or other embedded contexts)
    by creating a new loop in a separate thread if needed.
    """
    try:
        _ = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # An event loop is already running — run in a new thread
    import threading

    result: list = []
    exception: list = []

    def _run() -> None:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            r = new_loop.run_until_complete(coro)
            result.append(r)
        except Exception as e:
            exception.append(e)
        finally:
            new_loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join()

    if exception:
        raise exception[0]
    return result[0]
