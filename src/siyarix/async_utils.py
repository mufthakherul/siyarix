# SPDX-License-Identifier: AGPL-3.0-or-later
"""Async utilities — safely run coroutines from sync contexts."""

from __future__ import annotations

import asyncio
import logging
import threading
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
    result_holder: list[Any] = []
    exception_holder: list[Exception] = []

    def _run() -> None:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            r = new_loop.run_until_complete(coro)
            result_holder.append(r)
        except Exception as e:
            exception_holder.append(e)
        finally:
            new_loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join()

    if exception_holder:
        raise exception_holder[0]
    return result_holder[0]
