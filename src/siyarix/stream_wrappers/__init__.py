from __future__ import annotations

from typing import Any, Callable, Coroutine

LlmCallable = Callable[..., Coroutine[Any, Any, dict[str, Any]]]
StreamWrapper = Callable[[LlmCallable, str, str, dict[str, Any]], LlmCallable]

_wrappers: dict[str, list[StreamWrapper]] = {}


def register_wrapper(name: str, wrapper: StreamWrapper, prepend: bool = False) -> None:
    """Register a stream wrapper for a provider.

    OpenClaw pattern: stream-wrappers/*.ts
    """
    if prepend:
        _wrappers.setdefault(name, []).insert(0, wrapper)
    else:
        _wrappers.setdefault(name, []).append(wrapper)


def apply_wrappers(
    call_fn: LlmCallable,
    provider: str,
    model: str,
    options: dict[str, Any] | None = None,
) -> LlmCallable:
    """Apply all registered wrappers for a provider in order.

    Wrappers are applied outer-most first (last registered runs first).
    """
    opts = options or {}
    wrapped = call_fn
    wrappers = _wrappers.get(provider, []) + _wrappers.get("*", [])
    for w in wrappers:
        wrapped = w(wrapped, provider, model, opts)
    return wrapped


def clear_wrappers(provider: str | None = None) -> None:
    """Clear all wrappers for a provider, or all providers."""
    if provider:
        _wrappers.pop(provider, None)
    else:
        _wrappers.clear()


def list_wrappers(provider: str | None = None) -> dict[str, list[str]]:
    """List registered wrappers, optionally filtered by provider."""
    if provider:
        return {provider: [w.__name__ for w in _wrappers.get(provider, [])]}
    return {p: [w.__name__ for w in ws] for p, ws in _wrappers.items()}


# Auto-register built-in wrappers on import
from . import reasoning as _reasoning  # noqa: F401
from . import service_tier as _st  # noqa: F401
from . import cache_control as _cc  # noqa: F401
from . import proxy as _proxy  # noqa: F401
