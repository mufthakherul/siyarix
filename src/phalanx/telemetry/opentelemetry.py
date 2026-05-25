"""OpenTelemetry Instrumentation for Phalanx.

Adds structured traces and metrics to the execution engine, planner, and
agent framework so operators can see exactly what the system is doing.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

logger = logging.getLogger(__name__)

_trace_id_var: ContextVar[str] = ContextVar("phalanx_trace_id", default="")
_span_id_var: ContextVar[str] = ContextVar("phalanx_span_id", default="")
_span_stack_var: ContextVar[list[str]] = ContextVar("phalanx_span_stack", default=[])


@dataclass
class Span:
    """A single trace span."""

    span_id: str
    trace_id: str
    parent_span_id: str = ""
    name: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    attributes: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    error: str = ""


@dataclass
class Trace:
    """A complete trace consisting of multiple spans."""

    trace_id: str
    root_span_id: str
    spans: list[Span] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    service_name: str = "phalanx"


class OpenTelemetryCollector:
    """Collects and exports OpenTelemetry-style traces and spans.

    In-memory collector that can be extended to export to OTLP endpoints,
    Jaeger, Zipkin, or other backends.
    """

    def __init__(self) -> None:
        self._traces: dict[str, Trace] = {}
        self._active_spans: dict[str, Span] = {}
        self._exporters: list[Callable[[Trace], None]] = []
        self._enabled = True
        self._span_count = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def register_exporter(self, exporter: Callable[[Trace], None]) -> None:
        """Register a trace exporter callback."""
        self._exporters.append(exporter)

    def start_trace(
        self, name: str = "operation", attributes: dict[str, str] | None = None
    ) -> str:
        """Start a new trace, returning the trace_id."""
        if not self._enabled:
            return ""
        trace_id = uuid.uuid4().hex[:16]
        root_span = self._create_span(trace_id, "", name, attributes or {})
        trace = Trace(
            trace_id=trace_id, root_span_id=root_span.span_id, spans=[root_span]
        )
        self._traces[trace_id] = trace
        _trace_id_var.set(trace_id)
        _span_id_var.set(root_span.span_id)
        _span_stack_var.set([root_span.span_id])
        logger.debug("Started trace %s: %s", trace_id, name)
        return trace_id

    def end_trace(
        self,
        trace_id: str,
        status: str = "ok",
        error: str = "",
        attributes: dict[str, str] | None = None,
    ) -> Trace | None:
        """End a trace and export it."""
        trace = self._traces.get(trace_id)
        if not trace:
            return None
        trace.end_time = datetime.now()
        root_span = self._get_span(trace_id, trace.root_span_id)
        if root_span:
            root_span.end_time = time.monotonic()
        _trace_id_var.set("")
        _span_id_var.set("")
        _span_stack_var.set([])
        for exporter in self._exporters:
            try:
                exporter(trace)
            except Exception as e:
                logger.warning("Trace exporter failed: %s", e)
        return trace

    def start_span(self, name: str, attributes: dict[str, str] | None = None) -> str:
        """Start a child span under the current trace."""
        trace_id = _trace_id_var.get()
        if not trace_id or not self._enabled:
            return ""
        parent_span_id = _span_id_var.get()
        span = self._create_span(trace_id, parent_span_id, name, attributes or {})
        trace = self._traces.get(trace_id)
        if trace:
            trace.spans.append(span)
        stack = _span_stack_var.get()
        stack.append(span.span_id)
        _span_id_var.set(span.span_id)
        return span.span_id

    def end_span(self, span_id: str, status: str = "ok", error: str = "") -> None:
        """End a specific span."""
        trace_id = _trace_id_var.get()
        span = self._get_span(trace_id, span_id)
        if span:
            span.end_time = time.monotonic()
            span.status = status
            span.error = error
        stack = _span_stack_var.get()
        if stack:
            stack.pop()
            parent = stack[-1] if stack else ""
            _span_id_var.set(parent if parent else _trace_id_var.get())

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the current span."""
        trace_id = _trace_id_var.get()
        span_id = _span_id_var.get()
        span = self._get_span(trace_id, span_id)
        if span:
            span.events.append(
                {
                    "name": name,
                    "attributes": attributes or {},
                    "timestamp": time.monotonic(),
                }
            )

    def _create_span(
        self, trace_id: str, parent_span_id: str, name: str, attributes: dict[str, str]
    ) -> Span:
        self._span_count += 1
        return Span(
            span_id=uuid.uuid4().hex[:12],
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            name=name,
            start_time=time.monotonic(),
            attributes=attributes,
        )

    def _get_span(self, trace_id: str, span_id: str) -> Span | None:
        trace = self._traces.get(trace_id)
        if not trace:
            return None
        for span in trace.spans:
            if span.span_id == span_id:
                return span
        return None

    def get_trace(self, trace_id: str) -> Trace | None:
        return self._traces.get(trace_id)

    def stats(self) -> dict[str, Any]:
        return {
            "traces_active": len(self._traces),
            "total_spans": self._span_count,
            "exporters_registered": len(self._exporters),
            "enabled": self._enabled,
        }


# Global collector instance
_otel_collector = OpenTelemetryCollector()


def get_collector() -> OpenTelemetryCollector:
    """Get the global OpenTelemetry collector instance."""
    return _otel_collector


def trace(
    name: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps a function in an OpenTelemetry trace span."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            span_name = name or func.__name__
            collector = get_collector()
            if not collector.enabled:
                return await func(*args, **kwargs)
            span_id = collector.start_span(span_name, {"function": func.__name__})
            try:
                result = await func(*args, **kwargs)
                collector.end_span(span_id)
                return result
            except Exception as e:
                collector.end_span(span_id, status="error", error=str(e))
                raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            span_name = name or func.__name__
            collector = get_collector()
            if not collector.enabled:
                return func(*args, **kwargs)
            span_id = collector.start_span(span_name, {"function": func.__name__})
            try:
                result = func(*args, **kwargs)
                collector.end_span(span_id)
                return result
            except Exception as e:
                collector.end_span(span_id, status="error", error=str(e))
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class OpenTelemetryMiddleware:
    """Middleware that can wrap ExecutionEngine for automatic tracing."""

    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._collector = get_collector()

    async def execute(self, instruction: str, **kwargs: Any) -> Any:
        trace_id = self._collector.start_trace(
            "engine.execute", {"instruction": instruction[:200]}
        )
        try:
            result = await self._engine.execute(instruction, **kwargs)
            attributes: dict[str, str] = {
                "success": str(getattr(result, "success", False)),
                "findings": str(len(getattr(result, "all_findings", []))),
                "steps": str(len(getattr(result, "step_results", []))),
            }
            self._collector.end_trace(trace_id, attributes=attributes)
            return result
        except Exception as e:
            self._collector.end_trace(trace_id, status="error", error=str(e))
            raise


__all__ = [
    "OpenTelemetryCollector",
    "OpenTelemetryMiddleware",
    "Span",
    "Trace",
    "get_collector",
    "trace",
]
