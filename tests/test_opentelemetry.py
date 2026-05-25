"""Tests for OpenTelemetry instrumentation."""

import pytest
pytestmark = pytest.mark.opentelemetry
from siyarix.telemetry.opentelemetry import (
    OpenTelemetryCollector,
    OpenTelemetryMiddleware,
    trace,
)


class TestOpenTelemetryCollector:
    def setup_method(self):
        self.collector = OpenTelemetryCollector()

    def test_start_and_end_trace(self):
        trace_id = self.collector.start_trace("test-operation", {"key": "value"})
        assert trace_id
        trace = self.collector.get_trace(trace_id)
        assert trace is not None
        assert len(trace.spans) == 1
        assert trace.spans[0].name == "test-operation"

        self.collector.end_trace(trace_id)
        trace = self.collector.get_trace(trace_id)
        assert trace is not None

    def test_start_and_end_span(self):
        trace_id = self.collector.start_trace("root")
        span_id = self.collector.start_span("child-span", {"function": "test"})
        assert span_id
        self.collector.end_span(span_id)
        self.collector.end_trace(trace_id)
        trace = self.collector.get_trace(trace_id)
        assert len(trace.spans) >= 2

    def test_add_event(self):
        trace_id = self.collector.start_trace("test")
        self.collector.add_event("test-event", {"info": "something happened"})
        self.collector.end_trace(trace_id)

    def test_register_exporter(self):
        exported = []

        def exporter(trace):
            exported.append(trace)

        self.collector.register_exporter(exporter)
        trace_id = self.collector.start_trace("test")
        self.collector.end_trace(trace_id)
        assert len(exported) == 1

    def test_disabled_collector(self):
        self.collector.set_enabled(False)
        trace_id = self.collector.start_trace("disabled")
        assert trace_id == ""
        assert self.collector.stats()["total_spans"] == 0

    def test_stats(self):
        self.collector.start_trace("stats-test")
        stats = self.collector.stats()
        assert stats["traces_active"] >= 1
        assert "total_spans" in stats
        assert "enabled" in stats


@pytest.mark.asyncio
async def test_trace_decorator():
    @trace("test-decorator")
    async def async_func():
        return 42

    result = await async_func()
    assert result == 42

    @trace("sync-decorator")
    def sync_func():
        return "hello"

    result = sync_func()
    assert result == "hello"


class TestOpenTelemetryMiddleware:
    @pytest.mark.asyncio
    async def test_middleware_wraps_engine(self):
        class FakeEngine:
            async def execute(self, instruction, **kwargs):
                class FakeResult:
                    success = True
                    all_findings = []
                    step_results = []

                return FakeResult()

        middleware = OpenTelemetryMiddleware(FakeEngine())
        result = await middleware.execute("scan 10.0.0.1", interactive=False)
        assert result.success is True
