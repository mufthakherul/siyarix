"""Tests for siyarix.events - Event bus system."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.events import (
    Event,
    EventBus,
    EventType,
    _task_exception_callback,
    emit_sync,
    get_event_bus,
    reset_event_bus,
)


@pytest.fixture(autouse=True)
def reset_bus():
    reset_event_bus()
    yield
    reset_event_bus()


class TestEventType:
    def test_values(self):
        assert EventType.AGENT_START == "agent.start"
        assert EventType.AGENT_STOP == "agent.stop"
        assert EventType.AGENT_ERROR == "agent.error"
        assert EventType.PLAN_CREATED == "plan.created"
        assert EventType.PLAN_STEP_START == "plan.step.start"
        assert EventType.PLAN_STEP_COMPLETE == "plan.step.complete"
        assert EventType.PLAN_STEP_FAILED == "plan.step.failed"
        assert EventType.PLAN_COMPLETE == "plan.complete"
        assert EventType.TOOL_REGISTERED == "tool.registered"
        assert EventType.TOOL_UNREGISTERED == "tool.unregistered"
        assert EventType.TOOL_EXECUTING == "tool.executing"
        assert EventType.TOOL_COMPLETE == "tool.complete"
        assert EventType.TOOL_FAILED == "tool.failed"
        assert EventType.TOOL_NOT_FOUND == "tool.not_found"
        assert EventType.PROVIDER_SELECTED == "provider.selected"
        assert EventType.PROVIDER_FALLBACK == "provider.fallback"
        assert EventType.PROVIDER_ERROR == "provider.error"
        assert EventType.MEMORY_STORED == "memory.stored"
        assert EventType.MEMORY_RETRIEVED == "memory.retrieved"
        assert EventType.CONTEXT_COMPRESSED == "context.compressed"
        assert EventType.WORKFLOW_START == "workflow.start"
        assert EventType.WORKFLOW_STEP == "workflow.step"
        assert EventType.WORKFLOW_COMPLETE == "workflow.complete"
        assert EventType.VALIDATION_PASSED == "validation.passed"
        assert EventType.VALIDATION_FAILED == "validation.failed"
        assert EventType.RECOVERY_ATTEMPT == "recovery.attempt"
        assert EventType.RECOVERY_SUCCESS == "recovery.success"
        assert EventType.CONFIG_CHANGED == "config.changed"
        assert EventType.HEARTBEAT == "heartbeat"
        assert EventType.CUSTOM == "custom"

    def test_member_count(self):
        assert len(EventType) == 30


class TestEvent:
    def test_defaults(self):
        event = Event(type=EventType.CUSTOM)
        assert event.type == EventType.CUSTOM
        assert event.source == ""
        assert event.data == {}
        assert isinstance(event.timestamp, datetime)
        assert event.correlation_id == ""

    def test_custom_values(self):
        ts = datetime.now(timezone.utc)
        event = Event(
            type=EventType.AGENT_START,
            source="agent_1",
            data={"key": "val"},
            timestamp=ts,
            correlation_id="corr_123",
        )
        assert event.type == EventType.AGENT_START
        assert event.source == "agent_1"
        assert event.data == {"key": "val"}
        assert event.timestamp == ts
        assert event.correlation_id == "corr_123"

    def test_timestamp_dt(self):
        event = Event(type=EventType.HEARTBEAT)
        assert event.timestamp_dt == event.timestamp
        assert event.timestamp_dt.tzinfo is not None

    def test_timestamp_utc(self):
        event = Event(type=EventType.HEARTBEAT)
        assert event.timestamp.tzinfo == timezone.utc


class TestEventBus:
    @pytest.fixture
    def bus(self):
        return EventBus(max_history=10)

    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self, bus):
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        handler.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_subscribe_wildcard(self, bus):
        handler = AsyncMock()
        bus.on(None, handler)
        event = Event(type=EventType.AGENT_START)
        await bus.emit(event)
        handler.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        bus.off(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unsubscribe_wildcard(self, bus):
        handler = AsyncMock()
        bus.on(None, handler)
        bus.off(None, handler)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unsubscribe_nonexistent_type(self, bus):
        handler = AsyncMock()
        bus.off(EventType.CUSTOM, handler)

    @pytest.mark.asyncio
    async def test_unsubscribe_nonexistent_wildcard(self, bus):
        handler = AsyncMock()
        bus.off(None, handler)

    @pytest.mark.asyncio
    async def test_emit_only_matching(self, bus):
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.AGENT_START)
        await bus.emit(event)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_emit_both_specific_and_wildcard(self, bus):
        specific = AsyncMock()
        wildcard = AsyncMock()
        bus.on(EventType.CUSTOM, specific)
        bus.on(None, wildcard)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        specific.assert_awaited_once_with(event)
        wildcard.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_multiple_handlers(self, bus):
        h1 = AsyncMock()
        h2 = AsyncMock()
        bus.on(EventType.CUSTOM, h1)
        bus.on(EventType.CUSTOM, h2)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        h1.assert_awaited_once_with(event)
        h2.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_handler_exception(self, bus, caplog):
        failing = AsyncMock(side_effect=ValueError("handler error"))
        working = AsyncMock()
        bus.on(EventType.CUSTOM, failing)
        bus.on(EventType.CUSTOM, working)
        event = Event(type=EventType.CUSTOM)
        await bus.emit(event)
        working.assert_awaited_once_with(event)
        assert "Event handler error for" in caplog.text

    def test_get_history_all(self, bus):
        bus._history.append(Event(type=EventType.AGENT_START))
        bus._history.append(Event(type=EventType.CUSTOM))
        history = bus.get_history(limit=10)
        assert len(history) == 2

    def test_get_history_filtered(self, bus):
        bus._history.append(Event(type=EventType.AGENT_START))
        bus._history.append(Event(type=EventType.CUSTOM))
        history = bus.get_history(event_type=EventType.AGENT_START, limit=10)
        assert len(history) == 1
        assert history[0].type == EventType.AGENT_START

    def test_get_history_empty(self, bus):
        history = bus.get_history(limit=10)
        assert history == []

    def test_get_history_no_match(self, bus):
        bus._history.append(Event(type=EventType.AGENT_START))
        history = bus.get_history(event_type=EventType.CUSTOM, limit=10)
        assert history == []

    def test_get_history_limit(self, bus):
        for _ in range(20):
            bus._history.append(Event(type=EventType.AGENT_START))
        history = bus.get_history(limit=5)
        assert len(history) == 5

    def test_get_history_max_history_bound(self, bus):
        bus2 = EventBus(max_history=5)
        for _ in range(10):
            bus2._history.append(Event(type=EventType.AGENT_START))
        assert len(bus2._history) == 5

    def test_clear_history(self, bus):
        bus._history.append(Event(type=EventType.CUSTOM))
        bus.clear_history()
        assert bus.get_history() == []

    def test_clear_history_preserves_handlers(self, bus):
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        bus.clear_history()
        assert EventType.CUSTOM in bus._handlers
        assert handler in bus._handlers[EventType.CUSTOM]

    def test_clear_all(self, bus):
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        bus.on(None, handler)
        bus._history.append(Event(type=EventType.CUSTOM))
        bus.clear_all()
        assert bus._handlers == {}
        assert bus._wildcard_handlers == []
        assert bus.get_history() == []

    def test_clear_alias(self, bus):
        bus._history.append(Event(type=EventType.CUSTOM))
        bus.clear()
        assert bus.get_history() == []

    def test_max_history_attribute(self, bus):
        assert bus._max_history == 10


class TestGetEventBus:
    def test_singleton(self):
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_singleton_after_reset(self):
        bus1 = get_event_bus()
        reset_event_bus()
        bus2 = get_event_bus()
        assert bus1 is not bus2

    def test_reset_event_bus(self):
        bus = get_event_bus()
        bus.on(EventType.CUSTOM, AsyncMock())
        reset_event_bus()
        new_bus = get_event_bus()
        assert new_bus._handlers == {}

    def test_get_event_bus_type(self):
        bus = get_event_bus()
        assert isinstance(bus, EventBus)

    def test_default_max_history(self):
        bus = get_event_bus()
        assert bus._max_history == 1000


class TestEmitSync:
    @pytest.mark.asyncio
    async def test_emit_sync_with_running_loop(self):
        bus = get_event_bus()
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        emit_sync(event)
        await asyncio.sleep(0.01)
        handler.assert_called_once_with(event)

    def test_emit_sync_without_running_loop(self):
        reset_event_bus()
        bus = get_event_bus()
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        emit_sync(event)
        handler.assert_called_once_with(event)

    def test_emit_sync_fallback_failure(self, caplog):
        caplog.set_level(logging.DEBUG)
        import siyarix.events as evmod

        original_get = evmod.get_event_bus
        try:
            mock_bus = MagicMock()
            mock_bus.emit = AsyncMock()
            evmod.get_event_bus = MagicMock(return_value=mock_bus)
            evmod._bus = None
            with patch.object(evmod, "asyncio") as mock_asyncio:
                mock_asyncio.get_running_loop.side_effect = RuntimeError("no loop")
                mock_asyncio.run.side_effect = Exception("run failed")
                emit_sync(Event(type=EventType.CUSTOM))
                assert "Failed to run event loop for emit_sync" in caplog.text
        finally:
            evmod.get_event_bus = original_get
            reset_event_bus()

    def test_emit_sync_no_running_loop_success(self):
        reset_event_bus()
        bus = get_event_bus()
        handler = AsyncMock()
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        emit_sync(event)
        handler.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_emit_sync_handler_error_logged(self, caplog):
        bus = get_event_bus()
        handler = AsyncMock(side_effect=ValueError("handler err"))
        bus.on(EventType.CUSTOM, handler)
        event = Event(type=EventType.CUSTOM)
        emit_sync(event)
        await asyncio.sleep(0.05)
        assert "Event handler error for" in caplog.text

    def test_task_exception_callback_cancelled(self):
        task = MagicMock()
        task.cancelled.return_value = True
        _task_exception_callback(task)
        task.exception.assert_not_called()

    def test_task_exception_callback_no_exception(self):
        task = MagicMock()
        task.cancelled.return_value = False
        task.exception.return_value = None
        _task_exception_callback(task)

    def test_task_exception_callback_with_exception(self, caplog):
        task = MagicMock()
        task.cancelled.return_value = False
        exc = ValueError("test error")
        task.exception.return_value = exc
        _task_exception_callback(task)
        assert "emit_sync task failed" in caplog.text
        assert "test error" in caplog.text


class TestThreadSafety:
    def test_on_off_thread_safe(self):
        bus = EventBus()
        handler = AsyncMock()
        import threading

        def register():
            for _ in range(10):
                bus.on(EventType.CUSTOM, handler)
                bus.off(EventType.CUSTOM, handler)

        threads = [threading.Thread(target=register) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


class TestPublicAPI:
    def test_all_exports(self):
        from siyarix import events

        expected = [
            "Event",
            "EventBus",
            "EventType",
            "HandlerFn",
            "emit_sync",
            "get_event_bus",
        ]
        for name in expected:
            assert hasattr(events, name)
