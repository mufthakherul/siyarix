from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for ToolRegistry — covering all methods, branches, and error paths."""


import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.events import EventType
from siyarix.exceptions import PermissionDeniedError, ToolExecutionError, ToolNotFoundError
from siyarix.registry import (
    ToolRegistry,
)
from siyarix.tool_models import RiskLevel, ToolCapability, ToolCategory, ToolHandler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture
def sample_tool() -> ToolCapability:
    return ToolCapability(
        name="nmap",
        binary="nmap",
        installed=True,
        category=ToolCategory.RECON,
        risk_level=RiskLevel.MEDIUM,
        description="Network mapper",
        tags=["port-scan", "network"],
    )


@pytest.fixture
def sample_handler() -> ToolHandler:
    async def handler(**kwargs):
        return {"status": "success", "output": "scan done", "tool": "nmap"}

    return handler


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_init(self, registry: ToolRegistry):
        assert registry._graph is not None
        assert registry._handlers == {}
        assert registry._parser_registry is not None
        assert registry._loaded is False
        assert registry._load_count == 0
        assert registry._permission_gate is None
        assert registry._event_bus is None
        assert registry._lock is not None

    def test_init_with_permission_gate(self):
        gate = MagicMock()
        reg = ToolRegistry(permission_gate=gate)
        assert reg._permission_gate is gate

    def test_graph_property(self, registry: ToolRegistry):
        assert registry.graph is registry._graph

    def test_parser_registry_property(self, registry: ToolRegistry):
        assert registry.parser_registry is registry._parser_registry


# ---------------------------------------------------------------------------
# register / register_many
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_new_tool(self, registry: ToolRegistry, sample_tool: ToolCapability, sample_handler):
        registry.register(sample_tool, sample_handler)
        assert registry._graph.get_tool("nmap") is sample_tool
        assert registry._handlers["nmap"] is sample_handler

    def test_register_without_handler(self, registry: ToolRegistry, sample_tool: ToolCapability):
        registry.register(sample_tool)
        assert registry._graph.get_tool("nmap") is sample_tool
        assert "nmap" not in registry._handlers

    def test_register_updates_existing_stats(self, registry: ToolRegistry, sample_tool: ToolCapability):
        sample_tool.usage_count = 5
        sample_tool.last_used = 100.0
        sample_tool.avg_duration_ms = 200.0
        registry.register(sample_tool)
        new_tool = ToolCapability(name="nmap", installed=True, description="updated")
        registry.register(new_tool)
        merged = registry._graph.get_tool("nmap")
        assert merged.usage_count == 5
        assert merged.last_used == 100.0
        assert merged.avg_duration_ms == 200.0
        assert merged.description == "updated"

    def test_register_emits_event(self, registry: ToolRegistry, sample_tool: ToolCapability):
        with patch("siyarix.registry.emit_sync") as mock_emit:
            registry.register(sample_tool)
            mock_emit.assert_called_once()
            event = mock_emit.call_args[0][0]
            assert event.type == EventType.TOOL_REGISTERED
            assert event.data == {"tool": "nmap"}

    def test_register_many(self, registry: ToolRegistry):
        t1 = ToolCapability(name="tool_a", installed=True)
        t2 = ToolCapability(name="tool_b", installed=True)
        count = registry.register_many([(t1, None), (t2, None)])
        assert count == 2
        assert registry._graph.get_tool("tool_a") is t1
        assert registry._graph.get_tool("tool_b") is t2

    def test_register_many_empty(self, registry: ToolRegistry):
        assert registry.register_many([]) == 0


# ---------------------------------------------------------------------------
# unregister / unregister_many
# ---------------------------------------------------------------------------


class TestUnregister:
    def test_unregister_existing(self, registry: ToolRegistry, sample_tool: ToolCapability, sample_handler):
        registry.register(sample_tool, sample_handler)
        with patch("siyarix.registry.emit_sync") as mock_emit:
            result = registry.unregister("nmap")
            assert result is True
            assert registry._graph._nodes.get("nmap") is None
            assert registry._handlers.get("nmap") is None
            mock_emit.assert_called_once()
            event = mock_emit.call_args[0][0]
            assert event.type == EventType.TOOL_UNREGISTERED
            assert event.data == {"tool": "nmap"}

    def test_unregister_nonexistent(self, registry: ToolRegistry):
        with patch("siyarix.registry.emit_sync") as mock_emit:
            result = registry.unregister("ghost")
            assert result is False
            mock_emit.assert_not_called()

    def test_unregister_many(self, registry: ToolRegistry):
        t1 = ToolCapability(name="a", installed=True)
        t2 = ToolCapability(name="b", installed=True)
        t3 = ToolCapability(name="c", installed=True)
        registry.register_many([(t1, None), (t2, None), (t3, None)])
        count = registry.unregister_many(["a", "b", "missing"])
        assert count == 2
        assert registry._graph.get_tool("a") is None
        assert registry._graph.get_tool("b") is None
        assert registry._graph.get_tool("c") is not None

    def test_unregister_many_empty(self, registry: ToolRegistry):
        assert registry.unregister_many([]) == 0


# ---------------------------------------------------------------------------
# get_handler
# ---------------------------------------------------------------------------


class TestGetHandler:
    def test_get_existing_handler(self, registry: ToolRegistry, sample_tool: ToolCapability, sample_handler):
        registry.register(sample_tool, sample_handler)
        assert registry.get_handler("nmap") is sample_handler

    def test_get_missing_handler(self, registry: ToolRegistry):
        assert registry.get_handler("ghost") is None


# ---------------------------------------------------------------------------
# register_handler
# ---------------------------------------------------------------------------


class TestRegisterHandler:
    def test_register_handler_new(self, registry: ToolRegistry, sample_handler):
        registry.register_handler("custom_tool", sample_handler)
        assert registry._handlers["custom_tool"] is sample_handler

    def test_register_handler_overrides(self, registry: ToolRegistry):
        h1: ToolHandler = lambda **kw: None  # type: ignore
        h2: ToolHandler = lambda **kw: None  # type: ignore
        registry.register_handler("tool", h1)
        registry.register_handler("tool", h2)
        assert registry._handlers["tool"] is h2


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


class TestExecute:
    @patch("siyarix.registry.emit_sync")
    async def test_execute_success(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        handler = AsyncMock(return_value={"status": "success", "output": "result", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            result = await registry.execute("nmap", target="10.0.0.1")
            assert result["status"] == "success"
            assert result["output"] == "result"
            assert result["tool"] == "nmap"
            mock_thread.assert_called_once()

    async def test_execute_tool_not_found(self, registry: ToolRegistry):
        with pytest.raises(ToolNotFoundError, match="Tool not found: ghost"):
            await registry.execute("ghost")

    async def test_execute_no_handler(self, registry: ToolRegistry):
        tool = ToolCapability(name="handlerless", installed=True)
        registry.register(tool)
        with pytest.raises(ToolNotFoundError, match="No handler registered for: handlerless"):
            await registry.execute("handlerless")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_with_availability_check(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        sample_tool.availability = {"os": "linux"}
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("siyarix.tool_availability.ToolAvailabilityContext") as MockCtx, \
             patch("siyarix.tool_availability.evaluate_availability",
                   return_value=MagicMock(available=True)) as mock_eval, \
             patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap")
            assert result["status"] == "success"
            mock_eval.assert_called_once()

    @patch("siyarix.registry.emit_sync")
    async def test_execute_availability_fails(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        sample_tool.availability = {"os": "windows"}
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        mock_result = MagicMock()
        mock_result.available = False
        mock_result.diagnostics = [MagicMock(detail="Not available on this OS")]
        with patch("siyarix.tool_availability.ToolAvailabilityContext"), \
             patch("siyarix.tool_availability.evaluate_availability", return_value=mock_result):
            with pytest.raises(ToolNotFoundError, match="unavailable"):
                await registry.execute("nmap")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_permission_gate_allows(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=True, requires_review=False)
        registry._permission_gate = gate
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap", command="nmap target")
            assert result["status"] == "success"
            gate.check.assert_called_once_with("nmap target", tool="nmap")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_permission_gate_blocks(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=False, reason="Not allowed", requires_review=False)
        registry._permission_gate = gate
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with pytest.raises(PermissionDeniedError, match="Not allowed"):
            await registry.execute("nmap", command="nmap target")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_permission_gate_requires_review_approved(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=True, requires_review=True, reason="review needed")
        registry._permission_gate = gate
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("siyarix.shell_review.review_and_confirm", return_value="nmap target") as mock_review, \
             patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap", command="nmap target")
            assert result["status"] == "success"
            mock_review.assert_called_once()

    @patch("siyarix.registry.emit_sync")
    async def test_execute_permission_gate_review_cancelled(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        gate = MagicMock()
        gate.check.return_value = MagicMock(allowed=True, requires_review=True, reason="user review")
        registry._permission_gate = gate
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("siyarix.shell_review.review_and_confirm", return_value=None) as mock_review:
            with pytest.raises(PermissionDeniedError, match="Cancelled by user"):
                await registry.execute("nmap", command="nmap target")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_permission_gate_no_command(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        gate = MagicMock()
        registry._permission_gate = gate
        handler = AsyncMock(return_value={"status": "success", "output": "ok", "tool": "nmap"})
        registry.register(sample_tool, handler)
        with patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap")
            assert result["status"] == "success"
            gate.check.assert_not_called()

    @patch("siyarix.registry.emit_sync")
    async def test_execute_with_parser(self, mock_emit, registry: ToolRegistry):
        tool = ToolCapability(name="nmap", installed=True, parser="nmap")
        handler = AsyncMock(return_value={
            "status": "success", "output": "parsed output", "tool": "nmap"
        })
        registry.register(tool, handler)
        registry._parser_registry.has_parser = MagicMock(return_value=True)  # type: ignore
        registry._parser_registry.parse = MagicMock(return_value=[{"title": "open port"}])  # type: ignore
        with patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap")
            assert "findings" in result
            assert result["findings"] == [{"title": "open port"}]

    @patch("siyarix.registry.emit_sync")
    async def test_execute_no_output_no_parse(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        handler = AsyncMock(return_value={
            "status": "success", "output": "", "tool": "nmap"
        })
        registry.register(sample_tool, handler)
        registry._parser_registry.has_parser = MagicMock(return_value=True)  # type: ignore
        with patch("asyncio.to_thread", new_callable=AsyncMock):
            result = await registry.execute("nmap")
            assert "findings" not in result

    @patch("siyarix.registry.emit_sync")
    async def test_execute_handler_raises_tool_not_found(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        handler = AsyncMock(side_effect=ToolNotFoundError("missing binary"))
        registry.register(sample_tool, handler)
        with pytest.raises(ToolNotFoundError):
            await registry.execute("nmap")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_handler_raises_permission_denied(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        handler = AsyncMock(side_effect=PermissionDeniedError("blocked"))
        registry.register(sample_tool, handler)
        with pytest.raises(PermissionDeniedError):
            await registry.execute("nmap")

    @patch("siyarix.registry.emit_sync")
    async def test_execute_handler_raises_generic(self, mock_emit, registry: ToolRegistry, sample_tool: ToolCapability):
        handler = AsyncMock(side_effect=RuntimeError("unexpected crash"))
        registry.register(sample_tool, handler)
        with pytest.raises(ToolExecutionError, match="unexpected crash"):
            await registry.execute("nmap")

    async def test_execute_stats_update(self, registry: ToolRegistry):
        tool = ToolCapability(name="stats_test", installed=True)
        handler = AsyncMock(return_value={"status": "success", "output": "x", "tool": "stats_test"})
        registry.register(tool, handler)
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            await registry.execute("stats_test")
            mock_thread.assert_called_once()


# ---------------------------------------------------------------------------
# _build_tool_capability
# ---------------------------------------------------------------------------


class TestBuildToolCapability:
    def test_build_with_handler_factory(self, registry: ToolRegistry):
        handler_factory = MagicMock(return_value=MagicMock())
        with patch("siyarix.registry.get_tool_metadata", return_value={"personas": ["pentester"]}):
            cap, handler = registry._build_tool_capability("nmap", "/usr/bin/nmap", "7.94", handler_factory)
        assert cap.name == "nmap"
        assert cap.binary == "/usr/bin/nmap"
        assert cap.version == "7.94"
        assert cap.installed is True
        assert cap.metadata == {"personas": ["pentester"]}
        handler_factory.assert_called_once_with("nmap")
        assert handler is not None

    def test_build_with_no_handler_factory(self, registry: ToolRegistry):
        with patch("siyarix.registry.get_tool_metadata", return_value={}):
            cap, handler = registry._build_tool_capability("curl", "/usr/bin/curl", "7.0")
        assert cap.name == "curl"
        assert cap.parser == ""
        assert cap.metadata == {}
        assert handler is not None

    def test_build_with_parser(self, registry: ToolRegistry):
        registry._parser_registry.has_parser = MagicMock(return_value=True)  # type: ignore
        with patch("siyarix.registry.get_tool_metadata", return_value={}):
            cap, _ = registry._build_tool_capability("nmap", "/usr/bin/nmap", "7.94")
        assert cap.parser == "nmap"

    def test_build_with_meta_none(self, registry: ToolRegistry):
        with patch("siyarix.registry.get_tool_metadata", return_value=None):
            cap, handler = registry._build_tool_capability("custom_bin", "/bin/custom", "1.0")
        assert cap.metadata == {}
        assert cap.parser == ""
        assert handler is not None


# ---------------------------------------------------------------------------
# discover_from_path
# ---------------------------------------------------------------------------


class TestDiscoverFromPath:
    @patch.dict("siyarix.registry._HANDLER_MAP", {"nmap": MagicMock(return_value=AsyncMock())}, clear=True)
    @patch("siyarix.registry._cached_which", return_value="/usr/bin/nmap")
    @patch("siyarix.registry.get_tool_metadata", return_value={"version": "7.94"})
    @patch("siyarix.registry.emit_sync")
    def test_discover_curated_tool(self, mock_emit, mock_meta, mock_which, registry: ToolRegistry):
        count = registry.discover_from_path()
        assert count >= 1
        assert registry._loaded is True
        assert registry._load_count == 1
        nmap = registry._graph.get_tool("nmap")
        assert nmap is not None
        assert nmap.version == "7.94"

    @patch.dict("siyarix.registry._HANDLER_MAP", {"nmap": MagicMock(return_value=AsyncMock())}, clear=True)
    @patch("siyarix.registry._cached_which", return_value="/usr/bin/nmap")
    @patch("siyarix.registry.get_tool_metadata", return_value={})
    @patch("siyarix.registry.detect_version", return_value="7.95")
    @patch("siyarix.registry.emit_sync")
    def test_discover_curated_tool_fallback_version(self, mock_emit, mock_detect, mock_meta, mock_which, registry: ToolRegistry):
        count = registry.discover_from_path()
        assert count >= 1
        nmap = registry._graph.get_tool("nmap")
        assert nmap is not None
        assert nmap.version == "7.95"

    @patch("siyarix.registry._cached_which", side_effect=lambda n: f"/usr/bin/{n}" if n == "python3" else None)
    @patch("siyarix.registry.detect_version", return_value="3.11")
    @patch("siyarix.registry.emit_sync")
    def test_discover_interpreter(self, mock_emit, mock_detect, mock_which, registry: ToolRegistry):
        count = registry.discover_from_path()
        py = registry._graph.get_tool("python3")
        assert py is not None
        assert py.category == ToolCategory.UTILITY
        assert py.risk_level == RiskLevel.SAFE
        assert py.version == "3.11"

    @patch("siyarix.registry._cached_which", return_value=None)
    @patch("siyarix.registry.emit_sync")
    def test_discover_no_tools_found(self, mock_emit, mock_which, registry: ToolRegistry):
        count = registry.discover_from_path()
        assert count == 0
        assert registry._loaded is True

    @patch.dict("siyarix.registry._HANDLER_MAP", {"nmap": MagicMock(return_value=AsyncMock())}, clear=True)
    @patch("siyarix.registry._cached_which", return_value="/usr/bin/nmap")
    @patch("siyarix.registry.get_tool_metadata", return_value={})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_discover_uses_handler_map(self, mock_emit, mock_detect, mock_meta, mock_which, registry: ToolRegistry):
        count = registry.discover_from_path()
        assert count >= 1
        nmap_handler = registry._handlers.get("nmap")
        assert nmap_handler is not None


# ---------------------------------------------------------------------------
# update_metadata
# ---------------------------------------------------------------------------


class TestUpdateMetadata:
    @patch("siyarix.registry.emit_sync")
    def test_update_metadata_writes_json(self, mock_emit, registry: ToolRegistry, tmp_path: Path):
        tool = ToolCapability(
            name="nmap", description="Scanner", category=ToolCategory.RECON,
            risk_level=RiskLevel.MEDIUM, binary="nmap", installed=True,
            tags=["scan"], version="7.94",
        )
        registry.register(tool)
        output_path = tmp_path / "tools.json"
        count = registry.update_metadata(output_path)
        assert count >= 1
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert "nmap" in data
        assert isinstance(data["nmap"].get("version"), str)

    @patch("siyarix.registry.emit_sync")
    def test_update_metadata_empty(self, mock_emit, registry: ToolRegistry, tmp_path: Path):
        with patch.object(registry, "discover_from_path"), patch.object(registry, "scan_path", return_value=0):
            count = registry.update_metadata(tmp_path / "empty.json")
            assert count == 0


# ---------------------------------------------------------------------------
# scan_path
# ---------------------------------------------------------------------------


class TestScanPath:
    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={"category": "recon"})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_discovers_new_tools(
        self, mock_emit, mock_detect, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["mycustom_tool", "another_tool"]
            count = registry.scan_path()
            assert count == 2
            assert registry._graph.get_tool("mycustom_tool") is not None
            assert registry._graph.get_tool("another_tool") is not None

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={"category": "recon"})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_skips_blacklisted(
        self, mock_emit, mock_detect, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["my_tool", "svchost.exe", "my_other_tool"]
            count = registry.scan_path()
            assert count == 2
            assert registry._graph.get_tool("svchost.exe") is None

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={})
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_skips_utility_without_meta(
        self, mock_emit, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["ls", "grep"]
            count = registry.scan_path()
            assert count == 0

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={"personas": ["devsecops"]})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_includes_utility_with_personas(
        self, mock_emit, mock_detect, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["custom_util"]
            count = registry.scan_path()
            assert count == 1
            tool = registry._graph.get_tool("custom_util")
            assert tool is not None
            assert tool.metadata == {"personas": ["devsecops"]}

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_skips_duplicates(self, mock_emit, mock_listdir, registry: ToolRegistry):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["tool_a", "tool_a"]
            with patch("siyarix.registry.os.path.isfile", return_value=True), \
                 patch("siyarix.registry.os.access", return_value=True), \
                 patch("siyarix.registry.get_tool_metadata", return_value={"category": "recon"}), \
                 patch("siyarix.registry.detect_version", return_value="1.0"):
                count = registry.scan_path()
                assert count == 1

    @patch("siyarix.registry.os.listdir", side_effect=OSError("permission denied"))
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_handles_os_error(self, mock_emit, mock_listdir, registry: ToolRegistry):
        count = registry.scan_path()
        assert count == 0

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={"category": "recon"})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_windows_filters_extensions(
        self, mock_emit, mock_detect, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "nt"):
            mock_listdir.return_value = ["tool.exe", "script.ps1", "no_ext", "data.txt"]
            with patch.object(registry._graph, "get_tool", return_value=None):
                count = registry.scan_path()
                assert count == 2

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.os.path.isfile", return_value=True)
    @patch("siyarix.registry.os.access", return_value=True)
    @patch("siyarix.registry.get_tool_metadata", return_value={"category": "recon", "risk_level": "high", "version": "2.0"})
    @patch("siyarix.registry.detect_version", return_value="1.0")
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_uses_meta_category_and_risk(
        self, mock_emit, mock_detect, mock_meta, mock_access, mock_isfile, mock_listdir, registry: ToolRegistry
    ):
        with patch("siyarix.registry.os.name", "posix"):
            mock_listdir.return_value = ["advanced_tool"]
            count = registry.scan_path()
            assert count == 1
            tool = registry._graph.get_tool("advanced_tool")
            assert tool is not None
            assert tool.category == ToolCategory.RECON
            assert tool.risk_level == RiskLevel.HIGH

    @patch("siyarix.registry.os.listdir")
    @patch.dict("siyarix.registry.os.environ", {"PATH": "/usr/bin"}, clear=True)
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_empty_path_dir(self, mock_emit, mock_listdir, registry: ToolRegistry):
        mock_listdir.return_value = []
        count = registry.scan_path()
        assert count == 0

    @patch.dict("siyarix.registry.os.environ", {}, clear=True)
    @patch("siyarix.registry.emit_sync")
    def test_scan_path_no_path(self, mock_emit, registry: ToolRegistry):
        count = registry.scan_path()
        assert count == 0


# ---------------------------------------------------------------------------
# load_from_json
# ---------------------------------------------------------------------------


class TestLoadFromJson:
    def test_load_from_json_success(self, registry: ToolRegistry, tmp_path: Path):
        data = {
            "mytool": {
                "description": "Custom tool",
                "category": "recon",
                "risk_level": "medium",
                "binary": "mytool",
                "version": "1.0",
                "installed": True,
                "tags": ["custom"],
                "aliases": [],
                "parser": "",
            }
        }
        path = tmp_path / "tools.json"
        path.write_text(json.dumps(data))
        count = registry.load_from_json(path)
        assert count == 1
        tool = registry._graph.get_tool("mytool")
        assert tool is not None
        assert tool.description == "Custom tool"

    def test_load_from_json_with_handler(self, registry: ToolRegistry, tmp_path: Path):
        data = {"nmap": {"description": "Nmap"}}
        path = tmp_path / "nmap.json"
        path.write_text(json.dumps(data))
        count = registry.load_from_json(path, register_handlers=True)
        assert count == 1
        assert registry._handlers.get("nmap") is not None

    def test_load_from_json_without_handler(self, registry: ToolRegistry, tmp_path: Path):
        data = {"nmap": {"description": "Nmap"}}
        path = tmp_path / "nmap.json"
        path.write_text(json.dumps(data))
        count = registry.load_from_json(path, register_handlers=False)
        assert count == 1
        assert registry._handlers.get("nmap") is None

    def test_load_from_json_path_not_exists(self, registry: ToolRegistry):
        count = registry.load_from_json(Path("/nonexistent/path.json"))
        assert count == 0

    def test_load_from_json_malformed(self, registry: ToolRegistry, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json")
        count = registry.load_from_json(path)
        assert count == 0

    def test_load_from_json_invalid_category_logs_and_returns_zero(self, registry: ToolRegistry, tmp_path: Path):
        data = {"toolx": {"category": "invalid_category", "risk_level": "invalid"}}
        path = tmp_path / "toolx.json"
        path.write_text(json.dumps(data))
        count = registry.load_from_json(path)
        assert count == 0

    def test_load_from_json_info_is_not_dict(self, registry: ToolRegistry, tmp_path: Path):
        data = {"tooly": "just a string"}
        path = tmp_path / "tooly.json"
        path.write_text(json.dumps(data))
        count = registry.load_from_json(path)
        assert count == 1
        tool = registry._graph.get_tool("tooly")
        assert tool.description == ""


# ---------------------------------------------------------------------------
# load_custom_tools
# ---------------------------------------------------------------------------


class TestLoadCustomTools:
    @patch("siyarix.config.get_config_dir")
    def test_load_custom_tools_success(self, mock_config_dir, registry: ToolRegistry, tmp_path: Path):
        config_dir = tmp_path / ".config"
        config_dir.mkdir(parents=True)
        custom_file = config_dir / "custom_tools.json"
        data = {
            "custom_scanner": {
                "description": "My custom port scanner",
                "category": "recon",
                "risk_level": "medium",
                "binary": "custom_scan",
                "version": "2.0",
                "parser": "",
            }
        }
        custom_file.write_text(json.dumps(data))
        mock_config_dir.return_value = config_dir
        count = registry.load_custom_tools()
        assert count == 1
        tool = registry._graph.get_tool("custom_scanner")
        assert tool is not None
        assert tool.description == "My custom port scanner"
        assert tool.installed is True
        assert "custom" in tool.tags

    @patch("siyarix.config.get_config_dir")
    def test_load_custom_tools_no_file(self, mock_config_dir, registry: ToolRegistry):
        config_dir = MagicMock()
        config_dir.exists.return_value = False
        config_dir.__truediv__ = lambda self, other: Path("/nonexistent/custom_tools.json")
        mock_config_dir.return_value = config_dir
        count = registry.load_custom_tools()
        assert count == 0

    @patch("siyarix.config.get_config_dir")
    def test_load_custom_tools_malformed(self, mock_config_dir, registry: ToolRegistry, tmp_path: Path):
        config_dir = tmp_path / ".config"
        config_dir.mkdir(parents=True)
        bad_file = config_dir / "custom_tools.json"
        bad_file.write_text("{{{broken")
        mock_config_dir.return_value = config_dir
        count = registry.load_custom_tools()
        assert count == 0


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------


class TestListTools:
    def test_list_all(self, registry: ToolRegistry):
        t1 = ToolCapability(name="alpha", installed=True)
        t2 = ToolCapability(name="beta", installed=True)
        registry.register_many([(t1, None), (t2, None)])
        tools = registry.list_tools()
        assert len(tools) == 2
        assert tools[0].name == "alpha"
        assert tools[1].name == "beta"

    def test_list_by_category(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, category=ToolCategory.RECON)
        t2 = ToolCapability(name="nuclei", installed=True, category=ToolCategory.SCANNING)
        registry.register_many([(t1, None), (t2, None)])
        recon = registry.list_tools(category=ToolCategory.RECON)
        assert len(recon) == 1
        assert recon[0].name == "nmap"

    def test_list_available_only(self, registry: ToolRegistry):
        t1 = ToolCapability(name="avail", installed=True)
        t2 = ToolCapability(name="not_avail", installed=False, binary="")
        registry.register_many([(t1, None), (t2, None)])
        tools = registry.list_tools(available_only=True)
        assert len(tools) == 1
        assert tools[0].name == "avail"

    def test_list_by_tags(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, tags=["network", "scan"])
        t2 = ToolCapability(name="curl", installed=True, tags=["http", "client"])
        registry.register_many([(t1, None), (t2, None)])
        tools = registry.list_tools(tags=["network"])
        assert len(tools) == 1
        assert tools[0].name == "nmap"

    def test_list_by_tags_case_sensitive_matching(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, tags=["network"])
        registry.register(t1)
        tools = registry.list_tools(tags=["network"])
        assert len(tools) == 1

    def test_list_search_by_name(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, description="", tags=[])
        t2 = ToolCapability(name="nikto", installed=True, description="", tags=[])
        registry.register_many([(t1, None), (t2, None)])
        tools = registry.list_tools(search="nmap")
        assert len(tools) == 1

    def test_list_search_by_description(self, registry: ToolRegistry):
        t1 = ToolCapability(name="t1", installed=True, description="port scanner", tags=[])
        t2 = ToolCapability(name="t2", installed=True, description="vuln scanner", tags=[])
        registry.register_many([(t1, None), (t2, None)])
        tools = registry.list_tools(search="port")
        assert len(tools) == 1

    def test_list_search_by_tag(self, registry: ToolRegistry):
        t1 = ToolCapability(name="t1", installed=True, description="", tags=["port-scan"])
        registry.register(t1)
        tools = registry.list_tools(search="port-scan")
        assert len(tools) == 1

    def test_list_search_by_alias(self, registry: ToolRegistry):
        t1 = ToolCapability(name="zap", installed=True, description="", tags=[], aliases=["zaproxy"])
        registry.register(t1)
        tools = registry.list_tools(search="zaproxy")
        assert len(tools) == 1

    def test_list_search_no_match(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, description="", tags=[])
        registry.register(t1)
        tools = registry.list_tools(search="nonexistent")
        assert len(tools) == 0

    def test_list_combined_filters(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, category=ToolCategory.RECON, description="port scanner", tags=["scan"])
        t2 = ToolCapability(name="nuclei", installed=True, category=ToolCategory.SCANNING, description="vuln scanner", tags=["scan"])
        t3 = ToolCapability(name="gobuster", installed=False, category=ToolCategory.SCANNING, description="dir buster", tags=["web"])
        registry.register_many([(t1, None), (t2, None), (t3, None)])
        tools = registry.list_tools(
            category=ToolCategory.SCANNING, available_only=True, tags=["scan"], search="vuln"
        )
        assert len(tools) == 1
        assert tools[0].name == "nuclei"


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_delegates_to_graph(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, description="port scanner", tags=["scan"])
        t2 = ToolCapability(name="curl", installed=True, description="http client", tags=["web"])
        registry.register_many([(t1, None), (t2, None)])
        results = registry.search("port scanner")
        assert len(results) >= 1
        assert any(t.name == "nmap" for t in results)

    def test_search_returns_top_k(self, registry: ToolRegistry):
        tools = [ToolCapability(name=f"tool_{i}", installed=True, description=f"scanning tool {i}", tags=["scan"]) for i in range(20)]
        registry.register_many([(t, None) for t in tools])
        results = registry.search("scanning", top_k=5)
        assert len(results) <= 5


# ---------------------------------------------------------------------------
# get_tool_alternatives
# ---------------------------------------------------------------------------


class TestGetToolAlternatives:
    def test_alternatives_from_graph(self, registry: ToolRegistry):
        tool = ToolCapability(name="nmap", installed=True, related_tools=["masscan", "rustscan"])
        registry.register(tool)
        alts = registry.get_tool_alternatives("nmap")
        assert alts == ["masscan", "rustscan"]

    def test_alternatives_from_TOOL_ALTERNATIVES(self, registry: ToolRegistry):
        tool = ToolCapability(name="nmap", installed=True, related_tools=[])
        registry.register(tool)
        alts = registry.get_tool_alternatives("nmap")
        assert "masscan" in alts

    def test_alternatives_no_tool(self, registry: ToolRegistry):
        alts = registry.get_tool_alternatives("ghost")
        assert alts == []

    def test_alternatives_graph_has_no_related(self, registry: ToolRegistry):
        tool = ToolCapability(name="nonexistent_ref", installed=True)
        registry.register(tool)
        alts = registry.get_tool_alternatives("nonexistent_ref")
        assert alts == []


# ---------------------------------------------------------------------------
# get_by_tags
# ---------------------------------------------------------------------------


class TestGetByTags:
    def test_get_by_tags(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, tags=["network", "scan"])
        t2 = ToolCapability(name="curl", installed=True, tags=["http", "web"])
        t3 = ToolCapability(name="nuclei", installed=True, tags=["scan", "vuln"])
        registry.register_many([(t1, None), (t2, None), (t3, None)])
        results = registry.get_by_tags(["scan"])
        assert len(results) == 2

    def test_get_by_tags_case_sensitive(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, tags=["network"])
        registry.register(t1)
        results = registry.get_by_tags(["network"])
        assert len(results) == 1

    def test_get_by_tags_no_match(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, tags=["scan"])
        registry.register(t1)
        results = registry.get_by_tags(["cloud"])
        assert results == []


# ---------------------------------------------------------------------------
# get_popular_tools
# ---------------------------------------------------------------------------


class TestGetPopularTools:
    def test_get_popular_tools(self, registry: ToolRegistry):
        t1 = ToolCapability(name="most", installed=True, usage_count=100)
        t2 = ToolCapability(name="mid", installed=True, usage_count=50)
        t3 = ToolCapability(name="least", installed=True, usage_count=10)
        t4 = ToolCapability(name="never", installed=True, usage_count=0)
        registry.register_many([(t1, None), (t2, None), (t3, None), (t4, None)])
        popular = registry.get_popular_tools(top_n=3)
        assert len(popular) == 3
        assert popular[0].name == "most"
        assert popular[1].name == "mid"

    def test_get_popular_tools_top_n(self, registry: ToolRegistry):
        tools = [ToolCapability(name=f"t{i}", installed=True, usage_count=i * 10) for i in range(10)]
        registry.register_many([(t, None) for t in tools])
        popular = registry.get_popular_tools(top_n=2)
        assert len(popular) == 2

    def test_get_popular_tools_no_usage(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, usage_count=0)
        registry.register(t1)
        assert registry.get_popular_tools() == []


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_empty(self, registry: ToolRegistry):
        s = registry.stats()
        assert s["total"] == 0
        assert s["available"] == 0
        assert s["handlers"] == 0
        assert s["loaded"] is False
        assert s["load_count"] == 0

    def test_stats_with_tools(self, registry: ToolRegistry):
        t1 = ToolCapability(name="nmap", installed=True, category=ToolCategory.RECON)
        t2 = ToolCapability(name="nuclei", installed=False, category=ToolCategory.SCANNING)
        registry.register_many([(t1, None), (t2, None)])
        registry.register_handler("nmap", MagicMock())
        registry._loaded = True
        registry._load_count = 2
        s = registry.stats()
        assert s["total"] == 2
        assert s["available"] == 1
        assert s["categories"] == 2
        assert s["handlers"] == 1
        assert s["loaded"] is True
        assert s["load_count"] == 2
        assert s["category_counts"]["recon"] == 1
        assert s["category_counts"]["scanning"] == 1
