
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import os

from siyarix.internal_tools import make_graph_analyzer_handler, make_threat_intel_handler
class TestInternalTools:
    """Full coverage for internal_tools.py."""

    @pytest.mark.asyncio
    async def test_graph_analyzer_shortest_path(self):
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            kg = MagicMock()
            kg.shortest_path.return_value = [MagicMock(label="node1")]
            MockKG.return_value = kg
            result = await handler(action="shortest_path", args={"source": "a", "target": "b"})
            assert result["status"] == "success"
            kg.shortest_path.assert_called_once_with("a", "b")

    @pytest.mark.asyncio
    async def test_graph_analyzer_shortest_path_no_path(self):
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            kg = MagicMock()
            kg.shortest_path.return_value = None
            MockKG.return_value = kg
            result = await handler(action="shortest_path", args={"source": "a", "target": "b"})
            assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_graph_analyzer_blast_radius(self):
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            kg = MagicMock()
            kg.blast_radius.return_value = [MagicMock(label="affected")]
            MockKG.return_value = kg
            result = await handler(action="blast_radius", args={"node_id": "n1"})
            assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_graph_analyzer_crown_jewels(self):
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            kg = MagicMock()
            kg.find_crown_jewel_paths.return_value = [[MagicMock(label="jewel")]]
            MockKG.return_value = kg
            result = await handler(action="find_crown_jewel_paths", args={})
            assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_graph_analyzer_unknown_action(self):
        handler = make_graph_analyzer_handler()
        result = await handler(action="unknown", args={})
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_threat_intel_cve_lookup(self):
        handler = make_threat_intel_handler()
        with patch("siyarix.threat_intel.ThreatIntelFeed") as MockFeed:
            feed = MagicMock()
            feed.query_cve.return_value = {"cve": "CVE-2023-1", "info": "test"}
            MockFeed.return_value = feed
            result = await handler(action="cve_lookup", query="CVE-2023-1")
            assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_threat_intel_cve_lookup_empty(self):
        handler = make_threat_intel_handler()
        with patch("siyarix.threat_intel.ThreatIntelFeed") as MockFeed:
            feed = MagicMock()
            feed.query_cve.return_value = {}
            MockFeed.return_value = feed
            result = await handler(action="cve_lookup", query="CVE-2023-1")
            assert "cve_data" in result["output"]

    @pytest.mark.asyncio
    async def test_threat_intel_mitre_lookup(self):
        handler = make_threat_intel_handler()
        with patch("siyarix.threat_intel.MITREAttackDB") as MockDB:
            db = MagicMock()
            db.query_technique.return_value = {"technique": "T1059", "info": "test"}
            MockDB.return_value = db
            result = await handler(action="mitre_lookup", query="T1059")
            assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_threat_intel_unknown_action(self):
        handler = make_threat_intel_handler()
        result = await handler(action="unknown", query="test")
        assert result["status"] == "error"


# ═══════════════════════════════════════════════════════════════════
# opsec.py (94% - missing 106, 145-151, 199-204, 201-200, 220-219, 223-217, 329-331)
# ═══════════════════════════════════════════════════════════════════
class TestInternalToolsGraph:
    """Cover internal_tools.py remaining lines."""

    def test_graph_analyzer_handler_shortest_path_no_source(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        result = asyncio.run(handler(action="shortest_path", args={}))
        assert result["status"] == "success"

    def test_graph_analyzer_handler_blast_radius_no_node(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        result = asyncio.run(handler(action="blast_radius", args={}))
        assert result["status"] == "success"

    def test_graph_analyzer_handler_find_crown_jewels(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            mock_kg = MagicMock()
            mock_kg.find_crown_jewel_paths.return_value = [[MagicMock(), MagicMock()]]
            mock_kg.find_crown_jewel_paths.return_value[0][0].label = "host1"
            mock_kg.find_crown_jewel_paths.return_value[0][1].label = "host2"
            MockKG.return_value = mock_kg
            with patch.object(Path, "exists", return_value=True):
                result = asyncio.run(handler(action="find_crown_jewel_paths", args={}))
                assert "paths" in result["output"]

    def test_threat_intel_handler_mitre_lookup_empty(self):
        import asyncio
        handler = make_threat_intel_handler()
        with patch("siyarix.threat_intel.MITREAttackDB") as MockDB:
            mock_db = MagicMock()
            mock_db.query_technique.return_value = {}
            MockDB.return_value = mock_db
            result = asyncio.run(handler(action="mitre_lookup", query="T1059"))
            assert result["status"] == "success"


# ═══════════════════════════════════════════════════════════════════
# 15. parsers/__init__.py (91% - missing lines 189, 191, 194->181,
#     200-204, 206, 218-221)
# ═══════════════════════════════════════════════════════════════════
class TestInternalToolsCore:
    """Cover internal_tools.py remaining lines."""

    def test_graph_analyzer_handler_shortest_path_no_source(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        result = asyncio.run(handler(action="shortest_path", args={}))
        assert result["status"] == "success"

    def test_graph_analyzer_handler_blast_radius_no_node(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        result = asyncio.run(handler(action="blast_radius", args={}))
        assert result["status"] == "success"

    def test_graph_analyzer_handler_find_crown_jewels(self):
        import asyncio
        handler = make_graph_analyzer_handler()
        with patch("siyarix.knowledge_graph.KnowledgeGraph") as MockKG:
            mock_kg = MagicMock()
            mock_kg.find_crown_jewel_paths.return_value = [[MagicMock(), MagicMock()]]
            mock_kg.find_crown_jewel_paths.return_value[0][0].label = "host1"
            mock_kg.find_crown_jewel_paths.return_value[0][1].label = "host2"
            MockKG.return_value = mock_kg
            with patch.object(Path, "exists", return_value=True):
                result = asyncio.run(handler(action="find_crown_jewel_paths", args={}))
                assert "paths" in result["output"]

    def test_threat_intel_handler_mitre_lookup_empty(self):
        import asyncio
        handler = make_threat_intel_handler()
        with patch("siyarix.threat_intel.MITREAttackDB") as MockDB:
            mock_db = MagicMock()
            mock_db.query_technique.return_value = {}
            MockDB.return_value = mock_db
            result = asyncio.run(handler(action="mitre_lookup", query="T1059"))
            assert result["status"] == "success"


# ═══════════════════════════════════════════════════════════════════
# 15. parsers/__init__.py (91% - missing lines 189, 191, 194->181,
#     200-204, 206, 218-221)
# ═══════════════════════════════════════════════════════════════════
