"""Tests for ToolCapabilityGraph — 100% coverage."""

from __future__ import annotations

import pytest

from siyarix.tool_models import ToolCapability, ToolCategory, ToolEdge
from siyarix.tool_graph import ToolCapabilityGraph, __all__


class TestExports:
    def test_all(self):
        assert "ToolCapabilityGraph" in __all__


@pytest.fixture
def graph() -> ToolCapabilityGraph:
    return ToolCapabilityGraph()


@pytest.fixture
def nmap() -> ToolCapability:
    return ToolCapability(
        name="nmap",
        category=ToolCategory.RECON,
        description="Port scanner",
        tags=["network", "scan"],
        installed=True,
    )


@pytest.fixture
def nuclei() -> ToolCapability:
    return ToolCapability(
        name="nuclei",
        category=ToolCategory.SCANNING,
        description="Vulnerability scanner",
        tags=["vuln", "scan"],
        installed=True,
    )


@pytest.fixture
def gobuster() -> ToolCapability:
    return ToolCapability(
        name="gobuster",
        category=ToolCategory.SCANNING,
        description="Directory buster",
        tags=["web", "brute"],
        installed=False,
    )


@pytest.fixture
def zap() -> ToolCapability:
    return ToolCapability(
        name="zap",
        category=ToolCategory.WEB,
        description="Web app scanner",
        tags=["web", "scan"],
        installed=True,
        aliases=["zaproxy", "owasp-zap"],
    )


class TestInit:
    def test_empty_state(self, graph: ToolCapabilityGraph):
        assert graph._nodes == {}
        assert graph._edges == []
        assert graph._alias_map == {}
        assert graph.all_tools() == []
        assert graph.get_available_tools() == []


class TestAddTool:
    def test_single_tool(self, graph: ToolCapabilityGraph, nmap: ToolCapability):
        graph.add_tool(nmap)
        assert graph.get_tool("nmap") is nmap

    def test_multiple_tools(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        assert len(graph.all_tools()) == 2

    def test_tool_with_aliases(
        self, graph: ToolCapabilityGraph, zap: ToolCapability
    ):
        graph.add_tool(zap)
        assert graph.get_tool("zap") is zap
        assert graph.get_tool("zaproxy") is zap
        assert graph.get_tool("owasp-zap") is zap

    def test_add_duplicate_name_overwrites(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        nmap2 = ToolCapability(name="nmap", description="other")
        graph.add_tool(nmap)
        graph.add_tool(nmap2)
        assert graph.get_tool("nmap") is nmap2
        assert graph.get_tool("nmap").description == "other"


class TestAddEdge:
    def test_single_edge(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        edge = ToolEdge(source="nmap", target="nuclei", weight=1.5)
        graph.add_edge(edge)
        assert len(graph._edges) == 1
        assert graph._edges[0] is edge

    def test_multiple_edges(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
        gobuster: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        graph.add_tool(gobuster)
        graph.add_edge(ToolEdge(source="nmap", target="nuclei"))
        graph.add_edge(ToolEdge(source="nuclei", target="gobuster"))
        assert len(graph._edges) == 2


class TestGetTool:
    def test_by_name(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        assert graph.get_tool("nmap") is nmap

    def test_by_alias(
        self, graph: ToolCapabilityGraph, zap: ToolCapability
    ):
        graph.add_tool(zap)
        assert graph.get_tool("zaproxy") is zap

    def test_non_existent(self, graph: ToolCapabilityGraph):
        assert graph.get_tool("nonexistent") is None

    def test_alias_points_to_canonical(
        self, graph: ToolCapabilityGraph, zap: ToolCapability
    ):
        graph.add_tool(zap)
        gotten = graph.get_tool("zaproxy")
        assert gotten is not None
        assert gotten.name == "zap"


class TestGetToolsByCategory:
    def test_same_category(
        self,
        graph: ToolCapabilityGraph,
        nuclei: ToolCapability,
        gobuster: ToolCapability,
    ):
        graph.add_tool(nuclei)
        graph.add_tool(gobuster)
        scanning = graph.get_tools_by_category(ToolCategory.SCANNING)
        assert len(scanning) == 2

    def test_different_category(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        recon = graph.get_tools_by_category(ToolCategory.RECON)
        assert len(recon) == 1
        assert recon[0].name == "nmap"

    def test_empty_result(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        assert graph.get_tools_by_category(ToolCategory.CLOUD) == []


class TestGetAvailableTools:
    def test_all_available(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        assert len(graph.get_available_tools()) == 2

    def test_some_available(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        gobuster: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(gobuster)
        available = graph.get_available_tools()
        assert len(available) == 1
        assert available[0].name == "nmap"

    def test_none_available(
        self, graph: ToolCapabilityGraph, gobuster: ToolCapability
    ):
        gobuster.installed = False
        gobuster.binary = ""
        graph.add_tool(gobuster)
        assert graph.get_available_tools() == []


class TestGetChain:
    def test_valid_path(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        graph.add_edge(ToolEdge(source="nmap", target="nuclei", weight=1.0))
        chain = graph.get_chain("nmap", "nuclei")
        assert chain == ["nmap", "nuclei"]

    def test_no_path_disconnected(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        # no edge added
        assert graph.get_chain("nmap", "nuclei") == []

    def test_start_not_in_graph(
        self,
        graph: ToolCapabilityGraph,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nuclei)
        assert graph.get_chain("nmap", "nuclei") == []

    def test_goal_not_in_graph(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
    ):
        graph.add_tool(nmap)
        assert graph.get_chain("nmap", "nuclei") == []

    def test_weighted_edge_uses_dijkstra(
        self,
        graph: ToolCapabilityGraph,
    ):
        a = ToolCapability(name="a", installed=True)
        b = ToolCapability(name="b", installed=True)
        c = ToolCapability(name="c", installed=True)
        graph.add_tool(a)
        graph.add_tool(b)
        graph.add_tool(c)
        graph.add_edge(ToolEdge(source="a", target="b", weight=10.0))
        graph.add_edge(ToolEdge(source="a", target="c", weight=1.0))
        graph.add_edge(ToolEdge(source="c", target="b", weight=1.0))
        chain = graph.get_chain("a", "b")
        # Dijkstra finds a -> c -> b (total weight 2.0) not a -> b (10.0)
        assert chain == ["a", "c", "b"]

    def test_multiple_paths_shortest(
        self,
        graph: ToolCapabilityGraph,
    ):
        a = ToolCapability(name="a", installed=True)
        b = ToolCapability(name="b", installed=True)
        c = ToolCapability(name="c", installed=True)
        graph.add_tool(a)
        graph.add_tool(b)
        graph.add_tool(c)
        graph.add_edge(ToolEdge(source="a", target="b", weight=5.0))
        graph.add_edge(ToolEdge(source="a", target="c", weight=1.0))
        graph.add_edge(ToolEdge(source="c", target="b", weight=1.0))
        chain = graph.get_chain("a", "b")
        assert chain == ["a", "c", "b"]

    def test_start_equals_goal(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
    ):
        graph.add_tool(nmap)
        chain = graph.get_chain("nmap", "nmap")
        assert chain == ["nmap"]

    def test_visited_node_skipped_on_second_pop(self, graph: ToolCapabilityGraph):
        """Two paths reach same node; second pop finds it already visited."""
        a = ToolCapability(name="a", installed=True)
        b = ToolCapability(name="b", installed=True)
        c = ToolCapability(name="c", installed=True)
        d = ToolCapability(name="d", installed=True)
        e = ToolCapability(name="e", installed=True)
        graph.add_tool(a)
        graph.add_tool(b)
        graph.add_tool(c)
        graph.add_tool(d)
        graph.add_tool(e)
        graph.add_edge(ToolEdge(source="a", target="b", weight=1.0))
        graph.add_edge(ToolEdge(source="a", target="c", weight=1.0))
        graph.add_edge(ToolEdge(source="b", target="d", weight=1.0))
        graph.add_edge(ToolEdge(source="c", target="d", weight=1.0))
        graph.add_edge(ToolEdge(source="d", target="e", weight=1.0))
        chain = graph.get_chain("a", "e")
        assert chain == ["a", "b", "d", "e"] or chain == ["a", "c", "d", "e"]


class TestFindOptimalTools:
    def test_by_name_match(self, graph: ToolCapabilityGraph, nmap: ToolCapability):
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("nmap")
        assert len(result) == 1
        assert result[0].name == "nmap"

    def test_by_tag_match(self, graph: ToolCapabilityGraph, nmap: ToolCapability):
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("network")
        assert len(result) == 1
        assert result[0].name == "nmap"

    def test_by_description_match(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("port")
        assert len(result) == 1
        assert result[0].name == "nmap"

    def test_with_availability_filter(
        self, graph: ToolCapabilityGraph, gobuster: ToolCapability
    ):
        graph.add_tool(gobuster)
        result = graph.find_optimal_tools("gobuster")
        assert len(result) == 1

    def test_with_available_list_filter(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        result = graph.find_optimal_tools("scan", available=["nmap"])
        assert len(result) == 1
        assert result[0].name == "nmap"

    def test_no_matches(self, graph: ToolCapabilityGraph, nmap: ToolCapability):
        nmap.installed = False
        nmap.binary = ""
        nmap.description = ""
        nmap.tags = []
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("zzzzz")
        assert result == []

    def test_scoring_prioritization(
        self, graph: ToolCapabilityGraph
    ):
        low = ToolCapability(
            name="tool_a",
            description="exact alpha description",
            tags=["exact"],
            installed=True,
        )
        high = ToolCapability(
            name="exact_match",
            description="something else",
            tags=[],
            installed=True,
        )
        graph.add_tool(low)
        graph.add_tool(high)
        result = graph.find_optimal_tools("exact")
        # "exact" matches high.name (+10), low.description (+2), low.tags (+3), both available (+1)
        # high: name +10, available +1 = 11
        # low: desc +2, tag +3, available +1 = 6
        assert len(result) == 2
        assert result[0].name == "exact_match"

    def test_score_includes_availability_bonus(
        self, graph: ToolCapabilityGraph
    ):
        available_tool = ToolCapability(
            name="alpha", description="tool", installed=True
        )
        unavailable_tool = ToolCapability(
            name="beta", description="tool", installed=False
        )
        graph.add_tool(available_tool)
        graph.add_tool(unavailable_tool)
        result = graph.find_optimal_tools("tool")
        assert len(result) == 2
        # both match description (score 2.0), alpha gets +1 for availability
        # but both still have score > 0
        names = [t.name for t in result]
        assert "alpha" in names
        assert "beta" in names

    def test_available_list_filter_no_match(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("nmap", available=["other"])
        assert result == []

    def test_available_list_empty_is_noop(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        # empty list is falsy, so no filtering is applied
        result = graph.find_optimal_tools("nmap", available=[])
        assert len(result) == 1

    def test_available_none_returns_all_matching(
        self, graph: ToolCapabilityGraph, nmap: ToolCapability
    ):
        graph.add_tool(nmap)
        result = graph.find_optimal_tools("nmap", available=None)
        assert len(result) == 1


class TestAllTools:
    def test_returns_all_registered_tools(
        self,
        graph: ToolCapabilityGraph,
        nmap: ToolCapability,
        nuclei: ToolCapability,
    ):
        graph.add_tool(nmap)
        graph.add_tool(nuclei)
        tools = graph.all_tools()
        assert len(tools) == 2
        assert nmap in tools
        assert nuclei in tools

    def test_empty_graph(self, graph: ToolCapabilityGraph):
        assert graph.all_tools() == []
