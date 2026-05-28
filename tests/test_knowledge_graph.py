# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for knowledge_graph.py — KnowledgeGraph (229 stmts, ~58% covered)."""

from __future__ import annotations

import json

import pytest

from siyarix.knowledge_graph import (
    Edge,
    EdgeType,
    KnowledgeGraph,
    Node,
    NodeType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def kg():
    return KnowledgeGraph()


# ---------------------------------------------------------------------------
# Node dataclass
# ---------------------------------------------------------------------------

class TestNode:
    def test_to_dict(self):
        node = Node(node_id="_n1", node_type=NodeType.HOST, label="10.0.0.1",
                     properties={"os": "linux"}, discovered_by="nmap",
                     confidence=0.95)
        d = node.to_dict()
        assert d["node_id"] == "_n1"
        assert d["type"] == "host"
        assert d["label"] == "10.0.0.1"
        assert d["properties"]["os"] == "linux"
        assert d["discovered_by"] == "nmap"


# ---------------------------------------------------------------------------
# Edge dataclass
# ---------------------------------------------------------------------------

class TestEdge:
    def test_to_dict(self):
        edge = Edge(source_id="_n1", target_id="_n2", edge_type=EdgeType.HAS_PORT,
                     properties={"port": 80})
        d = edge.to_dict()
        assert d["source"] == "_n1"
        assert d["target"] == "_n2"
        assert d["type"] == "has_port"


# ---------------------------------------------------------------------------
# Node operations
# ---------------------------------------------------------------------------

class TestNodeOps:
    def test_add_node(self, kg):
        node = kg.add_node(NodeType.HOST, "10.0.0.1", discovered_by="nmap",
                            os="linux", arch="x64")
        assert node.label == "10.0.0.1"
        assert node.node_type == NodeType.HOST
        assert node.properties["os"] == "linux"
        assert kg.node_count == 1

    def test_add_node_dedup(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "10.0.0.1")
        _n2 = kg.add_node(NodeType.HOST, "10.0.0.1", extra="merged")
        assert _n1 is _n2
        assert _n2.properties["extra"] == "merged"
        assert kg.node_count == 1

    def test_add_node_custom_id(self, kg):
        node = kg.add_node(NodeType.HOST, "myhost", node_id="custom_1")
        assert node.node_id == "custom_1"

    def test_get_node(self, kg):
        node = kg.add_node(NodeType.HOST, "10.0.0.1")
        assert kg.get_node(node.node_id) == node
        assert kg.get_node("nonexistent") is None

    def test_find_nodes_by_type(self, kg):
        kg.add_node(NodeType.HOST, "10.0.0.1")
        kg.add_node(NodeType.HOST, "10.0.0.2")
        kg.add_node(NodeType.VULNERABILITY, "CVE-2023-1234")
        hosts = kg.find_nodes(NodeType.HOST)
        assert len(hosts) == 2

    def test_find_nodes_by_label(self, kg):
        kg.add_node(NodeType.HOST, "10.0.0.1")
        kg.add_node(NodeType.HOST, "192.168.1.1")
        results = kg.find_nodes(NodeType.HOST, label_contains="192")
        assert len(results) == 1

    def test_find_nodes_no_filter(self, kg):
        kg.add_node(NodeType.HOST, "_h1")
        kg.add_node(NodeType.PORT, "_p1")
        assert len(kg.find_nodes()) == 2

    def test_remove_node(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "to_remove")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.HOST, "other")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.CONNECTS_TO)
        assert kg.remove_node(_n1.node_id) is True
        assert kg.get_node(_n1.node_id) is None
        assert kg.edge_count == 0

    def test_remove_nonexistent(self, kg):
        assert kg.remove_node("ghost") is False

    def test_node_count_property(self, kg):
        assert kg.node_count == 0
        kg.add_node(NodeType.HOST, "a")
        assert kg.node_count == 1


# ---------------------------------------------------------------------------
# Edge operations
# ---------------------------------------------------------------------------

class TestEdgeOps:
    def test_add_edge(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "host1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "host1:80")
        edge = kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        assert edge is not None
        assert edge.edge_type == EdgeType.HAS_PORT
        assert kg.edge_count == 1

    def test_add_edge_missing_nodes(self, kg):
        edge = kg.add_edge("ghost", "ghost2", EdgeType.HAS_PORT)
        assert edge is None

    def test_add_edge_dedup(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "_h1:80")
        e1 = kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        e2 = kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT, extra="prop")
        assert e1 is e2
        assert e2.properties["extra"] == "prop"
        assert kg.edge_count == 1

    def test_get_edges(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n2 = kg.add_node(NodeType.PORT, "_p1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.HOST, "b", node_id="b")
        _n3 = kg.add_node(NodeType.PORT, "p2")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        kg.add_edge(_n1.node_id, _n3.node_id, EdgeType.HAS_PORT)
        assert len(kg.get_edges(source_id=_n1.node_id)) == 2
        assert len(kg.get_edges(edge_type=EdgeType.HAS_PORT)) == 2

    def test_get_edges_by_target(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "_p1")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        assert len(kg.get_edges(target_id=_n2.node_id)) == 1

    def test_edge_count_property(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "a")
        _n2 = kg.add_node(NodeType.PORT, "b")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.HOST, "b", node_id="b")
        assert kg.edge_count == 0
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        assert kg.edge_count == 1


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------

class TestTraversal:
    def test_neighbors_out(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "_p1")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        neighbors = kg.neighbors(_n1.node_id, direction="out")
        assert len(neighbors) == 1
        assert neighbors[0].node_id == _n2.node_id

    def test_neighbors_in(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "_p1")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        neighbors = kg.neighbors(_n2.node_id, direction="in")
        assert len(neighbors) == 1

    def test_neighbors_both(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "_h1")
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "_p1")
        kg.add_edge(_n1.node_id, _n2.node_id, EdgeType.HAS_PORT)
        neighbors = kg.neighbors(_n2.node_id, direction="both")
        assert len(neighbors) == 1

    def test_neighbors_empty(self, kg):
        assert kg.neighbors("ghost") == []

    def test_shortest_path(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.HOST, "b", node_id="b")
        _n3 = kg.add_node(NodeType.HOST, "c", node_id="c")
        kg.add_edge("a", "b", EdgeType.CONNECTS_TO)
        kg.add_edge("b", "c", EdgeType.CONNECTS_TO)
        path = kg.shortest_path("a", "c")
        assert path == ["a", "b", "c"]

    def test_shortest_path_same_node(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        path = kg.shortest_path("a", "a")
        assert path == ["a"]

    def test_shortest_path_no_path(self, kg):
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.HOST, "b", node_id="b")
        path = kg.shortest_path("a", "b")
        assert path is None

    def test_shortest_path_missing_nodes(self, kg):
        assert kg.shortest_path("ghost", "ghost2") is None


# ---------------------------------------------------------------------------
# subgraph
# ---------------------------------------------------------------------------

class TestSubgraph:
    def test_subgraph(self, kg):
        _h1 = kg.add_node(NodeType.HOST, "_h1", node_id="_h1")
        _p1 = kg.add_node(NodeType.PORT, "_p1", node_id="_p1")
        _v1 = kg.add_node(NodeType.VULNERABILITY, "_v1", node_id="_v1")
        kg.add_edge("_h1", "_p1", EdgeType.HAS_PORT)
        kg.add_edge("_h1", "_v1", EdgeType.HAS_VULN)
        sub = kg.subgraph(NodeType.VULNERABILITY)
        assert len(sub) >= 1


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_empty(self, kg):
        s = kg.stats()
        assert s["total_nodes"] == 0
        assert s["total_edges"] == 0

    def test_stats_with_data(self, kg):
        _h1 = kg.add_node(NodeType.HOST, "_h1")
        _h1 = kg.add_node(NodeType.HOST, "_h1", node_id="_h1")
        _p1 = kg.add_node(NodeType.PORT, "_p1")
        kg.add_edge(_h1.node_id, _p1.node_id, EdgeType.HAS_PORT)
        s = kg.stats()
        assert s["total_nodes"] == 2
        assert s["total_edges"] == 1
        assert s["nodes_by_type"]["host"] == 1
        assert s["nodes_by_type"]["port"] == 1


# ---------------------------------------------------------------------------
# ingest_finding
# ---------------------------------------------------------------------------

class TestIngestFinding:
    def test_ingest_basic(self, kg):
        finding = {"target": "10.0.0.1", "port": 80, "service": "http",
                    "severity": "high", "tool": "nmap"}
        kg.ingest_finding(finding, tool="nmap")
        assert kg.node_count >= 3  # host + port + service
        assert kg.edge_count >= 2

    def test_ingest_with_vuln(self, kg):
        finding = {"target": "10.0.0.1", "port": 80, "title": "CVE-2023-1234",
                    "severity": "critical", "description": "RCE via ...", "tool": "nuclei"}
        kg.ingest_finding(finding, tool="nuclei")
        vulns = kg.find_nodes(NodeType.VULNERABILITY)
        assert len(vulns) >= 1
        assert vulns[0].label == "CVE-2023-1234"

    def test_ingest_with_technology(self, kg):
        finding = {"target": "10.0.0.1", "technology": "nginx"}
        kg.ingest_finding(finding, tool="wappalyzer")
        techs = kg.find_nodes(NodeType.TECHNOLOGY)
        assert len(techs) >= 1

    def test_ingest_no_target(self, kg):
        finding = {"port": 80}
        kg.ingest_finding(finding, tool="test")
        assert kg.node_count == 0


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

class TestSearch:
    def test_search_label(self, kg):
        kg.add_node(NodeType.HOST, "192.168.1.1")
        kg.add_node(NodeType.HOST, "10.0.0.1")
        results = kg.search("192")
        assert len(results) == 1
        assert "192.168.1.1" in results[0]

    def test_search_property(self, kg):
        kg.add_node(NodeType.HOST, "example.com", server="nginx")
        results = kg.search("nginx")
        assert len(results) >= 1

    def test_search_limit(self, kg):
        for i in range(20):
            kg.add_node(NodeType.HOST, f"host-{i}")
        results = kg.search("host", limit=5)
        assert len(results) <= 5

    def test_search_no_match(self, kg):
        kg.add_node(NodeType.HOST, "unique")
        assert kg.search("nonexistent") == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_to_json(self, kg):
        kg.add_node(NodeType.HOST, "10.0.0.1")
        data = kg.to_json()
        parsed = json.loads(data)
        assert "nodes" in parsed
        assert "edges" in parsed

    def test_save_and_load(self, kg, tmp_path):
        kg.add_node(NodeType.HOST, "persist-test")
        p = tmp_path / "graph.json"
        kg.save(p)
        assert p.exists()

        loaded = KnowledgeGraph.load(p)
        assert loaded.node_count == 1
        assert loaded.find_nodes(NodeType.HOST)[0].label == "persist-test"

    def test_load_nonexistent(self, tmp_path):
        kg = KnowledgeGraph.load(tmp_path / "nope.json")
        assert kg.node_count == 0

    def test_load_with_edges(self, kg, tmp_path):
        _n1 = kg.add_node(NodeType.HOST, "a", node_id="a")
        _n2 = kg.add_node(NodeType.PORT, "p", node_id="p")
        kg.add_edge("a", "p", EdgeType.HAS_PORT)
        p = tmp_path / "graph.json"
        kg.save(p)
        loaded = KnowledgeGraph.load(p)
        assert loaded.edge_count == 1
        assert loaded.edge_count == 1
