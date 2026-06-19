from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from siyarix.knowledge_graph import KnowledgeGraph, NodeType, EdgeType

def test_knowledge_graph_node_operations():
    kg = KnowledgeGraph()
    n1 = kg.add_node(NodeType.HOST, "192.168.1.1", "host1")
    assert n1.label == "192.168.1.1"
    assert kg.node_count == 1
    
    # Update node
    n2 = kg.add_node(NodeType.HOST, "192.168.1.1", os="Linux")
    assert n2.node_id == n1.node_id
    assert n2.properties.get("os") == "Linux"
    
    assert kg.get_node(n1.node_id) == n1
    assert len(kg.find_nodes(NodeType.HOST)) == 1
    assert len(kg.find_nodes(label_contains="192")) == 1

def test_knowledge_graph_edge_operations():
    kg = KnowledgeGraph()
    n1 = kg.add_node(NodeType.HOST, "10.0.0.1")
    n2 = kg.add_node(NodeType.PORT, "80")
    
    e1 = kg.add_edge(n1.node_id, n2.node_id, EdgeType.HAS_PORT, protocol="tcp")
    assert e1 is not None
    assert kg.edge_count == 1
    
    # duplicate update properties
    e2 = kg.add_edge(n1.node_id, n2.node_id, EdgeType.HAS_PORT, state="open")
    assert e1.edge_id == e2.edge_id
    assert e1.properties.get("state") == "open"

    edges = kg.get_edges(source_id=n1.node_id)
    assert len(edges) == 1

def test_knowledge_graph_remove_node():
    kg = KnowledgeGraph()
    n1 = kg.add_node(NodeType.HOST, "host")
    n2 = kg.add_node(NodeType.PORT, "port")
    kg.add_edge(n1.node_id, n2.node_id, EdgeType.HAS_PORT)
    assert kg.node_count == 2
    assert kg.edge_count == 1
    
    kg.remove_node(n2.node_id)
    assert kg.node_count == 1
    assert kg.edge_count == 0

def test_knowledge_graph_traversal():
    kg = KnowledgeGraph()
    n1 = kg.add_node(NodeType.HOST, "A")
    n2 = kg.add_node(NodeType.HOST, "B")
    n3 = kg.add_node(NodeType.HOST, "C")
    
    kg.add_edge(n1.node_id, n2.node_id, EdgeType.CONNECTS_TO)
    kg.add_edge(n2.node_id, n3.node_id, EdgeType.CONNECTS_TO)
    
    assert len(kg.neighbors(n1.node_id, "out")) == 1
    assert len(kg.neighbors(n2.node_id, "in")) == 1
    
    path = kg.shortest_path(n1.node_id, n3.node_id)
    assert path == [n1.node_id, n2.node_id, n3.node_id]

    no_path = kg.shortest_path(n3.node_id, n1.node_id)
    assert no_path is None

def test_knowledge_graph_ingest_finding():
    kg = KnowledgeGraph()
    finding = {
        "host": "target.com",
        "port": 80,
        "service": "http",
        "title": "CVE-2021-1234",
        "technology": "nginx"
    }
    kg.ingest_finding(finding, "test_tool")
    
    assert kg.node_count == 5  # host, port, service, vuln, tech
    assert kg.edge_count == 4
    
def test_knowledge_graph_serialization(tmp_path: Path):
    kg = KnowledgeGraph()
    n1 = kg.add_node(NodeType.TARGET, "test_target")
    json_data = kg.to_json()
    assert "test_target" in json_data
    
    file_path = tmp_path / "kg.json"
    kg.save_json(file_path)
    
    kg2 = KnowledgeGraph.load_json(file_path)
    assert kg2.node_count == 1
    assert kg2.get_node(n1.node_id).label == "test_target"

def test_knowledge_graph_search():
    kg = KnowledgeGraph()
    kg.add_node(NodeType.TARGET, "alpha")
    kg.add_node(NodeType.HOST, "beta", data="some specific string")
    
    res1 = kg.search("alpha")
    assert len(res1) == 1
    
    res2 = kg.search("specific")
    assert len(res2) == 1

def test_knowledge_graph_stats():
    kg = KnowledgeGraph()
    kg.add_node(NodeType.TARGET, "t1")
    kg.add_node(NodeType.HOST, "h1")
    kg.add_node(NodeType.HOST, "h2")
    stats = kg.stats()
    assert stats["total_nodes"] == 3
    assert stats["nodes_by_type"]["host"] == 2



"""Exhaustive tests for KnowledgeGraph — covering all methods, branches, traversal, and edge cases."""


import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from siyarix.knowledge_graph import (
    Node,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def kg() -> KnowledgeGraph:
    return KnowledgeGraph()


@pytest.fixture
def host_a(kg: KnowledgeGraph) -> Node:
    return kg.add_node(NodeType.HOST, "host-a", "node_a")


@pytest.fixture
def host_b(kg: KnowledgeGraph) -> Node:
    return kg.add_node(NodeType.HOST, "host-b", "node_b")


@pytest.fixture
def port_80(kg: KnowledgeGraph) -> Node:
    return kg.add_node(NodeType.PORT, "host-a:80", "port_80", port=80)


@pytest.fixture
def service_http(kg: KnowledgeGraph) -> Node:
    return kg.add_node(NodeType.SERVICE, "http", "svc_http")


@pytest.fixture
def vuln_cve(kg: KnowledgeGraph) -> Node:
    return kg.add_node(NodeType.VULNERABILITY, "CVE-2024-1234", "vuln_1", severity="high", description="RCE")


# ---------------------------------------------------------------------------
# Node Operations
# ---------------------------------------------------------------------------


class TestNodeOperations:
    def test_add_node(self, kg: KnowledgeGraph):
        node = kg.add_node(NodeType.HOST, "10.0.0.1")
        assert node.node_type == NodeType.HOST
        assert node.label == "10.0.0.1"
        assert node.node_id is not None
        assert node.confidence == 1.0
        assert kg.node_count == 1

    def test_add_node_with_custom_id(self, kg: KnowledgeGraph):
        node = kg.add_node(NodeType.HOST, "custom", node_id="my_id")
        assert node.node_id == "my_id"
        assert kg.get_node("my_id") is node

    def test_add_node_dedup_by_label_and_type(self, kg: KnowledgeGraph):
        n1 = kg.add_node(NodeType.HOST, "server-1", os="linux")
        n2 = kg.add_node(NodeType.HOST, "server-1", os="windows")
        assert n1.node_id == n2.node_id
        assert n1.properties["os"] == "windows"  # merged
        assert kg.node_count == 1

    def test_add_node_different_type_same_label(self, kg: KnowledgeGraph):
        n1 = kg.add_node(NodeType.HOST, "shared-label")
        n2 = kg.add_node(NodeType.TARGET, "shared-label")
        assert n1.node_id != n2.node_id
        assert kg.node_count == 2

    def test_get_node(self, kg: KnowledgeGraph, host_a: Node):
        assert kg.get_node("node_a") is host_a
        assert kg.get_node("nonexistent") is None

    def test_find_nodes_by_type(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_node(NodeType.PORT, "80")
        hosts = kg.find_nodes(node_type=NodeType.HOST)
        assert len(hosts) == 2

    def test_find_nodes_by_label(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        results = kg.find_nodes(label_contains="host")
        assert len(results) == 2

    def test_find_nodes_by_type_and_label(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        results = kg.find_nodes(node_type=NodeType.HOST, label_contains="a")
        assert len(results) == 1
        assert results[0].label == "host-a"

    def test_find_nodes_no_match(self, kg: KnowledgeGraph):
        assert kg.find_nodes(node_type=NodeType.CREDENTIAL) == []

    def test_find_nodes_empty_graph(self, kg: KnowledgeGraph):
        assert kg.find_nodes() == []

    def test_remove_node(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        result = kg.remove_node(port_80.node_id)
        assert result is True
        assert kg.node_count == 1
        assert kg.edge_count == 0

    def test_remove_nonexistent_node(self, kg: KnowledgeGraph):
        assert kg.remove_node("ghost") is False

    def test_remove_node_cleans_adjacency(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(b.node_id, c.node_id, EdgeType.CONNECTS_TO)
        kg.remove_node(b.node_id)
        assert "b" not in kg._adjacency
        assert "b" not in kg._reverse_adj
        for adj in kg._adjacency.values():
            assert "b" not in adj
        for radj in kg._reverse_adj.values():
            assert "b" not in radj

    def test_remove_node_multiple_edges_same_target(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(a.node_id, b.node_id, EdgeType.HAS_PORT)
        kg.remove_node(b.node_id)
        assert kg.edge_count == 0
        assert "b" not in kg._adjacency.get("a", [])


# ---------------------------------------------------------------------------
# Edge Operations
# ---------------------------------------------------------------------------


class TestEdgeOperations:
    def test_add_edge(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        edge = kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        assert edge is not None
        assert edge.source_id == host_a.node_id
        assert edge.target_id == port_80.node_id
        assert edge.edge_type == EdgeType.HAS_PORT
        assert kg.edge_count == 1

    def test_add_edge_missing_source(self, kg: KnowledgeGraph, port_80: Node):
        edge = kg.add_edge("ghost", port_80.node_id, EdgeType.HAS_PORT)
        assert edge is None
        assert kg.edge_count == 0

    def test_add_edge_missing_target(self, kg: KnowledgeGraph, host_a: Node):
        edge = kg.add_edge(host_a.node_id, "ghost", EdgeType.HAS_PORT)
        assert edge is None
        assert kg.edge_count == 0

    def test_add_edge_missing_both(self, kg: KnowledgeGraph):
        edge = kg.add_edge("ghost1", "ghost2", EdgeType.HAS_PORT)
        assert edge is None
        assert kg.edge_count == 0

    def test_add_edge_dedup_updates_properties(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        e1 = kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT, state="open")
        e2 = kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT, state="filtered")
        assert e1.edge_id == e2.edge_id
        assert e1.properties["state"] == "filtered"
        assert kg.edge_count == 1

    def test_add_edge_builds_adjacency(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        assert port_80.node_id in kg._adjacency[host_a.node_id]
        assert host_a.node_id in kg._reverse_adj[port_80.node_id]

    def test_get_edges_by_source(self, kg: KnowledgeGraph, host_a: Node, host_b: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        kg.add_edge(host_b.node_id, port_80.node_id, EdgeType.CONNECTS_TO)
        edges = kg.get_edges(source_id=host_a.node_id)
        assert len(edges) == 1
        assert edges[0].edge_type == EdgeType.HAS_PORT

    def test_get_edges_by_target(self, kg: KnowledgeGraph, host_a: Node, host_b: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        kg.add_edge(host_b.node_id, port_80.node_id, EdgeType.CONNECTS_TO)
        edges = kg.get_edges(target_id=port_80.node_id)
        assert len(edges) == 2

    def test_get_edges_by_type(self, kg: KnowledgeGraph, host_a: Node, port_80: Node, service_http: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        kg.add_edge(port_80.node_id, service_http.node_id, EdgeType.RUNS_SERVICE)
        edges = kg.get_edges(edge_type=EdgeType.HAS_PORT)
        assert len(edges) == 1

    def test_get_edges_all(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        edges = kg.get_edges()
        assert len(edges) == 1

    def test_get_edges_no_match(self, kg: KnowledgeGraph):
        assert kg.get_edges(source_id="nonexistent") == []


# ---------------------------------------------------------------------------
# Traversal — Neighbors
# ---------------------------------------------------------------------------


class TestNeighbors:
    def test_outgoing(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        neighbors = kg.neighbors(host_a.node_id, direction="out")
        assert len(neighbors) == 1
        assert neighbors[0].node_id == port_80.node_id

    def test_incoming(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        neighbors = kg.neighbors(port_80.node_id, direction="in")
        assert len(neighbors) == 1
        assert neighbors[0].node_id == host_a.node_id

    def test_both_directions(self, kg: KnowledgeGraph, host_a: Node, port_80: Node, service_http: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        kg.add_edge(port_80.node_id, service_http.node_id, EdgeType.RUNS_SERVICE)
        neighbors = kg.neighbors(port_80.node_id, direction="both")
        assert len(neighbors) == 2

    def test_no_neighbors(self, kg: KnowledgeGraph, host_a: Node):
        assert kg.neighbors(host_a.node_id) == []

    def test_nonexistent_node(self, kg: KnowledgeGraph):
        assert kg.neighbors("ghost") == []


# ---------------------------------------------------------------------------
# Traversal — Shortest Path (BFS)
# ---------------------------------------------------------------------------


class TestShortestPath:
    def test_simple_path(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.CONNECTS_TO)
        path = kg.shortest_path(host_a.node_id, host_b.node_id)
        assert path == [host_a.node_id, host_b.node_id]

    def test_path_via_intermediate(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(b.node_id, c.node_id, EdgeType.CONNECTS_TO)
        path = kg.shortest_path(a.node_id, c.node_id)
        assert path == ["a", "b", "c"]

    def test_path_start_equals_end(self, kg: KnowledgeGraph, host_a: Node):
        path = kg.shortest_path(host_a.node_id, host_a.node_id)
        assert path == [host_a.node_id]

    def test_no_path(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        # no edge between them
        path = kg.shortest_path(host_a.node_id, host_b.node_id)
        assert path is None

    def test_start_missing(self, kg: KnowledgeGraph, host_b: Node):
        path = kg.shortest_path("ghost", host_b.node_id)
        assert path is None

    def test_end_missing(self, kg: KnowledgeGraph, host_a: Node):
        path = kg.shortest_path(host_a.node_id, "ghost")
        assert path is None

    def test_both_missing(self, kg: KnowledgeGraph):
        path = kg.shortest_path("ghost1", "ghost2")
        assert path is None

    def test_disconnected_graph(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        # c is disconnected
        path = kg.shortest_path(a.node_id, c.node_id)
        assert path is None

    def test_cycle_doesnt_break_bfs(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(b.node_id, a.node_id, EdgeType.CONNECTS_TO)  # cycle
        kg.add_edge(b.node_id, c.node_id, EdgeType.CONNECTS_TO)
        path = kg.shortest_path(a.node_id, c.node_id)
        assert path == ["a", "b", "c"]

    def test_empty_graph(self, kg: KnowledgeGraph):
        assert kg.shortest_path("a", "b") is None


# ---------------------------------------------------------------------------
# Traversal — _get_edge_weight
# ---------------------------------------------------------------------------


class TestGetEdgeWeight:
    def test_no_edge_infinity(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        weight = kg._get_edge_weight(host_a.node_id, host_b.node_id)
        assert weight == float("inf")

    def test_has_vuln_critical(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-critical", "v", severity="critical")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 1.0

    def test_has_vuln_high(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-high", "v", severity="high")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 3.0

    def test_has_vuln_medium(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-med", "v", severity="medium")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 5.0

    def test_has_vuln_low(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-low", "v", severity="low")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 10.0

    def test_has_vuln_unknown_severity(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-unk", "v", severity="unknown")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 10.0

    def test_has_vuln_no_severity(self, kg: KnowledgeGraph, host_a: Node):
        vuln = kg.add_node(NodeType.VULNERABILITY, "CVE-nosev", "v")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        weight = kg._get_edge_weight(host_a.node_id, vuln.node_id)
        assert weight == 10.0

    def test_authenticated_by(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.AUTHENTICATED_BY)
        weight = kg._get_edge_weight(host_a.node_id, host_b.node_id)
        assert weight == 2.0

    def test_has_port_or_runs_service(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        weight = kg._get_edge_weight(host_a.node_id, port_80.node_id)
        assert weight == 0.5

    def test_runs_service(self, kg: KnowledgeGraph, port_80: Node, service_http: Node):
        kg.add_edge(port_80.node_id, service_http.node_id, EdgeType.RUNS_SERVICE)
        weight = kg._get_edge_weight(port_80.node_id, service_http.node_id)
        assert weight == 0.5

    def test_default_weight(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.CONNECTS_TO)
        weight = kg._get_edge_weight(host_a.node_id, host_b.node_id)
        assert weight == 10.0

    def test_min_of_multiple_edges(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.CONNECTS_TO)  # 10.0
        vuln = kg.add_node(NodeType.VULNERABILITY, "crit", "vc", severity="critical")
        kg.add_edge(host_a.node_id, vuln.node_id, EdgeType.HAS_VULN)
        # Actually test multiple edges between same nodes
        # We can't directly add two edges between same nodes with different types
        # because they have different edge_types. Let's test real scenario:
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.AUTHENTICATED_BY)  # 2.0
        weight = kg._get_edge_weight(host_a.node_id, host_b.node_id)
        assert weight == 2.0


# ---------------------------------------------------------------------------
# Traversal — easiest_attack_path (Dijkstra)
# ---------------------------------------------------------------------------


class TestEasiestAttackPath:
    def test_simple_path(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        path = kg.easiest_attack_path("a", "b")
        assert path == ["a", "b"]

    def test_start_equals_end(self, kg: KnowledgeGraph, host_a: Node):
        path = kg.easiest_attack_path(host_a.node_id, host_a.node_id)
        assert path == [host_a.node_id]

    def test_start_missing(self, kg: KnowledgeGraph, host_b: Node):
        path = kg.easiest_attack_path("ghost", host_b.node_id)
        assert path is None

    def test_end_missing(self, kg: KnowledgeGraph, host_a: Node):
        path = kg.easiest_attack_path(host_a.node_id, "ghost")
        assert path is None

    def test_no_path(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        path = kg.easiest_attack_path("a", "b")
        assert path is None

    def test_prefers_lower_cost(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)  # cost 10
        kg.add_edge(a.node_id, c.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        kg.add_edge(c.node_id, b.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        path = kg.easiest_attack_path("a", "b")
        # Should take a -> c -> b (total 4) rather than a -> b (10)
        assert path == ["a", "c", "b"]

    def test_visited_skipped(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        d = kg.add_node(NodeType.HOST, "D", "d")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(a.node_id, c.node_id, EdgeType.AUTHENTICATED_BY)
        kg.add_edge(b.node_id, d.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(c.node_id, d.node_id, EdgeType.AUTHENTICATED_BY)
        path = kg.easiest_attack_path("a", "d")
        # Should find at least one path
        assert path is not None
        assert path[0] == "a"
        assert path[-1] == "d"

    def test_empty_graph(self, kg: KnowledgeGraph):
        assert kg.easiest_attack_path("a", "b") is None


# ---------------------------------------------------------------------------
# Traversal — blast_radius
# ---------------------------------------------------------------------------


class TestBlastRadius:
    def test_direct_neighbor_within_cost(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        radius = kg.blast_radius("a", max_cost=5.0)
        assert "b" in radius
        assert "a" in radius

    def test_beyond_cost(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)  # cost 10
        radius = kg.blast_radius("a", max_cost=5.0)
        assert "b" not in radius

    def test_start_not_in_graph(self, kg: KnowledgeGraph):
        radius = kg.blast_radius("ghost")
        assert radius == []

    def test_no_edges(self, kg: KnowledgeGraph, host_a: Node):
        radius = kg.blast_radius(host_a.node_id)
        assert radius == [host_a.node_id]

    def test_multi_hop_radius(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        kg.add_edge(b.node_id, c.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        radius = kg.blast_radius("a", max_cost=5.0)
        assert "b" in radius
        assert "c" in radius

    def test_insufficient_cost_for_far(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        c = kg.add_node(NodeType.HOST, "C", "c")
        kg.add_edge(a.node_id, b.node_id, EdgeType.AUTHENTICATED_BY)  # cost 2
        kg.add_edge(b.node_id, c.node_id, EdgeType.CONNECTS_TO)  # cost 10
        radius = kg.blast_radius("a", max_cost=5.0)
        assert "b" in radius
        assert "c" not in radius

    def test_cycle_doesnt_infinite_loop(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.AUTHENTICATED_BY)
        kg.add_edge(b.node_id, a.node_id, EdgeType.AUTHENTICATED_BY)
        radius = kg.blast_radius("a", max_cost=10.0)
        assert "a" in radius
        assert "b" in radius


# ---------------------------------------------------------------------------
# crown_jewel_paths
# ---------------------------------------------------------------------------


class TestCrownJewelPaths:
    def test_finds_crown_jewel(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b", crown_jewel=True)
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        paths = kg.find_crown_jewel_paths("a")
        assert b.node_id in paths
        assert paths[b.node_id] == ["a", "b"]

    def test_no_crown_jewels(self, kg: KnowledgeGraph, host_a: Node, host_b: Node):
        kg.add_edge(host_a.node_id, host_b.node_id, EdgeType.CONNECTS_TO)
        paths = kg.find_crown_jewel_paths(host_a.node_id)
        assert paths == {}

    def test_crown_jewel_is_start(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a", crown_jewel=True)
        paths = kg.find_crown_jewel_paths("a")
        assert paths == {}

    def test_multiple_crown_jewels(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b", crown_jewel=True)
        c = kg.add_node(NodeType.HOST, "C", "c", crown_jewel=True)
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(a.node_id, c.node_id, EdgeType.CONNECTS_TO)
        paths = kg.find_crown_jewel_paths("a")
        assert len(paths) == 2

    def test_crown_jewel_unreachable(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b", crown_jewel=True)
        # no edge
        paths = kg.find_crown_jewel_paths("a")
        assert paths == {}


# ---------------------------------------------------------------------------
# Subgraph
# ---------------------------------------------------------------------------


class TestSubgraph:
    def test_subgraph_contains_matching_edges(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        p = kg.add_node(NodeType.PORT, "80", "p")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        kg.add_edge(a.node_id, p.node_id, EdgeType.HAS_PORT)
        sub = kg.subgraph(NodeType.PORT)
        assert len(sub) == 1
        assert sub[0]["type"] == EdgeType.HAS_PORT.value

    def test_subgraph_no_match(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        sub = kg.subgraph(NodeType.CREDENTIAL)
        assert sub == []

    def test_subgraph_all_edges_when_type_in_both(self, kg: KnowledgeGraph):
        a = kg.add_node(NodeType.HOST, "A", "a")
        b = kg.add_node(NodeType.HOST, "B", "b")
        kg.add_edge(a.node_id, b.node_id, EdgeType.CONNECTS_TO)
        sub = kg.subgraph(NodeType.HOST)
        assert len(sub) == 1


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------


class TestPrune:
    def test_prune_old_nodes(self, kg: KnowledgeGraph):
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        node = kg.add_node(NodeType.HOST, "old-host", "old", discovered_by="test")
        kg._nodes["old"].discovered_at = old_time

        new_node = kg.add_node(NodeType.HOST, "new-host", "new")
        # relationship between old and new
        kg.add_edge("old", "new", EdgeType.CONNECTS_TO)

        count = kg.prune(ttl_seconds=86400 * 30)  # 30 days
        assert count == 1
        assert kg.get_node("old") is None
        assert kg.get_node("new") is not None
        assert kg.edge_count == 0

    def test_prune_invalid_date_skipped(self, kg: KnowledgeGraph):
        node = kg.add_node(NodeType.HOST, "bad-date", "bad")
        kg._nodes["bad"].discovered_at = "not-a-date"
        count = kg.prune(ttl_seconds=1)
        assert count == 0

    def test_prune_no_old_nodes(self, kg: KnowledgeGraph, host_a: Node):
        count = kg.prune(ttl_seconds=86400 * 30)
        assert count == 0

    def test_prune_empty_graph(self, kg: KnowledgeGraph):
        assert kg.prune() == 0


# ---------------------------------------------------------------------------
# Ingest Finding
# ---------------------------------------------------------------------------


class TestIngestFinding:
    def test_ingest_minimal(self, kg: KnowledgeGraph):
        kg.ingest_finding({"target": "10.0.0.1"}, tool="scanner")
        hosts = kg.find_nodes(node_type=NodeType.HOST)
        assert len(hosts) == 1
        assert hosts[0].label == "10.0.0.1"

    def test_ingest_with_host_fallback(self, kg: KnowledgeGraph):
        kg.ingest_finding({"host": "target.com"})
        hosts = kg.find_nodes(node_type=NodeType.HOST)
        assert len(hosts) == 1
        assert hosts[0].label == "target.com"

    def test_ingest_with_port_and_service(self, kg: KnowledgeGraph):
        kg.ingest_finding({
            "target": "server", "port": 443, "service": "https"
        })
        ports = kg.find_nodes(node_type=NodeType.PORT)
        assert len(ports) == 1
        services = kg.find_nodes(node_type=NodeType.SERVICE)
        assert len(services) == 1
        assert kg.edge_count == 2  # HAS_PORT + RUNS_SERVICE

    def test_ingest_with_vuln(self, kg: KnowledgeGraph):
        kg.ingest_finding({
            "target": "server", "title": "CVE-2024-5678",
            "severity": "critical", "description": "RCE vulnerability",
        })
        vulns = kg.find_nodes(node_type=NodeType.VULNERABILITY)
        assert len(vulns) == 1
        assert vulns[0].label == "CVE-2024-5678"

    def test_ingest_with_vulnerability_field(self, kg: KnowledgeGraph):
        kg.ingest_finding({
            "target": "server", "vulnerability": "SQL Injection"
        })
        vulns = kg.find_nodes(node_type=NodeType.VULNERABILITY)
        assert len(vulns) == 1
        assert vulns[0].label == "SQL Injection"

    def test_ingest_with_technology(self, kg: KnowledgeGraph):
        kg.ingest_finding({
            "target": "server", "technology": "nginx"
        })
        techs = kg.find_nodes(node_type=NodeType.TECHNOLOGY)
        assert len(techs) == 1
        assert techs[0].label == "nginx"

    def test_ingest_full_finding(self, kg: KnowledgeGraph):
        kg.ingest_finding({
            "target": "web.example.com",
            "port": 80,
            "service": "http",
            "title": "CVE-2024-0001",
            "severity": "high",
            "description": "Buffer overflow",
            "technology": "apache",
        }, tool="nuclei")
        assert kg.node_count == 5
        assert kg.edge_count == 4

    def test_ingest_empty_finding(self, kg: KnowledgeGraph):
        kg.ingest_finding({})
        assert kg.node_count == 0

    def test_ingest_dedup_same_host(self, kg: KnowledgeGraph):
        kg.ingest_finding({"target": "server", "port": 80}, tool="a")
        kg.ingest_finding({"target": "server", "port": 443}, tool="b")
        hosts = kg.find_nodes(node_type=NodeType.HOST)
        assert len(hosts) == 1
        ports = kg.find_nodes(node_type=NodeType.PORT)
        assert len(ports) == 2


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_by_label(self, kg: KnowledgeGraph):
        kg.add_node(NodeType.HOST, "target-server", "t1")
        kg.add_node(NodeType.PORT, "80", "p1")
        results = kg.search("target")
        assert len(results) == 1
        assert "target-server" in results[0]

    def test_search_by_property(self, kg: KnowledgeGraph):
        kg.add_node(NodeType.HOST, "server", "s1", os="linux-ubuntu")
        results = kg.search("ubuntu")
        assert len(results) == 1
        assert "[host] server" in results[0]

    def test_search_limited(self, kg: KnowledgeGraph):
        for i in range(20):
            kg.add_node(NodeType.HOST, f"node-{i}", f"n{i}")
        results = kg.search("node", limit=5)
        assert len(results) == 5

    def test_search_no_match(self, kg: KnowledgeGraph):
        kg.add_node(NodeType.HOST, "server")
        assert kg.search("nonexistent") == []

    def test_search_empty_graph(self, kg: KnowledgeGraph):
        assert kg.search("anything") == []

    def test_search_property_after_label_exhausted(self, kg: KnowledgeGraph):
        kg.add_node(NodeType.HOST, "alpha", "a1", data="secret-value")
        kg.add_node(NodeType.HOST, "beta", "b1")
        results = kg.search("secret")
        assert len(results) == 1
        assert "alpha" in results[0]


# ---------------------------------------------------------------------------
# Persistence — to_json / save_json / load_json
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_to_json(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        data = json.loads(kg.to_json())
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

    def test_to_json_empty(self, kg: KnowledgeGraph):
        data = json.loads(kg.to_json())
        assert data == {"nodes": [], "edges": []}

    def test_save_and_load_json(self, kg: KnowledgeGraph, host_a: Node, tmp_path: Path):
        kg.add_node(NodeType.PORT, "443", discovered_by="test")
        file_path = tmp_path / "graph.json"
        kg.save_json(file_path)
        assert file_path.exists()
        loaded = KnowledgeGraph.load_json(file_path)
        assert loaded.node_count == 2
        assert loaded.get_node(host_a.node_id) is not None

    def test_load_json_creates_dirs(self, kg: KnowledgeGraph, tmp_path: Path):
        nested = tmp_path / "sub" / "dir" / "graph.json"
        kg.add_node(NodeType.HOST, "test")
        kg.save_json(nested)
        assert nested.exists()

    def test_load_json_nonexistent_path(self):
        kg = KnowledgeGraph.load_json(Path("/nonexistent/path.json"))
        assert kg.node_count == 0

    def test_load_json_with_edges(self, kg: KnowledgeGraph, host_a: Node, port_80: Node, tmp_path: Path):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT, protocol="tcp")
        file_path = tmp_path / "graph.json"
        kg.save_json(file_path)
        loaded = KnowledgeGraph.load_json(file_path)
        assert loaded.edge_count == 1
        edges = loaded.get_edges()
        assert edges[0].properties.get("protocol") == "tcp"
        assert loaded.get_node(port_80.node_id) is not None

    def test_save_json_logs(self, kg: KnowledgeGraph, host_a: Node, tmp_path: Path):
        with patch("siyarix.knowledge_graph.logger") as mock_logger:
            kg.save_json(tmp_path / "log_test.json")
            mock_logger.info.assert_called_once()


# ---------------------------------------------------------------------------
# Properties — nodes, node_count, edge_count
# ---------------------------------------------------------------------------


class TestProperties:
    def test_nodes_property(self, kg: KnowledgeGraph, host_a: Node):
        assert kg.nodes == kg._nodes

    def test_node_count(self, kg: KnowledgeGraph, host_a: Node):
        assert kg.node_count == 1

    def test_edge_count(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT)
        assert kg.edge_count == 1

    def test_empty_counts(self, kg: KnowledgeGraph):
        assert kg.node_count == 0
        assert kg.edge_count == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_empty_stats(self, kg: KnowledgeGraph):
        stats = kg.stats()
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0
        assert stats["nodes_by_type"] == {}
        assert stats["edges_by_type"] == {}

    def test_stats_with_data(self, kg: KnowledgeGraph):
        kg.add_node(NodeType.HOST, "h1")
        kg.add_node(NodeType.HOST, "h2")
        kg.add_node(NodeType.PORT, "80")
        a = kg.add_node(NodeType.HOST, "a", "a_id")
        p = kg.add_node(NodeType.PORT, "443", "p_id")
        kg.add_edge(a.node_id, p.node_id, EdgeType.HAS_PORT)
        stats = kg.stats()
        assert stats["total_nodes"] == 5
        assert stats["total_edges"] == 1
        assert stats["nodes_by_type"]["host"] == 3
        assert stats["nodes_by_type"]["port"] == 2
        assert stats["edges_by_type"]["has_port"] == 1


# ---------------------------------------------------------------------------
# Node / Edge dataclass to_dict
# ---------------------------------------------------------------------------


class TestNodeToDict:
    def test_node_to_dict(self, host_a: Node):
        d = host_a.to_dict()
        assert d["node_id"] == "node_a"
        assert d["type"] == "host"
        assert d["label"] == "host-a"
        assert "discovered_at" in d
        assert "confidence" in d

    def test_node_to_dict_all_fields(self):
        node = Node(
            node_id="test_id",
            node_type=NodeType.VULNERABILITY,
            label="CVE-1234",
            properties={"severity": "high"},
            discovered_by="nmap",
            confidence=0.95,
        )
        d = node.to_dict()
        assert d["node_id"] == "test_id"
        assert d["type"] == "vulnerability"
        assert d["label"] == "CVE-1234"
        assert d["properties"] == {"severity": "high"}
        assert d["discovered_by"] == "nmap"
        assert d["confidence"] == 0.95


class TestEdgeToDict:
    def test_edge_to_dict(self, kg: KnowledgeGraph, host_a: Node, port_80: Node):
        edge = kg.add_edge(host_a.node_id, port_80.node_id, EdgeType.HAS_PORT, state="open")
        d = edge.to_dict()
        assert d["source"] == host_a.node_id
        assert d["target"] == port_80.node_id
        assert d["type"] == "has_port"
        assert d["properties"] == {"state": "open"}
        assert "edge_id" in d