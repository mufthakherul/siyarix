# SPDX-License-Identifier: AGPL-3.0-or-later

import json
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
