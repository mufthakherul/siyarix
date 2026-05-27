"""Tests for siyarix.security.attack_path — attack path analysis."""

from __future__ import annotations


import pytest

from siyarix.knowledge_graph import EdgeType, KnowledgeGraph, NodeType
from siyarix.security.attack_path import AttackPath, AttackPathAnalyzer


@pytest.fixture
def graph() -> KnowledgeGraph:
    return KnowledgeGraph()


class TestAttackPathDataclass:
    def test_attributes(self) -> None:
        path = AttackPath(
            origin_id="o1",
            target_id="t1",
            path_nodes=["o1", "m1", "t1"],
            severity="high",
            description="test path",
        )
        assert path.origin_id == "o1"
        assert path.target_id == "t1"
        assert path.path_nodes == ["o1", "m1", "t1"]
        assert path.severity == "high"
        assert path.description == "test path"


class TestAttackPathAnalyzer:
    def test_no_vulnerabilities_returns_empty(self, graph: KnowledgeGraph) -> None:
        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert paths == []

    def test_no_entry_nodes_returns_empty(self, graph: KnowledgeGraph) -> None:
        graph.add_node(NodeType.VULNERABILITY, "CVE-1234", severity="high")
        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert paths == []

    def test_path_from_entry_to_vuln(self, graph: KnowledgeGraph) -> None:
        _web = graph.add_node(NodeType.HOST, "web.example.com")
        _host = graph.add_node(NodeType.HOST, "example.com")
        _vuln = graph.add_node(NodeType.VULNERABILITY, "CVE-2024-0001", severity="critical")
        graph.add_edge(_web.node_id, _host.node_id, EdgeType.CONNECTS_TO)
        graph.add_edge(_host.node_id, _vuln.node_id, EdgeType.HAS_VULN)

        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert len(paths) >= 1
        assert paths[0].severity == "critical"
        assert any("web.example.com" in p.description for p in paths)

    def test_path_across_multiple_nodes(self, graph: KnowledgeGraph) -> None:
        _host = graph.add_node(NodeType.HOST, "target.com")
        port = graph.add_node(NodeType.PORT, "target.com:80", port=80)
        _host = graph.add_node(NodeType.HOST, "target.com")
        _vuln = graph.add_node(NodeType.VULNERABILITY, "CVE-2024-0002", severity="medium")
        graph.add_edge(_host.node_id, port.node_id, EdgeType.HAS_PORT)
        graph.add_edge(port.node_id, _vuln.node_id, EdgeType.HAS_VULN)

        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert len(paths) == 1
        assert len(paths[0].path_nodes) > 1

    def test_multiple_entry_nodes(self, graph: KnowledgeGraph) -> None:
        dom = graph.add_node(NodeType.DOMAIN, "example.com")
        sub = graph.add_node(NodeType.SUBDOMAIN, "sub.example.com")
        _vuln = graph.add_node(NodeType.VULNERABILITY, "CVE-2024-0003")
        graph.add_edge(dom.node_id, _vuln.node_id, EdgeType.HAS_VULN)
        graph.add_edge(sub.node_id, _vuln.node_id, EdgeType.HAS_VULN)

        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert len(paths) == 2

    def test_credential_reuse_path(self, graph: KnowledgeGraph) -> None:
        cred = graph.add_node(NodeType.CREDENTIAL, "admin_cred")
        svc1 = graph.add_node(NodeType.SERVICE, "ssh")
        svc2 = graph.add_node(NodeType.SERVICE, "mysql")
        graph.add_edge(cred.node_id, svc1.node_id, EdgeType.AUTHENTICATED_BY)
        graph.add_edge(cred.node_id, svc2.node_id, EdgeType.AUTHENTICATED_BY)

        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert len(paths) == 1
        assert "Lateral movement" in paths[0].description
        assert paths[0].severity == "high"

    def test_credential_single_service_no_lateral(self, graph: KnowledgeGraph) -> None:
        cred = graph.add_node(NodeType.CREDENTIAL, "single_cred")
        svc = graph.add_node(NodeType.SERVICE, "ssh")
        graph.add_edge(cred.node_id, svc.node_id, EdgeType.AUTHENTICATED_BY)

        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert paths == []

    def test_path_with_no_connection(self, graph: KnowledgeGraph) -> None:
        _host = graph.add_node(NodeType.HOST, "isolated.com")
        _vuln = graph.add_node(NodeType.VULNERABILITY, "CVE-2024-0004")
        analyzer = AttackPathAnalyzer(graph)
        paths = analyzer.find_all_paths()
        assert paths == []

    def test_generate_report_empty(self, graph: KnowledgeGraph) -> None:
        analyzer = AttackPathAnalyzer(graph)
        report = analyzer.generate_report()
        assert report["total_paths"] == 0
        assert report["high_severity_paths"] == 0
        assert report["paths"] == []

    def test_generate_report_with_paths(self, graph: KnowledgeGraph) -> None:
        _host = graph.add_node(NodeType.HOST, "server.com")
        _vuln = graph.add_node(NodeType.VULNERABILITY, "CVE-2024-0005", severity="high")
        graph.add_edge(_host.node_id, _vuln.node_id, EdgeType.HAS_VULN)

        analyzer = AttackPathAnalyzer(graph)
        report = analyzer.generate_report()
        assert report["total_paths"] == 1
        assert report["high_severity_paths"] == 1
        assert report["paths"][0]["origin"] == "server.com"
        assert report["paths"][0]["severity"] == "high"
