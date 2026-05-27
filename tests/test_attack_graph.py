from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from rich.console import Console

from siyarix.knowledge_graph import KnowledgeGraph, Node, NodeType
from siyarix.visualizations.attack_graph import AttackGraphVisualizer


@pytest.fixture
def graph() -> MagicMock:
    return MagicMock(spec=KnowledgeGraph)


@pytest.fixture
def viz() -> AttackGraphVisualizer:
    return AttackGraphVisualizer()


@pytest.fixture
def viz_with_console() -> tuple[AttackGraphVisualizer, MagicMock]:
    c = MagicMock(spec=Console)
    return AttackGraphVisualizer(console=c), c


def make_node(node_id: str, node_type: NodeType, label: str, properties: dict | None = None) -> Node:
    return Node(node_id=node_id, node_type=node_type, label=label, properties=properties or {})


class TestAttackGraphVisualizer:
    def test_init_default_console(self) -> None:
        v = AttackGraphVisualizer()
        assert isinstance(v.console, Console)

    def test_init_custom_console(self) -> None:
        c = Console()
        v = AttackGraphVisualizer(console=c)
        assert v.console is c

    @pytest.mark.parametrize("node_type,expected_color", [
        (NodeType.HOST, "cyan"),
        (NodeType.PORT, "blue"),
        (NodeType.SERVICE, "magenta"),
        (NodeType.VULNERABILITY, "red"),
        (NodeType.TECHNOLOGY, "yellow"),
        (NodeType.TARGET, "white"),
        (NodeType.DOMAIN, "white"),
    ])
    def test_get_node_color(self, viz: AttackGraphVisualizer, node_type: NodeType, expected_color: str) -> None:
        assert viz._get_node_color(node_type) == expected_color

    @pytest.mark.parametrize("node_type", [
        NodeType.HOST, NodeType.PORT, NodeType.SERVICE,
        NodeType.VULNERABILITY, NodeType.TECHNOLOGY,
    ])
    def test_get_node_icon_known(self, viz: AttackGraphVisualizer, node_type: NodeType) -> None:
        icon = viz._get_node_icon(node_type)
        assert isinstance(icon, str)
        assert len(icon) > 0

    def test_get_node_icon_unknown(self, viz: AttackGraphVisualizer) -> None:
        assert viz._get_node_icon(NodeType.TARGET) == "\U0001f539"

    def test_render_empty_graph(self, viz_with_console: tuple[AttackGraphVisualizer, MagicMock]) -> None:
        v, console = viz_with_console
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 0
        v.render(g)
        console.print.assert_called_once()

    def test_render_no_hosts(self, viz_with_console: tuple[AttackGraphVisualizer, MagicMock]) -> None:
        v, console = viz_with_console
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 5
        g.edge_count = 3
        g.find_nodes.return_value = []
        v.render(g)
        g.find_nodes.assert_called_once_with(node_type=NodeType.HOST)
        console.print.assert_called_once()

    def test_render_with_hosts(self, viz: AttackGraphVisualizer) -> None:
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 3
        host = make_node("host1", NodeType.HOST, "server-01")
        port = make_node("port1", NodeType.PORT, "22/tcp")
        g.find_nodes.return_value = [host]
        g.get_edges.return_value = [MagicMock(target_id="port1")]
        g.get_node.return_value = port
        viz.render(g)
        g.find_nodes.assert_called_once_with(node_type=NodeType.HOST)

    def test_render_with_vuln_severity_high(self, viz: AttackGraphVisualizer) -> None:
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 3
        host = make_node("host1", NodeType.HOST, "server-01")
        vuln = make_node("vuln1", NodeType.VULNERABILITY, "CVE-2024-0001", {"severity": "critical"})
        g.find_nodes.return_value = [host]
        g.get_edges.return_value = [MagicMock(target_id="vuln1")]
        g.get_node.return_value = vuln
        viz.render(g)

    def test_render_with_vuln_severity_low(self, viz: AttackGraphVisualizer) -> None:
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 3
        host = make_node("host1", NodeType.HOST, "server-01")
        vuln = make_node("vuln1", NodeType.VULNERABILITY, "CVE-2024-0002", {"severity": "low"})
        g.find_nodes.return_value = [host]
        g.get_edges.return_value = [MagicMock(target_id="vuln1")]
        g.get_node.return_value = vuln
        viz.render(g)

    def test_build_tree_skips_visited(self, viz: AttackGraphVisualizer) -> None:
        g = MagicMock(spec=KnowledgeGraph)
        g.get_edges.return_value = []
        tree = MagicMock()
        viz._build_tree(g, "node1", tree, set())
        g.get_edges.assert_called_once_with(source_id="node1")

    def test_build_tree_recursive(self, viz: AttackGraphVisualizer) -> None:
        g = MagicMock(spec=KnowledgeGraph)
        target = make_node("target", NodeType.HOST, "target")
        g.get_edges.side_effect = [
            [MagicMock(target_id="child1")],
            [],
        ]
        g.get_node.return_value = target
        tree = MagicMock()
        branch = MagicMock()
        tree.add.return_value = branch
        viz._build_tree(g, "parent", tree, set())
        g.get_edges.assert_called()
        tree.add.assert_called_once()

    def test_known_node_type_colors_all(self, viz: AttackGraphVisualizer) -> None:
        for nt in NodeType:
            color = viz._get_node_color(nt)
            assert isinstance(color, str)

    def test_known_node_type_icons_all(self, viz: AttackGraphVisualizer) -> None:
        for nt in NodeType:
            icon = viz._get_node_icon(nt)
            assert isinstance(icon, str)

    def test_render_host_with_edges(self, viz_with_console: tuple[AttackGraphVisualizer, MagicMock]) -> None:
        v, console = viz_with_console
        g = MagicMock(spec=KnowledgeGraph)
        g.node_count = 10
        host = make_node("h1", NodeType.HOST, "webserver")
        port = make_node("p1", NodeType.PORT, "443/tcp")
        g.find_nodes.return_value = [host]
        g.get_edges.return_value = [MagicMock(target_id="p1")]
        g.get_node.return_value = port
        v.render(g)
        assert console.print.call_count >= 2
