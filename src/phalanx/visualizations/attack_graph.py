"""Attack Graph Visualization Engine.

Renders the in-memory knowledge graph into a visual hierarchy in the terminal using Rich.
"""

from rich.console import Console
from rich.tree import Tree

from phalanx.knowledge_graph import KnowledgeGraph, NodeType


class AttackGraphVisualizer:
    """Renders the Knowledge Graph natively in the terminal."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def _get_node_color(self, node_type: NodeType) -> str:
        colors = {
            NodeType.HOST: "cyan",
            NodeType.PORT: "blue",
            NodeType.SERVICE: "magenta",
            NodeType.VULNERABILITY: "red",
            NodeType.TECHNOLOGY: "yellow",
        }
        return colors.get(node_type, "white")

    def _get_node_icon(self, node_type: NodeType) -> str:
        icons = {
            NodeType.HOST: "🖥️",
            NodeType.PORT: "🔌",
            NodeType.SERVICE: "⚙️",
            NodeType.VULNERABILITY: "🚨",
            NodeType.TECHNOLOGY: "💡",
        }
        return icons.get(node_type, "🔹")

    def render(self, graph: KnowledgeGraph) -> None:
        """Render the attack graph starting from target hosts."""
        if graph.node_count == 0:
            self.console.print("[dim]The knowledge graph is empty.[/dim]")
            return

        # Find root nodes (typically hosts)
        hosts = graph.find_nodes(node_type=NodeType.HOST)
        if not hosts:
            # Fallback if no specific host node
            self.console.print(
                f"[cyan]Knowledge Graph: {graph.node_count} nodes, {graph.edge_count} edges[/cyan]"
            )
            return

        for host in hosts:
            color = self._get_node_color(host.node_type)
            icon = self._get_node_icon(host.node_type)
            root_tree = Tree(f"[{color}]{icon} {host.label}[/{color}]")

            # Recursive helper to build tree
            self._build_tree(graph, host.node_id, root_tree, set([host.node_id]))

            self.console.print(root_tree)
            self.console.print()

    def _build_tree(
        self,
        graph: KnowledgeGraph,
        current_id: str,
        current_tree: Tree,
        visited: set[str],
    ) -> None:
        """Recursively build the tree from the graph edges."""
        # Find all edges from current node
        outgoing_edges = graph.get_edges(source_id=current_id)
        for edge in outgoing_edges:
            target_node = graph.get_node(edge.target_id)
            if not target_node or target_node.node_id in visited:
                continue

            visited.add(target_node.node_id)
            color = self._get_node_color(target_node.node_type)
            icon = self._get_node_icon(target_node.node_type)

            # Format label
            label = f"[{color}]{icon} {target_node.label}[/{color}]"

            # Add extra context for vulnerabilities
            if target_node.node_type == NodeType.VULNERABILITY:
                severity = target_node.properties.get("severity", "unknown")
                sev_color = "red bold" if severity in ("high", "critical") else "yellow"
                label += f" [{sev_color}](Severity: {severity})[/{sev_color}]"

            # Create branch
            branch = current_tree.add(label)

            # Recurse
            self._build_tree(graph, target_node.node_id, branch, visited.copy())
