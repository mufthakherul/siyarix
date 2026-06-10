# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Knowledge Graph — In-memory graph of targets, findings, and relationships.

Provides:
  • **KnowledgeGraph** — Central graph tracking targets, services, vulnerabilities,
    and their relationships discovered during operations.
  • **Node / Edge** — Graph primitives with typed labels and metadata.

The knowledge graph aggregates findings across sessions and tools, enabling
queries like:
  - "What services are exposed on this network?"
  - "Which targets share this vulnerability?"
  - "Show the attack path from external to this database server"
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

__all__ = [
    "KnowledgeGraph",
    "Node",
    "Edge",
    "NodeType",
    "EdgeType",
]

logger = logging.getLogger(__name__)


class NodeType(StrEnum):
    """Types of nodes in the knowledge graph."""

    TARGET = "target"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    CREDENTIAL = "credential"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    USER = "user"
    NETWORK = "network"


class EdgeType(StrEnum):
    """Types of edges (relationships) in the knowledge graph."""

    HAS_PORT = "has_port"
    RUNS_SERVICE = "runs_service"
    HAS_VULN = "has_vulnerability"
    RESOLVES_TO = "resolves_to"
    SUBDOMAIN_OF = "subdomain_of"
    SERVES_URL = "serves_url"
    USES_TECH = "uses_technology"
    HAS_CERT = "has_certificate"
    CONNECTS_TO = "connects_to"
    AUTHENTICATED_BY = "authenticated_by"
    DISCOVERED_BY = "discovered_by"
    EXPLOITABLE_VIA = "exploitable_via"
    PART_OF = "part_of"


@dataclass
class Node:
    """A node in the knowledge graph."""

    node_id: str
    node_type: NodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    discovered_by: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "discovered_at": self.discovered_at,
            "discovered_by": self.discovered_by,
            "confidence": self.confidence,
        }


@dataclass
class Edge:
    """An edge (relationship) in the knowledge graph."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "properties": self.properties,
        }


class KnowledgeGraph:
    """In-memory knowledge graph of cybersecurity findings.

    Supports:
    - Adding/querying nodes and edges
    - Neighbor traversal
    - Path finding between nodes
    - Subgraph extraction
    - JSON persistence
    """

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)

    # ── Node operations ──────────────────────────────────────────────────

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        node_id: str | None = None,
        discovered_by: str = "",
        confidence: float = 1.0,
        **properties: Any,
    ) -> Node:
        """Add a node to the graph. Returns existing node if label+type match."""
        # Dedup by label + type
        for existing in self._nodes.values():
            if existing.label == label and existing.node_type == node_type:
                # Merge properties
                existing.properties.update(properties)
                return existing

        nid = node_id or f"{node_type.value}_{str(uuid.uuid4())[:6]}"
        node = Node(
            node_id=nid,
            node_type=node_type,
            label=label,
            properties=properties,
            discovered_by=discovered_by,
            confidence=confidence,
        )
        self._nodes[nid] = node
        return node

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def find_nodes(self, node_type: NodeType | None = None, label_contains: str = "") -> list[Node]:
        """Search nodes by type and/or label substring."""
        results = []
        for node in self._nodes.values():
            if node_type and node.node_type != node_type:
                continue
            if label_contains and label_contains.lower() not in node.label.lower():
                continue
            results.append(node)
        return results

    def remove_node(self, node_id: str) -> bool:
        """Remove a node and all its edges."""
        if node_id not in self._nodes:
            return False
        del self._nodes[node_id]
        self._edges = [e for e in self._edges if e.source_id != node_id and e.target_id != node_id]
        self._adjacency.pop(node_id, None)
        self._reverse_adj.pop(node_id, None)
        for adj_list in self._adjacency.values():
            while node_id in adj_list:
                adj_list.remove(node_id)
        for adj_list in self._reverse_adj.values():
            while node_id in adj_list:
                adj_list.remove(node_id)
        return True

    # ── Edge operations ──────────────────────────────────────────────────

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        **properties: Any,
    ) -> Edge | None:
        """Add a directed edge between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            logger.warning(
                "Cannot add edge: source=%s or target=%s not in graph",
                source_id,
                target_id,
            )
            return None

        # Dedup
        for existing in self._edges:
            if (
                existing.source_id == source_id
                and existing.target_id == target_id
                and existing.edge_type == edge_type
            ):
                existing.properties.update(properties)
                return existing

        edge = Edge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties,
        )
        self._edges.append(edge)
        self._adjacency[source_id].append(target_id)
        self._reverse_adj[target_id].append(source_id)
        return edge

    def get_edges(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        edge_type: EdgeType | None = None,
    ) -> list[Edge]:
        """Query edges by source, target, and/or type."""
        results = []
        for edge in self._edges:
            if source_id and edge.source_id != source_id:
                continue
            if target_id and edge.target_id != target_id:
                continue
            if edge_type and edge.edge_type != edge_type:
                continue
            results.append(edge)
        return results

    # ── Traversal ────────────────────────────────────────────────────────

    def neighbors(self, node_id: str, direction: str = "out") -> list[Node]:
        """Get neighboring nodes. direction = 'out' | 'in' | 'both'."""
        ids: set[str] = set()
        if direction in ("out", "both"):
            ids.update(self._adjacency.get(node_id, []))
        if direction in ("in", "both"):
            ids.update(self._reverse_adj.get(node_id, []))
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def shortest_path(self, start_id: str, end_id: str) -> list[str] | None:
        """BFS shortest path between two nodes. Returns node IDs or None."""
        if start_id not in self._nodes or end_id not in self._nodes:
            return None
        if start_id == end_id:
            return [start_id]

        visited: set[str] = {start_id}
        queue: list[list[str]] = [[start_id]]

        while queue:
            path = queue.pop(0)
            current = path[-1]

            for neighbor_id in self._adjacency.get(current, []):
                if neighbor_id in visited:
                    continue
                new_path = path + [neighbor_id]
                if neighbor_id == end_id:
                    return new_path
                visited.add(neighbor_id)
                queue.append(new_path)

        return None  # No path found

    def subgraph(self, node_type: NodeType) -> list[dict[str, Any]]:
        """Extract a subgraph containing only nodes of a given type and their edges."""
        type_nodes = {n.node_id for n in self._nodes.values() if n.node_type == node_type}
        return [
            edge.to_dict()
            for edge in self._edges
            if edge.source_id in type_nodes or edge.target_id in type_nodes
        ]

    # ── Statistics ───────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def stats(self) -> dict[str, Any]:
        """Return graph statistics."""
        type_counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type.value] += 1

        edge_type_counts: dict[str, int] = defaultdict(int)
        for edge in self._edges:
            edge_type_counts[edge.edge_type.value] += 1

        return {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "nodes_by_type": dict(type_counts),
            "edges_by_type": dict(edge_type_counts),
        }

    # ── Ingest findings ──────────────────────────────────────────────────

    def ingest_finding(self, finding: dict[str, Any], tool: str = "") -> None:
        """Add a security finding to the graph, auto-creating nodes and edges."""
        target_label = finding.get("target", finding.get("host", ""))
        if target_label:
            host_node = self.add_node(NodeType.HOST, target_label, discovered_by=tool)

            port = finding.get("port")
            if port:
                port_node = self.add_node(
                    NodeType.PORT,
                    f"{target_label}:{port}",
                    discovered_by=tool,
                    port=port,
                )
                self.add_edge(host_node.node_id, port_node.node_id, EdgeType.HAS_PORT)

                service = finding.get("service")
                if service:
                    svc_node = self.add_node(
                        NodeType.SERVICE,
                        service,
                        discovered_by=tool,
                    )
                    self.add_edge(port_node.node_id, svc_node.node_id, EdgeType.RUNS_SERVICE)

            vuln = finding.get("title") or finding.get("vulnerability")
            if vuln:
                severity = finding.get("severity", "info")
                vuln_node = self.add_node(
                    NodeType.VULNERABILITY,
                    vuln,
                    discovered_by=tool,
                    severity=severity,
                    description=finding.get("description", ""),
                )
                self.add_edge(host_node.node_id, vuln_node.node_id, EdgeType.HAS_VULN)

            tech = finding.get("technology")
            if tech:
                tech_node = self.add_node(NodeType.TECHNOLOGY, tech, discovered_by=tool)
                self.add_edge(host_node.node_id, tech_node.node_id, EdgeType.USES_TECH)

    # ── Persistence ──────────────────────────────────────────────────────

    def search(self, query: str, limit: int = 10) -> list[str]:
        q = query.lower()
        results: list[str] = []
        for node in self._nodes.values():
            if q in node.label.lower():
                results.append(f"[{node.node_type.value}] {node.label} ({node.node_id})")
                if len(results) >= limit:
                    break
        if len(results) < limit:
            for node in self._nodes.values():
                for k, v in node.properties.items():
                    if (
                        q in str(v).lower()
                        and f"[{node.node_type.value}] {node.label} ({node.node_id})" not in results
                    ):
                        results.append(f"[{node.node_type.value}] {node.label} ({node.node_id})")
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break
        return results

    def to_json(self) -> str:
        """Serialize the graph to JSON."""
        data = {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }
        return json.dumps(data, indent=2, default=str)

    def save(self, path: Path) -> None:
        """Save graph to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        logger.info(
            "Knowledge graph saved to %s (%d nodes, %d edges)",
            path,
            self.node_count,
            self.edge_count,
        )

    @classmethod
    def load(cls, path: Path) -> KnowledgeGraph:
        """Load graph from a JSON file."""
        graph = cls()
        if not path.exists():
            return graph

        data = json.loads(path.read_text(encoding="utf-8"))
        for nd in data.get("nodes", []):
            graph._nodes[nd["node_id"]] = Node(
                node_id=nd["node_id"],
                node_type=NodeType(nd["type"]),
                label=nd["label"],
                properties=nd.get("properties", {}),
                discovered_at=nd.get("discovered_at", ""),
                discovered_by=nd.get("discovered_by", ""),
                confidence=float(nd.get("confidence", 1.0)),
            )
        for ed in data.get("edges", []):
            edge = Edge(
                source_id=ed["source"],
                target_id=ed["target"],
                edge_type=EdgeType(ed["type"]),
                properties=ed.get("properties", {}),
                edge_id=ed.get("edge_id", str(uuid.uuid4())[:8]),
            )
            graph._edges.append(edge)
            graph._adjacency[edge.source_id].append(edge.target_id)
            graph._reverse_adj[edge.target_id].append(edge.source_id)

        logger.info(
            "Knowledge graph loaded from %s (%d nodes, %d edges)",
            path,
            graph.node_count,
            graph.edge_count,
        )
        return graph
