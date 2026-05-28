# SPDX-License-Identifier: AGPL-3.0-or-later

"""Siyarix Attack Path Analyzer — Identifies exploit paths from the Knowledge Graph."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from siyarix.knowledge_graph import EdgeType, KnowledgeGraph, NodeType

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """Represents a potential attack vector from an origin to a vulnerable target."""

    origin_id: str
    target_id: str
    path_nodes: list[str]  # List of node IDs in sequence
    severity: str
    description: str


class AttackPathAnalyzer:
    """Analyzes a KnowledgeGraph to find multi-step attack paths."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self.graph = graph

    def find_all_paths(self) -> list[AttackPath]:
        """Discover all viable attack paths in the current graph."""
        paths: list[AttackPath] = []

        # 1. Find all vulnerable nodes
        vuln_nodes = self.graph.find_nodes(NodeType.VULNERABILITY)

        # 2. Find all external entry points (Domains, Subdomains, Hosts)
        if vuln_nodes:
            entry_nodes = (
                self.graph.find_nodes(NodeType.DOMAIN)
                + self.graph.find_nodes(NodeType.SUBDOMAIN)
                + self.graph.find_nodes(NodeType.HOST)
            )

            for entry in entry_nodes:
                for vuln in vuln_nodes:
                    path_ids = self.graph.shortest_path(entry.node_id, vuln.node_id)
                    if path_ids and len(path_ids) > 1:
                        severity = vuln.properties.get("severity", "medium")
                        description = f"Path from {entry.label} to {vuln.label}"

                        paths.append(
                            AttackPath(
                                origin_id=entry.node_id,
                                target_id=vuln.node_id,
                                path_nodes=path_ids,
                                severity=severity,
                                description=description,
                            )
                        )

        # 3. Find credential reuse paths
        cred_nodes = self.graph.find_nodes(NodeType.CREDENTIAL)
        for cred in cred_nodes:
            # If a credential connects to multiple services, that's lateral movement
            connected_services = []
            for edge in self.graph.get_edges(
                source_id=cred.node_id, edge_type=EdgeType.AUTHENTICATED_BY
            ):
                connected_services.append(edge.target_id)

            if len(connected_services) > 1:
                svcs = [self.graph.get_node(nid) for nid in connected_services]
                svc_labels = [s.label for s in svcs if s]
                paths.append(
                    AttackPath(
                        origin_id=cred.node_id,
                        target_id=connected_services[-1],
                        path_nodes=[cred.node_id] + connected_services,
                        severity="high",
                        description=f"Lateral movement risk: Credential '{cred.label}' reused across {', '.join(svc_labels)}",
                    )
                )

        return paths

    def generate_report(self) -> dict[str, Any]:
        """Generate a summary report of attack paths."""
        paths = self.find_all_paths()

        high_severity = [p for p in paths if p.severity.lower() in ("high", "critical")]

        return {
            "total_paths": len(paths),
            "high_severity_paths": len(high_severity),
            "paths": [
                {
                    "origin": (
                        origin_node.label
                        if (origin_node := self.graph.get_node(p.origin_id))
                        else p.origin_id
                    ),
                    "target": (
                        target_node.label
                        if (target_node := self.graph.get_node(p.target_id))
                        else p.target_id
                    ),
                    "severity": p.severity,
                    "description": p.description,
                    "steps": len(p.path_nodes) - 1,
                }
                for p in paths
            ],
        }
