# SPDX-License-Identifier: AGPL-3.0-or-later
"""Internal tools for Siyarix (Graph Analytics, Threat Intel)."""

from typing import Any
import json
from .tool_models import ToolHandler

def make_graph_analyzer_handler() -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        action = kwargs.get("action", "")
        args = kwargs.get("args", {})

        from .knowledge_graph import KnowledgeGraph
        from .config import get_config_dir
        kg = KnowledgeGraph()
        path = get_config_dir() / "knowledge_graph.json"
        if path.exists():
            kg.load_json(str(path))

        result: dict[str, Any] = {}
        if action == "shortest_path":
            source = args.get("source")
            target = args.get("target")
            if source and target:
                path_nodes = kg.shortest_path(source, target)
                result = {"path": [n for n in path_nodes]} if path_nodes else {"error": "No path found"}
        elif action == "blast_radius":
            node_id = args.get("node_id")
            if node_id:
                radius = kg.blast_radius(node_id)
                result = {"blast_radius": [n for n in radius]}
        elif action == "find_crown_jewel_paths":
            node_id = args.get("node_id")
            paths = kg.find_crown_jewel_paths(node_id) if node_id else {}
            result = {"paths": [[n for n in p] for p in paths.values()]}
        else:
            result = {"error": f"Unknown action: {action}. Supported: shortest_path, blast_radius, find_crown_jewel_paths"}

        return {
            "status": "success" if "error" not in result else "error",
            "output": json.dumps(result, indent=2),
            "error": result.get("error", ""),
            "exit_code": 1 if "error" in result else 0,
            "tool": "graph_analyzer",
        }
    return handler


def make_threat_intel_handler() -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        action = kwargs.get("action", "")
        query = kwargs.get("query", "")

        from .threat_intel import ThreatIntelFeed, MITREAttackDB

        result: dict[str, Any] = {}
        if action == "cve_lookup":
            feed = ThreatIntelFeed()
            data: dict[str, Any] = getattr(feed, "query_cve", lambda x: {})(query) # Using getattr in case methods aren't exactly named this
            if not data:
                data = {"cve": query, "info": "No offline data found or method missing"}
            result = {"cve_data": data}
        elif action == "mitre_lookup":
            db = MITREAttackDB()
            data = getattr(db, "query_technique", lambda x: {})(query)
            if not data:
                data = {"technique": query, "info": "No offline data found or method missing"}
            result = {"mitre_data": data}
        else:
            result = {"error": f"Unknown action: {action}. Supported: cve_lookup, mitre_lookup"}

        return {
            "status": "success" if "error" not in result else "error",
            "output": json.dumps(result, indent=2),
            "error": result.get("error", ""),
            "exit_code": 1 if "error" in result else 0,
            "tool": "threat_intel",
        }
    return handler
