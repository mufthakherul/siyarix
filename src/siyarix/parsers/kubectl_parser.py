# SPDX-License-Identifier: AGPL-3.0-or-later

"""kubectl CLI output parser — parses Kubernetes JSON output for security findings."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")


class KubectlParser:
    """Parse kubectl JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        if not _JSON_RE.match(output):
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("NAME") and len(line.split()) > 2:
                    continue
                findings.append(
                    {
                        "title": f"K8s: {line[:80]}",
                        "severity": "info",
                        "description": f"kubectl output: {line[:200]}",
                        "evidence": line.strip()[:200],
                        "tool": "kubectl",
                        "target": "kubernetes",
                        "timestamp": _now_iso(),
                    }
                )
            return findings

        try:
            data = json.loads(output)
            self._parse_items(data, findings)
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_items(self, data, findings: list[dict]) -> None:  # type: ignore
        if isinstance(data, dict):
            kind = data.get("kind", "Unknown")
            name = data.get("metadata", {}).get("name", "unknown")
            ns = data.get("metadata", {}).get("namespace", "default")

            items = data.get("items", [])
            if items:
                for item in items:
                    self._parse_items(item, findings)
                return

            spec = data.get("spec", {})
            if kind == "Pod":
                containers = spec.get("containers", [])
                for c in containers:
                    img = c.get("image", "?")
                    c.get("ports", [])
                    priv = c.get("securityContext", {}).get("privileged", False)
                    sev = "high" if priv else "info"
                    findings.append(
                        {
                            "title": f"Pod: {name} ({img})",
                            "severity": sev,
                            "description": f"K8s pod {name} in {ns} running {img}"
                            + (" (PRIVILEGED)" if priv else ""),
                            "evidence": f"Kind: {kind} | Name: {name} | Namespace: {ns}",
                            "tool": "kubectl",
                            "target": ns,
                            "timestamp": _now_iso(),
                        }
                    )
            elif kind == "Service":
                findings.append(
                    {
                        "title": f"Service: {name}",
                        "severity": "info",
                        "description": f"K8s service {name} in namespace {ns}",
                        "evidence": f"Kind: {kind} | Name: {name} | Namespace: {ns}",
                        "tool": "kubectl",
                        "target": ns,
                        "timestamp": _now_iso(),
                    }
                )
            elif kind in ("Role", "ClusterRole"):
                rules = spec.get("rules", [])
                for rule in rules:
                    verbs = rule.get("verbs", [])
                    resources = rule.get("resources", [])
                    if any(
                        v in ("*", "create", "update", "delete", "patch", "bind", "impersonate")
                        for v in verbs
                    ):
                        findings.append(
                            {
                                "title": f"RBAC: {'/'.join(resources)} [{','.join(verbs)}]",
                                "severity": "high",
                                "description": f"K8s role {name} grants {'/'.join(resources)} verbs: {','.join(verbs)}",
                                "evidence": f"Role: {name} | Verbs: {','.join(verbs)}",
                                "tool": "kubectl",
                                "target": ns,
                                "timestamp": _now_iso(),
                            }
                        )
            else:
                findings.append(
                    {
                        "title": f"{kind}: {name}",
                        "severity": "info",
                        "description": f"K8s {kind} {name} in namespace {ns}",
                        "evidence": f"Kind: {kind} | Name: {name} | Namespace: {ns}",
                        "tool": "kubectl",
                        "target": ns,
                        "timestamp": _now_iso(),
                    }
                )
        elif isinstance(data, list):
            for item in data:
                self._parse_items(item, findings)
