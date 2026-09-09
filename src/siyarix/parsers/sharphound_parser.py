# SPDX-License-Identifier: AGPL-3.0-or-later

"""SharpHound BloodHound collector output parser — parses SharpHound JSON data."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class SharphoundParser:
    """Parse SharpHound JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        any_json = False
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                any_json = True
            except json.JSONDecodeError:
                continue

            if isinstance(data, list):
                for item in data:
                    self._process_object(item, findings, seen)
            elif isinstance(data, dict):
                self._process_object(data, findings, seen)

        if not any_json:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line not in seen:
                    seen.add(line)
                    findings.append(
                        {
                            "title": f"SharpHound: {line[:60]}",
                            "severity": "info",
                            "description": f"SharpHound output: {line[:200]}",
                            "evidence": line,
                            "tool": "sharphound",
                            "target": "unknown",
                            "timestamp": _now_iso(),
                        },
                    )

        return findings

    def _process_object(self, obj: dict, findings: list, seen: set) -> None:
        obj_type = obj.get("Type", obj.get("type", "Object"))
        props = obj.get("Props", obj.get("props", {}))

        if isinstance(props, dict):
            name = props.get("name", props.get("Name", "unknown"))
            domain = props.get("domain", props.get("Domain", "unknown"))

            if obj_type.lower() == "user":
                dedup_key = f"user:{name}:{domain}"
                if dedup_key in seen:
                    return
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD User: {name}",
                        "severity": "info",
                        "description": f"SharpHound discovered user {name} in {domain}",
                        "evidence": f"User: {name} | Domain: {domain}",
                        "tool": "sharphound",
                        "target": domain,
                        "timestamp": _now_iso(),
                    },
                )
            elif obj_type.lower() == "group":
                dedup_key = f"group:{name}:{domain}"
                if dedup_key in seen:
                    return
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD Group: {name}",
                        "severity": "info",
                        "description": f"SharpHound discovered group {name} in {domain}",
                        "evidence": f"Group: {name} | Domain: {domain}",
                        "tool": "sharphound",
                        "target": domain,
                        "timestamp": _now_iso(),
                    },
                )
            elif obj_type.lower() == "computer":
                dedup_key = f"computer:{name}:{domain}"
                if dedup_key in seen:
                    return
                seen.add(dedup_key)
                os = props.get("operatingsystem", props.get("OperatingSystem", "unknown"))
                findings.append(
                    {
                        "title": f"AD Computer: {name}",
                        "severity": "info",
                        "description": f"SharpHound discovered computer {name} ({os}) in {domain}",
                        "evidence": f"Computer: {name} | OS: {os}",
                        "tool": "sharphound",
                        "target": domain,
                        "timestamp": _now_iso(),
                    },
                )
            elif obj_type.lower() == "session":
                computer = props.get("computer", props.get("Computer", "?"))
                dedup_key = f"session:{name}:{computer}"
                if dedup_key in seen:
                    return
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD Session: {name} -> {computer}",
                        "severity": "medium",
                        "description": f"SharpHound discovered session {name} on {computer}",
                        "evidence": f"User: {name} | Computer: {computer}",
                        "tool": "sharphound",
                        "target": domain,
                        "timestamp": _now_iso(),
                    },
                )
            elif obj_type.lower() == "acl":
                dedup_key = f"acl:{name}:{domain}"
                if dedup_key in seen:
                    return
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD ACL: {name}",
                        "severity": "low",
                        "description": f"SharpHound discovered ACL for {name} in {domain}",
                        "evidence": f"ACL: {name} | Domain: {domain}",
                        "tool": "sharphound",
                        "target": domain,
                        "timestamp": _now_iso(),
                    },
                )
