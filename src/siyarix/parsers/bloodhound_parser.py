# SPDX-License-Identifier: AGPL-3.0-or-later

"""BloodHound JSON output parser — extracts users, computers, groups, sessions, ACLs from BloodHound's custom JSON format."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class BloodhoundParser:
    """Parse BloodHound JSON output (one JSON object per line) into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            data_items = obj.get("data")
            if isinstance(data_items, list):
                for item in data_items:
                    if not isinstance(item, dict):
                        continue
                    label = item.get("Label", "")
                    obj_id = item.get("ObjectId", "")
                    obj_type = item.get("ObjectType", "")
                    if obj_type and label:
                        dedup_key = f"{obj_type}:{label}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        severity = "info"
                        if obj_type == "User":
                            target = label
                            title = f"BloodHound: User {label}"
                            desc = f"AD user: {label} (ObjectId: {obj_id})"
                        elif obj_type == "Computer":
                            target = label
                            title = f"BloodHound: Computer {label}"
                            desc = f"Computer: {label} (ObjectId: {obj_id})"
                        elif obj_type == "Group":
                            target = label
                            title = f"BloodHound: Group {label}"
                            desc = f"AD group: {label} (ObjectId: {obj_id})"
                        else:
                            target = label
                            title = f"BloodHound: {obj_type} {label}"
                            desc = f"{obj_type}: {label} (ObjectId: {obj_id})"
                        findings.append(
                            {
                                "title": title,
                                "severity": severity,
                                "description": desc,
                                "evidence": json.dumps(item, default=str),
                                "tool": "bloodhound",
                                "target": target,
                                "timestamp": _now_iso(),
                            },
                        )
                continue

            data_type = obj.get("type", "")
            props = obj.get("props", obj.get("properties", {}))

            if data_type in {"user", "User"}:
                sam = props.get("samaccountname", props.get("name", "unknown"))
                dedup_key = f"user:{sam}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                upn = props.get("userprincipalname", "")
                enabled = props.get("enabled", True)
                findings.append(
                    {
                        "title": f"BloodHound: User {sam}",
                        "severity": "info",
                        "description": f"AD user: {sam}, UPN: {upn}, Enabled: {enabled}",
                        "evidence": json.dumps(props, default=str),
                        "tool": "bloodhound",
                        "target": sam,
                        "timestamp": _now_iso(),
                    },
                )

            elif data_type in {"computer", "Computer"}:
                name = props.get("name", "unknown")
                dedup_key = f"computer:{name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                os = props.get("operatingsystem", "")
                sam = props.get("samaccountname", "")
                findings.append(
                    {
                        "title": f"BloodHound: Computer {name}",
                        "severity": "info",
                        "description": f"Computer: {name}, OS: {os}, SAM: {sam}",
                        "evidence": json.dumps(props, default=str),
                        "tool": "bloodhound",
                        "target": name,
                        "timestamp": _now_iso(),
                    },
                )

            elif data_type in {"group", "Group"}:
                name = props.get("name", "unknown")
                dedup_key = f"group:{name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"BloodHound: Group {name}",
                        "severity": "info",
                        "description": f"AD group: {name}",
                        "evidence": json.dumps(props, default=str),
                        "tool": "bloodhound",
                        "target": name,
                        "timestamp": _now_iso(),
                    },
                )

            elif data_type in {"session", "Session"}:
                user = props.get("user", "")
                computer = props.get("computer", "")
                dedup_key = f"session:{user}:{computer}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"BloodHound: Session {user} -> {computer}",
                        "severity": "medium",
                        "description": f"User {user} has an active session on {computer}",
                        "evidence": json.dumps(props, default=str),
                        "tool": "bloodhound",
                        "target": computer,
                        "timestamp": _now_iso(),
                    },
                )

            elif data_type in {"acl", "Acl", "ACE"}:
                principal = props.get("principal", "unknown")
                right = props.get("righttype", props.get("ace_type", ""))
                dedup_key = f"acl:{principal}:{right}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"BloodHound: ACL {right} granted to {principal}",
                        "severity": "medium",
                        "description": f"Principal {principal} has {right} ACE",
                        "evidence": json.dumps(props, default=str),
                        "tool": "bloodhound",
                        "target": principal,
                        "timestamp": _now_iso(),
                    },
                )

        return findings
