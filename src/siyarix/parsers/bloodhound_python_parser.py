# SPDX-License-Identifier: AGPL-3.0-or-later

"""BloodHound Python collector output parser — parses BloodHound JSONL data."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")


class BloodhoundPythonParser:
    """Parse BloodHound Python (bloodhound-python) JSONL output into findings."""

    _INFO_FOUND_RE = re.compile(
        r"INFO:\s*Found\s+(\d+)\s+(?P<type>\w+)",
        re.IGNORECASE,
    )

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            im = self._INFO_FOUND_RE.search(line)
            if im:
                count = im.group(1)
                kind = im.group("type")
                dedup_key = f"found:{kind}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"BloodHound: {kind.capitalize()} count — {count}",
                        "severity": "info",
                        "description": f"BloodHound Python discovered {count} {kind}",
                        "evidence": line,
                        "tool": "bloodhound-python",
                        "target": "unknown",
                        "timestamp": _now_iso(),
                    }
                )
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            obj_type = record.get("type", "unknown")
            props = record.get("props", {})
            name = props.get("name", props.get("samaccountname", "unknown"))
            domain = props.get("domain", "unknown")

            if obj_type == "user":
                dedup_key = f"user:{name}:{domain}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                props.get("enabled", True)
                props.get("pwdlastset", "")
                has_spn = props.get("serviceprincipalnames", [])
                severity = "medium" if has_spn else "info"
                findings.append(
                    {
                        "title": f"AD User: {name}",
                        "severity": severity,
                        "description": f"BloodHound discovered user {name} in {domain}"
                        + (" (has SPN — AS-REP roastable)" if has_spn else ""),
                        "evidence": f"User: {name} | Domain: {domain}",
                        "tool": "bloodhound-python",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )
            elif obj_type == "computer":
                dedup_key = f"computer:{name}:{domain}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                os = props.get("operatingsystem", "unknown")
                findings.append(
                    {
                        "title": f"AD Computer: {name}",
                        "severity": "info",
                        "description": f"BloodHound discovered computer {name} ({os}) in {domain}",
                        "evidence": f"Computer: {name} | OS: {os}",
                        "tool": "bloodhound-python",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )
            elif obj_type == "group":
                dedup_key = f"group:{name}:{domain}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD Group: {name}",
                        "severity": "info",
                        "description": f"BloodHound discovered group {name} in {domain}",
                        "evidence": f"Group: {name} | Domain: {domain}",
                        "tool": "bloodhound-python",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )
            elif obj_type == "session":
                computer = props.get("computer", "?")
                dedup_key = f"session:{name}:{computer}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD Session: {name} -> {computer}",
                        "severity": "medium",
                        "description": f"BloodHound discovered session: {name} logged into {computer}",
                        "evidence": f"Session: {name} -> {computer}",
                        "tool": "bloodhound-python",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )
            elif obj_type == "acl":
                right_guid = props.get("rightguid", "?")
                dedup_key = f"acl:{name}:{right_guid}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "title": f"AD ACE: {right_guid}",
                        "severity": "low",
                        "description": f"BloodHound discovered ACL: {name}",
                        "evidence": f"ACE: {right_guid} | Principal: {name}",
                        "tool": "bloodhound-python",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
