# SPDX-License-Identifier: AGPL-3.0-or-later

"""Massdns output parser — parses JSON and plain-text domain-to-IP resolution formats."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_TEXT_LINE_RE = re.compile(r"^(\S+)\s+([aA\d]+)\s+(\S+)")
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

_STATS_RE = re.compile(
    r"(?:resolved|queries|responses|found)\s*[:\s]\s*(\d+)",
    re.IGNORECASE,
)


class MassdnsParser:
    """Parse massdns JSON or plain-text output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        lines = output.splitlines()
        if lines and _JSON_LINE_RE.match(lines[0].strip()):
            return self._parse_json(output)
        return self._parse_text(output)

    def _parse_json(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            name = obj.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)

            data = obj.get("data", "")
            record_type = obj.get("type", "")

            ips = _IP_RE.findall(data) if data else []

            description = f"DNS resolution: {name}"
            evidence = name
            if ips:
                description += f" -> {', '.join(ips)} [{record_type}]"
                evidence += f" -> {', '.join(ips)}"
            if record_type:
                evidence += f" [{record_type}]"

            findings.append(
                {
                    "title": f"Massdns: {name}",
                    "severity": "info",
                    "description": description,
                    "evidence": evidence,
                    "tool": "massdns",
                    "target": name,
                    "timestamp": _now_iso(),
                }
            )

        return findings

    def _parse_text(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            sm = _STATS_RE.search(line_stripped)
            if sm:
                count = sm.group(1)
                sk = f"stats:{count}"
                if sk not in seen:
                    seen.add(sk)
                    findings.append(
                        {
                            "title": f"Massdns summary: {count} resolved",
                            "severity": "info",
                            "description": f"Massdns resolved {count} domains",
                            "evidence": line_stripped,
                            "tool": "massdns",
                            "target": "",
                            "timestamp": _now_iso(),
                        }
                    )

            m = _TEXT_LINE_RE.match(line_stripped)
            if m:
                domain = m.group(1)
                record_type = m.group(2)
                data = m.group(3)

                if domain in seen:
                    continue
                seen.add(domain)

                ips = _IP_RE.findall(data)

                description = f"DNS resolution: {domain}"
                evidence = domain
                if ips:
                    description += f" -> {', '.join(ips)} [{record_type}]"
                    evidence += f" -> {', '.join(ips)}"
                if record_type:
                    evidence += f" [{record_type}]"

                findings.append(
                    {
                        "title": f"Massdns: {domain}",
                        "severity": "info",
                        "description": description,
                        "evidence": evidence,
                        "tool": "massdns",
                        "target": domain,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
