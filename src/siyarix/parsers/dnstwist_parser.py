# SPDX-License-Identifier: AGPL-3.0-or-later

"""DNSTwist domain typosquatting output parser — parses JSON results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")


class DnstwistParser:
    """Parse dnstwist JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            data = json.loads(output)
            if isinstance(data, list):
                for entry in data:
                    domain = entry.get("domain", "")
                    fuzzed = entry.get("fuzzed", "")
                    display_name = fuzzed or domain
                    if display_name in seen:
                        continue
                    seen.add(display_name)
                    dns_a = entry.get("dns-a", [])
                    dns_aaaa = entry.get("dns-aaaa", [])
                    mx = entry.get("dns-mx", [])
                    entry.get("dns-ns", [])
                    score = entry.get("score", 0)

                    ips = []
                    if isinstance(dns_a, list):
                        ips.extend(dns_a)
                    if isinstance(dns_aaaa, list):
                        ips.extend(dns_aaaa)

                    severity = "low"
                    if isinstance(score, (int, float)) and score > 50:
                        severity = "medium"
                    if ips:
                        severity = "high"

                    desc = f"dnstwist discovered lookalike domain {display_name}"
                    evidence = f"Domain: {display_name} | Score: {score}"
                    if ips:
                        desc += f" resolving to {', '.join(ips[:3])}"
                        evidence += f" | IPs: {', '.join(ips[:3])}"
                    if mx:
                        evidence += f" | MX: {mx}"

                    findings.append(
                        {
                            "title": f"Typosquat domain: {display_name}",
                            "severity": severity,
                            "description": desc,
                            "evidence": evidence,
                            "tool": "dnstwist",
                            "target": domain,
                            "timestamp": _now_iso(),
                        },
                    )
            return findings
        except json.JSONDecodeError:
            pass

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if _JSON_RE.match(line):
                continue
            domain = line.split()[0] if line.split() else line
            if domain in seen:
                continue
            seen.add(domain)
            findings.append(
                {
                    "title": f"Typosquat domain: {domain[:60]}",
                    "severity": "info",
                    "description": f"dnstwist discovered potential typosquat domain: {line}",
                    "evidence": line,
                    "tool": "dnstwist",
                    "target": "unknown",
                    "timestamp": _now_iso(),
                },
            )

        return findings
