# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import re
from typing import Any

from . import BaseParser, build_finding

RECORD_RE = re.compile(
    r"^([\w.\-]+)\.?\s+(\d+)\s+(IN|CLASS\d+)?\s*(A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV|CAA)\s+(.+)$",
    re.IGNORECASE,
)


class DigParser(BaseParser):
    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith((";", ";;")):
                continue
            m = RECORD_RE.match(line)
            if m:
                domain = m.group(1).rstrip(".")
                rtype = m.group(4).upper()
                value = m.group(5).strip()
                key = f"{domain}:{rtype}:{value}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    build_finding(
                        title=f"DNS {rtype} record: {domain}",
                        severity="info",
                        description=f"DNS {rtype} record resolved to {value}",
                        evidence=f"{domain} {rtype} {value}",
                        tool="dig",
                        target=domain,
                    ),
                )
        return findings
