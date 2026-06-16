from __future__ import annotations

import re
from typing import Any

from . import BaseParser, build_finding

KEYVAL_RE = re.compile(r"^(\w[\w\s/]*?):\s*(.+)$")


class WhoisParser(BaseParser):
    INTERESTING_KEYS = {
        "domain name",
        "registrar",
        "creation date",
        "expiry date",
        "updated date",
        "name server",
        "registrant name",
        "registrant organization",
        "admin name",
        "admin organization",
        "tech name",
        "tech organization",
    }

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = ""
        records: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            m = KEYVAL_RE.match(line)
            if m:
                key = m.group(1).lower().strip()
                val = m.group(2).strip()
                if not target and "domain name" in key:
                    target = val.lower()
                for interesting in self.INTERESTING_KEYS:
                    if interesting in key:
                        records.append(f"{key}: {val}")
                        break
        if records:
            findings.append(
                build_finding(
                    title=f"WHOIS data for {target or 'domain'}",
                    severity="info",
                    description=f"WHOIS records: {len(records)} fields",
                    evidence="\n".join(records[:10]),
                    tool="whois",
                    target=target,
                )
            )
        return findings
