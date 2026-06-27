# SPDX-License-Identifier: AGPL-3.0-or-later

"""LinPEAS output parser — extracts potential privilege escalation vectors."""

from __future__ import annotations

import re
from typing import Any
from . import _now_iso


class LinpeasParser:
    """Parses LinPEAS plain-text output into normalised finding dicts."""

    def parse(self, text_output: str, target: str = "localhost") -> list[dict[str, Any]]:
        if not text_output or not text_output.strip():
            return []

        findings: list[dict[str, Any]] = []

        # In LinPEAS, typically lines with [+] indicate sections or interesting findings
        # Some findings have "RED/YELLOW" ANSI escapes, but assuming we get clean text,
        # we can look for "Vulnerable", "CVE-", or just lines that indicate a vector.

        cve_re = re.compile(r"(CVE-\d{4}-\d{4,})")
        interesting_re = re.compile(
            r"\[\+\](.*(?:Vulnerable|Exploit|Root|Admin|Password|Secret).*?)$", re.IGNORECASE
        )

        for line in text_output.splitlines():
            line = line.strip()
            if not line:
                continue

            cve_match = cve_re.search(line)
            if cve_match:
                findings.append(
                    {
                        "title": f"LinPEAS: Found {cve_match.group(1)}",
                        "severity": "high",
                        "description": line,
                        "evidence": line,
                        "tool": "linpeas",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            interesting_match = interesting_re.search(line)
            if interesting_match:
                findings.append(
                    {
                        "title": "LinPEAS: Potential Privilege Escalation Vector",
                        "severity": "medium",
                        "description": interesting_match.group(1).strip(),
                        "evidence": line,
                        "tool": "linpeas",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
