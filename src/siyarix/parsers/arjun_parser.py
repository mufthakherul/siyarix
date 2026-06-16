# SPDX-License-Identifier: AGPL-3.0-or-later

"""Arjun HTTP parameter discovery output parser — parses Arjun JSON results."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_RE = re.compile(r"^\s*[{\[]")


class ArjunParser:
    """Parse Arjun output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        if _JSON_RE.match(output):
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    for url, params in data.items():
                        if isinstance(params, dict):
                            for param, info in params.items():
                                dedup_key = f"{url}:{param}"
                                if dedup_key in seen:
                                    continue
                                seen.add(dedup_key)
                                severity = (
                                    "medium"
                                    if any(
                                        x in str(info).lower()
                                        for x in ("reflected", "xss", "sqli", "injection")
                                    )
                                    else "info"
                                )
                                findings.append(
                                    {
                                        "title": f"Parameter discovered: {param}",
                                        "severity": severity,
                                        "description": f"Arjun discovered parameter '{param}' on {url}",
                                        "evidence": f"{param}={info}" if info else param,
                                        "tool": "arjun",
                                        "target": url,
                                        "timestamp": _now_iso(),
                                    }
                                )
                        else:
                            dedup_key = f"{url}:{params}"
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                findings.append(
                                    {
                                        "title": f"Parameter discovered: {params}",
                                        "severity": "info",
                                        "description": f"Arjun discovered parameter(s) on {url}",
                                        "evidence": str(params),
                                        "tool": "arjun",
                                        "target": url,
                                        "timestamp": _now_iso(),
                                    }
                                )
            except json.JSONDecodeError:
                pass

        for line in output.splitlines():
            line = line.strip()
            if not line or _JSON_RE.match(output):
                continue
            if "?" in line or "&" in line:
                dedup_key = f"url:{line[:100]}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": "URL with parameters discovered",
                            "severity": "info",
                            "description": f"Arjun discovered parameters in URL: {line[:120]}",
                            "evidence": line.strip(),
                            "tool": "arjun",
                            "target": line.split("?")[0],
                            "timestamp": _now_iso(),
                        }
                    )

        return findings
