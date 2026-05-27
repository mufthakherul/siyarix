"""WPScan output parser — parses WPScan text output lines."""

from __future__ import annotations

from . import _now_iso

import re

_URL_RE = re.compile(r"^\[\+\]\s*URL:\s*(?P<url>\S+)")
_VULN_RE = re.compile(r"(?i)\b(vulnerable|vulnerability|CVE-\d{4}-\d+)\b")
_WARN_RE = re.compile(r"^\[!\]\s*(?P<msg>.+)$")
_PLUGIN_RE = re.compile(r"^\[\+\]\s*(?P<name>[^:]+):\s*(?P<value>.+)$")

class WpscanParser:
    """Parse WPScan output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            url_match = _URL_RE.match(line)
            if url_match:
                target = url_match.group("url")
                continue

            warn_match = _WARN_RE.match(line)
            if warn_match:
                msg = warn_match.group("msg")
                severity = "high" if _VULN_RE.search(msg) else "medium"
                findings.append(
                    {
                        "title": f"WPScan warning: {msg[:96]}",
                        "severity": severity,
                        "description": msg,
                        "evidence": target,
                        "tool": "wpscan",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            plugin_match = _PLUGIN_RE.match(line)
            if plugin_match and "version" in plugin_match.group("name").lower():
                value = plugin_match.group("value")
                findings.append(
                    {
                        "title": f"WP component metadata: {plugin_match.group('name')}",
                        "severity": "info",
                        "description": value,
                        "evidence": target,
                        "tool": "wpscan",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )

        return findings
