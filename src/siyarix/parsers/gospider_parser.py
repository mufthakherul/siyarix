# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gospider JSON output parser — extracts crawled URLs with source, status, and body length."""

from __future__ import annotations

from . import _now_iso

import json
import re

_JSON_LINE_RE = re.compile(r"^\s*[{[]")
_SUBDOMAIN_RE = re.compile(r"(?i)(?:subdomain|Subdomain|sub):\s*(\S+)")


class GospiderParser:
    """Parse gospider JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        subdomains_found: set[str] = set()

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or not _JSON_LINE_RE.match(line_stripped):
                continue

            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            url = obj.get("url", obj.get("URL", ""))
            if not url:
                continue

            url_path = url.split("?")[0]
            dedup_key = url_path
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            source = obj.get("source", obj.get("Source", ""))
            status = obj.get("status", obj.get("StatusCode", obj.get("status_code", 0)))
            body_length = obj.get("body_length", obj.get("BodyLength", obj.get("size", "")))
            redir = obj.get("redir", obj.get("redirect", obj.get("Redirect", "")))

            if _SUBDOMAIN_RE.search(line_stripped):
                sub_m = _SUBDOMAIN_RE.search(line_stripped)
                if sub_m:
                    sub = sub_m.group(1)
                    if sub not in subdomains_found:
                        subdomains_found.add(sub)
                        findings.append(
                            {
                                "title": f"Gospider subdomain: {sub}",
                                "severity": "info",
                                "description": f"Gospider discovered subdomain {sub}",
                                "evidence": f"Subdomain: {sub}",
                                "tool": "gospider",
                                "target": sub,
                                "timestamp": _now_iso(),
                            }
                        )

            severity = "info"
            if status and int(status) in (401, 403, 302, 301):
                severity = "low"
            elif status and int(status) >= 500:
                severity = "medium"

            description = f"Crawled URL: {url}"
            if source:
                description += f" (from {source})"
            if status:
                description += f" [HTTP {status}]"

            evidence = f"URL: {url}, Source: {source}, Status: {status}, Size: {body_length}"
            if redir:
                evidence += f", Redirect: {redir}"

            findings.append(
                {
                    "title": f"Gospider: {url}",
                    "severity": severity,
                    "description": description,
                    "evidence": evidence,
                    "tool": "gospider",
                    "target": url_path,
                    "timestamp": _now_iso(),
                }
            )

        return findings
