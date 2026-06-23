# SPDX-License-Identifier: AGPL-3.0-or-later

"""httpx JSON/text output parser --- extracts URL, status code, content length, title, and technology info."""

from __future__ import annotations

import json
from typing import Any

from . import _now_iso


class HttpxParser:
    """Parse httpx JSON/text output into normalized finding dicts.

    Handles JSON lines output (default with ``-json``) and plain text fallback.
    """

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output.strip():
            return []
        first_line = next((line for line in output.splitlines() if line.strip()), "")
        if first_line.startswith("{"):
            return self._parse_json_output(output)
        return self._parse_text(output)

    def _parse_json_output(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                obj = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue

            findings.extend(self._parse_json_obj(obj, seen))

        return findings

    def _parse_json_obj(self, obj: dict, seen: set[str] | None = None) -> list[dict[str, Any]]:
        if seen is None:
            seen = set()
        findings: list[dict[str, Any]] = []
        url = obj.get("url", obj.get("URL", obj.get("input", "")))
        if not url:
            return findings

        dedup_key = url
        if dedup_key in seen:
            return findings
        seen.add(dedup_key)

        status_code = str(obj.get("status_code", obj.get("StatusCode", obj.get("status", 0))))
        content_length = obj.get(
            "content_length",
            obj.get("ContentLength", obj.get("length", obj.get("content-length", ""))),
        )
        title = obj.get("title", obj.get("Title", ""))
        webserver = obj.get(
            "webserver", obj.get("Webserver", obj.get("server", obj.get("Server", ""))),
        )
        tech = obj.get(
            "tech", obj.get("Tech", obj.get("technologies", obj.get("Technologies", []))),
        )
        if isinstance(tech, str):
            tech = [t.strip() for t in tech.split(",") if t.strip()]
        cnames = obj.get("cnames", obj.get("Cnames", obj.get("cname", [])))
        if isinstance(cnames, str):
            cnames = [cnames]
        content_type = obj.get("content_type", obj.get("contentType", obj.get("Content-Type", "")))
        cdn_name = obj.get("cdn_name", obj.get("cdn", ""))
        response_time = obj.get("response_time", obj.get("time", obj.get("duration", "")))
        final_url = obj.get("final_url", obj.get("finalUrl", obj.get("redirect", "")))

        description_parts = [f"httpx probe: {url}", f"HTTP {status_code}" if status_code else ""]
        if content_length:
            description_parts.append(f"size {content_length}")
        if title:
            description_parts.append(f"title: {title}")
        if webserver:
            description_parts.append(f"server: {webserver}")
        if content_type:
            description_parts.append(f"type: {content_type}")
        if tech:
            description_parts.append(f"tech: {', '.join(tech[:5])}")
        if cdn_name:
            description_parts.append(f"cdn: {cdn_name}")
        if response_time:
            description_parts.append(f"time: {response_time}")

        severity = "info"
        try:
            sc = int(status_code) if status_code else 0
            if 400 <= sc < 500:
                severity = "low"
            elif 500 <= sc < 600:
                severity = "medium"
        except (ValueError, TypeError):
            pass

        target = url.split("?")[0]
        evidence_parts = [url]
        if final_url and final_url != url:
            evidence_parts.append(f"-> {final_url}")
        if title:
            evidence_parts.append(f"title: {title}")
        if tech:
            evidence_parts.append(f"tech: {', '.join(tech[:5])}")

        findings.append(
            {
                "title": f"httpx: {url} ({status_code})",
                "severity": severity,
                "description": " | ".join(p for p in description_parts if p),
                "evidence": " | ".join(evidence_parts),
                "tool": "httpx",
                "target": target,
                "timestamp": _now_iso(),
            },
        )

        return findings

    def _parse_text(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            url = ""
            status_code = ""
            for p in parts:
                if p.startswith(("http://", "https://")):
                    url = p
                elif p.isdigit() and len(p) == 3:
                    status_code = p

            if not url:
                continue

            dedup_key = url
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = "info"
            try:
                sc = int(status_code)
                if 400 <= sc < 500:
                    severity = "low"
                elif 500 <= sc < 600:
                    severity = "medium"
            except (ValueError, TypeError):
                pass

            findings.append(
                {
                    "title": f"httpx: {url}" + (f" ({status_code})" if status_code else ""),
                    "severity": severity,
                    "description": f"httpx probe: {url}"
                    + (f" HTTP {status_code}" if status_code else ""),
                    "evidence": line,
                    "tool": "httpx",
                    "target": url.split("?")[0],
                    "timestamp": _now_iso(),
                },
            )

        return findings
