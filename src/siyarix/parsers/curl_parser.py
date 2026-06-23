# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import re
from typing import Any

from . import BaseParser, build_finding

HEADER_RE = re.compile(r"^([^:]+):\s*(.+)$")
STATUS_RE = re.compile(r"^HTTP/\d+\.\d+\s+(\d+)\s+(.+)$")


class CurlParser(BaseParser):
    def parse(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        output = output.strip()
        if not output:
            return findings
        headers: dict[str, str] = {}
        status_code = ""
        status_text = ""
        target = ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            sm = STATUS_RE.match(line)
            if sm:
                status_code = sm.group(1)
                status_text = sm.group(2)
                continue
            hm = HEADER_RE.match(line)
            if hm:
                headers[hm.group(1).lower()] = hm.group(2)

        security_headers = {
            "strict-transport-security": ("HSTS", "HTTP Strict Transport Security"),
            "content-security-policy": ("CSP", "Content Security Policy"),
            "x-frame-options": ("XFO", "X-Frame-Options"),
            "x-content-type-options": ("XCTO", "X-Content-Type-Options"),
            "x-xss-protection": ("XSS", "X-XSS-Protection"),
        }
        present = []
        missing = []
        for hdr, (_short, full) in security_headers.items():
            if hdr in headers:
                present.append(full)
            else:
                missing.append(full)

        if status_code:
            findings.append(
                build_finding(
                    title=f"HTTP {status_code} {status_text}",
                    severity="info"
                    if status_code.startswith(("2", "3"))
                    else "medium",
                    description=f"HTTP response status {status_code}",
                    evidence=f"HTTP/{status_code} {status_text}",
                    tool="curl",
                    target=target,
                ),
            )

        if present:
            findings.append(
                build_finding(
                    title=f"Security headers: {', '.join(present)}",
                    severity="info",
                    description=f"{len(present)} security headers present",
                    evidence=", ".join(present),
                    tool="curl",
                    target=target,
                ),
            )
        if missing:
            findings.append(
                build_finding(
                    title=f"Missing security headers: {', '.join(missing[:3])}",
                    severity="low",
                    description=f"{len(missing)} security headers missing",
                    evidence=", ".join(missing),
                    tool="curl",
                    target=target,
                ),
            )

        interesting = {"server", "x-powered-by", "x-aspnet-version"}
        for hdr in interesting:
            if hdr in headers:
                findings.append(
                    build_finding(
                        title=f"Information disclosure: {hdr}: {headers[hdr]}",
                        severity="low",
                        description=f"Server leaked {hdr} header",
                        evidence=f"{hdr}: {headers[hdr]}",
                        tool="curl",
                        target=target,
                    ),
                )

        return findings
