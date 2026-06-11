from __future__ import annotations

import re
from typing import Any

from . import BaseParser, build_finding

URL_STATUS_RE = re.compile(r"^http[s]?://\S+")
TECH_RE = re.compile(r"(\w[\w.\-]*)(?:\[([^\]]*)\])?")


class WhatwebParser(BaseParser):
    def parse(self, output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            url_match = URL_STATUS_RE.search(line)
            target = url_match.group(0) if url_match else ""
            techs = []
            rest = line[url_match.end():] if url_match else line
            parts = rest.replace("[", " [").split()
            for part in parts:
                m = TECH_RE.match(part.strip(" ,;"))
                if m:
                    name = m.group(1)
                    version = m.group(2) or ""
                    techs.append(f"{name}" + (f" v{version}" if version else ""))
            if techs:
                findings.append(
                    build_finding(
                        title=f"Technology identified: {', '.join(techs[:5])}",
                        severity="info",
                        description=f"Web technology stack for {target}",
                        evidence=", ".join(techs),
                        tool="whatweb",
                        target=target,
                    )
                )
        return findings
