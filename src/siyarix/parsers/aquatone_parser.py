# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations
import json
from typing import Any
from . import BaseParser, build_finding


class AquatoneParser(BaseParser):
    """Parses Aquatone JSON session files."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        findings = []
        try:
            data = json.loads(output)
            pages = data.get("pages", {})
            if isinstance(pages, list):
                page_iter = enumerate(pages)
            else:
                page_iter = pages.items()
            for page_id, page_data in page_iter:
                url = page_data.get("url", "")
                status = page_data.get("status", "unknown")
                title = page_data.get("pageTitle", "No Title")
                has_screenshot = page_data.get("hasScreenshot", False)
                findings.append(
                    build_finding(
                        title=f"Aquatone Page: {title}",
                        severity="info",
                        description=f"Page {url} returned HTTP {status}. Screenshot captured: {has_screenshot}",
                        evidence=json.dumps(page_data),
                        tool="aquatone",
                        target=url,
                    )
                )
        except json.JSONDecodeError:
            pass
        return findings
