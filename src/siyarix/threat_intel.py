# SPDX-License-Identifier: AGPL-3.0-or-later
"""Threat Intelligence Integration for Siyarix.

This module provides real-time lookups to threat intelligence feeds
such as AlienVault OTX, Shodan, and NVD CVE database.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
import urllib.error
from typing import Any
import os

logger = logging.getLogger(__name__)


class ThreatIntelProvider:
    """Base class for Threat Intelligence integrations."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key


class AlienVaultOTX(ThreatIntelProvider):
    """AlienVault Open Threat Exchange integration."""

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self) -> None:
        super().__init__(api_key=os.getenv("ALIENVAULT_API_KEY"))

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup an IP address in AlienVault OTX."""
        url = f"{self.BASE_URL}/IPv4/{ip}/general"
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            _parsed = urllib.parse.urlparse(url)
            if _parsed.scheme not in ("http", "https"):
                raise ValueError(f"Disallowed URL scheme: {_parsed.scheme!r}")
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return {
                    "source": "AlienVault OTX",
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                }
        except urllib.error.URLError as e:
            logger.warning("AlienVault lookup failed for %s: %s", ip, e)
            return {"source": "AlienVault OTX", "error": str(e)}


class NVDDatabase(ThreatIntelProvider):
    """National Vulnerability Database (NVD) integration."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        """Fetch CVE details from NVD."""
        url = f"{self.BASE_URL}?cveId={cve_id}"
        try:
            _parsed = urllib.parse.urlparse(url)
            if _parsed.scheme not in ("http", "https"):
                raise ValueError(f"Disallowed URL scheme: {_parsed.scheme!r}")
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    base_score = None
                    if "cvssMetricV31" in metrics:
                        base_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    return {
                        "source": "NVD",
                        "id": cve_id,
                        "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                        "base_score": base_score,
                    }
                return {"source": "NVD", "error": "CVE not found"}
        except urllib.error.URLError as e:
            logger.warning("NVD lookup failed for %s: %s", cve_id, e)
            return {"source": "NVD", "error": str(e)}


class ThreatIntelManager:
    """Facade for querying all configured threat intel providers."""

    def __init__(self) -> None:
        self.alienvault = AlienVaultOTX()
        self.nvd = NVDDatabase()

    async def analyze_target(self, target: str) -> dict[str, Any]:
        """Perform a comprehensive threat intel sweep on a target."""
        # Simple heuristic to determine if target is IP or CVE
        if target.startswith("CVE-"):
            return await self.nvd.lookup_cve(target)
        else:
            # Assuming IP for now
            return await self.alienvault.lookup_ip(target)


# Stubs for chat handler compatibility
class ThreatIntelFeed:
    pass


class MITREAttackDB:
    pass


# Global singleton
intel_manager = ThreatIntelManager()
