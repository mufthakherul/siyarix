"""Threat Intelligence Ingestion Module.

Ingests MISP feeds, OpenCTI, STIX/TAXII sources into the Knowledge Graph.
Automatically enriches scan findings with known threat actor TTPs from MITRE
ATT&CK, creating linkages between vulnerabilities and real-world campaigns.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntel:
    """A single threat intelligence indicator or observation."""

    id: str = ""
    source: str = ""
    indicator: str = ""
    indicator_type: str = ""
    severity: str = "info"
    confidence: str = "medium"
    description: str = ""
    mitre_attack_id: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id or uuid.uuid4().hex[:12],
            "source": self.source,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description[:200],
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


@dataclass
class MITREMapping:
    """Mapping from CVE or finding to MITRE ATT&CK framework."""

    attack_id: str
    tactic: str
    technique: str
    technique_id: str
    description: str
    platforms: list[str] = field(default_factory=list)


class MITREAttackDB:
    """MITRE ATT&CK knowledge base with mappings from CVEs/findings."""

    TACTICS: dict[str, str] = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact",
        "TA0042": "Resource Development",
        "TA0043": "Reconnaissance",
    }

    TECHNIQUE_MAP: dict[str, tuple[str, str]] = {
        "T1046": ("Network Service Discovery", "Discovery"),
        "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
        "T1059": ("Command and Scripting Interpreter", "Execution"),
        "T1071": ("Application Layer Protocol", "Command and Control"),
        "T1082": ("System Information Discovery", "Discovery"),
        "T1083": ("File and Directory Discovery", "Discovery"),
        "T1090": ("Proxy", "Command and Control"),
        "T1110": ("Brute Force", "Credential Access"),
        "T1190": ("Exploit Public-Facing Application", "Initial Access"),
        "T1204": ("User Execution", "Execution"),
        "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
        "T1505": ("Server Software Component", "Persistence"),
        "T1528": ("Steal Application Access Token", "Credential Access"),
        "T1543": ("Create or Modify System Process", "Persistence"),
        "T1546": ("Event Triggered Execution", "Privilege Escalation"),
        "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
        "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
        "T1552": ("Unsecured Credentials", "Credential Access"),
        "T1555": ("Credentials from Password Stores", "Credential Access"),
        "T1557": ("Adversary-in-the-Middle", "Credential Access"),
        "T1562": ("Impair Defenses", "Defense Evasion"),
        "T1566": ("Phishing", "Initial Access"),
        "T1574": ("Hijack Execution Flow", "Persistence"),
        "T1580": ("Cloud Infrastructure Discovery", "Discovery"),
        "T1583": ("Acquire Infrastructure", "Resource Development"),
        "T1587": ("Develop Capabilities", "Resource Development"),
        "T1588": ("Obtain Capabilities", "Resource Development"),
        "T1595": ("Active Scanning", "Reconnaissance"),
        "T1598": ("Phishing for Information", "Reconnaissance"),
    }

    CVE_PATTERN_MAP: dict[str, list[str]] = {
        r"CVE-202[1-9]-\d{4,7}": ["T1190", "T1505"],
        r"CVE-20\d{2}-\d{4,}": ["T1190"],
    }

    _KEYWORD_MAP: dict[str, list[str]] = {
        "rce": ["T1059", "T1204"],
        "sqli": ["T1190", "T1505"],
        "xss": ["T1059", "T1204"],
        "ssrf": ["T1190"],
        "lfi": ["T1083"],
        "auth": ["T1110", "T1552"],
        "privesc": ["T1548", "T1546"],
        "information": ["T1082", "T1046"],
    }

    @classmethod
    def _extract_cve_ids(cls, text: str) -> list[str]:
        return re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)

    @classmethod
    def map_finding(cls, finding: dict[str, Any]) -> list[MITREMapping]:
        mappings: list[MITREMapping] = []
        title = str(finding.get("title", ""))
        description = str(finding.get("description", ""))
        combined = f"{title} {description}"
        combined_lower = combined.lower()

        seen: set[str] = set()

        def _add(tech_id: str, source: str) -> None:
            if tech_id in seen:
                return
            seen.add(tech_id)
            tech_info = cls.TECHNIQUE_MAP.get(tech_id)
            if tech_info:
                technique_name, tactic_name = tech_info
                mappings.append(
                    MITREMapping(
                        attack_id=tech_id,
                        tactic=tactic_name,
                        technique=technique_name,
                        technique_id=tech_id,
                        description=f"Related to {source}: {technique_name}",
                        platforms=["Windows", "Linux", "macOS"],
                    )
                )

        # 1. CVE ID pattern matching
        cve_ids = cls._extract_cve_ids(combined)
        for cve_id in cve_ids:
            for pattern, tech_ids in cls.CVE_PATTERN_MAP.items():
                if re.match(pattern, cve_id, re.IGNORECASE):
                    for tech_id in tech_ids:
                        _add(tech_id, cve_id)

        # 2. Keyword fallback for non-CVE findings
        for keyword, tech_ids in cls._KEYWORD_MAP.items():
            if keyword in combined_lower:
                for tech_id in tech_ids:
                    _add(tech_id, keyword)

        return mappings

    @classmethod
    def get_technique(cls, attack_id: str) -> MITREMapping | None:
        info = cls.TECHNIQUE_MAP.get(attack_id.upper())
        if not info:
            return None
        technique_name, tactic_name = info
        return MITREMapping(
            attack_id=attack_id.upper(),
            tactic=tactic_name,
            technique=technique_name,
            technique_id=attack_id.upper(),
            description=f"{technique_name} - {tactic_name}",
        )


class ThreatIntelFeed:
    """Ingests and manages threat intelligence from multiple sources."""

    def __init__(self) -> None:
        self._indicators: dict[str, ThreatIntel] = {}
        self._sources: dict[str, dict[str, Any]] = {}

    def ingest_stix(self, stix_data: str | dict[str, Any]) -> int:
        """Ingest STIX 2.x formatted data."""
        if isinstance(stix_data, str):
            try:
                stix_data = json.loads(stix_data)
            except json.JSONDecodeError as e:
                logger.error("Invalid STIX JSON: %s", e)
                return 0

        count = 0
        objects = (
            stix_data.get("objects", []) if isinstance(stix_data, dict) else stix_data
        )
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type", "")
            if obj_type in ("indicator", "observed-data"):
                indicator = self._parse_stix_object(obj)
                if indicator:
                    self._indicators[indicator.id] = indicator
                    count += 1
        logger.info("Ingested %d STIX indicators", count)
        return count

    def _parse_stix_object(self, obj: dict[str, Any]) -> ThreatIntel | None:
        try:
            pattern = obj.get("pattern", "")
            return ThreatIntel(
                id=obj.get("id", uuid.uuid4().hex[:12]),
                source="stix",
                indicator=pattern,
                indicator_type=obj.get("type", "unknown"),
                severity=obj.get("severity", "medium"),
                confidence=obj.get("confidence", "medium"),
                description=obj.get("description", ""),
                tags=obj.get("labels", []),
                first_seen=datetime.fromisoformat(
                    obj.get("created", datetime.now().isoformat())
                ),
                last_seen=datetime.now(),
                raw=obj,
            )
        except Exception as e:
            logger.debug("Failed to parse STIX object: %s", e)
            return None

    def ingest_misp(self, misp_data: str | dict[str, Any]) -> int:
        if isinstance(misp_data, str):
            try:
                misp_data = json.loads(misp_data)
            except json.JSONDecodeError as e:
                logger.error("Invalid MISP JSON: %s", e)
                return 0

        count = 0
        events = (
            misp_data.get("response", []) if isinstance(misp_data, dict) else misp_data
        )
        if not isinstance(events, list):
            events = [misp_data]

        for event in events:
            event_obj = event.get("Event", event) if isinstance(event, dict) else event
            attributes = (
                event_obj.get("Attribute", []) if isinstance(event_obj, dict) else []
            )
            for attr in attributes:
                indicator = ThreatIntel(
                    id=attr.get("uuid", uuid.uuid4().hex[:12]),
                    source="misp",
                    indicator=attr.get("value", ""),
                    indicator_type=attr.get("type", "unknown"),
                    severity=attr.get("to_ids", False) and "high" or "info",
                    confidence=attr.get("category", "medium"),
                    description=attr.get("comment", ""),
                    tags=[attr.get("category", "")],
                    first_seen=datetime.fromisoformat(
                        attr.get("first_seen", datetime.now().isoformat())
                    ),
                    last_seen=datetime.now(),
                    raw=attr,
                )
                if indicator.indicator:
                    self._indicators[indicator.id] = indicator
                    count += 1
        logger.info("Ingested %d MISP indicators", count)
        return count

    def find_matches(self, text: str) -> list[ThreatIntel]:
        """Find threat indicators that match the given text."""
        matches: list[ThreatIntel] = []
        for indicator in self._indicators.values():
            if indicator.indicator and indicator.indicator in text:
                matches.append(indicator)
            if (
                indicator.indicator_type == "ip-dst"
                or indicator.indicator_type == "domain"
            ):
                pattern = re.escape(indicator.indicator)
                if re.search(pattern, text, re.IGNORECASE):
                    if indicator not in matches:
                        matches.append(indicator)
        return matches[:50]

    def indicators_by_type(self, indicator_type: str) -> list[ThreatIntel]:
        return [
            i for i in self._indicators.values() if i.indicator_type == indicator_type
        ]

    def indicators_by_severity(self, min_severity: str = "medium") -> list[ThreatIntel]:
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_val = severity_order.get(min_severity, 0)
        return [
            i
            for i in self._indicators.values()
            if severity_order.get(i.severity, 0) >= min_val
        ]

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enrich a finding with MITRE ATT&CK mapping, threat matches, and CVSS scoring."""
        enriched = dict(finding)
        target = str(finding.get("target", ""))
        title = str(finding.get("title", ""))

        mitre_mappings = MITREAttackDB.map_finding(finding)
        if mitre_mappings:
            enriched["mitre_attack"] = [
                {
                    "attack_id": m.attack_id,
                    "tactic": m.tactic,
                    "technique": m.technique,
                }
                for m in mitre_mappings
            ]

        threat_matches = self.find_matches(f"{target} {title}")
        if threat_matches:
            enriched["threat_intel"] = [
                {
                    "source": t.source,
                    "indicator": t.indicator,
                    "description": t.description,
                }
                for t in threat_matches[:5]
            ]

        # CVSS scoring integration
        try:
            from phalanx.cvss_scorer import CVSSScorer

            scorer = CVSSScorer()
            result = scorer.score_from_finding(finding)
            enriched["cvss_score"] = result.score
            enriched["cvss_vector"] = result.vector_string
            enriched["cvss_severity"] = result.severity.value
        except ImportError:
            pass
        except Exception:
            logger.debug("CVSS scoring failed for finding", exc_info=True)

        return enriched

    def stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for indicator in self._indicators.values():
            source_counts[indicator.source] = source_counts.get(indicator.source, 0) + 1
            type_counts[indicator.indicator_type] = (
                type_counts.get(indicator.indicator_type, 0) + 1
            )
        return {
            "total_indicators": len(self._indicators),
            "by_source": dict(sorted(source_counts.items())),
            "by_type": dict(sorted(type_counts.items())),
        }


__all__ = [
    "ThreatIntelFeed",
    "ThreatIntel",
    "MITREAttackDB",
    "MITREMapping",
]
