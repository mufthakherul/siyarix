# SPDX-License-Identifier: AGPL-3.0-or-later

"""CVSS 3.1 auto-scoring engine.

Automatically calculates CVSS scores based on finding characteristics
and vulnerability metadata as described in Chapter 18.2.

Base Score calculation follows the FIRST CVSS v3.1 specification,
including Roundup and scope-dependent Privileges Required weights.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# CVSS 3.1 metric groups (FIRST specification)
METRIC_GROUPS = {
    "attack_vector": {
        "network": 0.85,
        "adjacent": 0.62,
        "local": 0.55,
        "physical": 0.20,
    },
    "attack_complexity": {
        "low": 0.77,
        "high": 0.44,
    },
    # PR weights depend on Scope — see privileges_required_unchanged / _changed
    "privileges_required_unchanged": {
        "none": 0.85,
        "low": 0.62,
        "high": 0.27,
    },
    "privileges_required_changed": {
        "none": 0.85,
        "low": 0.68,
        "high": 0.50,
    },
    # Legacy alias kept for callers that look up METRIC_GROUPS["privileges_required"]
    "privileges_required": {
        "none": 0.85,
        "low": 0.62,
        "high": 0.27,
    },
    "user_interaction": {
        "none": 0.85,
        "required": 0.62,
    },
    "scope": {
        "unchanged": 0.0,
        "changed": 1.0,
    },
    "confidentiality": {
        "none": 0.0,
        "low": 0.22,
        "high": 0.56,
    },
    "integrity": {
        "none": 0.0,
        "low": 0.22,
        "high": 0.56,
    },
    "availability": {
        "none": 0.0,
        "low": 0.22,
        "high": 0.56,
    },
}

_IMPACT_METRICS = frozenset({"confidentiality", "integrity", "availability"})
_INFO_SEVERITIES = frozenset({"info", "informational", "none", "unknown", ""})


def roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number to one decimal place ≥ *value*.

    Spec: Roundup(x) = ceil(x * 10) / 10, with an epsilon guard against
    floating-point representations that are infinitesimally below an exact
    tenth (e.g. 0.1 * n stored as slightly less than the true value).
    """
    return math.ceil(value * 10.0 - 1e-10) / 10.0


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class CVSSVector:
    """Full CVSS 3.1 vector with all metrics."""

    attack_vector: str = "network"
    attack_complexity: str = "low"
    privileges_required: str = "none"
    user_interaction: str = "none"
    scope: str = "unchanged"
    confidentiality: str = "high"
    integrity: str = "high"
    availability: str = "low"
    exploit_code_maturity: str = "not_defined"
    remediation_level: str = "not_defined"
    report_confidence: str = "not_defined"

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector[0].upper()}"
            f"/AC:{self.attack_complexity[0].upper()}"
            f"/PR:{self.privileges_required[0].upper()}"
            f"/UI:{self.user_interaction[0].upper()}"
            f"/S:{self.scope[0].upper()}"
            f"/C:{self.confidentiality[0].upper()}"
            f"/I:{self.integrity[0].upper()}"
            f"/A:{self.availability[0].upper()}"
        )


@dataclass
class CVSSResult:
    """Result of CVSS scoring."""

    score: float | None = 0.0
    severity: Severity = Severity.NONE
    vector: CVSSVector = field(default_factory=CVSSVector)
    vector_string: str = ""
    metrics: dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0
    inferred: bool = False
    unknown: bool = False


class CVSSScorer:
    """CVSS 3.1 auto-scoring engine."""

    SEVERITY_THRESHOLDS = [
        (Severity.CRITICAL, 9.0),
        (Severity.HIGH, 7.0),
        (Severity.MEDIUM, 4.0),
        (Severity.LOW, 0.1),
    ]

    # Auto-inference rules from finding metadata
    _INFERENCE_RULES: dict[str, tuple[str, str]] = {
        "rce": ("confidentiality", "high"),
        "remote": ("attack_vector", "network"),
        "sqli": ("confidentiality", "high"),
        "xss": ("confidentiality", "low"),
        "csrf": ("integrity", "low"),
        "dos": ("availability", "high"),
        "auth": ("privileges_required", "none"),
        "local": ("attack_vector", "local"),
        "physical": ("attack_vector", "physical"),
    }

    def score(self, vector: CVSSVector | None = None, **overrides: str) -> CVSSResult:
        if vector is None:
            vector = CVSSVector()

        # Apply overrides
        for key, value in overrides.items():
            if hasattr(vector, key):
                setattr(vector, key, value)

        # ISS (Impact Sub-Score)
        iss = 1.0 - (
            (1.0 - METRIC_GROUPS["confidentiality"].get(vector.confidentiality, 0.0))
            * (1.0 - METRIC_GROUPS["integrity"].get(vector.integrity, 0.0))
            * (1.0 - METRIC_GROUPS["availability"].get(vector.availability, 0.0))
        )

        # Impact depending on scope
        if vector.scope == "unchanged":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Privileges Required weight depends on Scope (CVSS 3.1)
        if vector.scope == "changed":
            pr_table = METRIC_GROUPS["privileges_required_changed"]
        else:
            pr_table = METRIC_GROUPS["privileges_required_unchanged"]
        pr = pr_table.get(vector.privileges_required, 0.85)

        # Exploitability
        exploitability = (
            8.22
            * METRIC_GROUPS["attack_vector"].get(vector.attack_vector, 0.85)
            * METRIC_GROUPS["attack_complexity"].get(vector.attack_complexity, 0.77)
            * pr
            * METRIC_GROUPS["user_interaction"].get(vector.user_interaction, 0.85)
        )

        # Base Score
        if impact <= 0:
            base = 0.0
        elif vector.scope == "unchanged":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)

        # FIRST Roundup — not banker's / half-up round
        score = roundup(base) if impact > 0 else 0.0

        return CVSSResult(
            score=score,
            severity=self._severity_from_score(score),
            vector=vector,
            vector_string=vector.to_vector_string(),
            metrics={
                "attack_vector": vector.attack_vector,
                "attack_complexity": vector.attack_complexity,
                "privileges_required": vector.privileges_required,
                "user_interaction": vector.user_interaction,
                "scope": vector.scope,
                "confidentiality": vector.confidentiality,
                "integrity": vector.integrity,
                "availability": vector.availability,
            },
            inferred=False,
            unknown=False,
        )

    def score_from_finding(self, finding: dict[str, Any]) -> CVSSResult:
        title = (finding.get("title", "") + " " + finding.get("description", "")).lower()
        severity = str(finding.get("severity", "") or "").lower().strip()

        # Informational / unknown findings must not invent critical scores.
        if severity in _INFO_SEVERITIES:
            return CVSSResult(
                score=None,
                severity=Severity.UNKNOWN,
                vector=CVSSVector(
                    confidentiality="none",
                    integrity="none",
                    availability="none",
                ),
                vector_string="",
                metrics={},
                confidence=0.0,
                inferred=False,
                unknown=True,
            )

        # Auto-infer CVSS metrics from text
        inferred: dict[str, str] = {}
        for keyword, (metric, value) in self._INFERENCE_RULES.items():
            if keyword in title:
                inferred[metric] = value

        # Map severity to base metrics
        if severity == "critical":
            inferred.setdefault("confidentiality", "high")
            inferred.setdefault("integrity", "high")
            inferred.setdefault("availability", "high")
        elif severity == "high":
            inferred.setdefault("confidentiality", "high")
            inferred.setdefault("integrity", "high")
        elif severity == "medium":
            inferred.setdefault("confidentiality", "low")
            inferred.setdefault("integrity", "low")
        elif severity == "low":
            inferred.setdefault("attack_vector", "local")
            inferred.setdefault("attack_complexity", "high")
            inferred.setdefault("privileges_required", "high")
            inferred.setdefault("user_interaction", "required")
            inferred.setdefault("confidentiality", "none")
            inferred.setdefault("integrity", "none")
            inferred.setdefault("availability", "none")
        else:
            # Unrecognized severity without enough impact metrics → unknown
            if not any(m in inferred for m in _IMPACT_METRICS):
                return CVSSResult(
                    score=None,
                    severity=Severity.UNKNOWN,
                    vector=CVSSVector(
                        confidentiality="none",
                        integrity="none",
                        availability="none",
                    ),
                    vector_string="",
                    metrics=dict(inferred),
                    confidence=0.0,
                    inferred=bool(inferred),
                    unknown=True,
                )

        result = self.score(**inferred)  # type: ignore[arg-type]
        result.inferred = True
        result.confidence = 0.6 if inferred else 0.4
        return result

    def score_from_cve(self, cve_id: str, description: str = "") -> CVSSResult:
        text = description.lower() if description else cve_id.lower()

        # Try to infer from CVE description keywords
        inferred: dict[str, str] = {}
        for keyword, (metric, value) in self._INFERENCE_RULES.items():
            if keyword in text:
                inferred[metric] = value

        result = self.score(**inferred)  # type: ignore[arg-type]
        result.inferred = True
        result.confidence = 0.5
        return result

    def parse_vector_string(self, vector_string: str) -> CVSSVector:
        vector = CVSSVector()
        pattern = re.compile(r"([A-Z]+):([A-Za-z]+)")
        abbr_map: dict[str, str] = {
            "AV": "attack_vector",
            "AC": "attack_complexity",
            "PR": "privileges_required",
            "UI": "user_interaction",
            "S": "scope",
            "C": "confidentiality",
            "I": "integrity",
            "A": "availability",
            "E": "exploit_code_maturity",
            "RL": "remediation_level",
            "RC": "report_confidence",
        }
        field_value_maps: dict[str, dict[str, str]] = {
            "attack_vector": {
                "N": "network",
                "A": "adjacent",
                "L": "local",
                "P": "physical",
            },
            "attack_complexity": {"L": "low", "H": "high"},
            "privileges_required": {"N": "none", "L": "low", "H": "high"},
            "user_interaction": {"N": "none", "R": "required"},
            "scope": {"U": "unchanged", "C": "changed"},
            "confidentiality": {"N": "none", "L": "low", "H": "high"},
            "integrity": {"N": "none", "L": "low", "H": "high"},
            "availability": {"N": "none", "L": "low", "H": "high"},
            "exploit_code_maturity": {
                "X": "not_defined",
                "U": "unproven",
                "P": "poc",
                "F": "functional",
                "H": "high",
            },
            "remediation_level": {
                "X": "not_defined",
                "U": "unavailable",
                "OF": "official_fix",
                "TF": "temporary_fix",
                "W": "workaround",
            },
            "report_confidence": {
                "X": "not_defined",
                "U": "unknown",
                "R": "reasonable",
                "C": "confirmed",
            },
        }
        default_value_map: dict[str, str] = {
            "N": "none",
            "L": "low",
            "H": "high",
            "U": "none",
            "C": "changed",
            "ND": "not_defined",
        }

        for match in pattern.findall(vector_string):
            abbr, val = match
            field_name = abbr_map.get(abbr)
            if field_name and hasattr(vector, field_name):
                field_map = field_value_maps.get(field_name, default_value_map)
                mapped_val = field_map.get(val, val.lower())
                setattr(vector, field_name, mapped_val)

        return vector

    def _severity_from_score(self, score: float | None) -> Severity:
        if score is None:
            return Severity.UNKNOWN
        for severity, threshold in self.SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return Severity.NONE


__all__ = ["METRIC_GROUPS", "CVSSResult", "CVSSScorer", "CVSSVector", "Severity", "roundup"]
