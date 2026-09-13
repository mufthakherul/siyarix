# SPDX-License-Identifier: AGPL-3.0-or-later

"""Anti-hallucination grounding verification engine.

Cross-validates security claims in LLM synthesis responses (CVE IDs, open ports,
discovered IP addresses, credentials) against raw tool execution outputs and
session findings. Prevents fabricated vulnerabilities and ensures enterprise auditability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GroundingResult:
    """Detailed verification outcome of LLM claims grounded in tool evidence."""

    score: float = 1.0
    verified_cves: list[str] = field(default_factory=list)
    unverified_cves: list[str] = field(default_factory=list)
    verified_ports: list[int] = field(default_factory=list)
    unverified_ports: list[int] = field(default_factory=list)
    verified_ips: list[str] = field(default_factory=list)
    unverified_ips: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)

    @property
    def is_grounded(self) -> bool:
        """True if the verification score is at or above 80% and has no unverified CVEs."""
        return self.score >= 0.8 and len(self.unverified_cves) == 0

    @property
    def total_claims(self) -> int:
        return (
            len(self.verified_cves)
            + len(self.unverified_cves)
            + len(self.verified_ports)
            + len(self.unverified_ports)
            + len(self.verified_ips)
            + len(self.unverified_ips)
        )

    @property
    def summary(self) -> str:
        if self.total_claims == 0:
            return "No verifiable technical claims extracted."
        verified_count = len(self.verified_cves) + len(self.verified_ports) + len(self.verified_ips)
        pct = int(self.score * 100)
        return f"{pct}% Grounded ({verified_count}/{self.total_claims} verified against raw tool evidence)"


class GroundingVerifier:
    """Validates LLM-generated security claims against execution evidence."""

    _CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    _PORT_PATTERN = re.compile(
        r"(?:(?:port|ports?)\s+(\d{1,5})|(\d{1,5})/(?:tcp|udp))\b", re.IGNORECASE
    )
    _IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    _IGNORE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}

    @classmethod
    def verify(
        cls,
        response_text: str,
        execution_outputs: list[str],
        findings: list[dict[str, Any]] | None = None,
    ) -> GroundingResult:
        """Analyze response_text and verify its security claims against tool evidence."""
        findings = findings or []
        evidence_corpus = "\n".join(execution_outputs).lower()

        # Also incorporate findings fields into evidence corpus
        finding_texts = []
        known_finding_ports: set[int] = set()
        known_finding_cves: set[str] = set()
        for f in findings:
            for val in f.values():
                if isinstance(val, (str, int)):
                    finding_texts.append(str(val).lower())
            if "port" in f:
                try:
                    known_finding_ports.add(int(f["port"]))
                except (ValueError, TypeError):
                    pass
            if "cve" in f:
                known_finding_cves.add(str(f["cve"]).upper())
        combined_evidence = f"{evidence_corpus}\n{' '.join(finding_texts)}"

        result = GroundingResult()

        # 1. Verify CVE claims
        cves = {m.upper() for m in cls._CVE_PATTERN.findall(response_text)}
        for cve in sorted(cves):
            if cve.lower() in combined_evidence or cve in known_finding_cves:
                result.verified_cves.append(cve)
                result.citations.append(f"✓ {cve} confirmed in execution logs/findings")
            else:
                result.unverified_cves.append(cve)
                result.advisories.append(
                    f"⚠ Claimed {cve} was not observed in any tool output (potential hallucination)"
                )

        # 2. Verify Port claims (filter to standard 1..65535)
        raw_ports = cls._PORT_PATTERN.findall(response_text)
        ports: set[int] = set()
        for p1, p2 in raw_ports:
            val = p1 or p2
            try:
                port_num = int(val)
                if 1 <= port_num <= 65535:
                    ports.add(port_num)
            except ValueError:
                continue

        for port in sorted(ports):
            # Port is verified if mentioned in port context in output or findings
            port_str = str(port)
            is_in_findings = port in known_finding_ports
            port_patterns = [
                f"{port_str}/tcp",
                f"{port_str}/udp",
                f"port {port_str}",
                f":{port_str} ",
                f":{port_str}\n",
                f":{port_str}\t",
            ]
            if is_in_findings or any(pat in combined_evidence for pat in port_patterns):
                result.verified_ports.append(port)
                result.citations.append(f"✓ Port {port} confirmed open/active in tool output")
            else:
                # Only flag as unverified if the text explicitly states the port is open/vulnerable
                if re.search(
                    rf"\b(open|listening|vulnerable)\b[^\.\n]*?\bport\s+{port_str}\b",
                    response_text,
                    re.IGNORECASE,
                ) or re.search(
                    rf"\bport\s+{port_str}\b[^\.\n]*?\b(open|listening|vulnerable)\b",
                    response_text,
                    re.IGNORECASE,
                ):
                    result.unverified_ports.append(port)
                    result.advisories.append(
                        f"⚠ Claimed open port {port} not found in scan results"
                    )
                else:
                    # Generic mention (e.g. standard port 80/443 reference) - count as verified
                    result.verified_ports.append(port)

        # 3. Verify IP claims
        ips = {ip for ip in cls._IP_PATTERN.findall(response_text) if ip not in cls._IGNORE_IPS}
        for ip in sorted(ips):
            if ip.lower() in combined_evidence:
                result.verified_ips.append(ip)
                result.citations.append(f"✓ IP {ip} confirmed in execution output")
            else:
                result.unverified_ips.append(ip)
                result.advisories.append(f"⚠ IP {ip} was not observed in tool output")

        # 4. Compute overall score
        total = result.total_claims
        if total == 0:
            result.score = 1.0
        else:
            verified = (
                len(result.verified_cves) + len(result.verified_ports) + len(result.verified_ips)
            )
            result.score = round(verified / total, 2)

        return result

    @classmethod
    def append_audit_to_response(cls, response_text: str, result: GroundingResult) -> str:
        """Append an enterprise evidence audit badge to the response text."""
        if result.total_claims == 0:
            return response_text

        lines = ["\n\n---", "### 🛡 Grounding Verification Audit"]
        if result.is_grounded:
            lines.append(f"**Status:** `[VERIFIED]` ({result.summary})")
        else:
            lines.append(f"**Status:** `[UNVERIFIED CLAIMS DETECTED]` ({result.summary})")

        if result.advisories:
            lines.append("\n**Verification Warnings:**")
            for adv in result.advisories:
                lines.append(f"- {adv}")

        if result.citations:
            lines.append("\n**Evidence Citations:**")
            for cit in result.citations[:6]:
                lines.append(f"- {cit}")
            if len(result.citations) > 6:
                lines.append(f"- *...and {len(result.citations) - 6} more verified citations*")

        return response_text + "\n" + "\n".join(lines)
