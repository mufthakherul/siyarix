# SPDX-License-Identifier: AGPL-3.0-or-later

"""ssh-audit output parser — extracts algorithm details, key exchange, and host key findings."""

from __future__ import annotations

import re
from typing import Any

from . import _now_iso

_FINDING_RE = re.compile(
    r"^[(\[](?P<severity>info|medium|high|fail|warn)[)\]]\s+(?P<finding>.+)",
    re.IGNORECASE,
)
_ALGORITHM_RE = re.compile(
    r"(?:algorithm|kex|key\s*exchange|host\s*key|cipher|mac|compression)[\s:]+(.+)",
    re.IGNORECASE,
)
_KEX_RE = re.compile(r"\[kex\]\s+(.+)", re.IGNORECASE)
_HOST_KEY_RE = re.compile(r"\[host_key\]\s+(.+)", re.IGNORECASE)
_SSH_VERSION_RE = re.compile(r"SSH-\d+\.\d+", re.IGNORECASE)
_TARGET_RE = re.compile(r"(?:Scanning|host)[:\s]+(\S+)", re.IGNORECASE)
_RECOMMEND_RE = re.compile(r"(?i)(recommend|should|avoid|deprecated|weak|strong)")
_SEVERITY_MAP = {
    "info": "info",
    "medium": "medium",
    "high": "high",
    "low": "low",
    "critical": "critical",
    "fail": "high",
    "warn": "medium",
}


class SshAuditParser:
    """Parse ssh-audit output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        target = "unknown"
        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            tm = _TARGET_RE.search(line_stripped)
            if tm:
                target = tm.group(1)

            m = _FINDING_RE.match(line_stripped)
            if m:
                severity_raw = m.group("severity").lower()
                finding_text = m.group("finding").strip()
                severity = _SEVERITY_MAP.get(severity_raw, "info")

                dedup_key = f"finding:{target}:{finding_text[:80]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                title = (
                    finding_text.split("--")[0].strip()
                    if "--" in finding_text
                    else finding_text.split("(")[0].strip()
                )
                if len(title) > 80:
                    title = title[:77] + "..."

                findings.append(
                    {
                        "title": f"ssh-audit: {title}",
                        "severity": severity,
                        "description": f"[{severity_raw}] {finding_text}",
                        "evidence": line_stripped,
                        "tool": "ssh_audit",
                        "target": target,
                        "timestamp": _now_iso(),
                    },
                )
                continue

            km = _KEX_RE.search(line_stripped)
            if km:
                dedup_key = f"kex:{target}:{line_stripped}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    sev = "medium" if _RECOMMEND_RE.search(line_stripped) else "info"
                    findings.append(
                        {
                            "title": "ssh-audit: Key exchange algorithms",
                            "severity": sev,
                            "description": f"Supported KEX algorithms: {km.group(1)}",
                            "evidence": line_stripped,
                            "tool": "ssh_audit",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            hm = _HOST_KEY_RE.search(line_stripped)
            if hm:
                dedup_key = f"hostkey:{target}:{line_stripped}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    sev = "medium" if _RECOMMEND_RE.search(line_stripped) else "info"
                    findings.append(
                        {
                            "title": "ssh-audit: Host key algorithms",
                            "severity": sev,
                            "description": f"Host key algorithms: {hm.group(1)}",
                            "evidence": line_stripped,
                            "tool": "ssh_audit",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )
                continue

            am = _ALGORITHM_RE.search(line_stripped)
            if am:
                dedup_key = f"algo:{target}:{line_stripped}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    sev = "medium" if _RECOMMEND_RE.search(line_stripped) else "info"
                    findings.append(
                        {
                            "title": "ssh-audit: Algorithm info",
                            "severity": sev,
                            "description": f"Algorithm details: {am.group(1)}",
                            "evidence": line_stripped,
                            "tool": "ssh_audit",
                            "target": target,
                            "timestamp": _now_iso(),
                        },
                    )

        return findings
