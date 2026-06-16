# SPDX-License-Identifier: AGPL-3.0-or-later

"""SSLscan output parser — extracts accepted ciphers, certificate info, and protocol support."""

from __future__ import annotations

from . import _now_iso

import re

_ACCEPTED_RE = re.compile(r"\bAccepted\s+\S+")
_CIPHER_RE = re.compile(r"(Accepted|Preferred|Rejected)\s+(\S+(?:\s+\S+)*)")
_CERT_RE = re.compile(
    r"(?:Certificate|Subject|Issuer|Not valid|SHA-1|SHA-256|MD5)[:\s]+(.+)", re.IGNORECASE
)
_PROTOCOL_RE = re.compile(
    r"(TLSv1\.\d|SSLv[23]|SSLv2|SSLv3)\s*:?\s+(supported|disabled|enabled)", re.IGNORECASE
)
_TARGET_RE = re.compile(r"(?:Host|Target)[:\s]+(\S+)", re.IGNORECASE)


class SslscanParser:
    """Parse sslscan output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
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

            pm = _PROTOCOL_RE.search(line_stripped)
            if pm:
                protocol = pm.group(1)
                status = pm.group(2).lower()
                dedup_key = f"proto:{target}:{protocol}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                severity = "info"
                if status == "disabled" and protocol in ("SSLv2", "SSLv3"):
                    severity = "info"
                elif status == "enabled" and protocol in ("SSLv2", "SSLv3"):
                    severity = "high"
                elif status == "supported" and protocol in ("SSLv2", "SSLv3"):
                    severity = "high"

                findings.append(
                    {
                        "title": f"SSLscan: {protocol} {status}",
                        "severity": severity,
                        "description": f"Protocol {protocol} is {status} on {target}",
                        "evidence": line_stripped,
                        "tool": "sslscan",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            cm = _CIPHER_RE.search(line_stripped)
            if cm:
                status_word = cm.group(1)
                cipher = cm.group(2)
                dedup_key = f"cipher:{target}:{cipher}:{status_word}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = "info"
                if status_word == "Accepted":
                    if "NULL" in cipher or "anon" in cipher.lower() or "EXPORT" in cipher:
                        severity = "high"
                    elif "RC4" in cipher or "DES" in cipher or "MD5" in cipher:
                        severity = "medium"

                findings.append(
                    {
                        "title": f"SSLscan: Cipher {status_word} — {cipher}",
                        "severity": severity,
                        "description": f"Cipher {cipher} is {status_word} on {target}",
                        "evidence": line_stripped,
                        "tool": "sslscan",
                        "target": target,
                        "timestamp": _now_iso(),
                    }
                )
                continue

            cm = _CERT_RE.search(line_stripped)
            if cm:
                dedup_key = f"cert:{target}:{line_stripped}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": "SSLscan: Certificate info",
                            "severity": "info",
                            "description": f"Certificate detail: {cm.group(1)}",
                            "evidence": line_stripped,
                            "tool": "sslscan",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

        return findings
