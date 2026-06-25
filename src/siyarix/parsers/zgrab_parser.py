# SPDX-License-Identifier: AGPL-3.0-or-later

"""ZGrab application layer protocol scanner output parser — parses JSON results."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")


class ZgrabParser:
    """Parse zgrab JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = data.get("ip", data.get("host", "unknown"))
            domain = data.get("domain", "")
            timestamp = data.get("timestamp", _now_iso())

            inner = data.get("data", data)
            for protocol in (
                "http",
                "https",
                "tls",
                "ssh",
                "ftp",
                "smtp",
                "pop3",
                "imap",
                "modbus",
                "bacnet",
            ):
                proto_data = inner.get(
                    protocol,
                    data.get(f"{protocol}_response", {}).get("result", {}),
                )
                if isinstance(proto_data, dict) and (
                    proto_data.get("status", "") == "success" or bool(proto_data)
                ):
                    findings.extend(
                        self._parse_protocol(protocol, proto_data, ip, domain, timestamp, seen),
                    )

            if not findings and ip:
                banner = data.get("banner", "")
                dedup_key = f"banner:{ip}:{banner[:40]}"
                if banner and dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"Banner: {banner[:40]}",
                            "severity": "info",
                            "description": f"zgrab grabbed banner from {ip}: {banner[:100]}",
                            "evidence": banner[:200],
                            "tool": "zgrab",
                            "target": ip,
                            "timestamp": timestamp,
                        },
                    )

        return findings

    def _parse_protocol(
        self,
        protocol: str,
        data: dict,
        ip: str,
        domain: str,
        timestamp: str,
        seen: set[str],
    ) -> list[dict[str, Any]]:
        r: list[dict[str, Any]] = []
        if protocol == "tls":
            tls_data = data.get("tls", data)
            if tls_data.get("handshake_done"):
                dedup_key = f"tls_handshake:{ip}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    r.append(
                        {
                            "title": f"TLS handshake: {ip}",
                            "severity": "info",
                            "description": f"zgrab completed TLS handshake with {ip}",
                            "evidence": f"TLS handshake done with {ip}",
                            "tool": "zgrab",
                            "target": ip,
                            "timestamp": timestamp,
                        },
                    )
            cert = tls_data.get("certificate", {})
            if isinstance(cert, dict):
                subject = cert.get("subject", {}).get("common_name", [])
                issuer = cert.get("issuer", {}).get("common_name", [])
                cert.get("not_after", "")
                subj_str = ",".join(subject[:2]) if subject else "unknown"
                dedup_key = f"tls_cert:{ip}:{subj_str}"
                if subject and dedup_key not in seen:
                    seen.add(dedup_key)
                    r.append(
                        {
                            "title": f"TLS cert: {subj_str}",
                            "severity": "info",
                            "description": f"zgrab found TLS certificate for {subj_str} issued by {','.join(issuer[:2])}",
                            "evidence": f"Subject: {subj_str} | Issuer: {','.join(issuer[:2])}",
                            "tool": "zgrab",
                            "target": ip,
                            "timestamp": timestamp,
                        },
                    )
            cipher = tls_data.get("cipher_suite", "")
            if cipher:
                dedup_key = f"tls_cipher:{ip}:{cipher}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    r.append(
                        {
                            "title": f"TLS cipher: {cipher}",
                            "severity": "low"
                            if cipher in ("TLS_RSA_WITH_RC4_128", "TLS_RSA_WITH_3DES_EDE_CBC")
                            else "info",
                            "description": f"zgrab detected TLS cipher {cipher} on {ip}",
                            "evidence": f"Cipher: {cipher}",
                            "tool": "zgrab",
                            "target": ip,
                            "timestamp": timestamp,
                        },
                    )
        elif protocol == "http":
            dedup_key = f"http:{ip}"
            if dedup_key in seen:
                return r
            seen.add(dedup_key)
            r.append(
                {
                    "title": f"HTTP: {ip}",
                    "severity": "info",
                    "description": f"zgrab scanned HTTP on {ip}"
                    + (f" (domain: {domain})" if domain else ""),
                    "evidence": f"IP: {ip}" + (f" | Domain: {domain}" if domain else ""),
                    "tool": "zgrab",
                    "target": ip,
                    "timestamp": timestamp,
                },
            )
        elif protocol == "ssh":
            banner = data.get("banner", {}).get("banner", "")
            dedup_key = f"ssh:{ip}:{banner[:40]}" if banner else f"ssh:{ip}"
            if banner and dedup_key not in seen:
                seen.add(dedup_key)
                r.append(
                    {
                        "title": f"SSH: {banner[:40]}",
                        "severity": "info",
                        "description": f"zgrab grabbed SSH banner from {ip}: {banner}",
                        "evidence": f"SSH banner: {banner[:200]}",
                        "tool": "zgrab",
                        "target": ip,
                        "timestamp": timestamp,
                    },
                )

        return r
