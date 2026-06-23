# SPDX-License-Identifier: AGPL-3.0-or-later

"""SSLyze SSL/TLS configuration scanner output parser — parses JSON output."""

from __future__ import annotations

import json
import re
from typing import Any

from . import _now_iso

_JSON_RE = re.compile(r"^\s*[{\[]")


class SslyzeParser:
    """Parse sslyze JSON output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict[str, Any]]:
        if not output or not output.strip():
            return []
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        if not _JSON_RE.match(output):
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                lower = line.lower()
                for sev in ("error", "warning", "info", "high"):
                    if sev in lower:
                        dedup_key = f"text:{line[:100]}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"SSLyze: {line[:60]}",
                                "severity": "high"
                                if sev == "error"
                                else "medium"
                                if sev in ("warning", "high")
                                else "info",
                                "description": line[:200],
                                "evidence": line.strip(),
                                "tool": "sslyze",
                                "target": "unknown",
                                "timestamp": _now_iso(),
                            },
                        )
                        break
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        server_info = data.get("server_info", data.get("server", {}))
        hostname = server_info.get("hostname", server_info.get("host", "unknown"))
        port = server_info.get(
            "port", server_info.get("network_configuration", {}).get("port", 443),
        )

        results = data.get("results", data.get("scan_results", {}))
        if isinstance(results, list):
            for item in results:
                if isinstance(item, dict):
                    sev = item.get("severity", "info")
                    result_text = item.get("result", "")
                    dedup_key = f"result:{result_text[:80]}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append(
                            {
                                "title": f"SSLyze: {result_text[:60]}",
                                "severity": sev,
                                "description": result_text[:200],
                                "evidence": json.dumps(item),
                                "tool": "sslyze",
                                "target": f"{hostname}:{port}",
                                "timestamp": _now_iso(),
                            },
                        )
        elif isinstance(results, dict):
            for scan_type, scan_result in results.items():
                if isinstance(scan_result, dict):
                    scan_result_data = scan_result.get("result", scan_result)
                    if isinstance(scan_result_data, dict):
                        self._parse_scan_result(
                            scan_type, scan_result_data, hostname, port, findings, seen,
                        )

        return findings

    def _parse_scan_result(
        self, scan_type: str, data: dict, hostname: str, port: int, findings: list, seen: set[str],
    ) -> None:
        if "tls_version" in scan_type or "protocol" in scan_type.lower():
            tls_version = data.get("tls_version", scan_type)
            supports = data.get("supports", data.get("is_protocol_enabled"))
            dedup_key = f"proto:{hostname}:{tls_version}"
            if dedup_key in seen:
                return
            seen.add(dedup_key)
            severity = "info"
            if supports is True:
                if "1.0" in tls_version or "1.1" in tls_version or "ssl" in tls_version.lower():
                    severity = "high"
            elif supports is False:
                severity = "info"
            findings.append(
                {
                    "title": f"SSL/TLS: {tls_version}",
                    "severity": severity,
                    "description": f"sslyze scanned {hostname}:{port} for {tls_version}: supported={supports}",
                    "evidence": f"Protocol: {tls_version} | Supported: {supports}",
                    "tool": "sslyze",
                    "target": f"{hostname}:{port}",
                    "timestamp": _now_iso(),
                },
            )
        elif "cipher" in scan_type.lower():
            accepted_ciphers = data.get("accepted_ciphers", data.get("accepted_cipher_list", []))
            if isinstance(accepted_ciphers, list):
                for cipher in accepted_ciphers:
                    if isinstance(cipher, dict):
                        name = cipher.get("name", cipher.get("cipher", "?"))
                        key_size = cipher.get("key_size", cipher.get("keySize", 0))
                        dedup_key = f"cipher:{hostname}:{name}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        severity = "low" if key_size and int(key_size) < 128 else "info"
                        findings.append(
                            {
                                "title": f"Cipher: {name}",
                                "severity": severity,
                                "description": f"sslyze found accepted cipher {name} ({key_size} bits) on {hostname}:{port}",
                                "evidence": f"Cipher: {name} | Keysize: {key_size}",
                                "tool": "sslyze",
                                "target": f"{hostname}:{port}",
                                "timestamp": _now_iso(),
                            },
                        )
        elif "certificate" in scan_type.lower():
            cert = (
                data.get("certificate", data.get("certificate_chain", [{}]))[0]
                if isinstance(data.get("certificate_chain"), list)
                else data.get("certificate", {})
            )
            if isinstance(cert, dict):
                subject = cert.get("subject", {}).get("CN", cert.get("common_name", "?"))
                issuer = cert.get("issuer", {}).get("CN", "")
                dedup_key = f"cert:{hostname}:{subject}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "title": f"Certificate: {subject}",
                            "severity": "info",
                            "description": f"sslyze found certificate for {subject} issued by {issuer} on {hostname}:{port}",
                            "evidence": f"Subject: {subject} | Issuer: {issuer}",
                            "tool": "sslyze",
                            "target": f"{hostname}:{port}",
                            "timestamp": _now_iso(),
                        },
                    )
