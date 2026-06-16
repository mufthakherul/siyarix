# SPDX-License-Identifier: AGPL-3.0-or-later

"""Certipy output parser — extracts certificate templates, CA info, ESC vulnerabilities and PKCS12 output."""

from __future__ import annotations

from . import _now_iso

import re

_SUCCESS_RE = re.compile(r"^\[\*\]\s*(.*)")
_TEMPLATE_RE = re.compile(r"(?:Template|Certificate\s+Template)[:\s]+(.+)", re.IGNORECASE)
_CA_INFO_RE = re.compile(
    r"(?:CA\s+Name|Certificate\s+Authority|CA\s+Server)[:\s]+(.+)", re.IGNORECASE
)
_PKCS12_RE = re.compile(
    r"(?:Saved\s+)?(?:PKCS12|\.p12|certificate|\.pfx)\s*(?:to|file)?[:\s]*(\S+)", re.IGNORECASE
)
_ESC_RE = re.compile(r"(ESC[0-9]+)", re.IGNORECASE)
_VULN_RE = re.compile(r"(?:Vulnerable|vuln|VULN|weakness)", re.IGNORECASE)
_UID_RE = re.compile(r"(?:User\s*ID|User\s*Principal|UPN|User)[:\s]+(\S+)", re.IGNORECASE)

_JSON_RE = re.compile(r"^\s*[{\[]")


class CertipyParser:
    """Parse Certipy output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        target = "unknown"
        stripped = output.strip()
        if not stripped:
            return findings

        seen_templates: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                import json

                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    template = item.get("template", item.get("CertificateTemplate", ""))
                    ca = item.get("ca", item.get("CA", ""))
                    esc = item.get("vulnerability", item.get("esc", ""))
                    if template:
                        dedup_key = f"template|{template}"
                        if dedup_key in seen_templates:
                            continue
                        seen_templates.add(dedup_key)
                        severity = "high"
                        if esc:
                            esc_upper = esc.upper()
                            if esc_upper in ("ESC8", "ESC1"):
                                severity = "critical"
                        findings.append(
                            {
                                "title": f"Certipy: Certificate template — {template}",
                                "severity": severity,
                                "description": json.dumps(item),
                                "evidence": json.dumps(item),
                                "tool": "certipy",
                                "target": ca or target,
                                "timestamp": _now_iso(),
                            }
                        )
                return findings
            except json.JSONDecodeError:
                pass

        lines = output.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            m = _SUCCESS_RE.match(line_stripped)
            if m:
                msg = m.group(1)

                esc_m = _ESC_RE.search(msg)
                if esc_m:
                    esc_id = esc_m.group(1)
                    severity = "high"
                    if esc_id.upper() in ("ESC8", "ESC1"):
                        severity = "critical"
                    dedup_key = f"esc|{esc_id}"
                    if dedup_key not in seen_templates:
                        seen_templates.add(dedup_key)
                        findings.append(
                            {
                                "title": f"Certipy: {esc_id} vulnerability detected",
                                "severity": severity,
                                "description": f"AD CS vulnerability {esc_id}: {msg}",
                                "evidence": line_stripped,
                                "tool": "certipy",
                                "target": target,
                                "timestamp": _now_iso(),
                            }
                        )

                if _VULN_RE.search(msg):
                    findings.append(
                        {
                            "title": "Certipy: Vulnerable certificate template",
                            "severity": "high",
                            "description": f"Vulnerable certificate template found: {msg}",
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

                if "enabled" in msg.lower():
                    findings.append(
                        {
                            "title": "Certipy: Feature enabled",
                            "severity": "info",
                            "description": msg,
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

                tm = _TEMPLATE_RE.search(msg)
                if tm:
                    tpl_name = tm.group(1).strip()
                    dedup_key = f"template|{tpl_name}"
                    if dedup_key not in seen_templates:
                        seen_templates.add(dedup_key)
                        findings.append(
                            {
                                "title": f"Certipy: Certificate template — {tpl_name}",
                                "severity": "info",
                                "description": msg,
                                "evidence": line_stripped,
                                "tool": "certipy",
                                "target": target,
                                "timestamp": _now_iso(),
                            }
                        )

                cm = _CA_INFO_RE.search(msg)
                if cm:
                    findings.append(
                        {
                            "title": f"Certipy: CA — {cm.group(1)}",
                            "severity": "info",
                            "description": msg,
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

                pm = _PKCS12_RE.search(msg)
                if pm:
                    findings.append(
                        {
                            "title": f"Certipy: PKCS12 certificate — {pm.group(1)}",
                            "severity": "high",
                            "description": f"PKCS12 certificate saved/loaded: {pm.group(1)}",
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

                uid_m = _UID_RE.search(msg)
                if uid_m:
                    findings.append(
                        {
                            "title": f"Certipy: User identifier — {uid_m.group(1)}",
                            "severity": "info",
                            "description": msg,
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

            if "Got certificate" in line_stripped or "certificate" in line_stripped.lower():
                pm = _PKCS12_RE.search(line_stripped)
                if pm:
                    findings.append(
                        {
                            "title": f"Certipy: Certificate obtained — {pm.group(1)}",
                            "severity": "high",
                            "description": f"Certificate retrieved: {pm.group(1)}",
                            "evidence": line_stripped,
                            "tool": "certipy",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )

        return findings
