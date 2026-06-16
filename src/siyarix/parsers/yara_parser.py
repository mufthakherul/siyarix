# SPDX-License-Identifier: AGPL-3.0-or-later

"""YARA scan output parser — extracts rule matches with offset and string identifier."""

from __future__ import annotations

from . import _now_iso

import re

_RULE_RE = re.compile(r"^(\w+)\s+\[(?:match|offset|addr)\s*[:=]?\s*(\S+)\]", re.IGNORECASE)
_RULE_SIMPLE_RE = re.compile(r"^(\w+)\s*$")
_RULE_DECL_RE = re.compile(r"^rule\s+(\w+)", re.IGNORECASE)
_OFFSET_RE = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)")
_STRING_RE = re.compile(r"\$(\w+)")
_META_RE = re.compile(r"(?:meta|description|author|reference)[:\s]+(.+)", re.IGNORECASE)
_SUMMARY_RE = re.compile(
    r"(?:matches|scanned|rules)[:\s]*(\d+)",
    re.IGNORECASE,
)


class YaraParser:
    """Parse yara scan output into normalized finding dicts."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        target = ""
        current_rule = ""
        current_meta = ""

        for raw in output.splitlines():
            line_stripped = raw.strip()
            if not line_stripped:
                continue

            m = _SUMMARY_RE.search(line_stripped)
            if m:
                key = "summary:match"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"YARA: {m.group(1)} matches",
                            "severity": "info",
                            "description": f"YARA reported {m.group(1)} rule matches",
                            "evidence": raw.strip(),
                            "tool": "yara",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _RULE_RE.match(line_stripped)
            if m:
                current_rule = m.group(1)
                offset_str = m.group(2)
                string_ids = _STRING_RE.findall(line_stripped)
                key = f"rule:{current_rule}:{offset_str}"
                if key not in seen:
                    seen.add(key)
                    description = f"YARA rule match: {current_rule}"
                    if offset_str:
                        description += f" at offset {offset_str}"

                    evidence = raw
                    if string_ids:
                        evidence += f" [strings: {', '.join(string_ids)}]"

                    findings.append(
                        {
                            "title": f"YARA: {current_rule}",
                            "severity": "medium",
                            "description": description,
                            "evidence": evidence,
                            "tool": "yara",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _RULE_DECL_RE.match(line_stripped)
            if m and current_rule == "":
                current_rule = m.group(1)
                key = f"rule:{current_rule}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "title": f"YARA: {current_rule}",
                            "severity": "medium",
                            "description": f"YARA rule match: {current_rule}",
                            "evidence": raw,
                            "tool": "yara",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            m = _RULE_SIMPLE_RE.match(line_stripped)
            if m and current_rule == "":
                current_rule = m.group(1)
                _OFFSET_RE.findall(line_stripped)
                string_ids = _STRING_RE.findall(line_stripped)
                key = f"rule:{current_rule}"
                if key not in seen:
                    seen.add(key)
                    description = f"YARA rule match: {current_rule}"
                    evidence = raw
                    if string_ids:
                        evidence += f" [strings: {', '.join(string_ids)}]"

                    findings.append(
                        {
                            "title": f"YARA: {current_rule}",
                            "severity": "medium",
                            "description": description,
                            "evidence": evidence,
                            "tool": "yara",
                            "target": target,
                            "timestamp": _now_iso(),
                        }
                    )
                continue

            meta_m = _META_RE.search(line_stripped)
            if meta_m and current_rule:
                current_meta = meta_m.group(1).strip()
                if current_meta:
                    key = f"meta:{current_rule}:{current_meta[:40]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            {
                                "title": f"YARA: Metadata — {current_rule}",
                                "severity": "info",
                                "description": f"Rule {current_rule} — {current_meta}",
                                "evidence": raw,
                                "tool": "yara",
                                "target": target,
                                "timestamp": _now_iso(),
                            }
                        )

        return findings
