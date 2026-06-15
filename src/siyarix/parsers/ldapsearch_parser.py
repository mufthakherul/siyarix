# SPDX-License-Identifier: AGPL-3.0-or-later

"""ldapsearch output parser — parses LDAP query results in LDIF, JSON, and -LLL formats."""

from __future__ import annotations

import base64
import json
import re

from . import _now_iso

_DN_RE = re.compile(
    r"^(?:dn|DN)\s*[:\-]+\s*(?P<dn>.+)",
    re.IGNORECASE,
)

_ATTR_RE = re.compile(
    r"^(?P<attr>[a-zA-Z][\w\-]*)\s*[:\-]{1,2}\s*(?P<value>.*)",
)

_BINARY_ATTR_RE = re.compile(
    r"^(?P<attr>[a-zA-Z][\w\-]*)\s*::\s*(?P<value>.+)",
)

_CONTINUATION_RE = re.compile(
    r"^\s+(?P<value>.*)",
)

_SEARCH_STATS_RE = re.compile(
    r"#\s*(numEntries|numCompleted|searchResult|numResponses|result)",
    re.IGNORECASE,
)

_RESULT_COUNT_RE = re.compile(
    r"#\s*num(?:Entries|Responses|Completed)\s*:\s*(\d+)",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(
    r"^#\s*(?P<text>.+)",
)

_VERSION_RE = re.compile(r"^#\s*version\s*:\s*\d+", re.IGNORECASE)

_ATTRS = {
    "cn", "sn", "uid", "ou", "dc", "o", "l", "st", "street",
    "postalCode", "telephoneNumber", "mail", "userPassword",
    "member", "memberOf", "description", "displayName",
    "sAMAccountName", "userPrincipalName", "objectClass",
    "objectCategory", "whenCreated", "whenChanged",
    "badPwdCount", "lockoutTime", "pwdLastSet",
    "userAccountControl", "servicePrincipalName",
    "objectGUID", "objectSid", "objectguid", "objectsid",
}

_SEVERITY_MAP: dict[str, str] = {
    "userpassword": "critical",
    "userpassword:": "critical",
    "memberof": "medium",
    "member": "low",
    "serviceprincipalname": "medium",
    "objectguid": "low",
    "objectsid": "low",
    "badpwdcount": "low",
    "lockouttime": "low",
}

_JSON_RE = re.compile(r"^\s*[{\[]")


class LdapsearchParser:
    """Parse ldapsearch output into normalized finding dictionaries."""

    def parse(self, output: str) -> list[dict]:
        findings: list[dict] = []
        stripped = output.strip()
        if not stripped:
            return findings

        seen_dns: set[str] = set()

        if _JSON_RE.match(stripped):
            try:
                data = json.loads(stripped)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    dn = item.get("dn", "")
                    attrs = item.get("attributes", item)
                    if dn:
                        dedup_key = f"dn|{dn}"
                        if dedup_key not in seen_dns:
                            seen_dns.add(dedup_key)
                            findings.append({
                                "title": f"LDAP entry: {dn[:60]}",
                                "severity": "info",
                                "description": f"ldapsearch returned LDAP entry with DN: {dn}",
                                "evidence": dn,
                                "tool": "ldapsearch",
                                "target": dn,
                                "timestamp": _now_iso(),
                            })
                    if isinstance(attrs, dict):
                        for attr, values in attrs.items():
                            if isinstance(values, list):
                                for val in values:
                                    findings.append({
                                        "title": f"LDAP attribute: {attr}",
                                        "severity": _SEVERITY_MAP.get(attr.lower(), "info"),
                                        "description": f"LDAP entry {dn} has {attr}: {str(val)[:100]}",
                                        "evidence": f"{attr}: {str(val)[:200]}",
                                        "tool": "ldapsearch",
                                        "target": dn,
                                        "timestamp": _now_iso(),
                                    })
                return findings
            except json.JSONDecodeError:
                pass

        current_dn = ""
        pending_attr = None
        pending_value = ""
        in_binary = False

        for line in stripped.splitlines():
            stripped_line = line.strip()

            if not stripped_line:
                current_dn = ""
                pending_attr = None
                pending_value = ""
                in_binary = False
                continue

            if _SEARCH_STATS_RE.match(stripped_line):
                rc = _RESULT_COUNT_RE.search(stripped_line)
                if rc:
                    findings.append({
                        "title": f"LDAP result count: {rc.group(1)}",
                        "severity": "info",
                        "description": f"ldapsearch returned {rc.group(1)} entries",
                        "evidence": stripped_line,
                        "tool": "ldapsearch",
                        "target": current_dn or "ldap",
                        "timestamp": _now_iso(),
                    })
                else:
                    findings.append({
                        "title": f"LDAP search result: {stripped_line}",
                        "severity": "info",
                        "description": f"ldapsearch statistics: {stripped_line}",
                        "evidence": stripped_line,
                        "tool": "ldapsearch",
                        "target": current_dn or "ldap",
                        "timestamp": _now_iso(),
                    })
                continue

            if _VERSION_RE.match(stripped_line):
                continue

            if _COMMENT_RE.match(stripped_line) and not current_dn:
                continue

            cm = _CONTINUATION_RE.match(line)
            if cm and pending_attr:
                pending_value += " " + cm.group("value").strip()
                continue

            if pending_attr:
                attr_lower = pending_attr.lower()
                value = pending_value.strip()
                if attr_lower in _ATTRS or attr_lower.replace("-", "").isalpha():
                    severity = _SEVERITY_MAP.get(attr_lower, "info")
                    if attr_lower in ("userpassword",) and len(value) > 40:
                        value_display = value[:40] + "..."
                    else:
                        value_display = value[:100]
                    findings.append({
                        "title": f"LDAP attribute: {pending_attr}",
                        "severity": severity,
                        "description": f"LDAP entry {current_dn} has {pending_attr}: {value_display}",
                        "evidence": f"{pending_attr}: {value[:200]}",
                        "tool": "ldapsearch",
                        "target": current_dn,
                        "timestamp": _now_iso(),
                    })
                pending_attr = None
                pending_value = ""

            bm = _BINARY_ATTR_RE.match(line)
            if bm:
                attr = bm.group("attr")
                b64_val = bm.group("value").strip()
                attr_lower = attr.lower()
                if attr_lower in _ATTRS or attr_lower.replace("-", "").isalpha():
                    try:
                        decoded = base64.b64decode(b64_val)
                        if attr_lower in ("objectguid", "objectsid"):
                            value = b64_val[:24] + "..."
                        else:
                            value = decoded.hex()[:40]
                    except Exception:
                        value = b64_val[:40]
                    severity = _SEVERITY_MAP.get(attr_lower, "info")
                    findings.append({
                        "title": f"LDAP binary attribute: {attr}",
                        "severity": severity,
                        "description": f"LDAP entry {current_dn} has binary {attr} (base64: {b64_val[:20]}...)",
                        "evidence": f"{attr}:: {b64_val[:100]}",
                        "tool": "ldapsearch",
                        "target": current_dn,
                        "timestamp": _now_iso(),
                    })
                current_dn = current_dn or "ldap"
                continue

            m = _DN_RE.match(line)
            if m:
                current_dn = m.group("dn").strip()
                dedup_key = f"dn|{current_dn}"
                if dedup_key not in seen_dns:
                    seen_dns.add(dedup_key)
                    findings.append({
                        "title": f"LDAP entry: {current_dn[:60]}",
                        "severity": "info",
                        "description": f"ldapsearch returned LDAP entry with DN: {current_dn}",
                        "evidence": current_dn,
                        "tool": "ldapsearch",
                        "target": current_dn,
                        "timestamp": _now_iso(),
                    })
                continue

            m = _ATTR_RE.match(line)
            if m:
                attr = m.group("attr")
                value = m.group("value").strip()
                if not value:
                    pending_attr = attr
                    pending_value = ""
                    continue
                attr_lower = attr.lower()
                if attr_lower in _ATTRS or attr_lower.replace("-", "").isalpha():
                    severity = _SEVERITY_MAP.get(attr_lower, "info")
                    if attr_lower in ("userpassword",) and len(value) > 40:
                        value_display = value[:40] + "..."
                    else:
                        value_display = value[:100]
                    findings.append({
                        "title": f"LDAP attribute: {attr}",
                        "severity": severity,
                        "description": f"LDAP entry {current_dn} has {attr}: {value_display}",
                        "evidence": f"{attr}: {value[:200]}",
                        "tool": "ldapsearch",
                        "target": current_dn,
                        "timestamp": _now_iso(),
                    })

        return findings
