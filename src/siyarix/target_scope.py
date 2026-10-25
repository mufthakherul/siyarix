# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorized target-scope validation for executor commands.

Enforces ``SIYARIX_ALLOWED_SCOPE`` fail-closed: every IP (v4/v6) and domain
found in a command must be explicitly covered by the configured scope.
CIDR-only scopes never silently allow domains; there are no hardcoded
public-domain exemptions.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable

from .exceptions import PermissionDeniedError

__all__ = [
    "assert_command_in_scope",
    "domain_in_scope",
    "extract_targets",
    "ip_in_scope",
    "parse_allowed_scope",
]

# IPv4 dotted-quad (bounded octets to reduce false positives).
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Bracketed IPv6 literals: https://[2001:db8::1]/80
_IPV6_BRACKETED_RE = re.compile(r"\[([0-9a-fA-F:]+)\]")

# Unbracketed IPv6 candidates (validated via ipaddress).
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])"
)

# Hostnames with a TLD; also match bare "localhost".
_DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|localhost)\b"
)

# Scope entry that is purely an IP or CIDR (not a domain / wildcard).
_IP_OR_CIDR_RE = re.compile(
    r"^(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"  # IPv4 / CIDR
    r"|[0-9a-fA-F:]+(?:/\d{1,3})?"  # IPv6 / CIDR
    r")$"
)


def parse_allowed_scope(scope_env: str | None = None) -> list[str]:
    """Parse ``SIYARIX_ALLOWED_SCOPE`` (comma-separated) into normalized items."""
    raw = scope_env if scope_env is not None else os.environ.get("SIYARIX_ALLOWED_SCOPE", "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def extract_targets(command: str) -> tuple[list[str], list[str]]:
    """Extract IP addresses and domain names referenced in *command*.

    Returns ``(ips, domains)`` with lowercase domains and string IP forms.
    IPv6 addresses are recognized in both bracketed and bare form.
    """
    ips: list[str] = []
    seen_ips: set[str] = set()

    def _add_ip(candidate: str) -> None:
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            return
        if normalized not in seen_ips:
            seen_ips.add(normalized)
            ips.append(normalized)

    for match in _IPV4_RE.findall(command):
        _add_ip(match)

    for match in _IPV6_BRACKETED_RE.findall(command):
        _add_ip(match)

    # Strip bracketed spans so bare IPv6 scan does not re-parse them oddly.
    scrubbed = _IPV6_BRACKETED_RE.sub(" ", command)
    # Avoid treating IPv4 as IPv6 candidates.
    scrubbed = _IPV4_RE.sub(" ", scrubbed)
    for match in _IPV6_CANDIDATE_RE.findall(scrubbed):
        _add_ip(match)

    domains: list[str] = []
    seen_domains: set[str] = set()
    for match in _DOMAIN_RE.findall(command):
        domain = match.lower()
        # Skip tokens that are valid IPs (e.g. odd parses).
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        if domain not in seen_domains:
            seen_domains.add(domain)
            domains.append(domain)

    return ips, domains


def ip_in_scope(ip_str: str, allowed_items: Iterable[str]) -> bool:
    """Return True if *ip_str* is covered by an exact IP or CIDR in *allowed_items*."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for allowed in allowed_items:
        if "/" in allowed:
            try:
                net = ipaddress.ip_network(allowed, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        else:
            try:
                if ip == ipaddress.ip_address(allowed):
                    return True
            except ValueError:
                continue
    return False


def domain_in_scope(domain: str, allowed_items: Iterable[str]) -> bool:
    """Return True only when *domain* matches an explicit domain scope entry.

    CIDR / IP-only scope entries never authorize a domain (fail-closed; no
    silent expansion via DNS or public allow-lists).
    """
    domain = domain.lower().rstrip(".")
    for allowed in allowed_items:
        if _IP_OR_CIDR_RE.match(allowed):
            continue
        if allowed.startswith("*."):
            suffix = allowed[1:]  # ".example.com"
            if domain.endswith(suffix) or domain == allowed[2:]:
                return True
        elif domain == allowed:
            return True
    return False


def assert_command_in_scope(command: str, scope_env: str | None = None) -> None:
    """Raise :class:`PermissionDeniedError` if any target is outside authorized scope.

    When scope is unset or empty, this is a no-op (caller decides policy).
    """
    allowed_items = parse_allowed_scope(scope_env)
    if not allowed_items:
        return

    scope_display = (
        scope_env if scope_env is not None else os.environ.get("SIYARIX_ALLOWED_SCOPE", "")
    )
    found_ips, found_domains = extract_targets(command)

    for ip_str in found_ips:
        if not ip_in_scope(ip_str, allowed_items):
            raise PermissionDeniedError(
                f"Target IP {ip_str} is out of authorized scope: {scope_display}"
            )

    for domain in found_domains:
        if not domain_in_scope(domain, allowed_items):
            raise PermissionDeniedError(
                f"Target domain {domain} is out of authorized scope: {scope_display}"
            )
