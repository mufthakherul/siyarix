# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook and Auto-Remediation dispatching for Siyarix.

This module pushes real-time alerts to SIEMs or team chats (Slack/Discord)
and generates auto-remediation scripts for Blue Teams.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.parse
import urllib.request
import urllib.error
import os
from typing import Any

from siyarix.events import get_event_bus, Event, EventType

logger = logging.getLogger(__name__)


_BLOCKED_WEBHOOK_HOSTS = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)


def _validate_url(url: str, *, allow_ip: bool = False) -> None:
    """Validate webhook destination URL (scheme + anti-SSRF host checks).

    Rejects IP literals by default (including private/link-local/metadata),
    loopback hostnames, and well-known cloud metadata DNS names.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"URL scheme must be https, got: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not include embedded credentials (userinfo)")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("URL must include a hostname")
    if host in _BLOCKED_WEBHOOK_HOSTS or host.endswith(".localhost"):
        raise ValueError(f"Blocked webhook hostname: {host}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if not allow_ip:
            raise ValueError(f"IP address hostname not allowed: {host}")
        if _is_blocked_ip(ip):
            raise ValueError(f"Blocked destination IP range: {host}")
        return

    # Resolve DNS and reject hosts that point at private/metadata ranges (SSRF).
    try:
        import socket

        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise ValueError(f"Unable to resolve webhook hostname: {host}") from exc

    for info in infos:
        sockaddr = info[4]
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise ValueError(f"Webhook hostname resolves to blocked IP: {host} -> {resolved}")


# RFC6598 CGNAT + RFC2544 benchmarking ranges are not covered by is_private.
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
)


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x) so CGNAT/metadata checks apply
    # to the embedded v4 address rather than the IPv4-mapped reserved range.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    return any(ip in net for net in _EXTRA_BLOCKED_NETWORKS)


def _resolve_public_ips(host: str, port: int = 443) -> list[str]:
    """Resolve *host* and return public IPs only (raises if any answer is blocked)."""
    import socket

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"Unable to resolve webhook hostname: {host}") from exc

    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise ValueError(f"Webhook hostname resolves to blocked IP: {host} -> {resolved}")
        text = str(resolved)
        if text not in ips:
            ips.append(text)
    if not ips:
        raise ValueError(f"Unable to resolve webhook hostname: {host}")
    return ips


def _https_request_pinned(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
) -> bytes:
    """HTTPS request after SSRF checks, connecting to a pinned resolved IP.

    DNS is resolved under policy; TCP/TLS targets that IP while SNI/Host keep the
    original hostname — shrinking DNS-rebinding TOCTOU. Redirects are not followed.
    """
    import http.client
    import socket
    import ssl

    _validate_url(url, allow_ip=False)
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Re-validate immediately before connect (hostname policy + fresh DNS).
    _validate_url(url, allow_ip=False)
    target_ip = _resolve_public_ips(host, port)[0]

    req_headers = {"Host": host, "User-Agent": "Siyarix/1.0"}
    if headers:
        req_headers.update(headers)

    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)

    def _pinned_connect() -> None:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        conn.sock = context.wrap_socket(sock, server_hostname=host)

    conn.connect = _pinned_connect  # type: ignore[method-assign]
    try:
        conn.request(method.upper(), path, body=body, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read()
        # Refuse redirects and errors — callers must not chase Location (SSRF).
        if resp.status >= 300:
            raise urllib.error.URLError(f"HTTPS {resp.status} for {host}{path}")
        return data
    finally:
        conn.close()


def _https_post_json_pinned(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
) -> None:
    """POST JSON to *url* via :func:`_https_request_pinned`."""
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    _https_request_pinned(
        url,
        method="POST",
        body=json.dumps(payload).encode("utf-8"),
        timeout=timeout,
        headers=req_headers,
    )


class WebhookDispatcher:
    """Dispatches alerts and remediation scripts to external services."""

    def __init__(self) -> None:
        self.webhook_url = os.getenv("SIYARIX_WEBHOOK_URL")
        self.bus = get_event_bus()
        self.bus.on(None, self._on_event)

    async def _on_event(self, event: Event) -> None:
        if event.type != EventType.CUSTOM:
            return
        if event.data.get("sub_type") == "finding":
            finding = event.data.get("finding", {})
            severity = finding.get("severity", "info").lower()
            if severity in ("high", "critical"):
                await self._dispatch_alert(finding)

    async def _dispatch_alert(self, finding: dict[str, Any]) -> None:
        """Async alert dispatch."""
        await self.dispatch_alert(finding)

    async def dispatch_alert(self, finding: dict[str, Any]) -> None:
        """Send an alert to the configured webhook."""
        if not self.webhook_url:
            logger.debug("No SIYARIX_WEBHOOK_URL configured. Skipping alert.")
            return

        remediation = self.generate_remediation(finding)

        payload = {
            "text": f"🚨 **CRITICAL VULNERABILITY DETECTED** 🚨\n"
            f"**Target:** {finding.get('target', 'Unknown')}\n"
            f"**Type:** {finding.get('type', finding.get('title', 'Unknown'))}\n"
            f"**Auto-Remediation Script:**\n```bash\n{remediation}\n```"
        }

        try:
            _https_post_json_pinned(self.webhook_url, payload, timeout=5.0)
            logger.info("Webhook alert dispatched for %s", finding.get("id", "vuln"))
        except ValueError as e:
            logger.error("Webhook URL rejected by SSRF policy: %s", e)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            logger.error("Failed to dispatch webhook: %s", e)

    def generate_remediation(self, finding: dict[str, Any]) -> str:
        """Generate a basic auto-remediation script based on the finding type."""
        f_type = str(finding.get("type", finding.get("title", ""))).lower()

        if "sql injection" in f_type:
            return "# Remediation: Use parameterized queries (Prepared Statements) in your application code."
        elif "xss" in f_type or "cross-site scripting" in f_type:
            return "# Remediation: Implement strict Content Security Policy (CSP) and sanitize HTML inputs."
        elif "open port" in f_type or "ssh" in f_type:
            return "sudo ufw deny 22/tcp\n# Or configure iptables to drop unauthorized SSH traffic."
        elif "outdated" in f_type or "cve-" in f_type:
            return (
                "sudo apt-get update && sudo apt-get upgrade -y\n# Ensure all packages are patched."
            )
        else:
            return "# Remediation script generation requires manual review for this vulnerability."


# Global singleton
webhook_dispatcher = WebhookDispatcher()
