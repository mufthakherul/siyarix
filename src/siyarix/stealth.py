# SPDX-License-Identifier: AGPL-3.0-or-later

"""Stealth and evasion helpers for scan traffic shaping.

Provides User-Agent rotation, request timing jitter, optional HTTP(S)
proxy selection for child processes, and decoy request *templates*
(returned as dicts — callers must send them).

Proxy chaining does **not** enable Tor by default. Pass an explicit
``proxy_list`` / ``configure_proxies()``, or opt into
``use_assumed_local_tor_proxies()`` (assumes-local-Tor: local Tor SOCKS
on 9050 / Privoxy on 8118; health-checked by default). This is not
network isolation or distributed routing.
"""

from __future__ import annotations

import logging
import random
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


EVASION_LEVELS = {
    "none": {
        "jitter_pct": 0,
        "user_agent_rotate": False,
        "proxy_chain": False,
        "decoy_traffic": False,
    },
    "light": {
        "jitter_pct": 10,
        "user_agent_rotate": True,
        "proxy_chain": False,
        "decoy_traffic": False,
    },
    "medium": {
        "jitter_pct": 30,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": False,
    },
    "heavy": {
        "jitter_pct": 50,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": True,
    },
    "paranoid": {
        "jitter_pct": 80,
        "user_agent_rotate": True,
        "proxy_chain": True,
        "decoy_traffic": True,
    },
}


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.4.0",
    "Wget/1.21.4",
]


# Optional hints only — never injected unless the operator opts in via
# ``use_assumed_local_tor_proxies()`` or an explicit ``proxy_list``.
# assumes-local-Tor: operator must already run Tor/Privoxy (or similar) locally.
ASSUMED_LOCAL_TOR_PROXIES = (
    "socks5://127.0.0.1:9050",  # Tor SOCKS (assumes-local-Tor)
    "http://127.0.0.1:8118",  # Privoxy → Tor (assumes-local-Tor)
    "socks4://127.0.0.1:9050",  # Tor SOCKS4 (assumes-local-Tor)
)

# Backward-compatible alias (empty — do not treat as auto-injected defaults).
PROXY_CHAINS: list[str] = []

DECOY_PAYLOADS = [
    {"path": "/wp-login.php", "method": "POST", "data": "log=admin&pwd=password"},
    {"path": "/.env", "method": "GET"},
    {"path": "/admin/", "method": "GET"},
    {"path": "/api/v1/users", "method": "GET"},
    {"path": "/phpinfo.php", "method": "GET"},
]


def _parse_proxy_host_port(proxy_url: str) -> tuple[str, int] | None:
    """Extract host/port from a proxy URL. Returns None if unparseable."""
    raw = proxy_url.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port
    if port is None:
        scheme = (parsed.scheme or "http").lower()
        if scheme in {"socks5", "socks5h", "socks4", "socks4a"}:
            port = 1080
        elif scheme == "https":
            port = 443
        else:
            port = 8080
    return host, port


def proxy_listener_healthy(proxy_url: str, timeout: float = 0.5) -> bool:
    """Return True if a TCP connect to the proxy host:port succeeds."""
    endpoint = _parse_proxy_host_port(proxy_url)
    if endpoint is None:
        return False
    host, port = endpoint
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@dataclass
class StealthConfig:
    """Configuration for stealth/evasion mode.

    ``proxy_list`` defaults to empty. Enabling medium+ sets
    ``use_proxy_chain`` but does **not** invent localhost Tor/Privoxy
    endpoints — configure proxies explicitly or call
    ``StealthEngine.use_assumed_local_tor_proxies()`` (assumes-local-Tor).
    """

    enabled: bool = False
    evasion_level: str = "none"
    jitter_percentage: int = 0
    rotate_user_agents: bool = False
    use_proxy_chain: bool = False
    use_decoy_traffic: bool = False
    proxy_list: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=lambda: list(USER_AGENTS))
    decoy_payloads: list[dict[str, Any]] = field(default_factory=lambda: list(DECOY_PAYLOADS))
    max_concurrent_decoy_requests: int = 2
    proxy_rotation_interval: int = 60  # seconds
    require_proxy_health_check: bool = True
    proxy_health_timeout: float = 0.5

    def apply_level(self, level: str) -> None:
        config = EVASION_LEVELS.get(level, EVASION_LEVELS["none"])
        self.evasion_level = level
        self.jitter_percentage = config["jitter_pct"]
        self.rotate_user_agents = bool(config["user_agent_rotate"])
        self.use_proxy_chain = bool(config["proxy_chain"])
        self.use_decoy_traffic = bool(config["decoy_traffic"])
        self.enabled = level != "none"

    def score(self) -> float:
        """Calculate a stealth effectiveness score (0-10)."""
        score = 0.0
        if self.jitter_percentage >= 30:
            score += 3.0
        elif self.jitter_percentage >= 10:
            score += 1.5
        if self.rotate_user_agents:
            score += 2.0
        if self.use_proxy_chain and self.proxy_list:
            score += 2.5
        if self.use_decoy_traffic:
            score += 1.5
        if self.evasion_level == "paranoid":
            score = min(score + 1.0, 10.0)
        return round(score, 1)


class StealthEngine:
    """Stealth helpers: UA rotation, jitter, optional proxies, decoy templates."""

    def __init__(self, config: StealthConfig | None = None) -> None:
        self._config = config or StealthConfig()
        self._proxy_index = 0
        self._last_proxy_rotation: float = 0.0
        self._lock = threading.Lock()

    @property
    def config(self) -> StealthConfig:
        return self._config

    def enable(self, level: str = "medium") -> None:
        self._config.apply_level(level)
        logger.info("Stealth mode enabled: %s (score: %.1f/10)", level, self._config.score())
        if self._config.use_proxy_chain and not self._config.proxy_list:
            logger.info(
                "Proxy chain flag set but proxy_list is empty — no proxies injected. "
                "Pass an explicit proxy_list or call use_assumed_local_tor_proxies() "
                "(assumes-local-Tor)."
            )

    def disable(self) -> None:
        self._config.apply_level("none")
        logger.info("Stealth mode disabled")

    def configure_proxies(
        self,
        proxies: list[str],
        *,
        health_check: bool | None = None,
    ) -> list[str]:
        """Set an explicit proxy list; optionally keep only healthy listeners.

        Returns the proxies actually retained. Does not invent localhost Tor
        endpoints — callers must supply URLs.
        """
        check = self._config.require_proxy_health_check if health_check is None else health_check
        if health_check is not None:
            self._config.require_proxy_health_check = health_check
        accepted = self._filter_proxies(list(proxies), health_check=check)
        with self._lock:
            self._config.proxy_list = accepted
            self._config.use_proxy_chain = bool(accepted)
            self._proxy_index = 0
            self._last_proxy_rotation = 0.0
        if not accepted and proxies:
            logger.warning(
                "No proxies accepted from explicit list (health_check=%s); proxy injection disabled",
                check,
            )
        return list(accepted)

    def use_assumed_local_tor_proxies(self, *, health_check: bool = True) -> list[str]:
        """Opt into ASSUMED_LOCAL_TOR_PROXIES (assumes-local-Tor).

        Only retained when ``health_check`` is False or a TCP connect to the
        listener succeeds. Never called automatically by ``enable()``.
        """
        return self.configure_proxies(list(ASSUMED_LOCAL_TOR_PROXIES), health_check=health_check)

    def _filter_proxies(self, proxies: list[str], *, health_check: bool) -> list[str]:
        if not health_check:
            return [p for p in proxies if p and p.strip()]
        healthy: list[str] = []
        for proxy in proxies:
            if not proxy or not proxy.strip():
                continue
            if proxy_listener_healthy(proxy, timeout=self._config.proxy_health_timeout):
                healthy.append(proxy)
            else:
                logger.debug("Skipping unreachable proxy candidate: %s", proxy)
        return healthy

    def get_current_user_agent(self) -> str:
        if not self._config.rotate_user_agents:
            return USER_AGENTS[0]
        return random.choice(self._config.user_agents)

    def get_randomized_delay(self, base_ms: float) -> float:
        if self._config.jitter_percentage <= 0:
            return base_ms
        jitter_range = base_ms * (self._config.jitter_percentage / 100.0)
        return base_ms + random.uniform(-jitter_range, jitter_range)

    def get_current_proxy(self) -> str | None:
        """Return next configured proxy, or None if unset/unverified.

        Never falls back to hardcoded Tor/Privoxy URLs.
        """
        if not self._config.use_proxy_chain:
            return None
        with self._lock:
            if not self._config.proxy_list:
                return None
            rotated = self._rotate_proxy_if_needed()
            if not rotated:
                self._proxy_index = (self._proxy_index + 1) % len(self._config.proxy_list)
            proxy = self._config.proxy_list[self._proxy_index]
            if self._config.require_proxy_health_check and not proxy_listener_healthy(
                proxy, timeout=self._config.proxy_health_timeout
            ):
                logger.warning("Configured proxy unhealthy; skipping injection: %s", proxy)
                return None
            return proxy

    def _rotate_proxy_if_needed(self) -> bool:
        now = time.monotonic()
        if now - self._last_proxy_rotation > self._config.proxy_rotation_interval:
            random.shuffle(self._config.proxy_list)
            self._last_proxy_rotation = now
            self._proxy_index = 0
            return True
        return False

    def get_decoy_requests(self, target: str) -> list[dict[str, Any]]:
        """Build decoy request templates (dicts); does not send traffic."""
        if not self._config.use_decoy_traffic:
            return []
        count = min(self._config.max_concurrent_decoy_requests, len(self._config.decoy_payloads))
        selected = random.sample(self._config.decoy_payloads, count)
        return [
            {
                "url": f"{target.rstrip('/')}{p['path']}",
                "method": p.get("method", "GET"),
                "data": p.get("data", ""),
                "user_agent": self.get_current_user_agent(),
            }
            for p in selected
        ]

    def get_config(self) -> StealthConfig:
        return self._config

    def set_config(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
        self._config.enabled = self._config.evasion_level != "none"

    def set_level(self, level: str) -> None:
        self._config.apply_level(level)

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": self._config.enabled,
            "level": self._config.evasion_level,
            "stealth_score": self._config.score(),
            "jitter_pct": self._config.jitter_percentage,
            "rotate_ua": self._config.rotate_user_agents,
            "proxy_chain": self._config.use_proxy_chain,
            "decoy_traffic": self._config.use_decoy_traffic,
            "proxy_count": (len(self._config.proxy_list) if self._config.use_proxy_chain else 0),
            "user_agents_pool": (
                len(self._config.user_agents) if self._config.rotate_user_agents else 0
            ),
            "require_proxy_health_check": self._config.require_proxy_health_check,
        }


stealth_engine = StealthEngine()

__all__ = [
    "ASSUMED_LOCAL_TOR_PROXIES",
    "EVASION_LEVELS",
    "PROXY_CHAINS",
    "StealthConfig",
    "StealthEngine",
    "proxy_listener_healthy",
    "stealth_engine",
]
