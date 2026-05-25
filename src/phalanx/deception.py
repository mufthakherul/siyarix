"""Deception Tactics Module.

Implements the attacker-facing side of defensive AI: delayed/falsified responses
to scanners, fake service banners, trapdoor credentials in the credential store
that trigger alerts when used.
"""

from __future__ import annotations

import logging
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class DeceptionType(StrEnum):
    HONEYPOT_DETECTION = "honeypot_detection"
    CANARY_TOKEN_DETECTION = "canary_token_detection"
    FAKE_BANNER = "fake_banner"
    DELAYED_RESPONSE = "delayed_response"
    TRAPDOOR_CREDENTIAL = "trapdoor_credential"
    DECOY_SERVICE = "decoy_service"


HONEYPOT_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "nmap-honeypot",
        "pattern": r"Nmap done:\s*\d+ IP addresses",
        "type": "scan_detection",
    },
    {"name": "cowrie-ssh", "pattern": r"SSH-\d+\.\d+-cowrie", "type": "ssh_honeypot"},
    {"name": "dionaea", "pattern": r"SIP/\d+\.\d+/Dionaea", "type": "malware_honeypot"},
    {"name": "honeyd", "pattern": r"220 Honeyd Virtual", "type": "virtual_honeypot"},
    {"name": "glastopf", "pattern": r"Glastopf Web Honeypot", "type": "web_honeypot"},
    {"name": "tpot", "pattern": r"T-Pot\s+\d+\.\d+", "type": "honeypot_platform"},
    {"name": "modern-honeypot-network", "pattern": r"MHN\s+Server", "type": "honeypot_platform"},
]


CANARY_TOKEN_PATTERNS: list[dict[str, Any]] = [
    {"name": "canary-aws-key", "pattern": r"AKIA[0-9A-Z]{16}", "context": "Canary AWS access key"},
    {"name": "canary-dns", "pattern": r"canarytokendns\.", "context": "Canary DNS token"},
    {"name": "canary-url", "pattern": r"canarytokens\.com", "context": "Canary token URL"},
    {"name": "canary-email", "pattern": r"canarytoken@", "context": "Canary email token"},
    {"name": "thinkst-canary", "pattern": r"canary\.thinkst\.com", "context": "Thinkst Canary"},
]


@dataclass
class DeceptionFinding:
    deception_type: DeceptionType
    target: str
    signature_name: str
    confidence: float
    description: str
    evidence: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "deception_type": self.deception_type.value,
            "target": self.target,
            "signature_name": self.signature_name,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence[:200],
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class FakeBannerTemplate:
    service: str
    banner: str
    port: int = 0
    version: str = ""
    os: str = ""


@dataclass
class TrapdoorCredential:
    username: str
    password_hash: str
    service: str
    description: str = ""
    alert_message: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    used: bool = False
    used_at: datetime | None = None
    used_by: str = ""


class HoneypotDetector:
    """Detects honeypots and canary tokens during scanning."""

    def __init__(self) -> None:
        self._findings: list[DeceptionFinding] = []
        self._signatures = HONEYPOT_SIGNATURES
        self._canary_patterns = CANARY_TOKEN_PATTERNS

    def analyze_scan_output(self, output: str, tool: str, target: str) -> list[DeceptionFinding]:
        findings: list[DeceptionFinding] = []
        output_lower = output.lower()

        for sig in self._signatures:
            pattern = sig["pattern"]
            if re.search(pattern, output, re.IGNORECASE):
                finding = DeceptionFinding(
                    deception_type=DeceptionType.HONEYPOT_DETECTION,
                    target=target,
                    signature_name=sig["name"],
                    confidence=0.85,
                    description=f"Honeypot detected: {sig['name']} ({sig['type']}) via {tool}",
                    evidence=output[:500],
                    metadata={"tool": tool, "signature_type": sig["type"]},
                )
                findings.append(finding)
                self._findings.append(finding)
                logger.warning("Honeypot detected on %s: %s", target, sig["name"])

        for pattern in self._canary_patterns:
            if re.search(pattern["pattern"], output_lower, re.IGNORECASE):
                finding = DeceptionFinding(
                    deception_type=DeceptionType.CANARY_TOKEN_DETECTION,
                    target=target,
                    signature_name=pattern["name"],
                    confidence=0.9,
                    description=f"Canary token detected: {pattern['context']}",
                    evidence=output[:500],
                    metadata={"tool": tool},
                )
                findings.append(finding)
                self._findings.append(finding)
                logger.warning("Canary token detected on %s: %s", target, pattern["context"])

        return findings

    def get_findings(self) -> list[DeceptionFinding]:
        return list(self._findings)


class FakeBannerGenerator:
    """Generates fake service banners to mislead scanners."""

    BANNER_TEMPLATES: dict[str, list[FakeBannerTemplate]] = {
        "ssh": [
            FakeBannerTemplate(
                "ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22, "8.9p1", "Ubuntu 22.04"
            ),
            FakeBannerTemplate("ssh", "SSH-2.0-OpenSSH_7.4", 22, "7.4", "CentOS 7"),
            FakeBannerTemplate("ssh", "SSH-2.0-OpenSSH_9.3p1 Debian-3", 22, "9.3p1", "Debian 12"),
        ],
        "http": [
            FakeBannerTemplate("http", "Apache/2.4.57 (Ubuntu)", 80, "2.4.57", "Ubuntu 22.04"),
            FakeBannerTemplate("http", "nginx/1.24.0", 80, "1.24.0", "Linux"),
            FakeBannerTemplate("http", "Microsoft-IIS/10.0", 80, "10.0", "Windows Server 2022"),
        ],
        "mysql": [
            FakeBannerTemplate("mysql", "5.7.42-0ubuntu0.18.04.1", 3306, "5.7.42", "Ubuntu 18.04"),
            FakeBannerTemplate("mysql", "8.0.33", 3306, "8.0.33", "Linux"),
        ],
    }

    @classmethod
    def generate_banner(cls, service: str, os_type: str = "") -> str:
        templates = cls.BANNER_TEMPLATES.get(service.lower(), [])
        if not templates:
            return f"{service} service ready"
        if os_type:
            matching = [t for t in templates if os_type.lower() in t.os.lower()]
            if matching:
                return random.choice(matching).banner
        return random.choice(templates).banner

    @classmethod
    def generate_response_delay(cls, service: str) -> float:
        delays = {
            "ssh": random.uniform(0.1, 0.5),
            "http": random.uniform(0.05, 0.3),
            "mysql": random.uniform(0.05, 0.2),
            "smtp": random.uniform(0.1, 0.8),
            "ftp": random.uniform(0.05, 0.2),
        }
        return delays.get(service.lower(), random.uniform(0.05, 0.5))


class TrapdoorCredentialManager:
    """Manages trapdoor credentials that alert when used."""

    def __init__(self) -> None:
        self._credentials: dict[str, TrapdoorCredential] = {}
        self._alert_callbacks: list[Callable[..., Any]] = []

    def add_trapdoor(
        self,
        username: str,
        password: str,
        service: str,
        description: str = "",
        alert_message: str = "",
    ) -> TrapdoorCredential:
        cred = TrapdoorCredential(
            username=username,
            password_hash=self._hash_password(password),
            service=service,
            description=description or f"Trapdoor credential for {service}",
            alert_message=alert_message or f"Trapdoor credential used: {username}@{service}",
        )
        self._credentials[f"{username}@{service}"] = cred
        logger.info("Trapdoor credential added: %s@%s", username, service)
        return cred

    def check_credential(self, username: str, password: str, service: str) -> bool:
        key = f"{username}@{service}"
        cred = self._credentials.get(key)
        if cred and not cred.used:
            hashed = self._hash_password(password)
            if cred.password_hash == hashed:
                cred.used = True
                cred.used_at = datetime.now()
                logger.warning("TRAPDOOR TRIGGERED: %s", cred.alert_message)
                for cb in self._alert_callbacks:
                    try:
                        cb(cred)
                    except Exception as e:
                        logger.error("Trapdoor callback error: %s", e)
                return True
        return False

    def list_trapdoors(self, include_used: bool = False) -> list[dict[str, Any]]:
        result = []
        for key, cred in self._credentials.items():
            if cred.used and not include_used:
                continue
            result.append(
                {
                    "username": cred.username,
                    "service": cred.service,
                    "description": cred.description,
                    "used": cred.used,
                    "used_at": cred.used_at.isoformat() if cred.used_at else None,
                }
            )
        return result

    def on_alert(self, callback: Callable[..., Any]) -> None:
        self._alert_callbacks.append(callback)

    def _hash_password(self, password: str) -> str:
        import hashlib

        return hashlib.sha256(password.encode()).hexdigest()


__all__ = [
    "HoneypotDetector",
    "FakeBannerGenerator",
    "TrapdoorCredentialManager",
    "DeceptionFinding",
    "DeceptionType",
    "TrapdoorCredential",
]
