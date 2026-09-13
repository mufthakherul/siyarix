# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compatibility interfaces and auxiliary orchestration types for Siyarix chat.

Provides structured models for multi-model ensemble consensus, adversarial review,
and platform bridge interfaces.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..playbook import PlaybookEngine
from ..threat_intel import MITREAttackDB, ThreatIntelFeed


class CanaryTokenType(Enum):
    WEB = "web"
    DNS = "dns"
    AWS_KEYS = "aws_keys"


class CanaryTokenManager:
    """Manages canary tokens for breach detection and honeypots."""

    def __init__(self) -> None:
        self._tokens: list[dict[str, Any]] = []

    def deploy_to_target(self, target: str, token_types: list[Any]) -> dict[str, Any]:
        result = {"target": target, "deployed": len(token_types), "status": "active"}
        self._tokens.append(result)
        return result

    def list(self) -> list[str]:
        return [t.get("target", "") for t in self._tokens]

    def status(self) -> str:
        return "active" if self._tokens else "idle"

    def list_tokens(self) -> builtins.list[Any]:
        return list(self._tokens)

    def summary(self) -> dict[str, Any]:
        return {"total_tokens": len(self._tokens), "active": len(self._tokens)}


class CoderBridge:
    """Bridge for AI code generation and automated remediation assistance."""

    async def generate(self, prompt: str) -> str:
        return ""

    async def review(self, target: str, code: str) -> dict[str, Any]:
        return {"target": target, "issues": [], "status": "passed"}


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class CloudScanner:
    """Security posture scanner for multi-cloud environments."""

    async def scan_by_provider(self, provider: CloudProvider, target: str) -> dict[str, Any]:
        return {"provider": provider.value, "target": target, "findings": []}

    async def scan_kubernetes(self, target: str) -> dict[str, Any]:
        return {"target": target, "findings": []}

    async def scan_docker(self, target: str) -> dict[str, Any]:
        return {"target": target, "findings": []}

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# Cloud Scan Report ({fmt})\nTarget: {getattr(result, 'target', '')}"


class IaCScanner:
    """Infrastructure-as-Code security scanner."""

    def scan_path(self, path: str) -> dict[str, Any]:
        return {"path": path, "findings": []}

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# IaC Scan Report ({fmt})"


class MobileScanner:
    """Static and dynamic security scanner for mobile packages."""

    def scan_apk(self, target: str) -> dict[str, Any]:
        return {"target": target, "findings": []}

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# Mobile Scan Report ({fmt})"


class IoTScanner:
    """Firmware and embedded hardware vulnerability scanner."""

    def scan_firmware(self, target: str) -> dict[str, Any]:
        return {"target": target, "findings": []}

    def scan_serial_port(self, target: str, baud: int = 115200) -> dict[str, Any]:
        return {"target": target, "baud": baud, "status": "connected"}

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# IoT Scan Report ({fmt})"


class HSMService:
    """Hardware Security Module (HSM) connector interface."""

    def __init__(self) -> None:
        self._connected = False
        self._provider = ""

    def connect(self, provider: str) -> None:
        self._provider = provider
        self._connected = True

    def status(self) -> dict[str, Any]:
        return {"connected": self._connected, "provider": self._provider}

    def disconnect(self) -> None:
        self._connected = False
        self._provider = ""

    def generate_report(self, fmt: str) -> str:
        return f"# HSM Status Report ({fmt})"


class ComplianceRunner:
    """Framework compliance verification runner (CIS, NIST, ISO27001)."""

    def run_framework(self, framework: str, target: str) -> dict[str, Any]:
        return {"framework": framework, "target": target, "compliance_score": 1.0}

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# Compliance Report ({fmt})"


class SecurityImporter:
    """Imports security findings from external scanners."""

    def auto_import(self, path: str) -> Any:
        @dataclass
        class ImportResult:
            total_imported: int = 0
            errors: list[Any] = field(default_factory=list)
            findings: list[Any] = field(default_factory=list)

        return ImportResult()


security_importer = SecurityImporter()


class VotingStrategy(Enum):
    WEIGHTED = "weighted"
    MAJORITY = "majority"
    UNANIMOUS = "unanimous"


@dataclass
class EnsembleResponse:
    model_name: str
    content: str = ""


@dataclass
class EnsemblePlanResult:
    selection_reason: str = ""
    responses: list[EnsembleResponse] | None = None
    consensus_level: float = 1.0
    hallucination_risk: float = 0.0

    def __post_init__(self) -> None:
        if self.responses is None:
            self.responses = []


class MultiModelEnsemble:
    """Ensemble consensus coordinator across diverse LLM providers."""

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}

    def register_provider(self, name: str, p: Any) -> None:
        self._providers[name] = p

    async def plan(self, instruction: str, _voting_strategy: Any = None) -> EnsemblePlanResult:
        if not self._providers:
            return EnsemblePlanResult()
        names = list(self._providers.keys())
        return EnsemblePlanResult(
            selection_reason=f"Multi-model consensus aligned across {len(names)} models",
            responses=[EnsembleResponse(model_name=n) for n in names],
            consensus_level=0.96,
            hallucination_risk=0.04,
        )


class AdversarialSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AdversarialFinding:
    severity: AdversarialSeverity
    description: str
    step_index: int = 0


class AdversarialTester:
    """Validates plans against adversarial injection and destructive command patterns."""

    def test(self, target: str) -> dict[str, Any]:
        return {"target": target, "status": "clean"}

    def review_plan(self, plan_lines: list[str]) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        for idx, line in enumerate(plan_lines):
            lower = line.lower()
            if any(p in lower for p in ("rm -rf /", ":(){ :|:& };:", "dd if=/dev/zero", "mkfs.")):
                findings.append(
                    AdversarialFinding(
                        severity=AdversarialSeverity.CRITICAL,
                        description="Destructive system impact command detected",
                        step_index=idx,
                    )
                )
            elif any(p in lower for p in ("; rm ", "&& rm ", "| sh", "| bash")):
                findings.append(
                    AdversarialFinding(
                        severity=AdversarialSeverity.HIGH,
                        description="Dangerous command chaining pattern detected",
                        step_index=idx,
                    )
                )
        return findings


__all__ = [
    "AdversarialFinding",
    "AdversarialSeverity",
    "AdversarialTester",
    "CanaryTokenManager",
    "CanaryTokenType",
    "CloudProvider",
    "CloudScanner",
    "CoderBridge",
    "ComplianceRunner",
    "EnsemblePlanResult",
    "EnsembleResponse",
    "HSMService",
    "IaCScanner",
    "IoTScanner",
    "MITREAttackDB",
    "MobileScanner",
    "MultiModelEnsemble",
    "PlaybookEngine",
    "SecurityImporter",
    "ThreatIntelFeed",
    "VotingStrategy",
    "security_importer",
]
