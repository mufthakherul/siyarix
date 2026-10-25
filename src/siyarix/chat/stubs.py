# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compatibility stubs and auxiliary orchestration types for Siyarix chat.

WARNING: Most scanner / HSM / canary / importer classes in this module are
intentionally incomplete placeholders that return empty results. Do not treat
them as production security capabilities. Prefer real modules
(``compliance.py``, ``threat_intel.py``, ``providers.manager.ensemble_decide``)
where they exist. Product docs must label these surfaces as Planned.
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


_NOT_IMPLEMENTED = "not_implemented"


def _stub_result(**kwargs: Any) -> dict[str, Any]:
    """Mark stub scanner results so callers cannot treat empty as clean."""
    out: dict[str, Any] = {"status": _NOT_IMPLEMENTED, "findings": [], "implemented": False}
    out.update(kwargs)
    return out


class CanaryTokenManager:
    """Stub — canary/honeypot deployment is not implemented."""

    def __init__(self) -> None:
        self._tokens: list[dict[str, Any]] = []

    def deploy_to_target(self, target: str, token_types: list[Any]) -> dict[str, Any]:
        result = _stub_result(
            target=target,
            deployed=0,
            requested=len(token_types),
            message="CanaryTokenManager is a stub; no tokens were deployed",
        )
        self._tokens.append(result)
        return result

    def list(self) -> list[str]:
        return []

    def status(self) -> str:
        return _NOT_IMPLEMENTED

    def list_tokens(self) -> builtins.list[Any]:
        return list(self._tokens)

    def summary(self) -> dict[str, Any]:
        return {"total_tokens": 0, "active": 0, "status": _NOT_IMPLEMENTED}


class CoderBridge:
    """Stub — AI code generation bridge is not implemented."""

    async def generate(self, prompt: str) -> str:
        return ""

    async def review(self, target: str, code: str) -> dict[str, Any]:
        return {
            "target": target,
            "issues": [],
            "status": _NOT_IMPLEMENTED,
            "implemented": False,
        }


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class CloudScanner:
    """Stub — multi-cloud posture scanning is not implemented."""

    async def scan_by_provider(self, provider: CloudProvider, target: str) -> dict[str, Any]:
        return _stub_result(provider=provider.value, target=target)

    async def scan_kubernetes(self, target: str) -> dict[str, Any]:
        return _stub_result(target=target)

    async def scan_docker(self, target: str) -> dict[str, Any]:
        return _stub_result(target=target)

    def generate_report(self, result: Any, fmt: str) -> str:
        return (
            f"# Cloud Scan Report ({fmt})\n"
            f"Status: not_implemented\n"
            f"Target: {getattr(result, 'target', result.get('target', '') if isinstance(result, dict) else '')}\n"
        )


class IaCScanner:
    """Stub — IaC scanning is not implemented."""

    def scan_path(self, path: str) -> dict[str, Any]:
        return _stub_result(path=path)

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# IaC Scan Report ({fmt})\nStatus: not_implemented\n"


class MobileScanner:
    """Stub — mobile package scanning is not implemented."""

    def scan_apk(self, target: str) -> dict[str, Any]:
        return _stub_result(target=target)

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# Mobile Scan Report ({fmt})\nStatus: not_implemented\n"


class IoTScanner:
    """Stub — firmware/IoT scanning is not implemented."""

    def scan_firmware(self, target: str) -> dict[str, Any]:
        return _stub_result(target=target)

    def scan_serial_port(self, target: str, baud: int = 115200) -> dict[str, Any]:
        return _stub_result(target=target, baud=baud, connected=False)

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# IoT Scan Report ({fmt})\nStatus: not_implemented\n"


class HSMService:
    """Stub — HSM connector is not implemented (see docs/security/hsm-integration.md)."""

    def __init__(self) -> None:
        self._connected = False
        self._provider = ""

    def connect(self, provider: str) -> None:
        self._provider = provider
        self._connected = False  # stub never connects

    def status(self) -> dict[str, Any]:
        return {
            "connected": False,
            "provider": self._provider,
            "status": _NOT_IMPLEMENTED,
            "implemented": False,
        }

    def disconnect(self) -> None:
        self._connected = False
        self._provider = ""

    def generate_report(self, fmt: str) -> str:
        return f"# HSM Status Report ({fmt})\nStatus: not_implemented\n"


class ComplianceRunner:
    """Stub — prefer siyarix.compliance for real local hygiene probes."""

    def run_framework(self, framework: str, target: str) -> dict[str, Any]:
        return _stub_result(
            framework=framework,
            target=target,
            compliance_score=None,
            message="Use siyarix.compliance ComplianceCheck for real probes",
        )

    def generate_report(self, result: Any, fmt: str) -> str:
        return f"# Compliance Report ({fmt})\nStatus: not_implemented\n"


class SecurityImporter:
    """Stub — external finding import is not implemented."""

    def auto_import(self, path: str) -> Any:
        @dataclass
        class ImportResult:
            total_imported: int = 0
            errors: list[Any] = field(
                default_factory=lambda: ["SecurityImporter is not_implemented"]
            )
            findings: list[Any] = field(default_factory=list)
            status: str = _NOT_IMPLEMENTED

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
    """Stub ensemble — prefer ``ProviderManager.ensemble_decide`` for real voting."""

    def __init__(self) -> None:
        self._providers: dict[str, Any] = {}

    def register_provider(self, name: str, p: Any) -> None:
        self._providers[name] = p

    async def plan(self, instruction: str, _voting_strategy: Any = None) -> EnsemblePlanResult:
        names = list(self._providers.keys())
        return EnsemblePlanResult(
            selection_reason=(
                "stub MultiModelEnsemble — use ProviderManager.ensemble_decide "
                "for real multi-model consensus"
            ),
            responses=[EnsembleResponse(model_name=n) for n in names],
            consensus_level=0.0,
            hallucination_risk=1.0,
        )


class AdversarialSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AdversarialFinding:
    severity: AdversarialSeverity
    message: str
    suggestion: str = ""
    step_index: int = 0

    @property
    def description(self) -> str:
        """Backward-compatible alias for ``message``."""
        return self.message


class AdversarialTester:
    """Validates plans against adversarial injection and destructive command patterns."""

    def test(self, target: str) -> dict[str, Any]:
        """Host/target scanning is not implemented — use ``review_plan`` for plan lines."""
        return {
            "target": target,
            "status": "not_implemented",
            "implemented": False,
            "message": (
                "AdversarialTester.test() does not scan hosts; "
                "use review_plan() for plan-line checks"
            ),
        }

    def review_plan(self, plan_lines: list[str]) -> list[AdversarialFinding]:
        findings: list[AdversarialFinding] = []
        for idx, line in enumerate(plan_lines):
            lower = line.lower()
            if any(
                p in lower
                for p in (
                    "rm -rf /",
                    "rm -fr /",
                    "rm --recursive",
                    ":(){ :|:& };:",
                    "dd if=/dev/zero",
                    "of=/dev/",
                    "mkfs.",
                    "mkfs ",
                    "fdisk ",
                    "parted ",
                    "ntfsformat",
                    "mkntfs",
                    "newfs",
                    "rsync ",
                )
            ):
                findings.append(
                    AdversarialFinding(
                        severity=AdversarialSeverity.CRITICAL,
                        message="Destructive system impact command detected",
                        suggestion="Remove destructive filesystem/device commands from the plan.",
                        step_index=idx,
                    )
                )
            elif any(p in lower for p in ("; rm ", "&& rm ", "| sh", "| bash")):
                findings.append(
                    AdversarialFinding(
                        severity=AdversarialSeverity.HIGH,
                        message="Dangerous command chaining pattern detected",
                        suggestion="Avoid shell chaining that can escalate into destructive side effects.",
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
