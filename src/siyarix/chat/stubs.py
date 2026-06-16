# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stubs for missing modules to satisfy static typing and allow graceful failure.

These classes act as placeholders for advanced enterprise features that
have not yet been implemented in the open-source release.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any
import typing

logger = logging.getLogger(__name__)


class CanaryTokenManager:
    def __init__(self) -> None:
        pass

    def deploy_to_target(self, target: str, _token_types: typing.List[Any]) -> Any:
        return None

    def list(self) -> typing.List[str]:
        return []

    def status(self) -> str:
        return "stubbed"

    def list_tokens(self) -> typing.List[Any]:
        return []

    def summary(self) -> dict[str, Any]:
        return {}


class CoderBridge:
    def __init__(self) -> None:
        pass

    async def generate(self, prompt: str) -> str:
        return ""

    async def review(self, target: str, code: str) -> Any:
        pass


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class CloudScanner:
    def __init__(self) -> None:
        pass

    async def scan_by_provider(self, provider: CloudProvider, target: str) -> Any:
        return {}

    async def scan_kubernetes(self, target: str) -> Any:
        return {}

    async def scan_docker(self, target: str) -> Any:
        return {}

    def generate_report(self, result: Any, fmt: str) -> str:
        return ""


class IaCScanner:
    def __init__(self) -> None:
        pass

    def scan_path(self, path: str) -> Any:
        return {}

    def generate_report(self, result: Any, fmt: str) -> str:
        return ""


class MobileScanner:
    def __init__(self) -> None:
        pass

    def scan_apk(self, target: str) -> Any:
        return {}

    def generate_report(self, result: Any, fmt: str) -> str:
        return ""


class IoTScanner:
    def __init__(self) -> None:
        pass

    def scan_firmware(self, target: str) -> Any:
        return {}

    def scan_serial_port(self, target: str, _baud: int) -> Any:
        return {}

    def generate_report(self, result: Any, fmt: str) -> str:
        return ""


class HSMService:
    def __init__(self) -> None:
        pass

    def connect(self, provider: str) -> None:
        pass

    def status(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def generate_report(self, fmt: str) -> str:
        return ""


class ComplianceRunner:
    def __init__(self) -> None:
        pass

    def run_framework(self, framework: str, target: str) -> Any:
        return {}

    def generate_report(self, result: Any, fmt: str) -> str:
        return ""


class SecurityImporter:
    def __init__(self) -> None:
        pass

    def auto_import(self, path: str) -> Any:
        class Res:
            total_imported: int = 0
            errors: list[Any] = []
            findings: list[Any] = []

        return Res()


security_importer = SecurityImporter()


class PlaybookEngine:
    def __init__(self) -> None:
        pass

    def execute(self, target: str) -> None:
        pass

    def list_playbooks(self) -> list[Any]:
        return []

    def create(self, name: str) -> None:
        pass

    def load(self, name: str) -> Any:
        return None

    def delete(self, name: str) -> bool:
        return False


class CanaryTokenType(Enum):
    WEB = "web"


class VotingStrategy(Enum):
    WEIGHTED = "weighted"


class MultiModelEnsemble:
    def __init__(self) -> None:
        pass

    def run(self, target: str) -> None:
        pass

    def plan(self, instruction: str, _voting_strategy: Any) -> Any:
        return None

    def register_provider(self, name: str, p: Any) -> None:
        pass


class AdversarialSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"


class AdversarialTester:
    def __init__(self) -> None:
        pass

    def test(self, target: str) -> None:
        pass

    def review_plan(self, plan_lines: list[str]) -> list[Any]:
        return []


class ThreatIntelFeed:
    def __init__(self) -> None:
        pass

    def search(self, target: str) -> list[dict[str, Any]]:
        return []

    def list_feeds(self) -> list[dict[str, Any]]:
        return []


class MITREAttackDB:
    def __init__(self) -> None:
        pass

    def search(self, tactic: str) -> list[dict[str, str]]:
        return []

    def list_techniques(self) -> list[dict[str, str]]:
        return []
