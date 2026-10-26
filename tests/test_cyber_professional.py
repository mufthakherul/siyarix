from __future__ import annotations

import os

import pytest

from siyarix.executor import BaseExecutor, PermissionDeniedError
from siyarix.models import PlanStep
from siyarix.nlp_engine import NaturalLanguageParser
from siyarix.output import OutputEngine, OutputFormat


class MockExecutor(BaseExecutor):
    async def _execute_step(self, step: PlanStep) -> dict:
        return {"status": "success"}


def test_target_normalization():
    nlp = NaturalLanguageParser()
    assert nlp.normalize_target("https://target.com/", "url") == "https://target.com"
    assert nlp.normalize_target("TARGET.local.", "domain") == "target.local"
    assert nlp.normalize_target("[10.0.0.1]", "ipv4") == "10.0.0.1"


def test_cyber_parameters_extraction():
    nlp = NaturalLanguageParser()
    params = nlp.extract_parameters(
        "scan 192.168.1.1 -p 80,443 --threads 16 ua 'Mozilla/5.0' cookie 'session=abc' verbosity high"
    )
    assert params.get("ports") == "80,443"
    assert params.get("threads") == "16"
    assert params.get("user_agent") == "mozilla/5.0"
    assert params.get("cookie") == "session=abc"
    assert params.get("verbosity") == "high"


@pytest.mark.asyncio
async def test_scope_enforcement():
    executor = MockExecutor()
    os.environ["SIYARIX_ALLOWED_SCOPE"] = "192.168.1.0/24,target.local"

    # Allowed IP
    step_allowed_ip = PlanStep(tool="nmap", command="nmap 192.168.1.5")
    await executor._check_permissions(step_allowed_ip)  # should pass

    # Forbidden IP
    step_forbidden_ip = PlanStep(tool="nmap", command="nmap 10.0.0.1")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_forbidden_ip)
    assert "out of authorized scope" in str(exc_info.value)

    # Allowed Domain
    step_allowed_domain = PlanStep(tool="nmap", command="nmap target.local")
    await executor._check_permissions(step_allowed_domain)  # should pass

    # Forbidden Domain
    step_forbidden_domain = PlanStep(tool="nmap", command="nmap untrusted.com")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_forbidden_domain)
    assert "out of authorized scope" in str(exc_info.value)

    # Clean up
    del os.environ["SIYARIX_ALLOWED_SCOPE"]


@pytest.mark.asyncio
async def test_destructive_command_blocking():
    executor = MockExecutor()

    # Fork bomb
    step_fork = PlanStep(tool="bash", command=":(){ :|:& };:")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_fork)
    assert "Fork bomb" in str(exc_info.value)

    # DD writing block device
    step_dd = PlanStep(tool="dd", command="dd if=/dev/zero of=/dev/sda bs=1M")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_dd)
    assert "Overwriting block devices" in str(exc_info.value)

    # Recursive delete of system dir
    step_rm = PlanStep(tool="bash", command="rm -rf /etc/passwd")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_rm)
    assert "Deleting system directory" in str(exc_info.value)

    # Storage formatting
    step_mkfs = PlanStep(tool="mkfs", command="mkfs.ext4 -d /dev/sda1")
    with pytest.raises(PermissionDeniedError) as exc_info:
        await executor._check_permissions(step_mkfs)
    assert "Formatting storage devices" in str(exc_info.value)


def test_output_engine_reporting_methods():
    engine = OutputEngine(output_format=OutputFormat.TABLE)

    # Verify these do not throw exceptions
    engine.print_mitre_mapping(
        [{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery", "tool": "nmap"}]
    )

    engine.print_finding_panel(
        {
            "title": "SQL Injection",
            "cve": "CVE-2023-xxxx",
            "cvss": "9.8",
            "description": "SQL injection vulnerability in endpoint",
            "poc": "SELECT * FROM users WHERE id = 1'",
            "remediation": "Use parameterized queries.",
            "severity": "Critical",
        }
    )

    engine.print_timeline(
        [
            {
                "timestamp": "2026-07-03 00:00:00",
                "source": "auth.log",
                "event_type": "Failed Login",
                "details": "Multiple failed logins from 192.168.1.100",
            }
        ]
    )
