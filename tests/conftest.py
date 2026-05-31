# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared test fixtures and configuration for the Siyarix test suite."""

from __future__ import annotations

import json
import os
import tempfile
import warnings
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning, module="gi")
try:
    from gi import PyGIDeprecationWarning as _GiDep
    warnings.filterwarnings("ignore", category=_GiDep)
except ImportError:
    pass

from getpass import GetPassWarning

from siyarix.planner import ExecutionPlan, PlanStep, PlanType, PlanStatus, StepStatus
from siyarix.providers import ProviderManager, ProviderProfile
from siyarix.registry import ToolCapability, ToolCategory, ToolRegistry

warnings.filterwarnings("ignore", category=GetPassWarning)


@pytest.fixture
def provider_manager() -> ProviderManager:
    return ProviderManager()


@pytest.fixture
def tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolCapability(name="nmap", binary="nmap", installed=True, category=ToolCategory.RECON, description="Port scanner"))
    registry.register(ToolCapability(name="nuclei", binary="nuclei", installed=True, category=ToolCategory.SCANNING, description="Vuln scanner"))
    registry.register(ToolCapability(name="gobuster", binary="gobuster", installed=True, category=ToolCategory.SCANNING, description="Dir buster"))
    return registry


@pytest.fixture
def step_result_success() -> PlanStep:
    return PlanStep(tool="test_tool", status=StepStatus.COMPLETED, result={"output": "test output"}, duration_ms=100.0)


@pytest.fixture
def step_result_failure() -> PlanStep:
    return PlanStep(tool="test_tool", status=StepStatus.FAILED, result={"error": "Something went wrong"}, duration_ms=50.0)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def temp_config_file(temp_dir: Path) -> Path:
    config_path = temp_dir / "config.toml"
    config_path.write_text('[siyarix]\nlog_level = "DEBUG"\npersona = "bug_hunter"\n')
    return config_path


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    siyarix_vars = [k for k in os.environ if k.startswith("SIYARIX_")]
    backup = {k: os.environ[k] for k in siyarix_vars}
    for k in siyarix_vars:
        del os.environ[k]
    yield
    os.environ.update(backup)


@pytest.fixture
def mock_nmap_output() -> str:
    return """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80,443 scanme.nmap.org" start="1700000000" version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.7"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.fixture
def mock_nuclei_output() -> str:
    lines = [
        json.dumps({"template-id": "CVE-2023-1234", "info": {"name": "Test Vuln", "severity": "high"}, "host": "https://example.com"}),
        json.dumps({"template-id": "tech-detect", "info": {"name": "Tech Detection", "severity": "info"}, "host": "https://example.com"}),
    ]
    return "\n".join(lines)


@pytest.fixture
def mock_gobuster_output() -> str:
    return "Url: https://example.com\n/admin (Status: 200) [Size: 1234]\n/backup (Status: 403) [Size: 567]\n"


@pytest.fixture
def mock_async_tool_executor() -> MagicMock:
    mock = MagicMock()
    mock.execute = AsyncMock(return_value={"status": "success", "output": "mock output", "tool": "mock_tool"})
    return mock


@pytest.fixture
def mock_execution_plan() -> ExecutionPlan:
    return ExecutionPlan(
        goal="Scan target with nmap and nuclei",
        plan_type=PlanType.SEQUENTIAL,
        steps=[
            PlanStep(id="step_1", tool="nmap", args={"target": "target"}, description="Nmap version scan"),
            PlanStep(id="step_2", tool="nuclei", args={"target": "target"}, description="Nuclei vuln scan", dependencies=["step_1"]),
            PlanStep(id="step_3", description="Generate report", dependencies=["step_2"]),
        ],
    )
