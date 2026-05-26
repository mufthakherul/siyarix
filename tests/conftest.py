"""Shared test fixtures and configuration for the Siyarix test suite."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from siyarix.engine_types import StepResult, StepStatus
from siyarix.knowledge_graph import KnowledgeGraph
from siyarix.masking import MaskingEngine
from siyarix.planner import ExecutionPlan, ExecutionStep, StepType
from siyarix.providers import NoopProvider, ProviderRegistry
from siyarix.tool_registry import ToolInfo, ToolRegistry

# ── Provider Fixtures ────────────────────────────────────────────────


@pytest.fixture
def noop_provider() -> NoopProvider:
    """Return a NoopProvider instance for testing."""
    return NoopProvider()


@pytest.fixture
def provider_registry() -> ProviderRegistry:
    """Return a ProviderRegistry with a noop provider registered."""
    registry = ProviderRegistry()
    registry.register("noop", NoopProvider())
    return registry


# ── Masking Engine Fixtures ──────────────────────────────────────────


@pytest.fixture
def masking_engine() -> MaskingEngine:
    """Return a fresh MaskingEngine instance."""
    return MaskingEngine()


# ── Tool Registry Fixtures ───────────────────────────────────────────


@pytest.fixture
def tool_registry() -> ToolRegistry:
    """Return a ToolRegistry with a few test tools registered."""
    registry = ToolRegistry()
    registry._tools = {
        "nmap": ToolInfo(
            name="nmap", path="/usr/bin/nmap", version="7.94", category="recon"
        ),
        "nuclei": ToolInfo(
            name="nuclei", path="/usr/bin/nuclei", version="3.1", category="web"
        ),
        "gobuster": ToolInfo(
            name="gobuster", path="/usr/bin/gobuster", version="3.5", category="web"
        ),
    }
    return registry


# ── Knowledge Graph Fixtures ─────────────────────────────────────────


@pytest.fixture
def knowledge_graph() -> KnowledgeGraph:
    """Return a fresh KnowledgeGraph instance."""
    return KnowledgeGraph()


# ── Step Result Fixtures ─────────────────────────────────────────────


@pytest.fixture
def step_result_success() -> StepResult:
    """Return a successful StepResult."""
    return StepResult(
        status=StepStatus.SUCCESS,
        output="test output",
        tool="test_tool",
        duration_ms=100.0,
    )


@pytest.fixture
def step_result_failure() -> StepResult:
    """Return a failed StepResult."""
    return StepResult(
        status=StepStatus.FAILURE,
        output="error occurred",
        tool="test_tool",
        duration_ms=50.0,
        error="Something went wrong",
    )


# ── Temporary Directory Fixtures ─────────────────────────────────────


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test file I/O."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def temp_config_file(temp_dir: Path) -> Path:
    """Create a temporary config file."""
    config_path = temp_dir / "config.toml"
    config_path.write_text('[siyarix]\nlog_level = "DEBUG"\npersona = "bug_hunter"\n')
    return config_path


# ── Environment Variable Fixtures ────────────────────────────────────


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    """Clean siyarix-related environment variables before each test."""
    siyarix_vars = [k for k in os.environ if k.startswith("SIYARIX_")]
    backup = {k: os.environ[k] for k in siyarix_vars}
    for k in siyarix_vars:
        del os.environ[k]
    yield
    os.environ.update(backup)


# ── Mock Tool Output Fixtures ────────────────────────────────────────


@pytest.fixture
def mock_nmap_output() -> str:
    """Return a realistic nmap XML output sample."""
    return """<?xml version="1.0"?>
<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN" "https://svn.nmap.org/nmap/docs/nmaprun.dtd">
<nmaprun scanner="nmap" args="nmap -sV -p 22,80,443 scanme.nmap.org" start="1700000000" version="7.94">
  <host starttime="1700000000" endtime="1700000100">
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset" reason_ttl="0"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.fixture
def mock_nuclei_output() -> str:
    """Return a realistic nuclei JSONL output sample."""
    lines = [
        json.dumps(
            {
                "template-id": "CVE-2023-1234",
                "info": {
                    "name": "Test Vulnerability",
                    "severity": "high",
                    "description": "A test vulnerability",
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/admin",
                "type": "http",
            }
        ),
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "Technology Detection", "severity": "info"},
                "host": "https://example.com",
                "matched-at": "https://example.com/",
            }
        ),
    ]
    return "\n".join(lines)


@pytest.fixture
def mock_gobuster_output() -> str:
    """Return a realistic gobuster dir output sample."""
    return """Url: https://example.com
======================================================
/admin (Status: 200) [Size: 1234]
/backup (Status: 403) [Size: 567]
/hidden (Status: 200) [Size: 89]
======================================================


"""


# ── Async Mock Helpers ───────────────────────────────────────────────


@pytest.fixture
def mock_async_tool_executor() -> MagicMock:
    """Return a mocked ToolExecutor with async execute method."""
    mock = MagicMock()
    mock.execute = AsyncMock(
        return_value=StepResult(
            status=StepStatus.SUCCESS,
            output="mock output",
            tool="mock_tool",
            duration_ms=10.0,
        )
    )
    return mock


# ── Execution Plan Fixtures ───────────────────────────────────────────


@pytest.fixture
def mock_execution_plan() -> ExecutionPlan:
    """Return a pre-built ExecutionPlan for testing planner/engine integration."""
    return ExecutionPlan(
        steps=[
            ExecutionStep(
                id="step_1",
                step_type=StepType.TOOL_RUN,
                tool="nmap",
                args=["-sV", "target"],
                target="target",
                description="Nmap version scan",
            ),
            ExecutionStep(
                id="step_2",
                step_type=StepType.TOOL_RUN,
                tool="nuclei",
                args=["target"],
                target="target",
                description="Nuclei vulnerability scan",
                depends_on=["step_1"],
            ),
            ExecutionStep(
                id="step_3",
                step_type=StepType.REPORT,
                description="Generate report",
                depends_on=["step_2"],
            ),
        ],
        raw_instruction="Scan target with nmap and nuclei",
        source="test",
    )
