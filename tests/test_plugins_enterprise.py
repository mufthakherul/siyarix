# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enterprise test suite for Siyarix Plugin Architecture."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from siyarix.plugins.manager import PluginManager
from siyarix.plugins.models import (
    PluginManifest,
    PluginType,
)
from siyarix.providers.manager import ProviderManager
from siyarix.registry import ToolRegistry
from siyarix.tool_models import RiskLevel, ToolCategory
from siyarix.planner_autonomous import SemanticToolSelector


@pytest.fixture
def temp_plugins_env(tmp_path: Path):
    """Fixture providing isolated plugin directory and registry."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)

    registry = ToolRegistry()
    provider_mgr = ProviderManager.get_instance()
    manager = PluginManager(
        registry=registry,
        provider_manager=provider_mgr,
        plugins_dir=plugins_dir,
        config_dir=config_dir,
    )
    return manager, registry, plugins_dir, config_dir


def test_plugin_manifest_parsing(tmp_path: Path):
    """Test PluginManifest parsing from dict and file."""
    manifest_data = {
        "name": "sample_vuln_scanner",
        "version": "1.2.0",
        "description": "Sample security scanner",
        "author": "Security Researcher",
        "category": "scanning",
        "risk_level": "medium",
        "tags": ["vuln", "scan"],
        "dependencies": ["requests>=2.28.0", {"name": "httpx", "version": "0.24.0"}],
        "capabilities": {
            "tools": ["sample_scanner"],
        },
    }

    manifest = PluginManifest.from_dict(manifest_data)
    assert manifest.name == "sample_vuln_scanner"
    assert manifest.version == "1.2.0"
    assert manifest.category == ToolCategory.SCANNING
    assert manifest.risk_level == RiskLevel.MEDIUM
    assert len(manifest.dependencies) == 2
    assert manifest.dependencies[0].name == "requests"
    assert manifest.dependencies[1].name == "httpx"
    assert manifest.capabilities.tools == ["sample_scanner"]

    # Test file reading
    file_path = tmp_path / "plugin.json"
    file_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    loaded = PluginManifest.from_file(file_path)
    assert loaded.name == manifest.name
    assert loaded.to_dict()["name"] == manifest.name


def test_plugin_discovery_and_loading(temp_plugins_env):
    """Test discovering and loading package and single-file plugins."""
    manager, registry, plugins_dir, _ = temp_plugins_env

    # 1. Create a package plugin
    pkg_dir = plugins_dir / "test_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "plugin.yaml").write_text(
        json.dumps(
            {
                "name": "test_pkg",
                "version": "1.0.0",
                "description": "Test Package Plugin",
                "category": "recon",
                "risk_level": "safe",
                "capabilities": {"tools": ["test_pkg_tool"]},
            }
        ),
        encoding="utf-8",
    )
    (pkg_dir / "plugin.py").write_text(
        """
from siyarix.registry import ToolRegistry
from siyarix.tool_models import ToolCapability, ToolCategory, RiskLevel

async def _tool_handler(**kwargs):
    return {"status": "success", "output": "pkg tool executed"}

def register_tools(registry: ToolRegistry):
    cap = ToolCapability(
        name="test_pkg_tool",
        description="Test tool",
        category=ToolCategory.RECON,
        risk_level=RiskLevel.SAFE,
    )
    registry.register(cap, _tool_handler)
""",
        encoding="utf-8",
    )

    # 2. Create a single-file plugin
    (plugins_dir / "test_single.py").write_text(
        """
\"\"\"Standalone Single File Plugin.\"\"\"
from siyarix.registry import ToolRegistry
from siyarix.tool_models import ToolCapability, ToolCategory, RiskLevel

async def _single_handler(**kwargs):
    return {"status": "success", "output": "single tool executed"}

def register_tools(registry: ToolRegistry):
    cap = ToolCapability(
        name="test_single_tool",
        description="Single file tool",
        category=ToolCategory.UTILITY,
        risk_level=RiskLevel.SAFE,
    )
    registry.register(cap, _single_handler)
""",
        encoding="utf-8",
    )

    discovered = manager.discover()
    assert "test_pkg" in discovered
    assert "test_single" in discovered
    assert discovered["test_pkg"].plugin_type == PluginType.PACKAGE
    assert discovered["test_single"].plugin_type == PluginType.SINGLE_FILE

    # Load all
    count = manager.load_all()
    assert count == 2
    assert "test_pkg_tool" in registry._graph._nodes
    assert "test_single_tool" in registry._graph._nodes


def test_plugin_enable_disable(temp_plugins_env):
    """Test enabling and disabling plugins."""
    manager, registry, plugins_dir, _ = temp_plugins_env

    pkg_dir = plugins_dir / "toggle_plugin"
    pkg_dir.mkdir()
    (pkg_dir / "plugin.yaml").write_text(
        json.dumps(
            {
                "name": "toggle_plugin",
                "version": "1.0.0",
                "category": "web",
                "capabilities": {"tools": ["toggle_tool"]},
            }
        ),
        encoding="utf-8",
    )
    (pkg_dir / "plugin.py").write_text(
        """
from siyarix.registry import ToolRegistry
from siyarix.tool_models import ToolCapability

async def _h(**kw):
    return {"status": "success"}

def register_tools(reg: ToolRegistry):
    reg.register(ToolCapability(name="toggle_tool"), _h)
""",
        encoding="utf-8",
    )

    manager.load_all()
    assert "toggle_tool" in registry._graph._nodes

    # Disable
    manager.disable("toggle_plugin")
    assert "toggle_tool" not in registry._graph._nodes
    assert not manager.is_enabled("toggle_plugin")

    # Re-enable
    manager.enable("toggle_plugin")
    assert "toggle_tool" in registry._graph._nodes
    assert manager.is_enabled("toggle_plugin")


def test_plugin_search_and_info(temp_plugins_env):
    """Test searching registry and inspecting plugin info."""
    manager, _, plugins_dir, config_dir = temp_plugins_env

    # Mock registry cache
    cache_file = config_dir / "registry_cache.json"
    cache_file.write_text(
        json.dumps(
            [
                {
                    "name": "cve_correlator",
                    "version": "1.0.0",
                    "description": "Correlate services with CVEs",
                    "category": "exploitation",
                    "tags": ["cve", "vuln"],
                    "tools": ["cve_correlator"],
                },
                {
                    "name": "cloud_audit",
                    "version": "1.0.0",
                    "description": "AWS and Azure auditor",
                    "category": "cloud",
                    "tags": ["cloud", "aws"],
                    "tools": ["cloud_audit"],
                },
            ]
        ),
        encoding="utf-8",
    )

    res = manager.search("cve")
    assert len(res) == 1
    assert res[0]["name"] == "cve_correlator"

    res_cloud = manager.search("", category="cloud")
    assert len(res_cloud) == 1
    assert res_cloud[0]["name"] == "cloud_audit"


def test_plugin_scaffold_create(temp_plugins_env):
    """Test scaffolding a new plugin with manager.create()."""
    manager, _, plugins_dir, _ = temp_plugins_env

    created_path = manager.create("new_agent_plugin", category="recon")
    assert created_path.exists()
    assert (created_path / "plugin.yaml").exists()
    assert (created_path / "plugin.py").exists()
    assert (created_path / "README.md").exists()

    manifest = PluginManifest.from_file(created_path / "plugin.yaml")
    assert manifest.name == "new_agent_plugin"
    assert manifest.category == ToolCategory.RECON


@pytest.mark.asyncio
async def test_plugin_tool_execution(temp_plugins_env):
    """Test executing a plugin tool through ToolRegistry."""
    manager, registry, plugins_dir, _ = temp_plugins_env

    pkg_dir = plugins_dir / "exec_plugin"
    pkg_dir.mkdir()
    (pkg_dir / "plugin.yaml").write_text(
        json.dumps(
            {
                "name": "exec_plugin",
                "version": "1.0.0",
                "capabilities": {"tools": ["exec_tool"]},
            }
        ),
        encoding="utf-8",
    )
    (pkg_dir / "plugin.py").write_text(
        """
from siyarix.registry import ToolRegistry
from siyarix.tool_models import ToolCapability

async def _h(**kw):
    return {"status": "success", "output": f"Target was {kw.get('target')}"}

def register_tools(reg: ToolRegistry):
    reg.register(ToolCapability(name="exec_tool"), _h)
""",
        encoding="utf-8",
    )

    manager.load_all()
    res = await registry.execute("exec_tool", target="192.168.1.100")
    assert res["status"] == "success"
    assert "192.168.1.100" in res["output"]


def test_semantic_tool_selection_with_plugin_tools():
    """Test that SemanticToolSelector picks up plugin tools when relevant."""
    schemas = [
        {"name": "nmap", "category": "scanning", "tags": ["port", "network"]},
        {"name": "curl", "category": "utility", "tags": ["http", "web"]},
        {"name": "cve_correlator", "category": "exploitation", "tags": ["cve", "vuln", "epss"]},
        {"name": "cloud_audit", "category": "cloud", "tags": ["cloud", "aws", "s3", "iam"]},
        {
            "name": "active_directory_inspector",
            "category": "network",
            "tags": ["ad", "kerberos", "ldap"],
        },
    ]

    # Goal targeting CVEs
    selected, _ = SemanticToolSelector.select_tools(
        goal="Correlate software version vulnerabilities and CVE exploitability",
        tool_schemas=schemas,
    )
    selected_names = [s["name"] for s in selected]
    assert "cve_correlator" in selected_names

    # Goal targeting Cloud security
    selected_cloud, _ = SemanticToolSelector.select_tools(
        goal="Audit AWS S3 bucket policies and IAM misconfigurations",
        tool_schemas=schemas,
    )
    cloud_names = [s["name"] for s in selected_cloud]
    assert "cloud_audit" in cloud_names

    # Goal targeting Active Directory
    selected_ad, _ = SemanticToolSelector.select_tools(
        goal="Inspect Active Directory domain for Kerberoasting",
        tool_schemas=schemas,
    )
    ad_names = [s["name"] for s in selected_ad]
    assert "active_directory_inspector" in ad_names
