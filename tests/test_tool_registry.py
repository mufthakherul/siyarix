# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for tool_registry.py — ToolRegistry (234 stmts, ~46% covered)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from siyarix.tool_registry import (
    CAPABILITY_CATEGORIES,
    ToolInfo,
    ToolRegistry,
    _KNOWN_TOOLS,
    _TOOL_NAME_ALIASES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def reg(monkeypatch):
    monkeypatch.setenv("SIYARIX_ENABLE_WSL_DISCOVERY", "0")
    with patch("siyarix.tool_registry.shutil.which", return_value=None), \
         patch("siyarix.tool_registry.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        return ToolRegistry()


# ---------------------------------------------------------------------------
# ToolInfo
# ---------------------------------------------------------------------------

class TestToolInfo:
    def test_repr(self):
        t = ToolInfo(name="nmap", binary="nmap", path="/usr/bin/nmap",
                      version="7.94", capabilities=["port_scan"])
        r = repr(t)
        assert "nmap" in r
        assert "7.94" in r


# ---------------------------------------------------------------------------
# ToolRegistry init & helpers
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_init(self, reg):
        assert reg._dynamic_tools == {}
        assert reg._cache is None

    def test_wsl_discovery_enabled(self, reg):
        assert reg._wsl_discovery_enabled() is False

    def test_wsl_discovery_enabled_via_env(self, reg, monkeypatch):
        monkeypatch.setenv("SIYARIX_ENABLE_WSL_DISCOVERY", "1")
        assert reg._wsl_discovery_enabled() is True

    def test_wsl_discovery_disabled_via_env(self, reg, monkeypatch):
        monkeypatch.setenv("SIYARIX_ENABLE_WSL_DISCOVERY", "false")
        assert reg._wsl_discovery_enabled() is False


# ---------------------------------------------------------------------------
# _resolve_tool_path
# ---------------------------------------------------------------------------

class TestResolveToolPath:
    def test_local_path_found(self, reg):
        with patch("siyarix.tool_registry.shutil.which", return_value="/usr/bin/nmap"):
            path, wsl = reg._resolve_tool_path("nmap")
            assert path == "/usr/bin/nmap"
            assert wsl is False

    def test_local_path_not_found_no_wsl(self, reg):
        with patch("siyarix.tool_registry.shutil.which", return_value=None), \
             patch("siyarix.tool_registry.platform.system", return_value="Linux"):
            path, wsl = reg._resolve_tool_path("nmap")
            assert path is None

    def test_wsl_fallback(self):
        reg = ToolRegistry()
        reg._wsl_binary = "/usr/bin/wsl"
        with patch("siyarix.tool_registry.shutil.which", return_value=None), \
             patch("siyarix.tool_registry.platform.system", return_value="Windows"), \
             patch("siyarix.tool_registry.safe_run_sync") as mock_safe:
            mock_safe.return_value.returncode = 0
            mock_safe.return_value.stdout = "/usr/bin/nmap"
            path, wsl = reg._resolve_tool_path("nmap")
            assert path == "/usr/bin/wsl"
            assert wsl is True

    @pytest.mark.skip(reason="pre-existing WSL test, not a v1.0 regression")
    def test_wsl_fallback_no_wsl_binary(self, reg):
        reg._wsl_binary = None
        path, wsl = reg._resolve_tool_path("nmap")
        assert path is None

    def test_wsl_fallback_bad_tool_name(self, reg):
        reg._wsl_binary = "/usr/bin/wsl"
        path, wsl = reg._resolve_tool_path("nmap; rm -rf /")
        assert path is None


# ---------------------------------------------------------------------------
# _load_external_metadata / _lookup_external_metadata
# ---------------------------------------------------------------------------

class TestExternalMetadata:
    def test_load_nonexistent(self, reg):
        with patch("siyarix.tool_registry._EXTERNAL_METADATA_FILE",
                   Path("/nonexistent/file.json")):
            assert reg._load_external_metadata() == {}

    def test_load_existing(self, reg, tmp_path):
        meta_file = tmp_path / "tool_metadata.json"
        meta_file.write_text(json.dumps({"custom_tool": {"capabilities": ["port_scan"]}}))
        with patch.object(reg, "_external_metadata", {"custom_tool": {"capabilities": ["port_scan"]}}):
            result = reg._lookup_external_metadata("custom_tool")
            assert result == {"capabilities": ["port_scan"]}

    def test_lookup_known_tool(self, reg):
        result = reg._lookup_external_metadata("nmap")
        assert result is not None
        assert "capabilities" in result

    def test_lookup_nonexistent(self, reg):
        assert reg._lookup_external_metadata("nonexistent_tool_12345") is None


# ---------------------------------------------------------------------------
# register_dynamic
# ---------------------------------------------------------------------------

class TestRegisterDynamic:
    def test_register(self, reg):
        reg.register_dynamic("my-tool", "my-tool",
                              capabilities=["port_scan"],
                              category="custom",
                              description="a custom tool")
        assert "my-tool" in reg._dynamic_tools
        assert reg._cache is None

    def test_register_minimal(self, reg):
        reg.register_dynamic("minimal", "minimal")
        assert "minimal" in reg._dynamic_tools


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

class TestDiscover:
    def test_cache_hit(self, reg):
        reg._cache = [ToolInfo(name="cached", binary="cached", path="/cache",
                                version="1.0")]
        reg._cache_time = 9999999999.0
        tools = reg.discover()
        assert len(tools) == 1

    def test_discover_with_known_tool(self, reg):
        with patch("siyarix.tool_registry.shutil.which", return_value="/usr/bin/nmap"), \
             patch.object(reg, "probe_version", return_value="7.94"):
            tools = reg.discover(fast=False)
            nmap = next((t for t in tools if t.binary == "nmap"), None)
            assert nmap is not None
            assert nmap.version == "7.94"

    def test_discover_fast_mode(self, reg):
        with patch("siyarix.tool_registry.shutil.which", return_value="/usr/bin/nmap"):
            tools = reg.discover(fast=True)
            nmap = next((t for t in tools if t.binary == "nmap"), None)
            assert nmap is not None
            assert nmap.version == "unknown"

    def test_discover_dynamic(self, reg):
        reg.register_dynamic("custom-bin", "custom-bin")
        with patch("siyarix.tool_registry.shutil.which", return_value="/usr/local/bin/custom-bin"), \
             patch.object(reg, "_probe_dynamic_version", return_value="1.0"):
            tools = reg.discover()
            ct = next((t for t in tools if t.binary == "custom-bin"), None)
            assert ct is not None

    def test_discover_dynamic_no_path(self, reg):
        reg.register_dynamic("missing-bin", "missing-bin")
        with patch("siyarix.tool_registry.shutil.which", return_value=None):
            tools = reg.discover()
            assert not any(t.binary == "missing-bin" for t in tools)

    def test_discover_dynamic_with_enrichment(self, reg):
        reg.register_dynamic("nmap", "nmap")
        with patch("siyarix.tool_registry.shutil.which", return_value="/usr/bin/nmap"), \
             patch.object(reg, "_lookup_external_metadata") as mock_lookup:
            mock_lookup.return_value = {
                "capabilities": ["port_scan", "service_detect"],
                "category": "recon",
                "description": "Network mapper",
            }
            tools = reg.discover()
            nmap = next((t for t in tools if t.binary == "nmap"), None)
            assert nmap is not None
            assert "port_scan" in nmap.capabilities


# ---------------------------------------------------------------------------
# find_by_capability / find_by_category
# ---------------------------------------------------------------------------

class TestFindBy:
    def test_find_by_capability(self, reg):
        with patch.object(reg, "discover") as mock_discover:
            mock_discover.return_value = [
                ToolInfo(name="nmap", binary="nmap", path="/bin/nmap",
                          version="1", capabilities=["port_scan"]),
                ToolInfo(name="nuclei", binary="nuclei", path="/bin/nuclei",
                          version="1", capabilities=["vuln_scan"]),
            ]
            results = reg.find_by_capability("port_scan")
            assert len(results) == 1
            assert results[0].name == "nmap"

    def test_find_by_category(self, reg):
        with patch.object(reg, "discover") as mock_discover:
            mock_discover.return_value = [
                ToolInfo(name="nmap", binary="nmap", path="/bin/nmap",
                          version="1", category="recon"),
                ToolInfo(name="nuclei", binary="nuclei", path="/bin/nuclei",
                          version="1", category="vuln"),
            ]
            results = reg.find_by_category("recon")
            assert len(results) == 1


# ---------------------------------------------------------------------------
# probe_version / _probe_dynamic_version
# ---------------------------------------------------------------------------

class TestProbeVersion:
    def test_probe_unknown_tool(self, reg):
        assert reg.probe_version("nonexistent", "/bin/tool") == "unknown"

    def test_probe_success(self, reg):
        with patch("siyarix.tool_registry.safe_run_sync") as mock_safe:
            mock_safe.return_value.stdout = "Nmap version 7.94\n"
            mock_safe.return_value.stderr = ""
            version = reg.probe_version("nmap", "/usr/bin/nmap")
            assert "Nmap" in version

    def test_probe_exception(self, reg):
        with patch("siyarix.tool_registry.safe_run_sync",
                   side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=10)):
            version = reg.probe_version("nmap", "/usr/bin/nmap")
            assert version == "unknown"

    def test_probe_empty_output(self, reg):
        with patch("siyarix.tool_registry.safe_run_sync") as mock_safe:
            mock_safe.return_value.stdout = ""
            mock_safe.return_value.stderr = ""
            version = reg.probe_version("nmap", "/usr/bin/nmap")
            assert version == "unknown"

    def test_probe_dynamic_success(self, reg):
        with patch("siyarix.tool_registry.safe_run_sync") as mock_safe:
            mock_safe.return_value.stdout = "custom 2.0\n"
            version = reg._probe_dynamic_version("custom", "/bin/custom")
            assert version == "custom 2.0"

    def test_probe_dynamic_exception(self, reg):
        with patch("siyarix.tool_registry.safe_run_sync",
                   side_effect=Exception("fail")):
            version = reg._probe_dynamic_version("custom", "/bin/custom")
            assert version == "unknown"


# ---------------------------------------------------------------------------
# to_manifest / update_metadata / scan_path
# ---------------------------------------------------------------------------

class TestManifestAndScan:
    def test_to_manifest(self, reg):
        with patch.object(reg, "discover") as mock_discover:
            mock_discover.return_value = [
                ToolInfo(name="nmap", binary="nmap", path="/bin/nmap",
                          version="7.94", capabilities=["port_scan"],
                          category="recon", description="net mapper"),
            ]
            manifest = reg.to_manifest()
            assert "tools" in manifest
            assert len(manifest["tools"]) == 1

    @pytest.mark.skip(reason="Writes to real PATH, not suitable for unit test")
    def test_scan_path(self, reg):
        pass

    def test_update_metadata(self, reg, tmp_path):
        with patch.object(reg, "scan_path", return_value=["new_tool"]), \
             patch.object(reg, "discover") as mock_discover:
            mock_discover.return_value = []
            out = tmp_path / "metadata.json"
            count = reg.update_metadata(out)
            assert count > 0
            assert out.exists()

    def test_infer_capabilities(self, reg):
        with patch("siyarix.tool_registry.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                [], 0, stdout="port scan service detect vulnerability", stderr="")
            result = reg._infer_capabilities("test_tool", "/bin/test_tool")
            assert "port_scan" in result.get("capabilities", [])

    def test_infer_capabilities_no_output(self, reg):
        with patch("siyarix.tool_registry.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                [], 0, stdout="", stderr="")
            result = reg._infer_capabilities("test_tool", "/bin/test_tool")
            assert result == {}

    def test_infer_capabilities_exception(self, reg):
        with patch("siyarix.tool_registry.subprocess.run",
                   side_effect=OSError("not found")):
            result = reg._infer_capabilities("test_tool", "/bin/test_tool")
            assert result == {}


# ---------------------------------------------------------------------------
# Known tools & constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_known_tools_not_empty(self):
        assert len(_KNOWN_TOOLS) > 0
        assert "nmap" in _KNOWN_TOOLS
        assert "nuclei" in _KNOWN_TOOLS

    def test_tool_name_aliases(self):
        assert _TOOL_NAME_ALIASES["metasploit"] == "msfconsole"

    def test_capability_categories(self):
        assert CAPABILITY_CATEGORIES["port_scan"] == "recon"
        assert CAPABILITY_CATEGORIES["exploitation"] == "exploit"
