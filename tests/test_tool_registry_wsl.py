from __future__ import annotations

import subprocess

from nexsec.tool_registry import ToolRegistry

def test_discover_uses_wsl_fallback_on_windows(monkeypatch):
    monkeypatch.setenv("COSMICSEC_ENABLE_WSL_DISCOVERY", "1")

    def fake_which(name: str):
        if name == "wsl":
            return "C:/Windows/System32/wsl.exe"
        if name == "nmap":
            return None
        return None

    def fake_run(cmd, capture_output, text, timeout):
        if cmd[:4] == ["C:/Windows/System32/wsl.exe", "-e", "sh", "-lc"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="/usr/bin/nmap\n", stderr="")
        if cmd[:3] == ["C:/Windows/System32/wsl.exe", "-e", "nmap"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="Nmap 7.94\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr("nexsec.tool_registry.platform.system", lambda: "Windows")
    monkeypatch.setattr("nexsec.tool_registry.shutil.which", fake_which)
    monkeypatch.setattr("nexsec.tool_registry.subprocess.run", fake_run)

    tools = ToolRegistry().discover()
    nmap = next((t for t in tools if t.binary == "nmap"), None)

    assert nmap is not None
    assert nmap.path == "C:/Windows/System32/wsl.exe"
    assert nmap.default_args[:2] == ["-e", "nmap"]
    assert nmap.version.startswith("Nmap")

def test_discover_prefers_local_binary_over_wsl(monkeypatch):
    monkeypatch.setenv("COSMICSEC_ENABLE_WSL_DISCOVERY", "1")

    def fake_which(name: str):
        if name == "wsl":
            return "C:/Windows/System32/wsl.exe"
        if name == "nmap":
            return "C:/Tools/nmap.exe"
        return None

    def fake_run(cmd, capture_output, text, timeout):
        if cmd[:1] == ["C:/Tools/nmap.exe"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="Nmap 7.95\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr("nexsec.tool_registry.platform.system", lambda: "Windows")
    monkeypatch.setattr("nexsec.tool_registry.shutil.which", fake_which)
    monkeypatch.setattr("nexsec.tool_registry.subprocess.run", fake_run)

    tools = ToolRegistry().discover()
    nmap = next((t for t in tools if t.binary == "nmap"), None)

    assert nmap is not None
    assert nmap.path == "C:/Tools/nmap.exe"
    assert nmap.default_args[:2] != ["-e", "nmap"]
    assert nmap.version.startswith("Nmap")
