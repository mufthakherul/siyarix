from __future__ import annotations

from phalanx.shell_knowledge import (INTENT_METADATA, ShellType,
                                     build_platform_context,
                                     detect_device_type, list_supported_shells,
                                     normalize_shell, render_intent, shell_key,
                                     terminal_type_from_env, translate_command)


def test_normalize_shell_aliases_to_canonical_keys() -> None:
    assert normalize_shell("pwsh") == ShellType.POWERSHELL
    assert normalize_shell("sh") == ShellType.BASH
    assert normalize_shell(ShellType.PWSH) == ShellType.POWERSHELL


def test_shell_key_maps_aliases_for_command_lookup() -> None:
    assert shell_key("pwsh") == "powershell"
    assert shell_key(ShellType.SH) == "bash"
    assert shell_key(None) == "bash"


def test_translate_command_uses_normalized_shell_targets() -> None:
    assert translate_command("list_files", ShellType.PWSH) == "Get-ChildItem -Force"
    assert translate_command("list_files", ShellType.SH) == "ls -la"
    assert translate_command("list_files", ShellType.UNKNOWN) == "ls -la"


def test_supported_shells_includes_tiered_entries() -> None:
    shells = dict(list_supported_shells())
    assert shells.get("bash") == "Tier 1"
    assert shells.get("nushell") == "Tier 2"


def test_render_intent_replaces_placeholders() -> None:
    cmd = render_intent("ssh_connect", user="root", target="10.0.0.1")
    assert "root@10.0.0.1" in cmd


def test_intent_metadata_contains_categories() -> None:
    assert INTENT_METADATA["list_files"]["category"] == "filesystem"


def test_detect_device_type_maps_platforms() -> None:
    assert detect_device_type("Windows") == "windows"
    assert detect_device_type("Darwin") == "macos"
    assert detect_device_type("Linux") == "linux"


def test_terminal_type_from_env_prefers_wsl() -> None:
    env = {"WSL_DISTRO_NAME": "Ubuntu"}
    assert terminal_type_from_env(env=env, sys_name="Linux") == "wsl"


def test_terminal_type_from_env_detects_vscode() -> None:
    env = {"VSCODE_PID": "1234"}
    assert terminal_type_from_env(env=env, sys_name="Linux") == "vscode"


def test_build_platform_context_exposes_enriched_runtime_fields() -> None:
    ctx = build_platform_context()
    required_keys = [
        "platform_pretty",
        "platform_release",
        "hostname",
        "username",
        "cwd",
        "shell_executable",
        "terminal_type",
        "cpu_count",
        "available_tools_count",
        "is_container",
        "container_runtime",
    ]
    for key in required_keys:
        assert key in ctx

    assert isinstance(ctx["available_tools_count"], int)
    assert isinstance(ctx["is_container"], bool)
