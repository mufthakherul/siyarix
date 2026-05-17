from __future__ import annotations

from nexsec.shell_knowledge import (
    ShellType,
    normalize_shell,
    shell_key,
    translate_command,
)


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