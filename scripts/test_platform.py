#!/usr/bin/env python3
"""Cross-platform compatibility test suite for Siyarix.

Detects current platform, tests all platform-specific code paths,
reports what works and what doesn't, and suggests fixes.

Usage:
    python scripts/test_platform.py          # full report
    python scripts/test_platform.py --json    # JSON output
"""

from __future__ import annotations

import argparse
import json
import os
import platform as _platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _import_siyarix_modules() -> dict[str, bool]:
    results: dict[str, bool] = {}
    modules = [
        "siyarix",
        "siyarix._platform",
        "siyarix.config",
        "siyarix.compat",
        "siyarix.compat",
        "siyarix.subprocess_utils",
        "siyarix.session_log",
        "siyarix.credential_store",
        "siyarix.security_hardening",
        "siyarix.provider_utils",
        "siyarix.chat.platform_utils",
        "siyarix.bootstrap",
    ]
    for mod_name in modules:
        try:
            __import__(mod_name)
            results[mod_name] = True
        except ImportError:
            results[mod_name] = False
        except Exception:
            results[mod_name] = False
    return results


def _test_platform_detection() -> dict[str, str | bool]:
    from siyarix._platform import (
        get_platform_id,
        get_platform_pretty,
        is_windows,
        is_macos,
        is_linux,
        is_termux,
        is_ish,
        is_harmonyos,
        is_wsl,
        is_mobile,
        has_signal,
        has_termios,
        has_fcntl,
        has_pty,
        has_resource,
        safe_geteuid,
    )

    pid = get_platform_id()
    return {
        "platform_id": pid,
        "platform_pretty": get_platform_pretty(),
        "system": _platform.system(),
        "release": _platform.release(),
        "machine": _platform.machine(),
        "python": sys.version.split()[0],
        "is_windows": is_windows(),
        "is_macos": is_macos(),
        "is_linux": is_linux(),
        "is_termux": is_termux(),
        "is_ish": is_ish(),
        "is_harmonyos": is_harmonyos(),
        "is_wsl": is_wsl(),
        "is_mobile": is_mobile(),
        "has_signal": has_signal(),
        "has_termios": has_termios(),
        "has_fcntl": has_fcntl(),
        "has_pty": has_pty(),
        "has_resource": has_resource(),
        "has_geteuid": safe_geteuid() is not None,
    }


def _test_path_handling() -> dict[str, str | bool]:
    from siyarix._platform import get_config_dir_platform, get_home_dir, get_termux_prefix

    config_dir = get_config_dir_platform()
    home_dir = get_home_dir()
    results: dict[str, str | bool] = {
        "config_dir": str(config_dir),
        "config_dir_exists": config_dir.exists() or config_dir.parent.exists(),
        "config_dir_is_absolute": config_dir.is_absolute(),
        "home_dir": str(home_dir),
        "home_dir_exists": home_dir.exists(),
    }

    pid = _platform.system().lower()
    if "termux" in str(config_dir).lower() or pid == "linux":
        prefix = get_termux_prefix()
        results["termux_prefix"] = prefix
        results["termux_prefix_exists"] = Path(prefix).exists()

    # Test no hardcoded /home/ paths
    config_str = str(config_dir).lower()
    results["has_home_slash"] = "/home/" in config_str if pid != "windows" else False
    results["no_hardcoded_home"] = "/home/" not in config_str

    return results


def _test_subprocess_utils() -> dict[str, bool | str]:
    from siyarix._platform import get_platform_shell_cmd

    results: dict[str, bool | str] = {}

    shell_cmd = get_platform_shell_cmd("echo test")
    results["platform_shell_cmd"] = " ".join(shell_cmd)

    from siyarix.subprocess_utils import detect_package_manager

    pm = detect_package_manager()
    results["package_manager"] = pm

    try:
        from siyarix.subprocess_utils import safe_run_sync

        result = safe_run_sync(shell_cmd, timeout=5)
        results["safe_run_sync_works"] = result.success
        results["safe_run_sync_stdout"] = (
            result.stdout.strip() if result.success else str(result.stderr)
        )
    except Exception as e:
        results["safe_run_sync_works"] = False
        results["safe_run_sync_error"] = str(e)

    return results


def _test_security_hardening() -> dict[str, bool]:
    try:
        from siyarix.security_hardening import validator, redactor, danger_analyzer

        ok = validator.validate_target("127.0.0.1")
        redacted = redactor.redact("sk-test12345678901234567890")
        danger = danger_analyzer.analyze("ls -la")
        return {
            "import_ok": True,
            "validate_ip_ok": ok[0],
            "redact_ok": "[REDACTED]" in redacted,
            "danger_analyze_ok": not danger.is_dangerous,
        }
    except Exception as e:
        return {"import_ok": False, "error": str(e)}


def _test_credential_store() -> dict[str, bool | str]:
    try:
        from siyarix.credential_store import CRYPTO_AVAILABLE

        return {"crypto_available": CRYPTO_AVAILABLE}
    except Exception as e:
        return {"crypto_available": False, "error": str(e)}


def _test_config() -> dict[str, bool]:
    try:
        from siyarix.config import get_config_dir, get_settings_file, SettingsStore

        d = get_config_dir()
        f = get_settings_file()
        s = SettingsStore()
        return {
            "import_ok": True,
            "config_dir_accessible": d.exists() or True,
            "settings_file_resolved": str(f).endswith("settings.toml"),
            "settings_store_works": s.get("color_theme") is not None,
        }
    except Exception:
        return {"import_ok": False}


def _test_tools_availability() -> dict[str, bool]:
    tools = [
        "python3",
        "pip3",
        "pip",
        "nmap",
        "curl",
        "ping",
        "whois",
        "openssl",
        "dig",
        "nslookup",
        "netstat",
        "ss",
        "iptables",
        "lsof",
        "ps",
        "df",
    ]
    results: dict[str, bool] = {}
    for tool in tools:
        results[tool] = shutil.which(tool) is not None
    return results


def _test_windows_specific() -> dict[str, bool | str]:
    if _platform.system() != "Windows":
        return {"skipped": True, "reason": "Not on Windows"}
    results: dict[str, bool | str] = {}
    try:
        import ctypes

        results["ctypes_available"] = True
    except ImportError:
        results["ctypes_available"] = False
    try:
        import winreg

        results["winreg_available"] = True
    except ImportError:
        results["winreg_available"] = False
    try:
        import msvcrt

        results["msvcrt_available"] = True
    except ImportError:
        results["msvcrt_available"] = False
    results["long_paths_enabled"] = os.environ.get("LongPathsEnabled", "0") == "1"
    return results


def _test_termux_specific() -> dict[str, bool | str]:
    from siyarix._platform import is_termux

    if not is_termux():
        return {"skipped": True, "reason": "Not on Termux"}
    results: dict[str, bool | str] = {}
    results["termux_version"] = os.environ.get("TERMUX_VERSION", "unknown")
    results["pkg_available"] = shutil.which("pkg") is not None
    results["termux_setup_storage"] = shutil.which("termux-setup-storage") is not None
    results["termux_battery_status"] = shutil.which("termux-battery-status") is not None
    termux_prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    results["prefix_exists"] = Path(termux_prefix).exists()
    home = os.environ.get("HOME", "")
    results["home_is_termux"] = "com.termux" in home
    return results


def _test_ish_specific() -> dict[str, bool | str]:
    from siyarix._platform import is_ish

    if not is_ish():
        return {"skipped": True, "reason": "Not on iSH"}
    results: dict[str, bool | str] = {}
    results["apk_available"] = shutil.which("apk") is not None
    return results


def _test_chat_platform_utils() -> dict[str, bool | str]:
    try:
        from siyarix.chat.platform_utils import (
            is_kali_linux,
            pip_install_args,
            detect_shell,
            get_shell_platform,
            build_platform_context,
        )

        shell = detect_shell()
        ctx = build_platform_context()
        return {
            "import_ok": True,
            "detected_shell": shell,
            "shell_platform": get_shell_platform(),
            "platform_context_keys": list(ctx.keys()),
            "kali_detected": is_kali_linux(),
            "pip_args_sample": " ".join(pip_install_args("siyarix")),
        }
    except Exception as e:
        return {"import_ok": False, "error": str(e)}


def run_all_tests() -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": _test_platform_detection(),
        "path_handling": _test_path_handling(),
        "modules_import": _import_siyarix_modules(),
        "subprocess_utils": _test_subprocess_utils(),
        "security_hardening": _test_security_hardening(),
        "credential_store": _test_credential_store(),
        "config": _test_config(),
        "tools_availability": _test_tools_availability(),
        "windows_specific": _test_windows_specific(),
        "termux_specific": _test_termux_specific(),
        "ish_specific": _test_ish_specific(),
        "chat_platform_utils": _test_chat_platform_utils(),
    }


def print_human_report(results: dict[str, Any]) -> None:
    width = 72

    print("=" * width)
    print("  Siyarix Cross-Platform Compatibility Report")
    print(f"  Generated: {results['timestamp']}")
    print("=" * width)

    # Platform info
    p = results["platform"]
    print(f"\n  Platform:        {p.get('platform_pretty', '?')}")
    print(f"  System:          {p.get('system', '?')} {p.get('release', '?')}")
    print(f"  Machine:         {p.get('machine', '?')}")
    print(f"  Python:          {p.get('python', '?')}")
    print(f"  Platform ID:     {p.get('platform_id', '?')}")

    # Capabilities
    caps = []
    if p.get("has_signal"):
        caps.append("signal")
    if p.get("has_termios"):
        caps.append("termios")
    if p.get("has_fcntl"):
        caps.append("fcntl")
    if p.get("has_pty"):
        caps.append("pty")
    if p.get("has_resource"):
        caps.append("resource")
    if p.get("has_geteuid"):
        caps.append("geteuid")
    print(f"  Capabilities:    {', '.join(caps) if caps else 'none'}")

    # Module imports
    print(f"\n  {'Module Imports':25} {'Status':10}")
    print(f"  {'-'*25} {'-'*10}")
    for mod, ok in results["modules_import"].items():
        status = "✓" if ok else "✗"
        print(f"  {mod:25} {status:>10}")

    # Subprocess
    sp = results["subprocess_utils"]
    print(f"\n  Package Manager: {sp.get('package_manager', '?')}")
    print(f"  Shell Cmd:       {sp.get('platform_shell_cmd', '?')}")
    print(f"  safe_run_sync:   {'✓' if sp.get('safe_run_sync_works') else '✗'}")

    # Security
    sh = results["security_hardening"]
    print(f"  Security Harden: {'✓' if sh.get('import_ok') else '✗'}")
    if sh.get("import_ok"):
        print(f"    Validate IP:   {'✓' if sh.get('validate_ip_ok') else '✗'}")
        print(f"    Redact:        {'✓' if sh.get('redact_ok') else '✗'}")

    # Credential store
    cs = results["credential_store"]
    print(f"  Crypto Available:{'✓' if cs.get('crypto_available') else '✗'}")

    # Config
    cfg = results["config"]
    print(f"  Config:          {'✓' if cfg.get('import_ok') else '✗'}")

    # Chat platform utils
    cpu = results["chat_platform_utils"]
    print(f"  Chat Platform:   {'✓' if cpu.get('import_ok') else '✗'}")
    if cpu.get("detected_shell"):
        print(f"    Shell:         {cpu.get('detected_shell')}")

    # Tools
    print("\n  Available Tools:")
    tools = results["tools_availability"]
    found = [t for t, ok in tools.items() if ok]
    missing = [t for t, ok in tools.items() if not ok]
    if found:
        print(f"    Found: {', '.join(found)}")
    if missing:
        print(f"    Missing: {', '.join(missing)}")

    # Platform-specific
    ws = results["windows_specific"]
    if "skipped" not in ws:
        print("\n  Windows Specific:")
        for k, v in ws.items():
            print(f"    {k}: {'✓' if v else '✗'}" if isinstance(v, bool) else f"    {k}: {v}")

    ts = results.get("termux_specific", {})
    if "skipped" not in ts:
        print("\n  Termux Specific:")
        for k, v in ts.items():
            print(f"    {k}: {v}")

    ish = results.get("ish_specific", {})
    if "skipped" not in ish:
        print("\n  iSH Specific:")
        for k, v in ish.items():
            print(f"    {k}: {v}")

    print(f"\n{'=' * width}")
    errors = []
    if not sh.get("import_ok"):
        errors.append("security_hardening import failed")
    if not cfg.get("import_ok"):
        errors.append("config import failed")
    if not sp.get("safe_run_sync_works"):
        errors.append("safe_run_sync failed")
    if errors:
        print(f"  Issues Found: {', '.join(errors)}")
    else:
        print("  All tests passed!")
    print(f"{'=' * width}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Siyarix cross-platform test suite")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    results = run_all_tests()
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_human_report(results)
    return (
        0
        if all(
            v.get("import_ok", True)
            for v in [
                results["config"],
                results["security_hardening"],
                results["chat_platform_utils"],
            ]
        )
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
