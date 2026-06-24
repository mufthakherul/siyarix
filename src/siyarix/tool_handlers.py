# SPDX-License-Identifier: AGPL-3.0-or-later
"""Execution handlers for specific tools, managing tool invocation and arguments."""

from __future__ import annotations

import shlex
from typing import Any

from .tool_models import ToolHandler


def _empty_target_result(tool: str) -> dict:
    return {
        "status": "error",
        "error": "No target specified",
        "tool": tool,
    }


def _run(tool_name: str, cmd: list[str], timeout: int = 120) -> Any:
    """Lazy import and run a command asynchronously, with sanitization."""
    from .subprocess_utils import safe_run_async as _run_async
    try:
        from .security_hardening import InputValidator
        validator = InputValidator()
        is_injected, pattern = validator.check_args_injection(cmd)
        if is_injected:
            # Re-create a mock result class to return an error instead of executing
            class MockResult:
                exit_code = 1
                stdout = ""
                stderr = f"Security error: Command injection detected ({pattern})"
            return MockResult()
        cmd = validator.sanitize_args(cmd)
    except Exception:
        pass

    return _run_async(cmd, timeout=timeout)


def _make_result(tool_name: str, result: Any) -> dict[str, Any]:
    return {
        "status": "success" if not result.exit_code else "error",
        "output": result.stdout,
        "error": result.stderr,
        "exit_code": result.exit_code,
        "tool": tool_name,
    }


def make_nmap_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        flags = kwargs.get("flags", "-sT -T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 120))
        return _make_result(tool_name, result)

    return handler


def make_web_handler(tool_name: str) -> ToolHandler:
    TARGET_FLAGS = {
        "nikto": "-h",
        "nuclei": "-duc -u",
        "gobuster": "-u",
        "ffuf": "-u",
        "wpscan": "--url",
        "sqlmap": "-u",
    }

    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")

        try:
            import os
            if target and os.getenv("SIYARIX_STEALTH") == "1":
                import urllib.request

                from .stealth import StealthEngine
                engine = StealthEngine()
                # Apply stealth configs from kwargs if available
                if "stealth" in kwargs:
                    engine.set_config(**kwargs["stealth"])
                reqs = engine.get_decoy_requests(target)
                for req in reqs:
                    try:
                        r = urllib.request.Request(req["url"], method=req["method"], headers={"User-Agent": req["user_agent"]})
                        urllib.request.urlopen(r, timeout=1)
                    except Exception:
                        pass
        except Exception:
            pass

        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()
        cmd = [tool_name] + extra_args
        if target:
            flag = TARGET_FLAGS.get(tool_name)
            if flag:
                cmd.extend(flag.split() + [target])
            else:
                cmd.append(target)
        result = await _run(tool_name, cmd, kwargs.get("timeout", 300))
        return _make_result(tool_name, result)

    return handler


def make_portscan_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        flags = kwargs.get("flags", "-T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 120))
        return _make_result(tool_name, result)

    return handler


def make_recon_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if tool_name == "amass":
            cmd = [tool_name, "enum", "-d", target] if target else [tool_name, "--help"]
        elif tool_name == "subfinder":
            cmd = [tool_name, "-d", target] if target else [tool_name, "--help"]
        elif tool_name == "shodan":
            cmd = (
                [tool_name, "info"]
                if not target or target.startswith("-")
                else [tool_name, "host", target]
            )
        else:
            cmd = [tool_name, "--help"]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 30))
        return _make_result(tool_name, result)

    return handler


def make_brute_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        service = kwargs.get("service", "ssh")
        username = kwargs.get("username", "root")
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        cmd = [tool_name, "-l", username, "-P", wordlist, service + "://" + target]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 120))
        return _make_result(tool_name, result)

    return handler


def make_network_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if tool_name == "bettercap" and target:
            cmd = [tool_name, "-eval", f"set arp.spoof.targets {target}; arp.spoof on"]
        elif tool_name == "ettercap" and target:
            cmd = [tool_name, "-T", "-M", "arp", f"/{target}//"]
        elif tool_name == "aircrack-ng" and "mode" in kwargs:
            mode = kwargs["mode"]
            if mode == "capture":
                cmd = [tool_name, "-c", target] if target else [tool_name, "--help"]
            elif mode == "crack":
                pcap = kwargs.get("pcap", "")
                wordlist = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
                cmd = [tool_name, "-w", wordlist, pcap] if pcap else [tool_name, "--help"]
            else:
                cmd = [tool_name, "--help"]
        else:
            cmd = [tool_name, "--help"]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 60))
        return _make_result(tool_name, result)

    return handler


def make_crypto_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if tool_name == "hashcat" and target:
            hashfile = kwargs.get("hashfile", target)
            wordlist = kwargs.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            mode = kwargs.get("mode", "0")
            cmd = [tool_name, "-m", mode, "-a", "0", hashfile, wordlist]
        elif tool_name == "john" and target:
            cmd = [tool_name, target]
        else:
            cmd = [tool_name, "--help"]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 120))
        return _make_result(tool_name, result)

    return handler


def make_curl_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        flags = kwargs.get("flags", "-sI")
        cmd = [tool_name] + flags.split() + [target]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 30))
        return _make_result(tool_name, result)

    return handler


def make_dns_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "")
        cmd = [tool_name]
        if flags:
            cmd.extend(flags.split())
        if target:
            cmd.append(target)
        if not flags and not target:
            return _empty_target_result(tool_name)
        result = await _run(tool_name, cmd, kwargs.get("timeout", 30))
        return _make_result(tool_name, result)

    return handler


def make_whois_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        cmd = [tool_name, target]
        result = await _run(tool_name, cmd, kwargs.get("timeout", 30))
        return _make_result(tool_name, result)

    return handler


def make_generic_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async
        from .validators import ValidationError, validate_target

        cmd = [tool_name]
        target = kwargs.get("target", "")
        args_raw = kwargs.get("args", [])
        flags = kwargs.get("flags", "")
        if isinstance(args_raw, str):
            cmd.extend(shlex.split(args_raw))
        elif isinstance(args_raw, (list, tuple)):
            cmd.extend(str(a) for a in args_raw)
        if flags:
            cmd.extend(flags.split())
        if target:
            cmd.append(target)
        timeout = kwargs.get("timeout", 120)
        try:
            result = await safe_run_async(cmd, timeout=timeout)
            return _make_result(tool_name, result)
        except Exception as exc:
            return {"status": "error", "error": str(exc), "tool": tool_name}

    return handler
