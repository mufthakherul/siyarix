# SPDX-License-Identifier: AGPL-3.0-or-later
"""Execution handlers for specific tools, managing tool invocation and arguments."""

from __future__ import annotations

import shlex
from typing import Any

from .tool_models import ToolHandler


def make_nmap_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-sT -T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_web_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()
        cmd = [tool_name] + extra_args
        if target:
            if tool_name in ("nikto",):
                cmd += ["-h", target]
            elif tool_name in ("nuclei",):
                cmd += ["-duc", "-u", target]
            elif tool_name in ("gobuster",):
                cmd += ["-u", target]
            elif tool_name in ("ffuf",):
                cmd += ["-u", target]
            elif tool_name in ("wpscan",):
                cmd += ["--url", target]
            elif tool_name in ("sqlmap",):
                cmd += ["-u", target]
            elif tool_name in ("whatweb",):
                cmd += [target]
            else:
                cmd += [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 300))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_portscan_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_recon_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

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
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_brute_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, "-l", target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_network_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        if tool_name in ("bettercap", "ettercap") and target:
            cmd = [tool_name, "-T", target, "-silent"] if tool_name == "bettercap" else [tool_name, "-T", target, "-M", "arp"]
        elif tool_name == "aircrack-ng" and "mode" in kwargs:
            mode = kwargs["mode"]
            if mode == "capture":
                cmd = [tool_name, "-c", target] if target else [tool_name, "--help"]
            elif mode == "crack":
                pcap = kwargs.get("pcap", "")
                wordlist = kwargs.get("wordlist", "")
                cmd = [tool_name, "-w", wordlist, pcap] if pcap and wordlist else [tool_name, "--help"]
            else:
                cmd = [tool_name, "--help"]
        else:
            cmd = [tool_name, "--help"]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 60))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }
    return handler


def make_crypto_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

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
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 120))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }
    return handler


def make_curl_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "-sI")
        cmd = [tool_name] + flags.split() + [target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_dns_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_whois_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

        target = kwargs.get("target", "")
        cmd = [tool_name, target]
        result = await safe_run_async(cmd, timeout=kwargs.get("timeout", 30))
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.exit_code,
        }

    return handler


def make_generic_handler(tool_name: str) -> ToolHandler:
    """Build a generic handler that passes kwargs as CLI arguments.

    Translates:
      handler(target="example.com", flags="-sV")  →  tool_name -sV example.com
    """

    async def handler(**kwargs: Any) -> dict[str, Any]:
        from .subprocess_utils import safe_run_async

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
            return {
                "status": "success" if result.exit_code == 0 else "error",
                "output": result.stdout,
                "error": result.stderr,
                "exit_code": result.exit_code,
                "tool": tool_name,
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc), "tool": tool_name}

    return handler
