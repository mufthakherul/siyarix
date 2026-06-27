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


async def _run(
    tool_name: str, cmd: list[str], timeout: int = 120, on_stdout: Any = None, on_stderr: Any = None
) -> Any:
    """Lazy import and run a command asynchronously, with sanitization."""
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

    if on_stdout or on_stderr:
        from .subprocess_utils import safe_run_async_stream as _run_async_stream

        return await _run_async_stream(
            cmd, timeout=timeout, on_stdout=on_stdout, on_stderr=on_stderr
        )
    else:
        from .subprocess_utils import safe_run_async as _run_async

        return await _run_async(cmd, timeout=timeout)


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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 120),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_web_handler(tool_name: str) -> ToolHandler:
    TARGET_FLAGS = {
        "nikto": "-h",
        "nuclei": "-duc -nt -u",
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
                        r = urllib.request.Request(
                            req["url"],
                            method=req["method"],
                            headers={"User-Agent": req["user_agent"]},
                        )
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
        # Nuclei: use dedicated longer timeout (default 600s) for template download on first run
        default_timeout = 600 if tool_name == "nuclei" else 300
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", default_timeout),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_portscan_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        flags = kwargs.get("flags", "-T4 --top-ports 100")
        cmd = [tool_name] + flags.split() + [target]
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 120),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 30),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 120),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 60),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 120),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_curl_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        flags = kwargs.get("flags", "-sI")
        cmd = [tool_name] + flags.split() + [target]
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 30),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
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
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 30),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_whois_handler(tool_name: str) -> ToolHandler:
    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", "")
        if not target:
            return _empty_target_result(tool_name)
        cmd = [tool_name, target]
        result = await _run(
            tool_name,
            cmd,
            kwargs.get("timeout", 30),
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


# ── Domain-specific target flags ────────────────────────────────────────────────

_FORENSICS_FLAGS: dict[str, str] = {
    "volatility": "-f",
    "sleuthkit": "-f",
    "exiftool": "",
    "bulk_extractor": "-o",
}

_SAST_FLAGS: dict[str, str] = {
    "semgrep": "--config=auto",
    "bandit": "-r",
    "gitleaks": "detect --no-git",
    "trufflehog": "",
}

_CLOUD_FLAGS: dict[str, str] = {
    "kubectl": "",
    "kube-hunter": "",
    "checkov": "-d",
    "prowler": "",
    "scoutsuite": "",
}

_CONTAINER_FLAGS: dict[str, str] = {
    "trivy": "",
    "grype": "",
    "syft": "",
}

_RE_FLAGS: dict[str, str] = {
    "radare2": "-A",
    "apktool": "d",
}


def make_forensics_handler(tool_name: str) -> ToolHandler:
    """Specialised handler for forensic analysis tools (Volatility, YARA, SleuthKit, etc.)."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        filepath = kwargs.get("target", kwargs.get("file", kwargs.get("path", "")))
        if not filepath:
            return _empty_target_result(tool_name)

        plugin = kwargs.get("plugin", "")
        profile = kwargs.get("profile", "")
        rules = kwargs.get("rules", "")
        output_dir = kwargs.get("output_dir", "")
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        cmd = [tool_name]

        # ── Volatility ────────────────────────────────────────────
        if tool_name == "volatility":
            vol_cmd = kwargs.get("vol_cmd", "windows.pslist")
            cmd += ["-f", filepath]
            if profile:
                cmd += ["--profile", profile]
            cmd += extra_args
            if plugin:
                cmd += [plugin]
            else:
                cmd += [vol_cmd]

        # ── YARA ──────────────────────────────────────────────────
        elif tool_name in ("yara", "yarac"):
            if not rules:
                rules = kwargs.get("rule", "/usr/share/yara/rules/index.yar")
            cmd = [tool_name, "-w", rules, filepath]
            cmd += extra_args

        # ── ExifTool ──────────────────────────────────────────────
        elif tool_name == "exiftool":
            cmd = [tool_name, filepath]
            cmd += extra_args

        # ── SleuthKit (fls, icat, mmls, fsstat) ─────────────────
        elif tool_name == "sleuthkit":
            st_cmd = kwargs.get("st_cmd", "fls")
            fstype = kwargs.get("fstype", "ntfs")
            inode = kwargs.get("inode", "")
            cmd = [st_cmd]
            if inode:
                cmd += ["-i", fstype, filepath, inode]
            else:
                cmd += ["-f", fstype, filepath]

        # ── foremost ──────────────────────────────────────────────
        elif tool_name == "foremost":
            out = output_dir or kwargs.get("output", "./foremost_output")
            cmd = [tool_name, "-i", filepath, "-o", out]
            cmd += extra_args

        # ── binwalk ───────────────────────────────────────────────
        elif tool_name == "binwalk":
            cmd = [tool_name, "-Me", filepath]
            cmd += extra_args

        # ── strings ───────────────────────────────────────────────
        elif tool_name == "strings":
            encoding = kwargs.get("encoding", "")
            cmd = [tool_name]
            if encoding:
                cmd += ["-e", encoding]
            cmd += extra_args
            cmd.append(filepath)

        # ── bulk_extractor ─────────────────────────────────────────
        elif tool_name == "bulk_extractor":
            out = output_dir or kwargs.get("output", "./bulk_output")
            cmd = [tool_name, "-o", out, filepath]
            cmd += extra_args

        # ── pypykatz / mimikatz ───────────────────────────────────
        elif tool_name == "pypykatz":
            pypy_cmd = kwargs.get("pypy_cmd", "lsa")
            cmd = [tool_name, pypy_cmd, filepath]
            cmd += extra_args
        elif tool_name == "mimikatz":
            cmd = [tool_name, filepath]
            cmd += extra_args

        # ── Generic fallback for unknown forensic tools ────────────
        else:
            if filepath:
                cmd.append(filepath)
            if extra_args:
                cmd += extra_args

        timeout = kwargs.get("timeout", 300)
        result = await _run(
            tool_name,
            cmd,
            timeout,
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_sast_handler(tool_name: str) -> ToolHandler:
    """Specialised handler for static analysis / SAST tools (Semgrep, Bandit, Gitleaks, etc.)."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        path = kwargs.get("target", kwargs.get("path", kwargs.get("dir", "")))
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        cmd = [tool_name]

        # ── Semgrep ───────────────────────────────────────────────
        if tool_name == "semgrep":
            config = kwargs.get("config", kwargs.get("rules", "auto"))
            cmd += extra_args
            if path:
                cmd += ["--config=" + config, path]
            else:
                cmd += ["--config=" + config, "."]

        # ── Bandit ────────────────────────────────────────────────
        elif tool_name == "bandit":
            cmd += ["-r"]
            # Map severity to -l count: high=-lll, medium=-ll, low=-l
            sev_levels = {"low": "-l", "medium": "-ll", "high": "-lll"}
            sev = kwargs.get("severity", "high")
            cmd.append(sev_levels.get(sev, "-lll"))
            if path:
                cmd += extra_args + [path]
            else:
                cmd += extra_args + ["."]

        # ── Gitleaks ──────────────────────────────────────────────
        elif tool_name == "gitleaks":
            scan_type = kwargs.get("scan_type", "detect")
            source = path or "."
            cmd += [scan_type, "--no-git", "--source=" + source]
            if extra_args:
                cmd += extra_args

        # ── TruffleHog ────────────────────────────────────────────
        elif tool_name == "trufflehog":
            if path:
                cmd += ["filesystem", path]
            else:
                cmd += ["filesystem", "."]
            if extra_args:
                cmd += extra_args

        # ── Generic fallback for other SAST tools ──────────────────
        else:
            if path:
                cmd.append(path)
            if extra_args:
                cmd += extra_args

        timeout = kwargs.get("timeout", 180)
        result = await _run(
            tool_name,
            cmd,
            timeout,
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_cloud_handler(tool_name: str) -> ToolHandler:
    """Specialised handler for cloud security auditing tools (Prowler, ScoutSuite, Checkov, etc.)."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", kwargs.get("dir", kwargs.get("region", "")))
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        cmd = [tool_name]

        # ── Prowler ───────────────────────────────────────────────
        if tool_name == "prowler":
            provider = kwargs.get("provider", "aws")
            region = kwargs.get("region", "us-east-1")
            service = kwargs.get("service", "")
            cmd += [provider, "--region", region]
            if service:
                cmd += ["--service", service]
            if extra_args:
                cmd += extra_args

        # ── ScoutSuite ────────────────────────────────────────────
        elif tool_name == "scoutsuite":
            provider = kwargs.get("provider", "aws")
            cmd += [provider]
            if extra_args:
                cmd += extra_args

        # ── Checkov ──────────────────────────────────────────────
        elif tool_name == "checkov":
            framework = kwargs.get("framework", "terraform")
            directory = target or "."
            cmd += ["-d", directory, "--framework", framework]
            if extra_args:
                cmd += extra_args

        # ── kubectl ───────────────────────────────────────────────
        elif tool_name == "kubectl":
            kube_cmd = kwargs.get("kube_cmd", "get")
            resource = kwargs.get("resource", "pods")
            namespace = kwargs.get("namespace", "default")
            kubeconfig = kwargs.get("kubeconfig", "")
            if kubeconfig:
                cmd += ["--kubeconfig", kubeconfig]
            cmd += [kube_cmd, resource, "-n", namespace]
            if extra_args:
                cmd += extra_args

        # ── kube-hunter ──────────────────────────────────────────
        elif tool_name == "kube-hunter":
            mode = kwargs.get("mode", "quick")
            if mode == "remote" and target:
                cmd += ["--remote", target]
            elif mode == "cidr" and target:
                cmd += ["--cidr", target]
            else:
                cmd += ["--" + mode]
            if extra_args:
                cmd += extra_args

        # ── Generic fallback ───────────────────────────────────────
        else:
            if target:
                cmd.append(target)
            if extra_args:
                cmd += extra_args

        timeout = kwargs.get("timeout", 180)
        result = await _run(
            tool_name,
            cmd,
            timeout,
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_container_handler(tool_name: str) -> ToolHandler:
    """Specialised handler for container security tools (Trivy, Grype, Syft)."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target", kwargs.get("image", kwargs.get("path", "")))
        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        cmd = [tool_name]

        # ── Trivy ─────────────────────────────────────────────────
        if tool_name == "trivy":
            scan_mode = kwargs.get("scan_mode", "image")
            if scan_mode == "image" and target:
                cmd += ["image", "--no-progress", target]
            elif scan_mode == "filesystem":
                cmd += ["filesystem", "--no-progress", target or "."]
            elif scan_mode == "config":
                cmd += ["config", "--no-progress", target or "."]
            elif scan_mode == "sbom":
                cmd += ["sbom", "--no-progress", target or "."]
            else:
                cmd += [scan_mode, target or "."]
            if extra_args:
                cmd += extra_args

        # ── Grype ─────────────────────────────────────────────────
        elif tool_name == "grype":
            if target:
                cmd += [target]
            else:
                cmd += ["."]
            if extra_args:
                cmd += extra_args

        # ── Syft ──────────────────────────────────────────────────
        elif tool_name == "syft":
            if target:
                cmd += [target]
            else:
                cmd += ["."]
            if extra_args:
                cmd += extra_args

        # ── Generic fallback ───────────────────────────────────────
        else:
            if target:
                cmd.append(target)
            if extra_args:
                cmd += extra_args

        timeout = kwargs.get("timeout", 180)
        result = await _run(
            tool_name,
            cmd,
            timeout,
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_re_handler(tool_name: str) -> ToolHandler:
    """Specialised handler for reverse engineering tools (Radare2, Apktool)."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        binary = kwargs.get("target", kwargs.get("file", kwargs.get("apk", "")))
        if not binary:
            return _empty_target_result(tool_name)

        extra_args = kwargs.get("args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        cmd = [tool_name]

        # ── Radare2 ───────────────────────────────────────────────
        if tool_name == "radare2":
            mode = kwargs.get("mode", "analyze")
            if mode == "analyze":
                cmd += ["-A", binary]
            elif mode == "strings":
                cmd += ["-z", binary]
            elif mode == "sections":
                cmd += ["-S", binary]
            elif mode == "imports":
                cmd += ["-i", binary]
            elif mode == "script":
                script = kwargs.get("script", "")
                if script:
                    cmd += ["-i", script, binary]
                else:
                    cmd += ["-c", "aaa; afl", binary]
            else:
                cmd += [binary]
            if extra_args:
                cmd += extra_args

        # ── Apktool ───────────────────────────────────────────────
        elif tool_name == "apktool":
            action = kwargs.get("action", "d")  # d=decode, b=build
            output = kwargs.get("output", "")
            if action == "d":
                cmd += ["d", binary]
                if output:
                    cmd += ["-o", output]
                if kwargs.get("force", False):
                    cmd += ["-f"]
            elif action == "b":
                if output:
                    cmd += ["b", binary, "-o", output]
                else:
                    cmd += ["b", binary]
            else:
                cmd += [action, binary]
            if extra_args:
                cmd += extra_args

        # ── Generic fallback for other RE tools ────────────────────
        else:
            cmd.append(binary)
            if extra_args:
                cmd += extra_args

        timeout = kwargs.get("timeout", 300)
        result = await _run(
            tool_name,
            cmd,
            timeout,
            on_stdout=kwargs.get("on_stdout"),
            on_stderr=kwargs.get("on_stderr"),
        )
        return _make_result(tool_name, result)

    return handler


def make_generic_handler(tool_name: str) -> ToolHandler:
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
        on_stdout = kwargs.get("on_stdout")
        on_stderr = kwargs.get("on_stderr")
        try:
            if on_stdout or on_stderr:
                from .subprocess_utils import safe_run_async_stream

                result = await safe_run_async_stream(
                    cmd, timeout=timeout, on_stdout=on_stdout, on_stderr=on_stderr
                )
            else:
                result = await safe_run_async(cmd, timeout=timeout)
            return _make_result(tool_name, result)
        except Exception as exc:
            return {"status": "error", "error": str(exc), "tool": tool_name}

    return handler
