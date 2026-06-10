# SPDX-License-Identifier: AGPL-3.0-or-later

"""First-run onboarding wizard — interactive TUI setup for Siyarix.

Walks the user through a multi-step process:
  0. Welcome + ethics pledge
  1. Platform detection (OS, arch, hardware, shell, PMs, env type)
  2. Python + basic requirements check (pip, git, curl)
  3. Python dependencies + SDKs
  4. Cybersecurity tool discovery & install
  5. Vault setup (create encrypted credential vault, set passphrase)
  6. Provider selection (recommended / online / offline / custom / skip)
  7. Mode selection
  8. Persona + system message
  9. Preferences (theme, security defaults, notifications, output, history, log level)
 10. Network diagnostics (internet, DNS, provider connectivity)
 11. Finalize (health check, .env migration, shell/PATH setup, restart)
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.markdown import Markdown
    from rich.align import Align
    from rich.syntax import Syntax
except ImportError:
    Console = None  # type: ignore

from siyarix.bootstrap import SIYARIX_HOME, INITIALIZED_MARKER, BootstrapEngine
from siyarix.config import SettingsStore
from siyarix.providers import ProviderManager


# ── Helpers ────────────────────────────────────────────────────────────────

_SIYARIX_LOGO = """
[bold cyan]
   \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
   \u2551                                                  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552 \u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2552\u2550\u2550\u2550\u2550\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552 \u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2552\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552 \u2552\u2588\u2588\u2588\u2588\u2552 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2552\u2550\u2550\u2550\u2550\u2588\u2588\u2552\u2588\u2588\u2552  \u2552\u2588\u2588\u2552  \u2588\u2588\u2552\u2552\u2550\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552   \u2588\u2588\u2552   \u2588\u2588\u2552  \u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2552\u2588\u2588\u2552\u2588\u2588\u2552  \u2551
   \u2551     \u2552\u2550\u2550\u2550\u2550\u2550\u2550\u2552\u2552\u2550\u2552   \u2552\u2550\u2552   \u2552\u2550\u2552  \u2552\u2550\u2552\u2552\u2550\u2550\u2550\u2550\u2550\u2552\u2552\u2550\u2552\u2552\u2550\u2552  \u2551
   \u2551                                                  \u2551
   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
[/bold cyan]
"""

_ONLINE_PROVIDERS = [
    ("openai", "OpenAI", "GPT-5 series, o-series"),
    ("anthropic", "Anthropic", "Claude Opus/Sonnet/Haiku"),
    ("gemini", "Google Gemini", "Gemini 2.0/2.5/2.5-Lite/3.0/3.1/3.1-Lite/3.5 series"),
    ("groq", "Groq", "Llama, Mixtral \u2014 fast inference"),
    ("together", "Together AI", "Llama, DeepSeek, open models"),
    ("openrouter", "OpenRouter", "Unified API for 200+ models"),
    ("deepseek", "DeepSeek", "DeepSeek V4/V3 series"),
    ("xai", "xAI (Grok)", "Grok 4 series"),
    ("mistral", "Mistral AI", "Mistral Large/Pixal"),
    ("perplexity", "Perplexity", "Sonar models"),
    ("azure", "Azure OpenAI", "GPT via Azure"),
]

_OFFLINE_PROVIDERS = [
    ("ollama", "Ollama", "Local LLM runner \u2014 recommended"),
    ("lmstudio", "LM Studio", "GUI-based local model runner"),
    ("llamacpp", "llama.cpp", "C++ LLM inference server"),
    ("vllm", "vLLM", "High-throughput LLM serving"),
    ("localai", "LocalAI", "OpenAI-compatible local API"),
]

_REQUIRED_TOOLS = [
    ("curl", "curl", "HTTP requests & API communication"),
    ("git", "git", "Version control & tool downloads"),
]

_MINIMAL_CYBER_TOOLS = [
    ("nmap", "nmap", "Network discovery & port scanning"),
    ("curl", "curl", "HTTP requests & API testing"),
    ("dig", "bind-tools/dnsutils", "DNS resolution & enumeration"),
    ("openssl", "openssl", "TLS/SSL & cryptography"),
    ("whois", "whois", "WHOIS domain lookups"),
    ("nuclei", "nuclei", "Vulnerability scanner"),
    ("sqlmap", "sqlmap", "SQL injection automation"),
    ("john", "john", "Password cracking"),
    ("hydra", "hydra", "Online password attacks"),
]

_CYBER_TOOL_HOMEPAGES = {
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "sqlmap": "https://sqlmap.org",
    "john": "https://www.openwall.com/john/",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
}

_ARCH_MAP: dict[str, str] = {
    "AMD64": "x86_64 (64-bit)", "x86_64": "x86_64 (64-bit)",
    "x86": "x86 (32-bit)", "i386": "x86 (32-bit)", "i686": "x86 (32-bit)",
    "arm64": "ARM64 (AArch64)", "aarch64": "ARM64 (AArch64)",
    "armv7l": "ARM (32-bit)", "armv6l": "ARM (32-bit)",
    "ARM64": "ARM64 (AArch64)",
}

_PM_CHECKS: list[tuple[str, str]] = [
    ("winget", "winget"), ("choco", "choco"),
    ("apt-get", "apt"), ("apt", "apt"),
    ("brew", "brew"), ("pkg", "pkg"),
    ("pacman", "pacman"), ("dnf", "dnf"), ("yum", "yum"),
    ("apk", "apk"), ("port", "macports"),
    ("nix-env", "nix"), ("scoop", "scoop"),
]

_DEFAULT_PREFERENCES = {
    "theme": "default",
    "output_format": "table",
    "notifications": True,
    "stealth_mode": False,
    "command_review": True,
    "history_days": 90,
    "log_level": "warning",
    "auto_update": True,
}


# ── OnboardingWizard ────────────────────────────────────────────────────────

class OnboardingWizard:
    """Interactive first-run setup wizard for Siyarix."""

    def __init__(
        self,
        settings: SettingsStore | None = None,
        vault: Any | None = None,
        console: Any | None = None,
    ) -> None:
        self._settings = settings or SettingsStore()
        self._vault = vault
        self._console = console or Console()
        self._bootstrap = BootstrapEngine()
        self._provider_mgr = ProviderManager()

        self._choices: dict[str, Any] = {
            "ethics_accepted": False,
            "platform": {},
            "provider_type": "",
            "provider_name": "",
            "provider_model": "",
            "api_keys": {},
            "mode": "integrated",
            "persona": "auto",
            "additional_sysmsg": "",
            "tools_installed": [],
            "dependencies_installed": [],
            "vault_initialized": False,
            "preferences": dict(_DEFAULT_PREFERENCES),
            "network_ok": False,
            "env_migrated": False,
            "shell_completion_done": False,
            "path_setup_done": False,
        }

    # ── Public entry point ──────────────────────────────────────────────

    async def run(self) -> bool:
        if not self._welcome_screen():
            self._exit_greeting()
            return False
        self._step_platform_detection()
        await self._step_requirements()
        await self._step_dependencies()
        await self._step_tool_discovery()
        self._step_vault_setup()
        await self._step_provider()
        self._step_mode()
        self._step_persona_sysmsg()
        self._step_preferences()
        await self._step_network_diagnostics()
        await self._finalize()
        return True

    # ── Step 0: Welcome + Ethics ────────────────────────────────────────

    def _welcome_screen(self) -> bool:
        self._clear_screen()
        self._console.print(_SIYARIX_LOGO)
        self._console.print(
            Panel(
                "[bold yellow]First-Time Setup Wizard[/bold yellow]\n\n"
                "Welcome to [bold cyan]Siyarix[/bold cyan] \u2014 your open-source\n"
                "cybersecurity command center.\n\n"
                "This wizard will help you configure Siyarix for your\n"
                "environment in just a few steps.",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        self._console.print()
        self._console.print(
            Panel(
                "[bold red]Ethical Use Pledge[/bold red]\n\n"
                "Siyarix is a [bold]cybersecurity tool[/bold] designed for:\n"
                "  \u2022 Authorized penetration testing\n"
                "  \u2022 Security research on systems you own or have\n"
                "    explicit permission to test\n"
                "  \u2022 Educational purposes\n\n"
                "[italic]Unauthorized use of this tool against systems\n"
                "without permission is illegal and unethical.[/italic]\n\n"
                "By continuing, you agree to use Siyarix responsibly\n"
                "and only on systems you have authorization to test.",
                border_style="red",
                box=box.ROUNDED,
            )
        )
        self._console.print()
        choice = Prompt.ask(
            "[bold]Do you accept the ethical use pledge?[/bold]\n"
            "  Type [green]c[/green] to continue or [yellow]e[/yellow] to exit",
            choices=["c", "e"],
            default="c",
            show_choices=True,
        )
        if choice.lower() != "c":
            return False
        self._choices["ethics_accepted"] = True
        return True

    def _exit_greeting(self) -> None:
        self._clear_screen()
        self._console.print(
            Panel(
                "[yellow]Exiting setup.[/yellow]\n\n"
                "You can run the setup again at any time with:\n"
                "[bold]  siyarix init[/bold]\n\n"
                "[italic]Stay curious. Stay ethical.[/italic]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    # ── Step 1: Platform Detection ──────────────────────────────────────

    def _step_platform_detection(self) -> None:
        """Detect OS, architecture, hardware, shell, package managers, and environment."""
        self._step_header("Platform Detection")
        self._console.print("Siyarix detects your environment to adapt installation\nand configuration for your platform.\n")

        system = platform.system()
        release = platform.release()
        version = platform.version()
        machine = platform.machine()
        os_name = os.name

        arch_label = _ARCH_MAP.get(machine, machine)

        # WSL detection
        is_wsl = False
        if system == "Linux":
            wsl_check = platform.release().lower()
            is_wsl = "microsoft" in wsl_check or "wsl" in wsl_check

        # Container detection
        is_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")

        # Desktop vs headless
        if os.name == "nt":
            is_desktop = not bool(os.environ.get("SIYARIX_HEADLESS"))
        else:
            is_desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DESKTOP_SESSION"))

        # Shell detection
        shell_path = (os.environ.get("SHELL") or os.environ.get("ComSpec") or "").lower()
        if not shell_path and os.name == "nt":
            shell_path = os.environ.get("ComSpec", "cmd.exe")
        shell_name = os.path.basename(shell_path).replace(".exe", "").replace(".com", "")
        if not shell_name:
            shell_name = "cmd.exe" if os.name == "nt" else "sh"

        # Terminal
        term = os.environ.get("TERM", "unknown")
        term_program = os.environ.get("TERM_PROGRAM", "")

        # Package managers
        available_pms = [name for binary, name in _PM_CHECKS if shutil.which(binary)]

        # Proxy
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""

        # ── Hardware detection ──────────────────────────────────────────
        cpu_count = os.cpu_count() or 0
        cpu_label = f"{cpu_count} core(s)" if cpu_count else "Unknown"

        # RAM (best-effort cross-platform)
        ram_total_gb = 0.0
        try:
            if os.name == "nt":
                import ctypes
                kernel32 = ctypes.windll.kernel32  # type: ignore
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
                mem = MEMORYSTATUSEX()
                mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
                    ram_total_gb = mem.ullTotalPhys / (1024**3)
            elif system == "Linux":
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ram_total_gb = int(parts[1]) / (1024 * 1024)
                            break
            elif system == "Darwin":
                result = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    ram_total_gb = int(result.stdout.strip()) / (1024**3)
        except Exception:
            pass

        ram_label = f"{ram_total_gb:.1f} GB" if ram_total_gb > 0 else "Unknown"

        # Disk space for ~/.siyarix home
        disk_free_gb = 0.0
        try:
            siyarix_home = Path.home() / ".siyarix"
            siyarix_home.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                free_bytes = shutil.disk_usage(siyarix_home).free
                disk_free_gb = free_bytes / (1024**3)
            else:
                st = os.statvfs(str(siyarix_home))
                disk_free_gb = (st.f_frsize * st.f_bavail) / (1024**3)
        except Exception:
            pass

        disk_label = f"{disk_free_gb:.1f} GB free" if disk_free_gb > 0 else "Unknown"

        # Virtual environment detection
        in_venv = sys.prefix != sys.base_prefix
        venv_label = f"Active: {sys.prefix}" if in_venv else "No"

        # ── Display table ──────────────────────────────────────────────
        info_table = Table(box=box.SIMPLE, show_header=False)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value")
        info_table.add_row("Operating System", f"{system} {release}")
        if machine in _ARCH_MAP:
            info_table.add_row("Architecture", arch_label)
        info_table.add_row("CPU", cpu_label)
        info_table.add_row("RAM", ram_label)
        info_table.add_row("Disk (~/.siyarix)", disk_label)
        info_table.add_row("Python", sys.version.split()[0])
        info_table.add_row("Virtual Environment", venv_label)
        info_table.add_row("Shell", shell_name)
        if term_program:
            info_table.add_row("Terminal", f"{term_program} ({term})")
        else:
            info_table.add_row("Terminal", term)
        info_table.add_row("Package Managers", ", ".join(available_pms) or "None detected")
        if is_wsl:
            info_table.add_row("WSL", "[green]Yes[/green]")
        if is_container:
            info_table.add_row("Container", "[yellow]Detected[/yellow]")
        if not is_desktop and os.name != "nt":
            info_table.add_row("Desktop", "[yellow]Headless mode[/yellow]")
        if http_proxy or https_proxy:
            info_table.add_row("Proxy", "[yellow]Configured[/yellow]")

        self._console.print(info_table)
        self._console.print()

        # Confirm or override
        if not Confirm.ask("Is this correct?", default=True):
            self._console.print("\n[bold]Override Detection[/bold]")
            system = Prompt.ask("Operating System", default=system)
            machine = Prompt.ask("Architecture", default=machine)
            arch_label = _ARCH_MAP.get(machine, machine)
            shell_name = Prompt.ask("Shell", default=shell_name)

        self._choices["platform"] = {
            "system": system,
            "os_name": os_name,
            "release": release,
            "version": version,
            "machine": machine,
            "arch_label": arch_label,
            "cpu_count": cpu_count,
            "ram_gb": ram_total_gb,
            "disk_free_gb": disk_free_gb,
            "in_venv": in_venv,
            "is_wsl": is_wsl,
            "is_container": is_container,
            "is_desktop": is_desktop,
            "shell": shell_name,
            "terminal": term,
            "term_program": term_program,
            "package_managers": available_pms,
            "http_proxy": http_proxy,
            "https_proxy": https_proxy,
        }

        self._console.print(f"[green]\u2713 Platform: {system} ({arch_label})[/green]\n")

    # ── Step 2: Requirements Check ───────────────────────────────────────

    async def _step_requirements(self) -> None:
        self._step_header("Requirements Check")
        self._console.print("Checking Python version and basic requirements...\n")

        checks: list[tuple[str, bool]] = []

        py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 12)
        checks.append(("Python >= 3.12", py_ok))
        if not py_ok:
            self._console.print(
                f"[red]Python {sys.version_info.major}.{sys.version_info.minor} found \u2014 "
                f"3.12+ required[/red]"
            )
            self._console.print("[yellow]Please upgrade Python and try again.[/yellow]")
            Confirm.ask("[dim]Press Enter to exit[/dim]")
            sys.exit(1)

        pip_ok = shutil.which("pip") is not None or shutil.which("pip3") is not None
        checks.append(("pip / pip3", pip_ok))

        for cmd, label, _desc in _REQUIRED_TOOLS:
            checks.append((label, shutil.which(cmd) is not None))

        # Writable config directory
        config_dir = Path.home() / ".siyarix"
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            test_file = config_dir / ".write_test"
            test_file.write_text("ok")
            test_file.unlink()
            dir_writable = True
        except Exception:
            dir_writable = False
        checks.append(("Config dir writable", dir_writable))
        if not dir_writable:
            self._console.print(
                f"[red]Cannot write to {config_dir}[/red]"
            )
            self._console.print("[yellow]Check permissions and try again.[/yellow]")
            Confirm.ask("[dim]Press Enter to exit[/dim]")
            sys.exit(1)

        # PATH issue detection
        path_issues: list[str] = []
        if not shutil.which("siyarix") and not Path(sys.argv[0]).name.startswith("siyarix"):
            path_issues.append("Siyarix not found in PATH (may need pip install -e .)")

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Requirement", style="cyan")
        table.add_column("Status", justify="center")
        for label, ok in checks:
            status = "[green]\u2713[/green]" if ok else "[red]\u2717[/red]"
            table.add_row(label, status)
        self._console.print(table)
        self._console.print()

        if path_issues:
            for issue in path_issues:
                self._console.print(f"[yellow]\u26a0 {issue}[/yellow]")

        missing = [cmd for cmd, label, _desc in _REQUIRED_TOOLS if not shutil.which(cmd)]
        if missing:
            self._console.print("[yellow]Some basic requirements are missing.[/yellow]")
            if Confirm.ask("Install missing requirements?", default=True):
                for cmd in missing:
                    self._install_system_tool(cmd)
        self._console.print("[green]\u2713 Requirements check complete[/green]")
        self._pause()

    # ── Step 3: Dependencies & SDKs ──────────────────────────────────────

    async def _step_dependencies(self) -> None:
        self._step_header("Dependencies & Python Packages")
        self._console.print("Checking required Python packages...\n")

        core_deps = [
            ("pydantic", "import pydantic"),
            ("rich", "import rich"),
            ("httpx", "import httpx"),
            ("cryptography", "import cryptography"),
            ("tomli", "import tomli" if sys.version_info < (3, 11) else "stdlib tomllib"),
            ("prompt_toolkit", "import prompt_toolkit"),
            ("pyyaml", "import yaml"),
            ("jinja2", "import jinja2"),
            ("packaging", "import packaging"),
            ("pygments", "import pygments"),
        ]

        results: list[tuple[str, bool, str]] = []
        missing: list[str] = []

        for pkg, import_str in core_deps:
            try:
                if "stdlib" in import_str:
                    results.append((pkg, True, "built-in"))
                else:
                    exec(import_str)
                    results.append((pkg, True, "installed"))
            except ImportError:
                results.append((pkg, False, "missing"))
                missing.append(pkg)

        if not shutil.which("pip") and not shutil.which("pip3"):
            self._console.print("[red]pip not found! Cannot install packages.[/red]")
            self._pause()
            return

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Package", style="cyan")
        table.add_column("Status", justify="center")
        for pkg, ok, detail in results:
            status = f"[green]\u2713 {detail}[/green]" if ok else f"[red]\u2717 {detail}[/red]"
            table.add_row(pkg, status)
        self._console.print(table)
        self._console.print()

        if missing:
            self._console.print(
                f"[yellow]{len(missing)} package(s) need installation.[/yellow]"
            )
            if Confirm.ask("Install missing packages automatically?", default=True):
                for pkg in missing:
                    self._pip_install(pkg)
                self._console.print("[green]\u2713 Packages installed[/green]")
            else:
                self._console.print(
                    "[yellow]Skipping. Some features may be unavailable.[/yellow]"
                )

        self._console.print("[green]\u2713 Dependencies check complete[/green]")
        self._pause()

    # ── Step 4: Tool Discovery ──────────────────────────────────────────

    async def _step_tool_discovery(self) -> None:
        self._step_header("Cybersecurity Tool Discovery")
        self._console.print("Scanning for security tools...\n")

        found = []
        missing = []
        for exe, pkg, desc in _MINIMAL_CYBER_TOOLS:
            if shutil.which(exe):
                found.append(exe)
            else:
                missing.append((exe, pkg, desc))

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Description")
        for exe, pkg, desc in _MINIMAL_CYBER_TOOLS:
            ok = shutil.which(exe) is not None
            status = "[green]\u2713 Found[/green]" if ok else "[red]\u2717 Missing[/red]"
            table.add_row(exe, status, desc)
        self._console.print(table)
        self._console.print()

        self._choices["tools_installed"] = found

        if not missing:
            self._console.print("[bold green]\u2713 All cybersecurity tools present![/bold green]")
            self._pause()
            return

        self._console.print(
            f"[yellow]{len(missing)} security tool(s) not found.[/yellow]"
        )
        self._console.print("[dim]These tools extend Siyarix's capabilities.[/dim]\n")

        install_choices = {}
        for exe, pkg, desc in missing:
            want = Confirm.ask(f"  Install [cyan]{exe}[/cyan]? ({desc})", default=False)
            if want:
                install_choices[exe] = pkg

        if install_choices:
            self._console.print(f"\nInstalling {len(install_choices)} tool(s)...")
            for exe, pkg in install_choices.items():
                self._install_system_tool(exe, pkg)
        else:
            self._console.print("[yellow]Skipping tool installation.[/yellow]")

        self._console.print("[green]\u2713 Tool discovery complete[/green]")
        self._pause()

    # ── Step 5: Vault Setup ─────────────────────────────────────────────

    def _step_vault_setup(self) -> None:
        """Initialize the encrypted credential vault."""
        self._step_header("Credential Vault Setup")
        self._console.print(
            "Siyarix uses an [bold]encrypted vault[/bold] to store API keys\n"
            "and secrets securely. The vault is:\n"
            "  \u2022 AES-256-GCM encrypted\n"
            "  \u2022 Bound to your device + environment (anti-theft)\n"
            "  \u2022 Locked after inactivity (auto-seal)\n"
            "  \u2022 Backed up automatically\n\n"
        )

        if not Confirm.ask("Set up the credential vault now?", default=True):
            self._console.print("[yellow]Vault setup skipped. Secrets will not be stored securely.[/yellow]")
            return

        # Check if vault already exists
        vault_path = Path.home() / ".siyarix" / "vault.json"
        vault_exists = vault_path.exists()

        if vault_exists:
            self._console.print("[green]Vault file already exists.[/green]")
            if Confirm.ask("Re-initialize (overwrite existing vault)?", default=False):
                vault_path.unlink(missing_ok=True)
            else:
                self._console.print("[yellow]Using existing vault.[/yellow]")
                self._choices["vault_initialized"] = True
                return

        # Passphrase setup
        self._console.print("\n[bold]Create a Vault Passphrase[/bold]")
        self._console.print(
            "[dim]Requirements: 12+ characters, 3 of 4: uppercase, lowercase,\n"
            "digit, symbol. This passphrase is needed to unlock the vault.[/dim]"
        )

        for attempt in range(3):
            passphrase = Prompt.ask("Enter passphrase", password=True)
            if len(passphrase) < 12:
                self._console.print("[red]Too short (min 12 characters).[/red]")
                continue
            confirm = Prompt.ask("Confirm passphrase", password=True)
            if passphrase != confirm:
                self._console.print("[red]Passphrases do not match.[/red]")
                continue
            # Validate strength
            categories = 0
            if any(c.isupper() for c in passphrase):
                categories += 1
            if any(c.islower() for c in passphrase):
                categories += 1
            if any(c.isdigit() for c in passphrase):
                categories += 1
            if any(not c.isalnum() for c in passphrase):
                categories += 1
            if categories < 3:
                self._console.print(
                    "[red]Weak passphrase. Use 3 of 4: uppercase, lowercase, digit, symbol.[/red]"
                )
                continue

            # Attempt vault initialization
            try:
                from siyarix.credential_vault import CredentialVault
                vault = CredentialVault(passphrase=passphrase)
                self._vault = vault
                self._choices["vault_initialized"] = True
                self._settings.set("vault_initialized", True)

                # Store the vault reference globally for later use
                try:
                    from siyarix import credential_vault as cv
                    cv._VAULT_INSTANCE = vault
                except Exception:
                    pass

                self._console.print("[green]\u2713 Vault initialized successfully[/green]")
                self._console.print(
                    "[dim]Your secrets are now stored encrypted at rest.[/dim]"
                )

                # Offer to test
                if Confirm.ask("Test vault by storing and retrieving a sample?", default=False):
                    try:
                        vault.set("_test_key", "test_value")
                        val = vault.get("_test_key")
                        vault.delete("_test_key")
                        self._console.print(
                            "[green]\u2713 Vault read/write test passed[/green]"
                        )
                    except Exception as exc:
                        self._console.print(
                            f"[red]Vault test failed: {exc}[/red]"
                        )

                break
            except Exception as exc:
                self._console.print(f"[red]Vault creation failed: {exc}[/red]")
                if attempt < 2:
                    self._console.print("[yellow]Please try again.[/yellow]")
                else:
                    self._console.print("[red]Vault setup failed after 3 attempts.[/red]")
                    self._console.print("[yellow]You can configure the vault later with: siyarix auth set-key[/yellow]")
                continue
        else:
            self._console.print("[yellow]Vault setup abandoned.[/yellow]")

        self._pause()

    # ── Step 6: Provider Selection ──────────────────────────────────────

    async def _step_provider(self) -> None:
        self._step_header("Provider Configuration")
        self._console.print(
            "Siyarix needs an AI provider to power its autonomous\n"
            "and integrated modes.\n"
        )

        options = Table(box=box.ROUNDED, show_header=False)
        options.add_column("Option", style="yellow", width=8)
        options.add_column("Description")
        options.add_row("[bold]0[/bold]", "[bold]Recommended[/bold] \u2014 Install Ollama + WhiteRabbitNeo model")
        options.add_row("[bold]1[/bold]", "Online Provider \u2014 cloud API (OpenAI, Anthropic, Gemini...)")
        options.add_row("[bold]2[/bold]", "Offline Provider \u2014 run locally (Ollama, LM Studio...)")
        options.add_row("[bold]3[/bold]", "Custom Provider \u2014 your own endpoint / private model")
        options.add_row("[bold]4[/bold]", "Skip \u2014 configure later")
        self._console.print(options)
        self._console.print()

        choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4"], default="0")

        if choice == "0":
            await self._setup_recommended()
        elif choice == "1":
            await self._setup_online_provider()
        elif choice == "2":
            await self._setup_offline_provider()
        elif choice == "3":
            await self._setup_custom_provider()
        else:
            self._choices["provider_type"] = "skip"
            self._console.print("[yellow]Provider setup skipped.[/yellow]")

        self._pause()

    async def _setup_recommended(self) -> None:
        """Option 0: Install Ollama + pull WhiteRabbitNeo model."""
        self._console.print("\n[bold]Setting up recommended provider: Ollama[/bold]\n")

        ollama_found = shutil.which("ollama") is not None

        if not ollama_found:
            self._console.print("[yellow]Ollama not found on your system.[/yellow]")
            if Confirm.ask("Install Ollama?", default=True):
                ok = self._install_ollama()
                if not ok:
                    self._console.print("[red]Ollama installation failed.[/red]")
                    self._console.print("Install manually from: https://ollama.com")
                    if not Confirm.ask("Try an online provider instead?", default=True):
                        return
                    await self._setup_online_provider()
                    return
            else:
                self._console.print("[yellow]Ollama required for recommended setup.[/yellow]")
                if Confirm.ask("Try an online provider instead?", default=True):
                    await self._setup_online_provider()
                return

        ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._console.print(f"Ollama gateway: [cyan]{ollama_url}[/cyan]")

        running = self._check_ollama_running(ollama_url)
        if not running:
            self._console.print("[yellow]Ollama service is not running.[/yellow]")
            if Confirm.ask("Start Ollama now?", default=True):
                self._start_ollama_service()
                import asyncio
                await asyncio.sleep(3)
                running = self._check_ollama_running(ollama_url)

        model_name = "whiterabbitneo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
        self._console.print(f"\nModel to pull: [cyan]{model_name}[/cyan]")
        self._console.print("[dim]Size: ~4.5 GB download. May take several minutes.[/dim]")

        if Confirm.ask("Pull this model now?", default=True):
            self._console.print("Pulling model...")
            try:
                result = subprocess.run(
                    ["ollama", "pull", model_name],
                    capture_output=True, text=True, timeout=3600,
                )
                if result.returncode == 0:
                    self._console.print("[green]\u2713 Model downloaded[/green]")
                else:
                    self._console.print(f"[red]Pull failed: {result.stderr.strip()}[/red]")
                    model_name = "llama3.1"
                    self._console.print(f"Falling back to [cyan]{model_name}[/cyan]")
            except Exception as exc:
                self._console.print(f"[red]Error: {exc}[/red]")
                model_name = "llama3.1"
        else:
            model_name = "llama3.1"

        self._choices["provider_type"] = "offline"
        self._choices["provider_name"] = "ollama"
        self._choices["provider_model"] = model_name
        self._settings.set("model_provider", "ollama")
        self._settings.set("ollama_url", ollama_url)
        self._settings.set("ollama_model", model_name)
        self._console.print(f"[green]\u2713 Provider configured: Ollama / {model_name}[/green]")

    async def _setup_online_provider(self) -> None:
        """Option 1: Pick an online/cloud provider."""
        self._console.print("\n[bold]Available Online Providers[/bold]\n")

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("#", style="yellow", width=4)
        table.add_column("Provider", style="cyan")
        table.add_column("Description")
        for i, (key, name, desc) in enumerate(_ONLINE_PROVIDERS, 1):
            table.add_row(str(i), name, desc)
        self._console.print(table)
        self._console.print()

        choice = Prompt.ask(
            "Select a provider",
            choices=[str(i) for i in range(1, len(_ONLINE_PROVIDERS) + 1)],
        )
        idx = int(choice) - 1
        key, name, _desc = _ONLINE_PROVIDERS[idx]

        self._choices["provider_type"] = "online"
        self._choices["provider_name"] = key

        profile = self._provider_mgr.get_profile(key)
        models = profile.get_model_names() if profile else []
        if models:
            self._console.print(f"\n[bold]Available models for {name}[/bold]")
            for i, m in enumerate(models, 1):
                self._console.print(f"  {i}. {m}")
            self._console.print(f"  {len(models) + 1}. Enter custom model name")
            mc = Prompt.ask(
                "Select model",
                choices=[str(i) for i in range(1, len(models) + 2)],
                default="1",
            )
            mc_int = int(mc)
            if 1 <= mc_int <= len(models):
                model = models[mc_int - 1]
            else:
                model = Prompt.ask("Enter custom model name")
        else:
            model = Prompt.ask(f"Enter model name for {name}")

        self._choices["provider_model"] = model

        self._settings.set("model_provider", key)
        model_key = f"{key}_model"
        if model_key in self._settings.get(model_key, None) or True:
            self._settings.set(model_key, model)

        self._console.print(f"\n[bold]API Key for {name}[/bold]")
        self._console.print("[dim]Your key is stored in the encrypted vault.[/dim]")
        api_key = Prompt.ask("Enter API key", password=True)
        if api_key.strip():
            self._choices["api_keys"][key] = api_key.strip()
            self._store_api_key(key, api_key.strip())

        env_var = profile.api_key_env if profile else f"{key.upper()}_API_KEY"
        os.environ[env_var] = api_key.strip()

        self._console.print(f"[green]\u2713 Provider configured: {name} / {model}[/green]")

    async def _setup_offline_provider(self) -> None:
        """Option 2: Pick a local/offline provider."""
        self._console.print("\n[bold]Available Offline Providers[/bold]\n")

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("#", style="yellow", width=4)
        table.add_column("Provider", style="cyan")
        table.add_column("Description")
        for i, (key, name, desc) in enumerate(_OFFLINE_PROVIDERS, 1):
            table.add_row(str(i), name, desc)
        self._console.print(table)
        self._console.print()

        choice = Prompt.ask(
            "Select a provider",
            choices=[str(i) for i in range(1, len(_OFFLINE_PROVIDERS) + 1)],
            default="1",
        )
        idx = int(choice) - 1
        key, name, _desc = _OFFLINE_PROVIDERS[idx]

        self._choices["provider_type"] = "offline"
        self._choices["provider_name"] = key

        profile = self._provider_mgr.get_profile(key)
        models = profile.get_model_names() if profile else []

        config_map = {
            "ollama": ("ollama_url", "http://localhost:11434", "ollama_model"),
            "lmstudio": ("lmstudio_url", "http://localhost:1234", "lmstudio_model"),
            "llamacpp": ("llamacpp_url", "http://localhost:8080", "llamacpp_model"),
            "vllm": ("vllm_url", "http://localhost:8000", "vllm_model"),
            "localai": ("localai_url", "http://localhost:8080", "localai_model"),
        }
        url_key, default_url, model_key = config_map.get(key, ("", "", ""))

        endpoint = Prompt.ask(
            f"API endpoint for {name}",
            default=default_url,
        )
        if url_key:
            self._settings.set(url_key, endpoint)

        if models:
            self._console.print(f"\n[bold]Available models for {name}[/bold]")
            for i, m in enumerate(models, 1):
                self._console.print(f"  {i}. {m}")
            self._console.print(f"  {len(models) + 1}. Enter custom model name")
            mc = Prompt.ask(
                "Select model",
                choices=[str(i) for i in range(1, len(models) + 2)],
                default="1",
            )
            mc_int = int(mc)
            if 1 <= mc_int <= len(models):
                model = models[mc_int - 1]
            else:
                model = Prompt.ask("Enter model name")
        else:
            model = Prompt.ask(f"Enter default model name for {name}")

        self._choices["provider_model"] = model
        self._settings.set("model_provider", key)
        if model_key:
            self._settings.set(model_key, model)

        if key == "ollama":
            self._settings.set("_start_ollama_on_launch", True)
            self._console.print("[dim]Ollama will be started automatically when needed.[/dim]")

        self._console.print(f"[green]\u2713 Provider configured: {name} / {model}[/green]")

    async def _setup_custom_provider(self) -> None:
        """Option 3: Custom provider with user-specified endpoint."""
        self._console.print("\n[bold]Custom Provider Setup[/bold]\n")

        name = Prompt.ask("Provider name", default="custom")
        base_url = Prompt.ask("API endpoint URL", default="http://localhost:8080/v1")
        api_key = Prompt.ask("API key (leave blank if not needed)", password=True, default="")
        model = Prompt.ask("Default model name")

        self._choices["provider_type"] = "custom"
        self._choices["provider_name"] = name.lower()
        self._choices["provider_model"] = model

        self._settings.set("model_provider", name.lower())
        try:
            self._settings.set(f"{name.lower()}_url", base_url)
        except KeyError:
            pass
        try:
            self._settings.set(f"{name.lower()}_model", model)
        except KeyError:
            pass
        if api_key.strip():
            self._choices["api_keys"][name.lower()] = api_key.strip()
            self._store_api_key(name.lower(), api_key.strip())

        self._console.print(
            f"[green]\u2713 Custom provider configured: {name} / {model}[/green]"
        )

    # ── Step 7: Mode Selection ───────────────────────────────────────────

    def _step_mode(self) -> None:
        self._step_header("Mode Configuration")
        self._console.print(
            "Siyarix has three operating modes:\n"
        )

        mode_table = Table(box=box.SIMPLE, show_header=True)
        mode_table.add_column("#", style="yellow", width=4)
        mode_table.add_column("Mode", style="cyan")
        mode_table.add_column("Description")
        mode_table.add_row("1", "Autonomous", "Full LLM-driven agent \u2014 requires an AI provider")
        mode_table.add_row("2", "Integrated", "Hybrid: tries LLM first, falls back to registry")
        mode_table.add_row("3", "Registry", "Offline mode \u2014 tool-based only, no LLM needed")
        mode_table.add_row("4", "Skip", "Keep default (Integrated)")
        self._console.print(mode_table)
        self._console.print()

        choice = Prompt.ask(
            "Select mode",
            choices=["1", "2", "3", "4"],
            default="2",
        )
        mode_map = {"1": "autonomous", "2": "integrated", "3": "registry", "4": "integrated"}
        self._choices["mode"] = mode_map[choice]
        self._settings.set("default_mode", self._choices["mode"])
        self._console.print(
            f"[green]\u2713 Mode set to: {self._choices['mode']}[/green]"
        )
        self._pause()

    # ── Step 8: Persona + System Message ─────────────────────────────────

    def _step_persona_sysmsg(self) -> None:
        self._step_header("Persona & System Message")
        self._console.print("Siyarix personas tailor the AI's behavior.\n")

        try:
            from siyarix.personas import list_personas, get_persona
            personas = list_personas()
        except ImportError:
            personas = []

        if personas:
            ptable = Table(box=box.SIMPLE, show_header=True)
            ptable.add_column("#", style="yellow", width=4)
            ptable.add_column("Persona", style="cyan")
            ptable.add_column("Focus")
            for i, p in enumerate(personas, 1):
                info = get_persona(p) if not isinstance(p, dict) else p
                label = (info.get("label") or info.get("name", p)) if isinstance(info, dict) else p
                desc = info.get("description", "") if isinstance(info, dict) else ""
                short = textwrap.shorten(desc, width=50, placeholder="...") if desc else ""
                ptable.add_row(str(i), str(label), short)
            self._console.print(ptable)
            self._console.print()

            choice = Prompt.ask(
                "Select persona ([a]uto / [u]niversal / [n]one / #)",
                choices=[str(i) for i in range(1, len(personas) + 1)] + ["a", "u", "n"],
                default="a",
            )
            if choice == "a":
                persona = "auto"
            elif choice == "u":
                persona = "universal"
            elif choice == "n":
                persona = "none"
            else:
                persona = personas[int(choice) - 1]
        else:
            persona = "auto"

        self._choices["persona"] = persona
        self._settings.set("persona", persona)
        self._console.print(f"[green]\u2713 Persona set to: {persona}[/green]")

        self._console.print("\n[bold]Additional System Instructions[/bold]")
        self._console.print(
            "[dim]These instructions are appended to the Siyarix system\n"
            "prompt in every session. The default system message is:\n"
            "[/dim]"
        )
        from siyarix.chat.prompts import SIYARIX_SYSTEM_PROMPT
        self._console.print(
            Panel(
                textwrap.shorten(SIYARIX_SYSTEM_PROMPT, width=60, placeholder="..."),
                border_style="dim",
                title="Default System Message",
                title_align="left",
            )
        )
        self._console.print(
            "[dim]You can add custom instructions that extend or override\n"
            "the defaults (e.g., preferred output format, specific tools\n"
            "to prioritize). Leave blank to keep the defaults.[/dim]"
        )
        existing = self._settings.get("additional_system_message")
        extra = Prompt.ask("Additional instructions", default=existing or "")
        if extra.strip():
            self._choices["additional_sysmsg"] = extra.strip()
            self._settings.set("additional_system_message", extra.strip())
            self._console.print("[green]\u2713 Custom instructions saved[/green]")
        else:
            self._settings.set("additional_system_message", "")
            self._console.print("[dim]Using default Siyarix system message.[/dim]")

        self._pause()

    # ── Step 9: Preferences ────────────────────────────────────────────

    def _step_preferences(self) -> None:
        """Configure theme, security defaults, output, notifications, history, log level."""
        self._step_header("Preferences & Security Defaults")
        self._console.print(
            "Configure Siyarix behavior, appearance, and security.\n"
        )

        prefs = self._choices["preferences"]

        # Theme selection
        self._console.print("[bold]Appearance[/bold]")
        themes = ["default", "dark", "light", "neon", "minimal"]
        theme_choice = Prompt.ask(
            "  Color theme",
            choices=themes,
            default=prefs["theme"],
        )
        prefs["theme"] = theme_choice
        self._settings.set("color_theme", theme_choice)

        # Output format
        output_formats = ["table", "json", "yaml", "csv"]
        fmt_choice = Prompt.ask(
            "  Default output format",
            choices=output_formats,
            default=prefs["output_format"],
        )
        prefs["output_format"] = fmt_choice
        self._settings.set("default_output_format", fmt_choice)

        # Notifications
        self._console.print()
        self._console.print("[bold]Notifications[/bold]")
        notif = Confirm.ask(
            "  Show notifications for key events?",
            default=prefs["notifications"],
        )
        prefs["notifications"] = notif
        self._settings.set("notifications_enabled", notif)

        # Log level
        self._console.print()
        self._console.print("[bold]Logging[/bold]")
        log_levels = ["debug", "info", "warning", "error"]
        log_choice = Prompt.ask(
            "  Logging verbosity",
            choices=log_levels,
            default=prefs["log_level"],
        )
        prefs["log_level"] = log_choice
        self._settings.set("log_level", log_choice)

        # History retention
        history_days = Prompt.ask(
            "  History retention (days, 0 = forever)",
            default=str(prefs["history_days"]),
        )
        try:
            prefs["history_days"] = int(history_days)
            self._settings.set("history_retention_days", int(history_days))
        except ValueError:
            pass

        # Security defaults
        self._console.print()
        self._console.print("[bold]Security[/bold]")

        cmd_review = Confirm.ask(
            "  Review shell commands before execution?",
            default=prefs["command_review"],
        )
        prefs["command_review"] = cmd_review
        self._settings.set("command_review", cmd_review)

        stealth = Confirm.ask(
            "  Enable stealth mode (evasion techniques)?",
            default=prefs["stealth_mode"],
        )
        prefs["stealth_mode"] = stealth
        self._settings.set("stealth_mode", stealth)

        # Auto-update
        self._console.print()
        self._console.print("[bold]Updates[/bold]")
        auto_upd = Confirm.ask(
            "  Check for updates automatically?",
            default=prefs["auto_update"],
        )
        prefs["auto_update"] = auto_upd
        self._settings.set("auto_update_check", auto_upd)

        self._console.print("[green]\u2713 Preferences saved[/green]")
        self._pause()

    # ── Step 10: Network Diagnostics ────────────────────────────────────

    async def _step_network_diagnostics(self) -> None:
        """Test internet connectivity, DNS resolution, and provider API."""
        self._step_header("Network Diagnostics")
        self._console.print("Checking network connectivity...\n")

        diag_results: list[tuple[str, bool, str]] = []
        all_ok = True

        # 1. Basic internet connectivity
        self._console.print("[bold]1. Internet Connectivity[/bold]")
        targets = [
            ("https://1.1.1.1", "Cloudflare"),
            ("https://8.8.8.8", "Google DNS"),
        ]
        for url, label in targets:
            ok = False
            detail = ""
            try:
                import httpx
                r = httpx.get(url, timeout=5)
                ok = r.status_code < 500
                detail = f"{r.elapsed.total_seconds():.1f}s"
            except httpx.ConnectError:
                detail = "Connection refused"
            except httpx.TimeoutException:
                detail = "Timeout"
            except Exception as exc:
                detail = str(exc)[:40]
            status_str = "[green]\u2713[/green]" if ok else "[red]\u2717[/red]"
            self._console.print(f"  {label}: {status_str} {detail}")
            diag_results.append((f"Internet ({label})", ok, detail))
            if not ok:
                all_ok = False

        # 2. DNS resolution
        self._console.print()
        self._console.print("[bold]2. DNS Resolution[/bold]")
        dns_targets = ["google.com", "github.com"]
        for host in dns_targets:
            ok = False
            detail = ""
            try:
                addrs = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
                ok = len(addrs) > 0
                detail = addrs[0][4][0] if addrs else ""
            except socket.gaierror:
                detail = "DNS failure"
            except Exception as exc:
                detail = str(exc)[:40]
            status_str = "[green]\u2713[/green]" if ok else "[red]\u2717[/red]"
            self._console.print(f"  {host}: {status_str} {detail}")
            diag_results.append((f"DNS ({host})", ok, detail))
            if not ok:
                all_ok = False

        # 3. Provider API test (if configured)
        provider_name = self._choices.get("provider_name", "")
        if provider_name and self._choices.get("api_keys", {}).get(provider_name):
            self._console.print()
            self._console.print(f"[bold]3. Provider API Test ({provider_name})[/bold]")
            env_var = f"{provider_name.upper()}_API_KEY"
            test_key = os.environ.get(env_var, "")
            if test_key:
                ok = False
                detail = ""
                try:
                    import httpx
                    headers = {"Authorization": f"Bearer {test_key}"}
                    api_urls = {
                        "openai": "https://api.openai.com/v1/models",
                        "anthropic": "https://api.anthropic.com/v1/messages",
                        "gemini": f"https://generativelanguage.googleapis.com/v1beta/models?key={test_key}",
                        "groq": "https://api.groq.com/openai/v1/models",
                        "openrouter": "https://openrouter.ai/api/v1/models",
                    }
                    url = api_urls.get(provider_name, "")
                    if url:
                        r = httpx.get(url, headers=headers, timeout=10)
                        ok = r.status_code < 500
                        detail = f"HTTP {r.status_code} ({r.elapsed.total_seconds():.1f}s)"
                    else:
                        detail = "No test URL for provider"
                except Exception as exc:
                    detail = str(exc)[:40]
                status_str = "[green]\u2713[/green]" if ok else "[red]\u2717[/red]"
                self._console.print(f"  {provider_name}: {status_str} {detail}")
                diag_results.append(("Provider API", ok, detail))
                if not ok:
                    all_ok = self._console.print(
                        f"  [yellow]Key stored but API unreachable. Check endpoint or key.[/yellow]"
                    )
        else:
            self._console.print()
            self._console.print("[bold]3. Provider API Test[/bold] [dim](no provider configured, skipped)[/dim]")

        self._choices["network_ok"] = all_ok

        self._console.print()
        if all_ok:
            self._console.print("[green]\u2713 All network checks passed[/green]")
        else:
            self._console.print(
                "[yellow]\u26a0 Some checks failed. Siyarix will work offline or with local providers.[/yellow]"
            )

        self._pause()

    # ── Step 11: Finalize ───────────────────────────────────────────────

    async def _finalize(self) -> None:
        self._clear_screen()
        self._console.print(_SIYARIX_LOGO)
        self._console.print(
            Panel(
                "[bold green]Setup Complete![/bold green]\n\n"
                "Siyarix is now configured and ready to use.\n\n"
                "Here is a summary of your choices:\n",
                border_style="green",
                box=box.ROUNDED,
            )
        )

        summary = Table(box=box.SIMPLE, show_header=False)
        summary.add_column("Setting", style="cyan")
        summary.add_column("Value")
        summary.add_row("Provider", self._choices["provider_name"] or "Not configured")
        summary.add_row("Model", self._choices["provider_model"] or "-")
        summary.add_row("Mode", self._choices["mode"])
        summary.add_row("Persona", self._choices["persona"])
        summary.add_row("Vault", "\u2713 Initialized" if self._choices["vault_initialized"] else "\u2717 Skipped")
        summary.add_row("Theme", self._choices["preferences"]["theme"])
        summary.add_row("Log Level", self._choices["preferences"]["log_level"])
        summary.add_row("Output Format", self._choices["preferences"]["output_format"])
        summary.add_row("Command Review", str(self._choices["preferences"]["command_review"]))
        summary.add_row("Stealth Mode", str(self._choices["preferences"]["stealth_mode"]))
        if self._choices["additional_sysmsg"]:
            summary.add_row("Custom Instructions", textwrap.shorten(self._choices["additional_sysmsg"], width=40))
        summary.add_row("Tools Found", str(len(self._choices.get("tools_installed", []))))
        summary.add_row("Network", "\u2713 OK" if self._choices["network_ok"] else "\u26a0 Issues")
        self._console.print(summary)
        self._console.print()

        # ── Health check ────────────────────────────────────────────────
        self._console.print("[bold]Quick Health Check[/bold]")
        health_warnings: list[str] = []
        try:
            from siyarix.health import get_health
            health = await get_health().check_all()
            for comp in health.components:
                if comp.state.value != "healthy":
                    health_warnings.append(f"{comp.name}: {comp.message}")
        except Exception:
            health_warnings.append("Health check unavailable")

        if health_warnings:
            for w in health_warnings:
                self._console.print(f"  [yellow]\u26a0 {w}[/yellow]")
        else:
            self._console.print("  [green]\u2713 All systems healthy[/green]")
        self._console.print()

        # ── .env migration ─────────────────────────────────────────────
        dotenv_path = Path.home() / ".siyarix" / ".env"
        alt_path = Path.cwd() / ".env"
        found_env = dotenv_path if dotenv_path.exists() else (alt_path if alt_path.exists() else None)
        if found_env and self._choices["vault_initialized"]:
            self._console.print("[bold].env Migration[/bold]")
            self._console.print(
                "[dim]Found an existing .env file with environment variables.[/dim]"
            )
            if Confirm.ask("Migrate API keys from .env to vault?", default=True):
                migrated = self._migrate_from_dotenv(found_env)
                if migrated:
                    self._choices["env_migrated"] = True
                    self._console.print(f"[green]\u2713 Migrated {migrated} key(s) from .env[/green]")
                else:
                    self._console.print("[dim]No API keys found in .env to migrate.[/dim]")
            self._console.print()

        # ── Shell completion + PATH setup ──────────────────────────────
        if Confirm.ask("Set up shell completions and add Siyarix to PATH?", default=False):
            await self._step_shell_setup()

        # ── Write marker + settings ─────────────────────────────────────
        plat = self._choices.get("platform", {})
        marker_data = {
            "version": "2.0.0",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "python_version": sys.version,
            "platform": {
                "system": plat.get("system", os.name),
                "architecture": plat.get("arch_label", platform.machine()),
                "cpu": plat.get("cpu_count", 0),
                "ram_gb": plat.get("ram_gb", 0),
                "shell": plat.get("shell", ""),
                "package_managers": plat.get("package_managers", []),
                "is_wsl": plat.get("is_wsl", False),
            },
            "health_warnings": health_warnings,
            "choices": {
                "provider_type": self._choices["provider_type"],
                "provider_name": self._choices["provider_name"],
                "model": self._choices["provider_model"],
                "mode": self._choices["mode"],
                "persona": self._choices["persona"],
                "vault": self._choices["vault_initialized"],
                "theme": self._choices["preferences"]["theme"],
                "log_level": self._choices["preferences"]["log_level"],
            },
        }

        self._settings.set("onboarding_complete", True)
        self._bootstrap.ensure_directory_structure()

        INITIALIZED_MARKER.parent.mkdir(parents=True, exist_ok=True)
        INITIALIZED_MARKER.write_text(
            json.dumps(marker_data, indent=2),
            encoding="utf-8",
        )

        self._console.print("[dim]Settings saved to ~/.siyarix/settings.toml[/dim]")
        self._console.print("[dim]Marker written to ~/.siyarix/.initialized[/dim]\n")

        # ── Restart ────────────────────────────────────────────────────
        self._console.print(
            Panel(
                "[bold white]Press ENTER to restart Siyarix[/bold white]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        input()
        self._restart_siyarix()

    # ── Utilities ────────────────────────────────────────────────────────

    def _step_header(self, title: str) -> None:
        self._clear_screen()
        step_num = {
            "Platform Detection": 1, "Requirements Check": 2,
            "Dependencies & Python Packages": 3, "Cybersecurity Tool Discovery": 4,
            "Credential Vault Setup": 5, "Provider Configuration": 6,
            "Mode Configuration": 7, "Persona & System Message": 8,
            "Preferences & Security Defaults": 9, "Network Diagnostics": 10,
        }.get(title, "")
        prefix = f"[{step_num}/10] " if step_num else ""
        self._console.print(f"\n[bold cyan]== {prefix}{title} ==[/bold cyan]\n")

    def _pause(self) -> None:
        self._console.print()
        Confirm.ask("[dim]Press Enter to continue[/dim]", default=True)

    @staticmethod
    def _clear_screen() -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _store_api_key(self, provider: str, key: str) -> None:
        """Store API key in vault and environment."""
        os.environ[provider.upper() + "_API_KEY"] = key
        if self._vault:
            try:
                self._vault.set(provider, key)
            except Exception:
                pass
        try:
            from siyarix.credential_vault import vault_set
            vault_set(provider, key)
        except Exception:
            pass

    def _migrate_from_dotenv(self, env_path: Path) -> int:
        """Migrate API keys from .env file to vault. Returns count of migrated keys."""
        api_key_patterns = ("_API_KEY", "_SECRET", "_PASSWORD", "_TOKEN")
        migrated = 0
        try:
            content = env_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'").strip('"')
                if not key or not val:
                    continue
                if any(p in key.upper() for p in api_key_patterns):
                    provider = key.replace("_API_KEY", "").replace("_SECRET", "").lower()
                    if provider:
                        self._store_api_key(provider, val)
                        migrated += 1
            return migrated
        except Exception:
            return 0

    async def _step_shell_setup(self) -> None:
        """Install shell completions and optionally add Siyarix to PATH."""
        self._console.print()
        self._console.print("[bold]Shell Completion & PATH Setup[/bold]\n")

        shell = self._choices.get("platform", {}).get("shell", "")
        if not shell:
            shell = "bash"

        # Shell completions
        self._console.print(f"  Detected shell: [cyan]{shell}[/cyan]")

        if Confirm.ask("  Install shell completions?", default=True):
            try:
                rc_files = {
                    "bash": Path.home() / ".bashrc",
                    "zsh": Path.home() / ".zshrc",
                    "fish": Path.home() / ".config" / "fish" / "config.fish",
                    "pwsh": Path.home() / ".config" / "powershell" / "profile.ps1",
                    "powershell": Path.home() / ".config" / "powershell" / "profile.ps1",
                }
                rc_file = rc_files.get(shell)
                if os.name == "nt" and shell in ("pwsh", "powershell"):
                    rc_file = Path.home() / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"

                if rc_file and rc_file.parent.exists():
                    completion_cmd = f'eval "$(siyarix completion {shell})"'
                    if rc_file.exists():
                        existing = rc_file.read_text(encoding="utf-8")
                        if completion_cmd not in existing:
                            with rc_file.open("a", encoding="utf-8") as f:
                                f.write(f"\n# Siyarix completions\n{completion_cmd}\n")
                            self._console.print(f"  [green]\u2713 Completions added to {rc_file}[/green]")
                        else:
                            self._console.print(f"  [dim]Completions already in {rc_file}[/dim]")
                    else:
                        rc_file.parent.mkdir(parents=True, exist_ok=True)
                        rc_file.write_text(f"# Siyarix completions\n{completion_cmd}\n", encoding="utf-8")
                        self._console.print(f"  [green]\u2713 Completions file created: {rc_file}[/green]")

                    self._choices["shell_completion_done"] = True
                    self._settings.set("shell_completion_installed", True)
                else:
                    self._console.print("  [yellow]Could not determine shell config file.[/yellow]")
            except Exception as exc:
                self._console.print(f"  [red]Failed to install completions: {exc}[/red]")

        # PATH setup
        self._console.print()
        if Confirm.ask("  Add Siyarix to system PATH?", default=True):
            try:
                siyarix_bin = str(Path(sys.executable).parent)
                if os.name == "nt":
                    # Windows: add to user PATH via setx
                    current_path = os.environ.get("PATH", "")
                    if siyarix_bin.lower() not in current_path.lower():
                        escaped = siyarix_bin.replace("'", "''")
                        script = (
                            f'$oldPath = [Environment]::GetEnvironmentVariable("PATH", "User"); '
                            f'if ($oldPath -notlike "*{escaped}*") {{ '
                            f'  [Environment]::SetEnvironmentVariable("PATH", "$oldPath;{escaped}", "User") '
                            f'}}'
                        )
                        subprocess.run(["powershell", "-Command", script], capture_output=True, timeout=30)
                        self._console.print(f"  [green]\u2713 Added to user PATH: {siyarix_bin}[/green]")
                    else:
                        self._console.print("  [dim]Already in PATH[/dim]")
                else:
                    # Linux/macOS: add to shell rc
                    if rc_file and rc_file.exists():
                        path_line = f'export PATH="$PATH:{siyarix_bin}"'
                        existing = rc_file.read_text(encoding="utf-8")
                        if path_line not in existing:
                            with rc_file.open("a", encoding="utf-8") as f:
                                f.write(f"\n# Siyarix PATH\n{path_line}\n")
                            self._console.print(f"  [green]\u2713 PATH added to {rc_file}[/green]")
                        else:
                            self._console.print("  [dim]PATH already configured[/dim]")

                self._choices["path_setup_done"] = True
                self._settings.set("path_setup_done", True)
            except Exception as exc:
                self._console.print(f"  [red]Failed to set up PATH: {exc}[/red]")

        self._console.print()

    def _pip_install(self, package: str) -> bool:
        self._console.print(f"  Installing [cyan]{package}[/cyan]...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package, "--quiet"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                self._console.print(f"  [green]\u2713 {package} installed[/green]")
                return True
            self._console.print(f"  [red]\u2717 {package} failed: {result.stderr.strip()}[/red]")
            return False
        except Exception as exc:
            self._console.print(f"  [red]\u2717 {package}: {exc}[/red]")
            return False

    def _install_system_tool(self, tool: str, pkg: str | None = None) -> bool:
        """Install a system tool using the appropriate package manager."""
        pkg = pkg or tool
        self._console.print(f"  Installing [cyan]{tool}[/cyan]...")

        if os.name == "nt":
            return self._elevated_install_win(tool, pkg)
        else:
            return self._elevated_install_nix(tool, pkg)

    def _elevated_install_win(self, tool: str, pkg: str) -> bool:
        """Elevated install on Windows via winget/choco."""
        if shutil.which("winget"):
            try:
                script = f'Start-Process -FilePath "winget" -ArgumentList "install --silent {pkg}" -Verb RunAs -Wait'
                subprocess.run(
                    ["powershell", "-Command", script],
                    capture_output=True, text=True, timeout=300,
                )
                if shutil.which(tool):
                    self._console.print(f"  [green]\u2713 {tool} installed via winget[/green]")
                    return True
            except Exception:
                pass
        if shutil.which("choco"):
            try:
                script = f'Start-Process -FilePath "choco" -ArgumentList "install -y {pkg}" -Verb RunAs -Wait'
                subprocess.run(
                    ["powershell", "-Command", script],
                    capture_output=True, text=True, timeout=300,
                )
                if shutil.which(tool):
                    self._console.print(f"  [green]\u2713 {tool} installed via choco[/green]")
                    return True
            except Exception:
                pass
        self._console.print(
            f"  [yellow]Could not auto-install {tool}.[/yellow]"
        )
        self._console.print(f"  [dim]Install manually: winget install {pkg}[/dim]")
        return False

    def _elevated_install_nix(self, tool: str, pkg: str) -> bool:
        """Elevated install on Linux/macOS via sudo."""
        pm = self._bootstrap.detect_platform().package_manager
        if not pm:
            pm = "apt-get" if shutil.which("apt-get") else "brew"

        install_cmd = {
            "apt": ["apt-get", "install", "-y", pkg],
            "apt-get": ["apt-get", "install", "-y", pkg],
            "brew": ["brew", "install", pkg],
            "pacman": ["pacman", "-S", "--noconfirm", pkg],
            "dnf": ["dnf", "install", "-y", pkg],
            "apk": ["apk", "add", pkg],
        }.get(pm, [pm, "install", "-y", pkg])

        try:
            self._console.print(f"  Running: sudo {' '.join(install_cmd)}")
            result = subprocess.run(
                ["sudo", "-p", "Password required for installation: "] + install_cmd,
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                if shutil.which(tool):
                    self._console.print(f"  [green]\u2713 {tool} installed[/green]")
                    return True
            self._console.print(f"  [red]\u2717 {tool}: {result.stderr.strip()}[/red]")
            return False
        except subprocess.TimeoutExpired:
            self._console.print(f"  [red]\u2717 {tool}: installation timed out[/red]")
            return False
        except Exception as exc:
            self._console.print(f"  [red]\u2717 {tool}: {exc}[/red]")
            return False

    def _install_ollama(self) -> bool:
        """Install Ollama on the current platform."""
        self._console.print("  Installing Ollama...\n")
        try:
            if os.name == "nt":
                self._console.print("  Downloading Ollama for Windows...")
                script = (
                    '$url = "https://ollama.com/download/OllamaSetup.exe"; '
                    '$out = "$env:TEMP\\OllamaSetup.exe"; '
                    "Invoke-WebRequest -Uri $url -OutFile $out; "
                    'Start-Process -FilePath $out -ArgumentList "/S" -Verb RunAs -Wait'
                )
                subprocess.run(
                    ["powershell", "-Command", script],
                    capture_output=True, text=True, timeout=600,
                )
                if shutil.which("ollama"):
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                    return True
                self._console.print("  [yellow]Ollama installer may need user interaction.[/yellow]")
                return shutil.which("ollama") is not None
            elif sys.platform == "darwin":
                self._console.print("  Downloading Ollama for macOS...")
                subprocess.run(
                    ["curl", "-fsSL", "https://ollama.com/install.sh"],
                    capture_output=True, text=True, timeout=60,
                )
                result = subprocess.run(
                    'curl -fsSL https://ollama.com/install.sh | sh',
                    shell=True, capture_output=True, text=True, timeout=600,  # nosec B602
                )
                ok = result.returncode == 0
                if ok:
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                else:
                    self._console.print(f"  [red]Install failed: {result.stderr.strip()}[/red]")
                return ok
            else:
                self._console.print("  Installing via official script...")
                result = subprocess.run(
                    'curl -fsSL https://ollama.com/install.sh | sh',
                    shell=True, capture_output=True, text=True, timeout=600,  # nosec B602
                )
                ok = result.returncode == 0
                if ok:
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                else:
                    self._console.print(f"  [red]Install failed: {result.stderr.strip()}[/red]")
                return ok
        except Exception as exc:
            self._console.print(f"  [red]Ollama installation error: {exc}[/red]")
            return False

    @staticmethod
    def _check_ollama_running(url: str) -> bool:
        try:
            import httpx
            r = httpx.get(f"{url}/api/tags", timeout=5)
            return r.status_code < 500
        except Exception:
            return False

    @staticmethod
    def _start_ollama_service() -> None:
        try:
            if os.name == "nt":
                subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception as exc:
            logger.warning("Failed to start Ollama: %s", exc)

    @staticmethod
    def _restart_siyarix() -> None:
        OnboardingWizard._clear_screen()
        if os.name == "nt":
            subprocess.Popen(
                [sys.executable, "-m", "siyarix"] + sys.argv[1:],
                shell=True,  # nosec B602
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            os.execv(sys.executable, [sys.executable, "-m", "siyarix"] + sys.argv[1:])
        sys.exit(0)


__all__ = [
    "OnboardingWizard",
    "INITIALIZED_MARKER",
]
