# SPDX-License-Identifier: AGPL-3.0-or-later

"""First-run onboarding wizard — interactive TUI setup for Siyarix.

Walks the user through a multi-step process:
  0. Welcome + ethics pledge
  1. Platform detection (OS, arch, hardware, shell, PMs, env type)
  2. Python + basic requirements check (pip, git, curl)
  3. Python dependencies + SDKs
  4. Cybersecurity tool discovery & install
   5. Credential storage setup (initialize encrypted credential store)

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
import shutil
import socket
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siyarix.bootstrap import INITIALIZED_MARKER, BootstrapEngine
from siyarix.config import SettingsStore, get_config_dir
from siyarix.templates.wizard_text import (
    SIYARIX_LOGO as _SIYARIX_LOGO,
    WELCOME_PANEL_TEXT as _WELCOME_PANEL_TEXT,
    ETHICS_PLEDGE_TEXT as _ETHICS_PLEDGE_TEXT,
    EXIT_GREETING_TEXT as _EXIT_GREETING_TEXT,
    ONLINE_PROVIDERS as _ONLINE_PROVIDERS,
    OFFLINE_PROVIDERS as _OFFLINE_PROVIDERS,
    REQUIRED_TOOLS as _REQUIRED_TOOLS,
    MINIMAL_CYBER_TOOLS as _MINIMAL_CYBER_TOOLS,
    PERSONA_TOOLS as _PERSONA_TOOLS,
    ARCH_MAP as _ARCH_MAP,
    PM_CHECKS as _PM_CHECKS,
    DEFAULT_PREFERENCES as _DEFAULT_PREFERENCES,
)
from siyarix.tool_installer import ToolInstaller

logger = logging.getLogger(__name__)

# ── Cybersecurity model tiers for recommended setup ────────────────────
# Ordered by free RAM tiers. All models are security-focused.
SECURITY_MODEL_TIERS: list[dict[str, Any]] = [
    {
        "tier": "light",
        "label": "Light  (≤ 4 GB RAM)",
        "min_ram": 0,
        "max_ram": 4,
        "models": [
            ("IHA089/drana-infinity-3b", "1.8 GB", "Cybersecurity research, bug bounty, vulnerability analysis — fast 3B model"),
            ("qwen3.5:4b", "3.4 GB", "Tool-calling champion (97.5% FC pass rate), general intelligence, coding — fits any system"),
            ("luisppb16/gemma4-e4b-secops", "2.5 GB", "Gemma 4-based SecOps (native function calling), offensive/defensive security, code review"),
            ("xploiter/pentester", "1.6 GB", "Pentesting methodology, OWASP, tool guidance — lightest option"),
        ],
        "default_idx": 0,
        "fallback": "IHA089/drana-infinity-3b",
    },
    {
        "tier": "balanced",
        "label": "Balanced (4-8 GB RAM)",
        "min_ram": 4,
        "max_ram": 8,
        "models": [
            ("IHA089/drana-infinity-7b", "4.5 GB", "Elite cybersecurity research, exploit logic, multi-step attack chains — 7B"),
            ("luisppb16/qwen3.5-9b-red-team", "5.5 GB", "Red team operations (Qwen3.5 base = elite function calling)"),
            ("supergoatscriptguy/mythos-sec:8b", "5 GB", "CTF, bug bounty, pentest — Gemma-4 based, native function calling, no disclaimers"),
            ("luisppb16/gemma4-e4b-secops", "2.5 GB", "Gemma 4-based SecOps (native function calling) — fast 4B"),
        ],
        "default_idx": 0,
        "fallback": "IHA089/drana-infinity-7b",
    },
    {
        "tier": "capable",
        "label": "Capable (8-16 GB RAM)",
        "min_ram": 8,
        "max_ram": 16,
        "models": [
            ("supergoatscriptguy/mythos-sec:8b", "5 GB", "CTF, bug bounty, pentest — Gemma-4 based, native function calling, no disclaimers"),
            ("qwen3:14b", "9.3 GB", "Best accuracy-to-size ratio, 88-92% function calling, strong reasoning & tool orchestration"),
            ("luisppb16/qwen3.5-9b-red-team", "5.5 GB", "Red team operations, adversary simulation — Qwen3.5 fine-tune"),
            ("IHA089/drana-infinity-7b", "4.5 GB", "Elite cybersecurity research, exploit logic — solid 7B specialist"),
        ],
        "default_idx": 0,
        "fallback": "IHA089/drana-infinity-7b",
    },
    {
        "tier": "high-end",
        "label": "High-end (16+ GB RAM)",
        "min_ram": 16,
        "max_ram": 999,
        "models": [
            ("supergoatscriptguy/mythos-sec:24b", "14 GB", "Flagship security: 30B-class quality at 8B-class speed (MoE), tool-calling ready"),
            ("gemma4:26b", "18 GB", "Native function calling (92% FC), MoE with 4B active params — best FC among local models"),
            ("luisppb16/qwen3.5-9b-red-team", "5.5 GB", "Red team specialist, adversary simulation — highly rated, Qwen3.5 FC"),
            ("IHA089/drana-infinity-7b", "4.5 GB", "Elite cybersecurity research — always a solid choice"),
        ],
        "default_idx": 0,
        "fallback": "luisppb16/qwen3.5-9b-red-team",
    },
]

try:
    from rich.console import Console
    from rich.markup import escape as rich_escape
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich import box
except ImportError:
    Console = None  # type: ignore[assignment,misc]
    Panel = None  # type: ignore[assignment,misc]
    Prompt = None  # type: ignore[assignment,misc]
    Confirm = None  # type: ignore[assignment,misc]
    Table = None  # type: ignore[assignment,misc]
    box = None  # type: ignore[assignment]



# ── OnboardingWizard ────────────────────────────────────────────────────────


class OnboardingWizard:
    """Interactive first-run setup wizard for Siyarix."""

    def __init__(
        self,
        settings: SettingsStore | None = None,
        cred_store: Any | None = None,
        console: Any | None = None,
    ) -> None:
        self._settings = settings or SettingsStore()
        self._cred_store = cred_store
        self._console = console or Console()
        self._bootstrap = BootstrapEngine()
        self._provider_mgr = ProviderManager.get_instance()

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
            "credential_store_initialized": False,
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
        self._step_credential_setup()
        await self._step_provider()
        self._step_mode()
        self._step_persona_sysmsg()
        self._step_install_persona_tools()
        self._step_preferences()
        await self._step_network_diagnostics()
        await self._finalize()
        return True

    # ── Step 0: Welcome + Ethics ────────────────────────────────────────

    def _welcome_screen(self) -> bool:
        self._clear_screen()
        self._console.print(
            Panel.fit(
                _SIYARIX_LOGO,
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
        self._console.print(
            Panel(
                _WELCOME_PANEL_TEXT,
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        self._console.print()
        self._console.print(
            Panel(
                _ETHICS_PLEDGE_TEXT,
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
                _EXIT_GREETING_TEXT,
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    # ── Step 1: Platform Detection ──────────────────────────────────────

    def _step_platform_detection(self) -> None:
        """Detect OS, architecture, hardware, shell, package managers, and environment."""
        self._step_header("Platform Detection")
        self._console.print(
            "Siyarix detects your environment to adapt installation\nand configuration for your platform.\n"
        )

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
            is_desktop = bool(
                os.environ.get("DISPLAY")
                or os.environ.get("WAYLAND_DISPLAY")
                or os.environ.get("DESKTOP_SESSION")
            )

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
        seen = set()
        available_pms = []
        for binary, name in _PM_CHECKS:
            if shutil.which(binary) and name not in seen:
                seen.add(name)
                available_pms.append(name)

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

                windll = getattr(ctypes, "windll", None)
                if windll is not None:
                    kernel32 = windll.kernel32

                    class MEMORYSTATUSEX(ctypes.Structure):
                        _fields_ = [
                            ("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                        ]

                    mem = MEMORYSTATUSEX()
                    mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                    if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
                        ram_total_gb = mem.ullTotalPhys / (1024**3)
            elif system == "Linux":
                with open("/proc/meminfo", encoding='utf-8') as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ram_total_gb = int(parts[1]) / (1024 * 1024)
                            break
            elif system == "Darwin":
                result = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if not result.returncode:
                    ram_total_gb = int(result.stdout.strip()) / (1024**3)
        except (ValueError, OSError, subprocess.SubprocessError):
            pass

        ram_label = f"{ram_total_gb:.1f} GB" if ram_total_gb > 0 else "Unknown"

        # Free / available RAM (using psutil for consistency)
        ram_free_gb = 0.0
        try:
            import psutil
            mem = psutil.virtual_memory()
            ram_free_gb = mem.available / (1024**3)
        except Exception:
            pass

        # Physical CPU cores
        cpu_physical = 0
        try:
            import psutil as _ps
            cpu_physical = _ps.cpu_count(logical=False) or 0
        except Exception:
            pass

        # ── GPU detection ─────────────────────────────────────────────
        gpu_type = "none"
        gpu_vram_gb = 0
        gpu_name = ""

        # NVIDIA
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if not result.returncode and result.stdout.strip():
                parts = [p.strip() for p in result.stdout.split(",")]
                gpu_type = "nvidia"
                gpu_name = parts[0] if len(parts) > 0 else ""
                try:
                    gpu_vram_gb = round(int(parts[1]) / 1024, 1) if len(parts) > 1 else 0
                except (ValueError, IndexError):
                    pass
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        # AMD ROCm
        if gpu_type == "none":
            try:
                result = subprocess.run(
                    ["rocm-smi", "--showmeminfo", "vram"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if not result.returncode and "VRAM" in result.stdout:
                    gpu_type = "amd"
                    for line in result.stdout.splitlines():
                        if "VRAM Total" in line:
                            val = line.split(":")[-1].strip().split()[0] if ":" in line else ""
                            try:
                                gpu_vram_gb = round(float(val) / 1024, 1) if val else 0
                            except (ValueError, IndexError):
                                pass
                            break
            except (FileNotFoundError, subprocess.SubprocessError):
                pass

        # Apple Metal (macOS)
        if gpu_type == "none" and system == "Darwin":
            try:
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if not result.returncode:
                    for line in result.stdout.splitlines():
                        if "Chip" in line or "Apple" in line:
                            gpu_type = "apple"
                            gpu_name = line.split(":")[-1].strip()
                            break
            except (FileNotFoundError, subprocess.SubprocessError):
                pass

        # ── Battery / Server detection ─────────────────────────────────
        has_battery = False
        try:
            import psutil as _ps
            bat = _ps.sensors_battery()
            has_battery = bat is not None
        except Exception:
            pass
        is_server = not has_battery and ram_total_gb >= 16

        gpu_label = f"{gpu_name} ({gpu_vram_gb:.1f} GB)" if gpu_name else gpu_type.upper() if gpu_type != "none" else "None"

        # Disk space for ~/.siyarix home
        disk_free_gb = 0.0
        try:
            siyarix_home = get_config_dir()
            siyarix_home.mkdir(parents=True, exist_ok=True)
            free_bytes = shutil.disk_usage(siyarix_home).free
            disk_free_gb = free_bytes / (1024**3)
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
        info_table.add_row("CPU (logical)", cpu_label)
        info_table.add_row("CPU (physical)", str(cpu_physical) if cpu_physical else "Unknown")
        info_table.add_row("GPU", gpu_label)
        info_table.add_row("RAM (total)", ram_label)
        info_table.add_row("RAM (free)", f"{ram_free_gb:.1f} GB" if ram_free_gb > 0 else "Unknown")
        info_table.add_row("Device", "Server" if is_server else "Desktop/Laptop")
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
            "cpu_physical": cpu_physical,
            "ram_gb": ram_total_gb,
            "ram_free_gb": round(ram_free_gb, 1),
            "gpu_type": gpu_type,
            "gpu_vram_gb": gpu_vram_gb,
            "gpu_name": gpu_name,
            "has_battery": has_battery,
            "is_server": is_server,
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

        checks: list[tuple[str, bool, str]] = []

        py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 12)
        checks.append(("Python >= 3.12", py_ok, "All features require Python 3.12+"))
        if not py_ok:
            self._console.print(
                f"[red]Python {sys.version_info.major}.{sys.version_info.minor} found \u2014 "
                f"3.12+ required[/red]"
            )
            self._console.print("[yellow]Please upgrade Python and try again.[/yellow]")
            Confirm.ask("[dim]Press Enter to exit[/dim]")
            sys.exit(1)

        pip_ok = shutil.which("pip") is not None or shutil.which("pip3") is not None
        checks.append(("pip / pip3", pip_ok, "Package installer for Python dependencies"))

        for cmd, label, desc in _REQUIRED_TOOLS:
            checks.append((label, shutil.which(cmd) is not None, desc))

        # Writable config directory
        config_dir = get_config_dir()
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            test_file = config_dir / ".write_test"
            test_file.write_text("ok")
            test_file.unlink()
            dir_writable = True
        except Exception:
            dir_writable = False
        checks.append(("Config dir writable", dir_writable, "Siyarix needs to store settings and credentials"))
        if not dir_writable:
            self._console.print(f"[red]Cannot write to {config_dir}[/red]")
            self._console.print("[yellow]Check permissions and try again.[/yellow]")
            Confirm.ask("[dim]Press Enter to exit[/dim]")
            sys.exit(1)

        # PATH issue detection
        path_issues: list[str] = []
        if not shutil.which("siyarix") and not Path(sys.argv[0]).name.startswith("siyarix"):
            path_issues.append("Siyarix not found in PATH (may need pip install -e .)")

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Requirement", style="cyan")
        table.add_column("Why")
        table.add_column("Status", justify="center")
        for label, ok, reason in checks:
            status = "[green]\u2713[/green]" if ok else "[red]\u2717[/red]"
            table.add_row(label, f"[dim]{reason}[/dim]", status)
        self._console.print(table)
        self._console.print()

        if path_issues:
            for issue in path_issues:
                self._console.print(f"[yellow]\u26a0 {issue}[/yellow]")

        missing = [cmd for cmd, label, _desc in _REQUIRED_TOOLS if not shutil.which(cmd)]
        if missing:
            self._console.print("[yellow]Some basic requirements are missing.[/yellow]")
            if Confirm.ask("Install missing requirements?", default=True):
                installer = ToolInstaller(console=self._console)
                for cmd in missing:
                    installer.install_tool(cmd)
        self._console.print("[green]\u2713 Requirements check complete[/green]")
        self._pause()

    # ── Step 3: Dependencies & SDKs ──────────────────────────────────────

    async def _step_dependencies(self) -> None:
        self._step_header("Dependencies & Python Packages")
        self._console.print("Checking required Python packages...\n")

        core_deps = [
            ("pydantic", "pydantic", "Settings, data validation"),
            ("rich", "rich", "Terminal UI, tables, prompts"),
            ("httpx", "httpx", "HTTP requests to providers and APIs"),
            ("cryptography", "cryptography", "Encrypted credential storage"),
            ("tomli", "tomli" if sys.version_info < (3, 11) else "stdlib tomllib", "Config file parsing"),
            ("prompt_toolkit", "prompt_toolkit", "Interactive REPL and input"),
            ("pyyaml", "yaml", "YAML config support"),
            ("jinja2", "jinja2", "Prompt templating engine"),
            ("packaging", "packaging", "Version comparison for tools"),
            ("pygments", "pygments", "Code syntax highlighting in output"),
            ("openai", "openai", "OpenAI-compatible SDK (all providers use this under the hood)"),
        ]

        results: list[tuple[str, bool, str]] = []
        missing: list[str] = []

        import importlib
        for pkg, import_str, reason in core_deps:
            try:
                if "stdlib" in import_str:
                    results.append((pkg, True, "built-in", reason))
                else:
                    importlib.import_module(import_str)
                    results.append((pkg, True, "installed", reason))
            except ImportError:
                results.append((pkg, False, "missing", reason))
                missing.append(pkg)

        if not shutil.which("pip") and not shutil.which("pip3"):
            self._console.print("[red]pip not found! Cannot install packages.[/red]")
            self._pause()
            return

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Package", style="cyan")
        table.add_column("Why")
        table.add_column("Status", justify="center")
        for pkg, ok, detail, reason in results:
            status = f"[green]\u2713 {detail}[/green]" if ok else f"[red]\u2717 {detail}[/red]"
            table.add_row(pkg, f"[dim]{reason}[/dim]", status)
        self._console.print(table)
        self._console.print()

        if missing:
            self._console.print(f"[yellow]{len(missing)} package(s) need installation.[/yellow]")
            if Confirm.ask("Install missing packages automatically?", default=True):
                for pkg in missing:
                    self._pip_install(pkg)
                self._console.print("[green]\u2713 Packages installed[/green]")
            else:
                self._console.print("[yellow]Skipping. Some features may be unavailable.[/yellow]")

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

        self._console.print(f"[yellow]{len(missing)} security tool(s) not found.[/yellow]")
        self._console.print("[dim]These tools extend Siyarix's capabilities.[/dim]\n")

        install_choices = {}
        for exe, pkg, desc in missing:
            want = Confirm.ask(f"  Install [cyan]{exe}[/cyan]? ({desc})", default=False)
            if want:
                install_choices[exe] = pkg

        if install_choices:
            self._console.print(f"\nInstalling {len(install_choices)} tool(s)...")
            installer = ToolInstaller(console=self._console)
            for exe, pkg in install_choices.items():
                installer.install_tool(exe, pkg)
        else:
            self._console.print("[yellow]Skipping tool installation.[/yellow]")

        self._console.print("[green]\u2713 Tool discovery complete[/green]")
        self._pause()

    # ── Step 5: Vault Setup ─────────────────────────────────────────────

    def _step_credential_setup(self) -> None:
        """Initialize the encrypted credential storage."""
        self._step_header("Credential Storage Setup")
        self._console.print(
            "Siyarix uses an [bold]encrypted credential store[/bold] to keep API keys\n"
            "secure at rest. Keys are encrypted with Fernet (AES-128-CBC) and\n"
            "automatically managed.\n\n"
        )
        try:
            from siyarix.credential_store import CredentialStore

            store = CredentialStore()
            self._cred_store = store
            self._choices["credential_store_initialized"] = True
            self._console.print("[green]\u2713 Credential store initialized[/green]")
        except Exception as exc:
            self._console.print(f"[yellow]Credential store unavailable: {exc}[/yellow]")
            self._choices["credential_store_initialized"] = False
            self._console.print(
                "[yellow]You can configure API keys later with: siyarix auth set-key[/yellow]"
            )

        self._pause()

    # ── Step 6: Provider Selection ──────────────────────────────────────

    async def _step_provider(self) -> None:
        self._step_header("Provider Configuration")
        self._console.print(
            "Siyarix needs an AI provider to power its autonomous\n" "and integrated modes.\n"
        )

        options = Table(box=box.ROUNDED, show_header=False)
        options.add_column("Option", style="yellow", width=8)
        options.add_column("Description")
        options.add_row(
            "[bold]0[/bold]",
            "[bold]Recommended[/bold] \u2014 Auto-detect & setup local provider (Ollama/llama.cpp)",
        )
        options.add_row(
            "[bold]1[/bold]", "Online Provider \u2014 cloud API (OpenAI, Anthropic, Gemini...)"
        )
        options.add_row(
            "[bold]2[/bold]", "Offline Provider \u2014 run locally (Ollama, LM Studio...)"
        )
        options.add_row(
            "[bold]3[/bold]", "Custom Provider \u2014 your own endpoint / private model"
        )
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
        """Option 0: Auto-detect device, recommend provider + cybersecurity model."""
        import asyncio

        specs = self._choices.get("platform", {})
        ram_free = specs.get("ram_free_gb", 0)
        has_gpu = specs.get("gpu_type", "none") != "none"

        # Show device summary (already detected in Step 1)
        self._console.print("\n[bold]== Your System ==[/bold]\n")
        dev_table = Table(box=box.SIMPLE, show_header=False)
        dev_table.add_column("Property", style="cyan")
        dev_table.add_column("Value")
        dev_table.add_row("RAM (total)", f"{specs.get('ram_gb', 0):.1f} GB")
        dev_table.add_row("RAM (free)", f"{ram_free:.1f} GB")
        dev_table.add_row("CPU (logical)", str(specs.get("cpu_count", 0)))
        dev_table.add_row("CPU (physical)", str(specs.get("cpu_physical", 0)))
        if has_gpu:
            gpu_n = specs.get("gpu_name", "")
            gpu_v = specs.get("gpu_vram_gb", 0)
            gl = f"{gpu_n} ({gpu_v:.1f} GB)" if gpu_n else specs["gpu_type"].upper()
            dev_table.add_row("GPU", gl)
        else:
            dev_table.add_row("GPU", "[yellow]Not detected (CPU mode)[/yellow]")
        dev_table.add_row("Free Disk (~/.siyarix)", f"{specs.get('disk_free_gb', 0):.1f} GB")
        dev_table.add_row("Device", "[green]Server[/green]" if specs.get("is_server") else "[blue]Desktop/Laptop[/blue]")
        self._console.print(dev_table)
        self._console.print()

        # Classify tier based on free RAM
        _tier_config, models, default_idx, fallback_model = self._suggest_models({"ram_free_gb": ram_free})
        tier_label = _tier_config["label"]
        self._console.print(f"Detected tier: [bold cyan]{tier_label}[/bold cyan]\n")

        # ── Step 2: Provider choice ──────────────────────────────────────
        self._console.print("[bold]== Choose Your Provider ==[/bold]\n")
        self._console.print(
            "Both providers will be auto-installed. Pick based on your preference:\n"
        )

        prov_table = Table(box=box.ROUNDED, show_header=True)
        prov_table.add_column("#", style="yellow", width=4)
        prov_table.add_column("Provider", style="cyan")
        prov_table.add_column("Idle RAM", justify="center")
        prov_table.add_column("GPU Support")
        prov_table.add_column("Model Management")
        prov_table.add_column("Best For")
        prov_table.add_row(
            "1", "llama.cpp",
            "Zero (on-demand)",
            "CUDA, Metal, Vulkan",
            "Manual (GGUF files)",
            "Low-RAM, power users",
        )
        prov_table.add_row(
            "2", "Ollama",
            "~200 MB daemon",
            "CUDA, Metal",
            "Built-in (ollama pull)",
            "Most users, convenience",
        )
        self._console.print(prov_table)
        self._console.print()

        # Default: llama.cpp for low-RAM/no-GPU, Ollama for well-resourced systems
        prov_default = "1" if ram_free < 6 or not has_gpu else "2"
        prov_choice = Prompt.ask(
            "Select provider",
            choices=["1", "2"],
            default=prov_default,
        )

        is_llamacpp = prov_choice == "1"
        provider_name = "llamacpp" if is_llamacpp else "ollama"
        provider_label = "llama.cpp" if is_llamacpp else "Ollama"

        self._console.print()
        self._console.print(f"[bold]== Installing {provider_label} ==[/bold]\n")

        # ── Step 3: Install & start provider ─────────────────────────────
        if is_llamacpp:
            bin_path = Path.home() / ".siyarix" / "bin" / "llama-server"
            if os.name == "nt":
                bin_path = Path.home() / ".siyarix" / "bin" / "llama-server.exe"
            llamacpp_found = bin_path.exists() or bool(shutil.which("llama-server"))

            if not llamacpp_found:
                self._console.print("[yellow]llama-server not found on your system.[/yellow]")
                if Confirm.ask("Install llama.cpp?", default=True):
                    ok = self._install_llamacpp()
                    if not ok:
                        self._console.print("[red]llama.cpp installation failed.[/red]")
                        if Confirm.ask("Try an online provider instead?", default=True):
                            await self._setup_online_provider()
                        return
                else:
                    self._console.print("[yellow]llama.cpp required for recommended setup.[/yellow]")
                    if Confirm.ask("Try an online provider instead?", default=True):
                        await self._setup_online_provider()
                    return

            if bin_path.exists():
                os.environ["PATH"] = str(bin_path.parent) + os.pathsep + os.environ.get("PATH", "")

            llamacpp_url = os.environ.get("LLAMACPP_HOST", "http://localhost:18080")
            running = self._check_llamacpp_running(llamacpp_url)
            if not running:
                self._console.print("[yellow]llama.cpp server is not running.[/yellow]")
                if Confirm.ask("Start llama.cpp server now?", default=True):
                    self._start_llamacpp_service()
                    await asyncio.sleep(2)

            self._settings.set("llamacpp_url", llamacpp_url)
            pull_cmd = None
            self._console.print(f"[green]\u2713 {provider_label} ready[/green]")
        else:
            ollama_found = shutil.which("ollama") is not None
            if not ollama_found:
                self._console.print("[yellow]Ollama not found on your system.[/yellow]")
                if Confirm.ask("Install Ollama?", default=True):
                    ok = self._install_ollama()
                    if not ok:
                        self._console.print("[red]Ollama installation failed.[/red]")
                        self._console.print("Install manually from: https://ollama.com")
                        if Confirm.ask("Try an online provider instead?", default=True):
                            await self._setup_online_provider()
                        return
                else:
                    self._console.print("[yellow]Ollama required for recommended setup.[/yellow]")
                    if Confirm.ask("Try an online provider instead?", default=True):
                        await self._setup_online_provider()
                    return

            ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            running = self._check_ollama_running(ollama_url)
            if not running:
                self._console.print("[yellow]Ollama service is not running.[/yellow]")
                if Confirm.ask("Start Ollama now?", default=True):
                    self._start_ollama_service()
                    await asyncio.sleep(3)

            self._settings.set("ollama_url", ollama_url)
            self._settings.set("_start_ollama_on_launch", True)
            pull_cmd = ["ollama", "pull"]
            self._console.print(f"[green]\u2713 {provider_label} ready[/green]")

        # ── Step 4: Model selection ──────────────────────────────────────
        self._console.print()
        self._console.print("[bold]== Choose Your Cybersecurity Model ==[/bold]\n")
        self._console.print(
            f"Based on your system ({ram_free:.1f} GB free RAM), "
            f"here are recommended security-focused models:\n"
        )

        model_table = Table(box=box.ROUNDED, show_header=True)
        model_table.add_column("#", style="yellow", width=4)
        model_table.add_column("Model", style="cyan")
        model_table.add_column("Size", justify="center")
        model_table.add_column("Description")
        for i, (m_name, m_size, m_desc) in enumerate(models, 1):
            model_table.add_row(str(i), m_name, m_size, m_desc)
        custom_idx = len(models) + 1
        model_table.add_row(str(custom_idx), "[bold]Custom[/bold]", "—", "Enter your own model name")
        self._console.print(model_table)
        self._console.print()

        model_choices = [str(i) for i in range(1, custom_idx + 1)]
        model_choice = Prompt.ask(
            "Select model",
            choices=model_choices,
            default=str(default_idx + 1),
        )

        model_choice_int = int(model_choice)
        if 1 <= model_choice_int <= len(models):
            model_name = models[model_choice_int - 1][0]
        else:
            model_name = Prompt.ask("Enter custom model name (e.g., your-org/your-model)")

        # ── Step 5: Download model ──────────────────────────────────────
        self._console.print()
        self._console.print(f"[bold]== Downloading {model_name} ==[/bold]\n")

        if not is_llamacpp:
            self._console.print(f"Pulling [cyan]{model_name}[/cyan] with Ollama...")
            self._console.print("[dim]This may take several minutes depending on model size.[/dim]")
            if Confirm.ask("Pull this model now?", default=True):
                try:
                    result = subprocess.run(
                        [*pull_cmd, model_name],
                        capture_output=True,
                        text=True,
                        timeout=7200,
                        check=False,
                    )
                    if not result.returncode:
                        self._console.print("[green]\u2713 Model downloaded[/green]")
                    else:
                        self._console.print(f"[red]Pull failed: {result.stderr.strip()}[/red]")
                        model_name = fallback_model
                        self._console.print(f"Falling back to [cyan]{model_name}[/cyan]")
                        subprocess.run(
                            [*pull_cmd, model_name],
                            capture_output=True,
                            text=True,
                            timeout=7200,
                            check=False,
                        )
                except Exception as exc:
                    self._console.print(f"[red]Error: {exc}[/red]")
                    model_name = fallback_model
                    self._console.print(f"Falling back to [cyan]{model_name}[/cyan]")
            else:
                model_name = fallback_model
                self._console.print(f"Using fallback: [cyan]{model_name}[/cyan]")

            self._settings.set("ollama_model", model_name)
        else:
            # llama.cpp: try Ollama pull as convenience download
            downloaded = False
            ollama_installed_by_us = False
            models_dir = Path.home() / ".siyarix" / "models"
            models_dir.mkdir(parents=True, exist_ok=True)

            # Install Ollama if not already present
            if not shutil.which("ollama"):
                self._console.print("[yellow]Ollama is required to download this model.[/yellow]")
                if Confirm.ask("Install Ollama now?", default=True):
                    if self._install_ollama():
                        ollama_installed_by_us = True
                        self._console.print("[green]\u2713 Ollama installed[/green]")
                    else:
                        self._console.print("[red]Ollama install failed, falling back to manual download.[/red]")
                else:
                    self._console.print("[yellow]Skipping Ollama install.[/yellow]")

            # Ensure Ollama server is running before pulling
            if shutil.which("ollama") and not self._check_ollama_running("http://localhost:11434"):
                self._console.print("  Starting Ollama server...")
                self._start_ollama_service()
                import asyncio as _asyncio
                for _ in range(15):
                    if self._check_ollama_running("http://localhost:11434"):
                        break
                    await _asyncio.sleep(1)

            if shutil.which("ollama") and self._check_ollama_running("http://localhost:11434") and Confirm.ask(
                f"Pull [cyan]{model_name}[/cyan] via Ollama?",
                default=True,
            ):
                self._console.print(f"Pulling [cyan]{model_name}[/cyan] with Ollama...")
                self._console.print("[dim]This may take several minutes depending on model size.[/dim]")
                result = subprocess.run(
                    ["ollama", "pull", model_name],
                    capture_output=True, text=True, timeout=7200, check=False,
                )
                if not result.returncode:
                    self._console.print("[green]\u2713 Downloaded via Ollama[/green]")
                    # Find the GGUF in Ollama's blob cache
                    self._console.print("  Locating GGUF file in Ollama cache...")
                    gguf_path = self._ollama_gguf_path(model_name)
                    if gguf_path:
                        self._console.print(f"  [dim]Found blob: {gguf_path.name}[/dim]")
                        # Validate GGUF magic bytes before copying
                        try:
                            header = gguf_path.read_bytes()[:4]
                            if header != b"GGUF":
                                self._console.print(
                                    f"[yellow]Warning: blob at {gguf_path} is not a valid GGUF "
                                    "(bad magic bytes). Skipping copy.[/yellow]"
                                )
                                downloaded = True
                            else:
                                dest = models_dir / f"{model_name.replace('/', '_').replace(':', '_')}.gguf"
                                try:
                                    self._console.print(f"  Copying GGUF to [cyan]{dest}[/cyan]...")
                                    shutil.copy2(gguf_path, dest)
                                    self._console.print(
                                        f"[green]\u2713 GGUF copied to: {dest}[/green]\n"
                                        f"[dim]  llama-server --model {dest} --port 18080[/dim]"
                                    )
                                    downloaded = True
                                except OSError as exc:
                                    self._console.print(
                                        f"[yellow]Warning: couldn't copy GGUF: {exc}[/yellow]\n"
                                        f"[dim]GGUF found at: {gguf_path}[/dim]"
                                    )
                                    downloaded = True
                        except OSError as exc:
                            self._console.print(
                                f"[yellow]Warning: couldn't read blob: {exc}[/yellow]"
                            )
                            downloaded = True
                    else:
                        self._console.print(
                            "[yellow]Could not locate GGUF blob in Ollama cache.[/yellow]\n"
                            "  The model was downloaded but the GGUF file could not be extracted.\n"
                            "  You can still use it by selecting [bold]Ollama[/bold] as your provider instead."
                        )
                        downloaded = True
                else:
                    self._console.print(
                        f"[red]\u2717 Pull failed[/red]\n"
                        f"[red]  {result.stderr.strip() or result.stdout.strip()}[/red]"
                    )
                    if not Confirm.ask("Try downloading manually instead?", default=True):
                        return

            # If we installed Ollama just for this, offer to remove it
            if downloaded and ollama_installed_by_us:
                self._console.print(
                    "[dim]Ollama is no longer needed — the GGUF file has been extracted.[/dim]"
                )
                if Confirm.ask("Uninstall Ollama to free up space?", default=False):
                    self._console.print("  Uninstalling Ollama...")
                    if self._uninstall_ollama():
                        self._console.print("[green]\u2713 Ollama uninstalled[/green]")
                    else:
                        self._console.print(
                            "[yellow]Automatic uninstall failed. You can uninstall manually:\n"
                            "  Windows: Control Panel -> Programs -> Uninstall Ollama\n"
                            "  macOS:   drag /Applications/Ollama.app to Trash\n"
                            "  Linux:   sudo apt remove ollama[/yellow]"
                        )

            if not downloaded:
                # Fallback: show links to verifiable public GGUF repos
                hf_links = {
                    "qwen3:14b": "https://huggingface.co/Qwen/Qwen3-14B-GGUF",
                    "gemma4:26b": "https://huggingface.co/ggml-org/gemma-4-26B-A4B-it-GGUF",
                    "gemma4:e4b": "https://huggingface.co/ggml-org/gemma-4-e4b-it-GGUF",
                }
                self._console.print(
                    "[yellow]Download the GGUF model file manually from Hugging Face:[/yellow]"
                )
                link = hf_links.get(model_name, "")
                if link:
                    self._console.print(f"  [cyan]{link}[/cyan]")
                else:
                    self._console.print(
                        f"  Search for [cyan]{model_name}[/cyan] GGUF on Hugging Face"
                    )
                self._console.print()
                self._console.print(
                    "[dim]Place the .gguf file in ~/.siyarix/models/ and run:\n"
                    "  llama-server --model ~/.siyarix/models/your-model.gguf --port 18080[/dim]"
                )
                if not Confirm.ask("Continue without downloading? (You can configure the model later)", default=True):
                    return

            self._settings.set("llamacpp_model", model_name)

        # ── Save settings ───────────────────────────────────────────────
        self._choices["provider_type"] = "offline"
        self._choices["provider_name"] = provider_name
        self._choices["provider_model"] = model_name
        self._settings.set("model_provider", provider_name)

        self._console.print()
        self._console.print(
            f"[green]\u2713 Provider configured: {provider_label} / {model_name}[/green]"
        )

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
        self._console.print("[dim]Your key is stored in the encrypted credential store.[/dim]")
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
            "llamacpp": ("llamacpp_url", "http://localhost:18080", "llamacpp_model"),
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

        self._console.print(f"[green]\u2713 Custom provider configured: {name} / {model}[/green]")

    # ── Step 7: Mode Selection ───────────────────────────────────────────

    def _step_mode(self) -> None:
        self._step_header("Mode Configuration")
        self._console.print("Siyarix has three operating modes:\n")

        mode_table = Table(box=box.SIMPLE, show_header=True)
        mode_table.add_column("#", style="yellow", width=4)
        mode_table.add_column("Mode", style="cyan")
        mode_table.add_column("Description")
        mode_table.add_row(
            "1", "Autonomous", "Full LLM-driven agent \u2014 requires an AI provider"
        )
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
        self._console.print(f"[green]\u2713 Mode set to: {self._choices['mode']}[/green]")
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
            ptable.add_row("a", "Auto", "Adaptive persona selection based on context")
            ptable.add_row("u", "Universal", "General-purpose assistant without specialization")
            ptable.add_row("n", "None", "No persona — raw Siyarix defaults")
            self._console.print(ptable)
            self._console.print()

            choice = Prompt.ask(
                rich_escape("Select persona ([a]uto / [u]niversal / [n]one / #)"),
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
                pdata = personas[int(choice) - 1]
                persona = pdata.get("name") or pdata.get("label") or str(pdata)
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
                SIYARIX_SYSTEM_PROMPT,
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

    # ── Step 9.5: Persona Tool Installation ──────────────────────────────

    def _step_install_persona_tools(self) -> None:
        persona = self._choices.get("persona", "none")
        if persona not in _PERSONA_TOOLS:
            return

        self._step_header(f"Specialized Tools for: {persona}")
        self._console.print(f"Scanning for specialized tools required by [bold]{persona}[/bold]...\n")

        tools_to_check = _PERSONA_TOOLS[persona]
        missing = []
        for exe, pkg, desc in tools_to_check:
            if not shutil.which(exe):
                missing.append((exe, pkg, desc))

        if not missing:
            self._console.print(f"[bold green]\u2713 All specialized tools for {persona} present![/bold green]")
            self._pause()
            return

        self._console.print(f"[yellow]{len(missing)} specialized tool(s) not found.[/yellow]")
        install_choices = {}
        for exe, pkg, desc in missing:
            want = Confirm.ask(f"  Install [cyan]{exe}[/cyan]? ({desc})", default=False)
            if want:
                install_choices[exe] = pkg

        if install_choices:
            self._console.print(f"\nInstalling {len(install_choices)} tool(s)...")
            installer = ToolInstaller(console=self._console)
            for exe, pkg in install_choices.items():
                installer.install_tool(exe, pkg)
        else:
            self._console.print("[yellow]Skipping persona tool installation.[/yellow]")

        self._console.print("[green]\u2713 Persona tool setup complete[/green]")
        self._pause()

    # ── Step 9: Preferences ────────────────────────────────────────────

    def _step_preferences(self) -> None:
        """Configure theme, security defaults, output, notifications, history, log level."""
        self._step_header("Preferences & Security Defaults")
        self._console.print("Configure Siyarix behavior, appearance, and security.\n")

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
                detail = str(addrs[0][4][0]) if addrs else ""
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
        provider_type = self._choices.get("provider_type", "")
        if provider_name:
            if provider_type == "offline":
                self._console.print()
                self._console.print(
                    f"[bold]3. Provider API Test ({provider_name})[/bold] "
                    "[dim](local provider, skipping remote test)[/dim]"
                )
            else:
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
                        self._console.print(
                            "  [yellow]Key stored but API unreachable. Check endpoint or key.[/yellow]"
                        )
                        all_ok = False
                else:
                    self._console.print(
                        f"  [dim]No API key for {provider_name}, skipped.[/dim]"
                    )
        else:
            self._console.print()
            self._console.print(
                "[bold]3. Provider API Test[/bold] [dim](no provider configured, skipped)[/dim]"
            )

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
        self._console.print(
            Panel.fit(
                _SIYARIX_LOGO,
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
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
        summary.add_row(
            "Credential Store",
            "\u2713 Initialized" if self._choices.get("credential_store_initialized") else "\u2717 Skipped",
        )
        summary.add_row("Theme", self._choices["preferences"]["theme"])
        summary.add_row("Log Level", self._choices["preferences"]["log_level"])
        summary.add_row("Output Format", self._choices["preferences"]["output_format"])
        summary.add_row("Command Review", str(self._choices["preferences"]["command_review"]))
        summary.add_row("Stealth Mode", str(self._choices["preferences"]["stealth_mode"]))
        if self._choices["additional_sysmsg"]:
            summary.add_row(
                "Custom Instructions",
                textwrap.shorten(self._choices["additional_sysmsg"], width=40),
            )
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
        dotenv_path = get_config_dir() / ".env"
        alt_path = Path.cwd() / ".env"
        found_env = (
            dotenv_path if dotenv_path.exists() else (alt_path if alt_path.exists() else None)
        )
        if found_env and self._choices.get("credential_store_initialized"):
            self._console.print("[bold].env Migration[/bold]")
            self._console.print(
                "[dim]Found an existing .env file with environment variables.[/dim]"
            )
            if Confirm.ask("Migrate API keys from .env to credential store?", default=True):
                migrated = self._migrate_from_dotenv(found_env)
                if migrated:
                    self._choices["env_migrated"] = True
                    self._console.print(
                        f"[green]\u2713 Migrated {migrated} key(s) from .env[/green]"
                    )
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
                "credential_store": self._choices.get("credential_store_initialized", False),
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
            "Platform Detection": 1,
            "Requirements Check": 2,
            "Dependencies & Python Packages": 3,
            "Cybersecurity Tool Discovery": 4,
            "Credential Vault Setup": 5,
            "Provider Configuration": 6,
            "Mode Configuration": 7,
            "Persona & System Message": 8,
            "Preferences & Security Defaults": 9,
            "Network Diagnostics": 10,
        }.get(title, "")
        prefix = f"[{step_num}/10] " if step_num else ""
        self._console.print(f"\n[bold cyan]== {prefix}{title} ==[/bold cyan]\n")

    def _pause(self) -> None:
        self._console.print()
        Confirm.ask("[dim]Press Enter to continue[/dim]", default=True)

    def _clear_screen(self) -> None:
        if hasattr(self, "_console") and self._console:
            self._console.clear()
        else:
            print("\033[2J\033[H", end="", flush=True)

    def _store_api_key(self, provider: str, key: str) -> None:
        """Store API key in credential store and environment."""
        os.environ[provider.upper() + "_API_KEY"] = key
        if self._cred_store:
            try:
                self._cred_store.store(provider, key, "api_key")
            except Exception:
                pass

    def _migrate_from_dotenv(self, env_path: Path) -> int:
        """Migrate API keys from .env file to credential store. Returns count of migrated keys."""
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

        if shell == "cmd":
            self._console.print("  [dim]Command Prompt (cmd) does not support shell completions. Siyarix recommends PowerShell (pwsh).[/dim]")
            self._choices["shell_completion_done"] = False
        elif Confirm.ask("  Install shell completions?", default=True):
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
                    rc_file = (
                        Path.home()
                        / "Documents"
                        / "PowerShell"
                        / "Microsoft.PowerShell_profile.ps1"
                    )

                if rc_file and rc_file.parent.exists():
                    # Typer/Click shell completion via env-var: _<APP>_COMPLETE=<shell>_source <app>
                    typer_shell = shell
                    if shell == "pwsh":
                        typer_shell = "powershell"
                    if shell in ("powershell", "pwsh"):
                        completion_cmd = (
                            '$env:_SIYARIX_COMPLETE="powershell_source"; '
                            "siyarix | Out-String | Invoke-Expression"
                        )
                    else:
                        completion_cmd = (
                            f'eval "$(_SIYARIX_COMPLETE={typer_shell}_source siyarix)"'
                        )
                    if rc_file.exists():
                        existing = rc_file.read_text(encoding="utf-8")
                        # Clean up old broken eval line (siyarix completion — singular, no such command)
                        import re as _re
                        cleaned = _re.sub(
                            r'\neval "\$\(siyarix? completion \w+\)"\n?',
                            "",
                            existing,
                        )
                        if cleaned != existing:
                            rc_file.write_text(cleaned, encoding="utf-8")
                            existing = cleaned
                            self._console.print(
                                "  [dim]Removed old broken completion line.[/dim]"
                            )
                        if completion_cmd not in existing:
                            with rc_file.open("a", encoding="utf-8") as f:
                                f.write(f"\n# Siyarix completions\n{completion_cmd}\n")
                            self._console.print(
                                f"  [green]\u2713 Completions added to {rc_file}[/green]"
                            )
                        else:
                            self._console.print(f"  [dim]Completions already in {rc_file}[/dim]")
                    else:
                        rc_file.parent.mkdir(parents=True, exist_ok=True)
                        rc_file.write_text(
                            f"# Siyarix completions\n{completion_cmd}\n", encoding="utf-8"
                        )
                        self._console.print(
                            f"  [green]\u2713 Completions file created: {rc_file}[/green]"
                        )

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
                            f"}}"
                        )
                        subprocess.run(
                            ["powershell", "-Command", script], capture_output=True, timeout=30,
                            check=False,
                        )
                        self._console.print(
                            f"  [green]\u2713 Added to user PATH: {siyarix_bin}[/green]"
                        )
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
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if not result.returncode:
                self._console.print(f"  [green]\u2713 {package} installed[/green]")
                return True
            self._console.print(f"  [red]\u2717 {package} failed: {result.stderr.strip()}[/red]")
            return False
        except Exception as exc:
            self._console.print(f"  [red]\u2717 {package}: {exc}[/red]")
            return False



    def _suggest_models(self, specs: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, str, str]], int, str]:
        """Return the best matching tier, models list, default index, and fallback model."""
        free_ram = specs.get("ram_free_gb", 0)
        for tier_config in SECURITY_MODEL_TIERS:
            if tier_config["min_ram"] <= free_ram < tier_config["max_ram"]:
                return (
                    tier_config,
                    tier_config["models"],
                    tier_config["default_idx"],
                    tier_config["fallback"],
                )
        last = SECURITY_MODEL_TIERS[-1]
        return last, last["models"], last["default_idx"], last["fallback"]

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
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                if shutil.which("ollama"):
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                    return True
                self._console.print(
                    "  [yellow]Ollama installer may need user interaction.[/yellow]"
                )
                return shutil.which("ollama") is not None
            elif sys.platform == "darwin":
                self._console.print("  Downloading Ollama for macOS...")
                subprocess.run(
                    ["curl", "-fsSL", "https://ollama.com/install.sh"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                result = subprocess.run(
                    ["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                ok = not result.returncode
                if ok:
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                else:
                    self._console.print(f"  [red]Install failed: {result.stderr.strip()}[/red]")
                return ok
            else:
                self._console.print("  Installing via official script...")
                result = subprocess.run(
                    ["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                ok = not result.returncode
                if ok:
                    self._console.print("  [green]\u2713 Ollama installed[/green]")
                else:
                    self._console.print(f"  [red]Install failed: {result.stderr.strip()}[/red]")
                return ok
        except Exception as exc:
            self._console.print(f"  [red]Ollama installation error: {exc}[/red]")
            return False

    def _uninstall_ollama(self) -> bool:
        """Uninstall Ollama. Best-effort per platform."""
        try:
            if os.name == "nt":
                script = '''
$ollama = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "Ollama" }
if ($ollama) { $ollama.Uninstall() | Out-Null }
'''
                r = subprocess.run(
                    ["powershell", "-Command", script],
                    capture_output=True, text=True, timeout=120, check=False,
                )
                if not r.returncode and "Error" not in r.stderr:
                    return True
                uninstaller = "C:\\Program Files\\Ollama\\uninstall.exe"
                if os.path.isfile(uninstaller):
                    r = subprocess.run(
                        [uninstaller, "/S"],
                        capture_output=True, text=True, timeout=120, check=False,
                    )
                    return not r.returncode
                return False
            elif sys.platform == "darwin":
                bin_path = shutil.which("ollama") or "/usr/local/bin/ollama"
                r = subprocess.run(
                    ["sudo", "rm", "-f", bin_path],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                return not r.returncode
            else:
                # Official Linux uninstall: service → binary → libs
                script = """
sudo systemctl stop ollama 2>/dev/null
sudo systemctl disable ollama 2>/dev/null
sudo rm -f /etc/systemd/system/ollama.service
sudo systemctl daemon-reload
OLLAMA_BIN=$(command -v ollama 2>/dev/null)
if [ -n "$OLLAMA_BIN" ]; then sudo rm -f "$OLLAMA_BIN"; fi
sudo rm -rf /usr/local/lib/ollama /usr/lib/ollama /lib/ollama 2>/dev/null
"""
                r = subprocess.run(
                    ["sh", "-c", script],
                    capture_output=True, text=True, timeout=60, check=False,
                )
                if not r.returncode:
                    return True
                # Fallback: just remove the binary
                bin_path = shutil.which("ollama") or "/usr/local/bin/ollama"
                r = subprocess.run(
                    ["sudo", "rm", "-f", bin_path],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                return not r.returncode
        except Exception:
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
    def _ollama_gguf_path(model_name: str) -> Path | None:
        """Find the GGUF blob path in Ollama's cache for a given model.
        Tries manifest parsing first, falls back to newest blob scan.
        """
        # Method 1: parse the "FROM" line from "ollama show"
        try:
            r = subprocess.run(
                ["ollama", "show", model_name, "--modelfile"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if not r.returncode:
                for line in r.stdout.splitlines():
                    if line.startswith("FROM "):
                        ref = line[5:].strip()
                        if ref.startswith("sha256:"):
                            blob = (
                                Path.home()
                                / ".ollama"
                                / "models"
                                / "blobs"
                                / ref.replace("sha256:", "sha256-")
                            )
                            if blob.is_file():
                                return blob
                        if os.path.isabs(ref) and os.path.isfile(ref):
                            return Path(ref)
        except Exception:
            pass

        # Method 2: parse the JSON manifest on disk
        tag = "latest"
        model_sans_tag = model_name
        if ":" in model_name:
            model_sans_tag, tag = model_name.split(":", 1)
        parts = model_sans_tag.split("/")
        if len(parts) == 2:
            namespace, name = parts[0], parts[1]
        else:
            namespace, name = "library", parts[0]
        manifest = (
            Path.home()
            / ".ollama"
            / "models"
            / "manifests"
            / "registry.ollama.ai"
            / namespace
            / name
            / tag
        )
        if manifest.is_file():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                for layer in data.get("layers", []):
                    if layer.get("mediaType") == "application/vnd.ollama.image.model":
                        digest = layer["digest"].replace("sha256:", "sha256-")
                        blob = Path.home() / ".ollama" / "models" / "blobs" / digest
                        if blob.is_file():
                            return blob
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        # Method 3: find the newest blob file (just downloaded)
        blobs_dir = Path.home() / ".ollama" / "models" / "blobs"
        if blobs_dir.is_dir():
            try:
                blobs = [p for p in blobs_dir.iterdir() if p.is_file()]
                if blobs:
                    return max(blobs, key=lambda p: p.stat().st_mtime)
            except OSError:
                pass

        return None

    # ── llama.cpp helpers ───────────────────────────────────────────

    def _install_llamacpp(self) -> bool:
        """Download and install llama.cpp pre-built binary."""
        import platform as _platform
        import urllib.request
        import json
        import zipfile
        import tarfile

        self._console.print("  Installing llama.cpp...\n")

        machine = _platform.machine().lower()
        system = _platform.system().lower()

        # Fetch the latest release tag from GitHub API
        try:
            api_url = "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest"
            resp = urllib.request.urlopen(api_url, timeout=15)
            release_data = json.loads(resp.read())
            tag = release_data.get("tag_name", "")
            if not tag:
                raise ValueError("No tag_name in release data")
        except Exception as exc:
            self._console.print(f"  [red]Failed to fetch latest release: {exc}[/red]")
            self._console.print("[yellow]Install manually from: https://github.com/ggml-org/llama.cpp/releases[/yellow]")
            return False

        # Map platform to GitHub release asset pattern (new naming: llama-{tag}-bin-{os}-{arch}.tar.gz)
        suffix = ""
        if system == "linux":
            if machine in ("x86_64", "amd64"):
                suffix = "ubuntu-x64.tar.gz"
            elif "aarch64" in machine or "arm64" in machine:
                suffix = "ubuntu-arm64.tar.gz"
        elif system == "darwin":
            if "arm" in machine or "aarch64" in machine:
                suffix = "macos-arm64.tar.gz"
            else:
                suffix = "macos-x64.tar.gz"
        elif os.name == "nt":
            arch = "x64" if machine in ("x86_64", "amd64") else "arm64"
            suffix = f"win-cpu-{arch}.zip"

        if not suffix:
            self._console.print("[red]Unsupported platform for llama.cpp auto-install.[/red]")
            self._console.print("[yellow]Install manually from: https://github.com/ggml-org/llama.cpp/releases[/yellow]")
            return False

        asset_name = f"llama-{tag}-bin-{suffix}"
        download_url = f"https://github.com/ggml-org/llama.cpp/releases/download/{tag}/{asset_name}"

        bin_dir = Path.home() / ".siyarix" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._console.print(f"  Downloading [cyan]{asset_name}[/cyan]...")
            archive_path = bin_dir / asset_name
            urllib.request.urlretrieve(download_url, archive_path)
            self._console.print("  [green]\u2713 Downloaded[/green]")

            # Extract
            self._console.print("  Extracting...")
            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(bin_dir)
            else:
                with tarfile.open(archive_path, "r:gz") as tf:
                    tf.extractall(bin_dir)

            # Remove the versioned extract directory prefix if present
            for entry in list(bin_dir.iterdir()):
                if entry.is_dir() and (entry.name.startswith(f"llama-{tag}") and not entry.name.startswith(".")):
                    extract_root = entry
                    for child in entry.iterdir():
                        dest = bin_dir / child.name
                        if child.is_dir():
                            shutil.copytree(child, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(child, dest)
                    shutil.rmtree(extract_root)
                    break

            # Find the llama-server binary and any shared libs
            for f in bin_dir.rglob("*"):
                if f.is_file() and f.name in ("llama-server", "llama-server.exe"):
                    if f.parent != bin_dir:
                        shutil.copy2(f, bin_dir / f.name)
                        # Also copy shared libraries from the same directory
                        for lib in f.parent.glob("*.so*"):
                            shutil.copy2(lib, bin_dir / lib.name)

            # Cleanup archive
            archive_path.unlink(missing_ok=True)

            # Add to PATH for this session
            os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

            # Verify
            llama_bin = bin_dir / "llama-server"
            if os.name == "nt":
                llama_bin = bin_dir / "llama-server.exe"
            if llama_bin.exists():
                self._console.print(f"  [green]\u2713 llama-server installed: {llama_bin}[/green]")
                return True
            self._console.print("[yellow]llama-server binary not found after extraction.[/yellow]")
            return False
        except Exception as exc:
            self._console.print(f"  [red]llama.cpp installation failed: {exc}[/red]")
            self._console.print("[yellow]Install manually from: https://github.com/ggml-org/llama.cpp/releases[/yellow]")
            return False

    @staticmethod
    def _check_llamacpp_running(url: str = "http://localhost:18080") -> bool:
        """Check if llama.cpp server is running."""
        try:
            import httpx
            r = httpx.get(f"{url}/health", timeout=5)
            return r.status_code < 500
        except Exception:
            return False

    @staticmethod
    def _start_llamacpp_service(model_path: str | None = None, port: int = 18080) -> None:
        """Start llama.cpp server in background."""
        try:
            # Validate GGUF model if provided
            if model_path:
                try:
                    p = Path(model_path)
                    if p.is_file() and p.read_bytes()[:4] != b"GGUF":
                        logger.warning("Invalid GGUF (bad magic), starting without --model")
                        model_path = None
                except OSError:
                    pass

            bin_dir = Path.home() / ".siyarix" / "bin"
            llama_bin = bin_dir / "llama-server"
            if os.name == "nt":
                llama_bin = bin_dir / "llama-server.exe"

            if not llama_bin.exists():
                logger.warning("llama-server not found at %s", llama_bin)
                return

            # One-time promotion of shared libraries from stale subdirectories
            for d in bin_dir.iterdir():
                if d.is_dir() and d.name.startswith("llama-"):
                    for lib in d.glob("*.so*"):
                        dest = bin_dir / lib.name
                        if not dest.exists():
                            shutil.copy2(lib, dest)

            cmd = [str(llama_bin), "--port", str(port), "--host", "127.0.0.1"]
            if model_path:
                cmd.extend(["--model", model_path])

            if os.name == "nt":
                subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception as exc:
            logger.warning("Failed to start llama.cpp: %s", exc)

    @staticmethod
    def _restart_siyarix() -> None:
        print("\033[2J\033[H", end="", flush=True)
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            subprocess.Popen(
                ["start", "cmd", "/c", sys.executable, "-m", "siyarix"] + sys.argv[1:],
                shell=True,  # nosec - required for 'start' on windows but safe here
                creationflags=creationflags,
            )
        else:
            os.execv(sys.executable, [sys.executable, "-m", "siyarix"] + sys.argv[1:])
        sys.exit(0)


__all__ = [
    "OnboardingWizard",
    "INITIALIZED_MARKER",
]
