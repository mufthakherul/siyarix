"""Cross-platform compatibility layer for Siyarix.

Provides safe wrappers for platform-specific functionality (signal, termios,
fcntl, pty, resource, chmod, geteuid) and unified OS/platform detection
supporting Linux, macOS, Windows, Android/Termux, iOS/iSH, and HarmonyOS.
"""

from __future__ import annotations

import logging
import os
import platform as _platform
import shutil
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PLATFORM_CACHE: dict[str, Any] = {}


def get_system() -> str:
    return _platform.system()


def is_windows() -> bool:
    return os.name == "nt" or sys.platform == "win32"


def is_macos() -> bool:
    return get_system() == "Darwin"


def is_linux() -> bool:
    return get_system() == "Linux"


def is_termux() -> bool:
    if "TERMUX_VERSION" in os.environ:
        return True
    try:
        return Path("/data/data/com.termux/files/usr/bin/pkg").exists()
    except Exception:
        return False


def is_ish() -> bool:
    if "iSH" in os.environ.get("TERM_PROGRAM", ""):
        return True
    try:
        release = _platform.release().lower()
        return "ish" in release or "iSH" in _platform.version()
    except Exception:
        return False


def is_harmonyos() -> bool:
    try:
        if "ohos" in get_system().lower():
            return True
        if Path("/system/etc/param/ohos.para").exists():
            return True
        if "OHOS" in os.environ.get("OHOS_ARCH", ""):
            return True
        return False
    except Exception:
        return False


def is_wsl() -> bool:
    if not is_linux():
        return False
    try:
        release = _platform.release().lower()
        return "microsoft" in release or "wsl" in release
    except Exception:
        return False


def is_mobile() -> bool:
    return is_termux() or is_ish() or is_harmonyos()


def get_platform_id() -> str:
    if is_termux():
        return "android"
    if is_ish():
        return "ios"
    if is_harmonyos():
        return "harmonyos"
    if is_wsl():
        return "wsl"
    if is_windows():
        return "windows"
    if is_macos():
        return "macos"
    if is_linux():
        return "linux"
    return "unknown"


def get_platform_pretty() -> str:
    pid = get_platform_id()
    mapping = {
        "android": "Android/Termux",
        "ios": "iOS/iSH",
        "harmonyos": "HarmonyOS",
        "wsl": "WSL",
        "windows": "Windows",
        "macos": "macOS",
        "linux": "Linux",
    }
    return mapping.get(pid, f"Unknown ({get_system()})")


def get_config_dir_platform() -> Path:
    pid = get_platform_id()
    if pid == "android":
        return Path.home() / ".siyarix"
    if pid == "ios":
        return Path.home() / ".siyarix"
    if pid == "harmonyos":
        return Path(os.environ.get("OHOS_USER_HOME", str(Path.home()))) / ".siyarix"
    if pid == "windows":
        return Path(os.environ.get("APPDATA", str(Path.home()))) / "siyarix"
    if is_macos():
        return Path.home() / ".siyarix"
    return Path.home() / ".siyarix"


def get_termux_prefix() -> str:
    termux_prefix = os.environ.get("PREFIX", "")
    if termux_prefix:
        return termux_prefix
    if is_termux():
        return "/data/data/com.termux/files/usr"
    return "/data/data/com.termux/files/usr"


def detect_package_manager_platform() -> str:
    pid = get_platform_id()
    if pid == "android":
        return "pkg"
    if pid == "ios":
        return "apk" if shutil.which("apk") else "pip"
    if pid == "harmonyos":
        for pm in ("ohpm", "hpm", "npm"):
            if shutil.which(pm):
                return pm
        return "pip"
    if pid == "windows":
        for pm in ("winget", "choco", "scoop"):
            if shutil.which(pm):
                return pm
        return "pip"
    if pid == "macos":
        if shutil.which("brew"):
            return "brew"
        if shutil.which("port"):
            return "port"
        return "pip"
    for pm in ("apt-get", "apt", "dnf", "yum", "pacman", "zypper", "emerge", "apk", "xbps-install"):
        if shutil.which(pm):
            return pm
    return "pip"


def get_home_dir() -> Path:
    pid = get_platform_id()
    if pid == "android":
        return Path(os.environ.get("HOME", "/data/data/com.termux/files/home"))
    if pid == "ios":
        return Path(os.environ.get("HOME", "/root"))
    if pid == "harmonyos":
        return Path(os.environ.get("OHOS_USER_HOME", str(Path.home())))
    return Path.home()


_signal_available = False
try:
    import signal as _signal_mod

    _signal_available = True
except ImportError:
    _signal_mod = None  # type: ignore

_termios_available = False
try:
    import termios as _termios_mod

    _termios_available = True
except ImportError:
    _termios_mod = None  # type: ignore

_fcntl_available = False
try:
    import fcntl as _fcntl_mod

    _fcntl_available = True
except ImportError:
    _fcntl_mod = None  # type: ignore

_pty_available = False
try:
    import pty as _pty_mod

    _pty_available = True
except ImportError:
    _pty_mod = None  # type: ignore

_resource_available = False
try:
    import resource as _resource_mod

    _resource_available = True
except ImportError:
    _resource_mod = None  # type: ignore


def get_signal() -> Any:
    if _signal_available:
        return _signal_mod
    return None


def get_termios() -> Any:
    if _termios_available:
        return _termios_mod
    return None


def get_fcntl() -> Any:
    if _fcntl_available:
        return _fcntl_mod
    return None


def get_pty() -> Any:
    if _pty_available:
        return _pty_mod
    return None


def get_resource() -> Any:
    if _resource_available:
        return _resource_mod
    return None


def has_signal() -> bool:
    return _signal_available


def has_termios() -> bool:
    return _termios_available


def has_fcntl() -> bool:
    return _fcntl_available


def has_pty() -> bool:
    return _pty_available


def has_resource() -> bool:
    return _resource_available


def safe_chmod(path: Path, mode: int) -> None:
    try:
        if is_windows():
            return
        path.chmod(mode)
    except Exception:
        pass


def safe_geteuid() -> int | None:
    if is_windows():
        return None
    try:
        return os.geteuid()
    except AttributeError:
        return None
    except OSError:
        return None


def set_event_loop_policy() -> None:
    if is_windows():
        try:
            import asyncio

            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except (ImportError, AttributeError, RuntimeError):
            pass


def get_platform_shell_cmd(command: str) -> list[str]:
    pid = get_platform_id()
    if pid == "windows":
        return ["cmd", "/c", command]
    if pid == "android":
        return ["sh", "-c", command]
    return ["sh", "-c", command]


def get_platform_env() -> dict[str, str]:
    env = dict(os.environ)
    pid = get_platform_id()
    if pid == "ios":
        env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if pid == "android":
        termux_prefix = get_termux_prefix()
        env.setdefault(
            "PATH",
            f"{termux_prefix}/bin:/usr/local/bin:/usr/bin:/bin:{termux_prefix}/bin/applets",
        )
        env.setdefault("LD_LIBRARY_PATH", f"{termux_prefix}/lib")
    if pid == "harmonyos":
        env.setdefault("PATH", "/system/bin:/vendor/bin:/product/bin")
    return env


__all__ = [
    "get_system",
    "is_windows",
    "is_macos",
    "is_linux",
    "is_termux",
    "is_ish",
    "is_harmonyos",
    "is_wsl",
    "is_mobile",
    "get_platform_id",
    "get_platform_pretty",
    "get_config_dir_platform",
    "get_termux_prefix",
    "detect_package_manager_platform",
    "get_home_dir",
    "has_signal",
    "has_termios",
    "has_fcntl",
    "has_pty",
    "has_resource",
    "get_signal",
    "get_termios",
    "get_fcntl",
    "get_pty",
    "get_resource",
    "safe_chmod",
    "safe_geteuid",
    "set_event_loop_policy",
    "get_platform_shell_cmd",
    "get_platform_env",
]
