from __future__ import annotations
import logging
import platform as _platform
import os
import shutil
import sys
from typing import Any


from siyarix.config import get_config_dir

from .session import ChatMessage as ChatMessage, ChatSession as ChatSession
from .ui import (
    SmartAutocomplete as SmartAutocomplete,
    CommandPalette as CommandPalette,
    SplitPane as SplitPane,
    ConfigPanel as ConfigPanel,
)

logger = logging.getLogger(__name__)

CROSS_PLATFORM_COMMANDS: dict[str, dict[str, str]] = {}

def build_platform_context() -> dict[str, Any]:
    uname = _platform.uname()
    return {
        "platform": uname.system,
        "platform_pretty": f"{uname.system} {uname.release}",
        "platform_release": uname.release,
        "arch": uname.machine,
        "processor": uname.processor,
        "hostname": uname.node,
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "cwd": os.getcwd(),
        "terminal_type": os.environ.get("TERM", ""),
        "term_program": os.environ.get("TERM_PROGRAM", ""),
        "term": os.environ.get("TERM", ""),
        "shell": detect_shell(),
        "shell_platform": get_shell_platform(),
        "shell_executable": detect_shell(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count() or 0,
        "memory_total_mb": "unknown",
        "load_avg_1m": "n/a",
        "load_avg_5m": "n/a",
        "load_avg_15m": "n/a",
        "is_container": False,
        "container_runtime": "none",
        "is_codespaces": False,
        "is_terminal_ssh": False,
        "is_terminal_cloud": False,
        "has_wsl": False,
        "available_tools_count": 0,
    }


def detect_shell() -> str:
    if os.name == "nt":
        return os.environ.get("COMSPEC", "cmd.exe")
    shell = os.environ.get("SHELL", "")
    if shell:
        return shell
    for sh in ("pwsh", "powershell", "bash", "zsh", "fish", "sh"):
        found = shutil.which(sh)
        if found:
            return found
    return os.environ.get("COMSPEC", "cmd.exe") if os.name == "nt" else "/bin/sh"


def get_shell_platform() -> str:
    return _platform.system()


def provider_env_var(provider: str) -> str:
    return f"{provider.upper()}_API_KEY"


def list_supported_shells() -> list[tuple[str, str]]:
    return [("bash", "native"), ("zsh", "native"), ("powershell", "compat")]


def load_env_file() -> None:
    """Load environment variables from ~/.siyarix/.env (simple key=value parser).

    NOTE: API key env vars (*_API_KEY) are intentionally NOT loaded from .env
    for security. Use /key set <provider> <key> instead.
    """
    _api_key_patterns = ("_API_KEY", "_SECRET", "_PASSWORD", "_TOKEN")
    env_path = get_config_dir() / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key and not os.environ.get(key):
            if any(p in key.upper() for p in _api_key_patterns):
                logger.debug("Skipping %s from .env (use /key command instead)", key)
                continue
            os.environ[key] = val


class _Shell:
    def __init__(self, value: str) -> None:
        self.value = value


def normalize_shell(shell: str) -> _Shell:
    return _Shell(shell)


def get_security_commands(shell: str = "") -> dict[str, str]:
    import sys
    is_win = sys.platform == "win32"
    if is_win:
        return {
            "Firewall status": "netsh advfirewall show allprofiles state",
            "Open ports": "netstat -an | findstr LISTEN",
            "Active connections": "netstat -bno",
            "Running services": "sc query | findstr SERVICE_NAME",
            "Startup programs": "wmic startup get caption,command",
            "Scheduled tasks": "schtasks /query /fo LIST /v",
            "Local users": "net user",
            "Admin group": "net localgroup Administrators",
            "Audit policy": "auditpol /get /category:*",
            "Process list": "tasklist /v",
            "Event log (security)": 'wevtutil qe Security "/q:*[System[(Level=1 or Level=2)]]" /c:10 /rd:true /f:text',
            "Registry autoruns": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "DNS cache": "ipconfig /displaydns",
            "ARP table": "arp -a",
            "Route table": "route print",
        }
    return {
        "Listening ports": "ss -tulpn",
        "Active connections": "netstat -tulpn",
        "Running processes": "ps aux",
        "Open files": "lsof -i",
        "Sudoers": "cat /etc/sudoers | grep -v '^#' | grep -v '^$'",
        "Cron jobs": "crontab -l",
        "System logs": "tail -100 /var/log/syslog 2>/dev/null || journalctl -n 100 --no-pager",
        "Auth logs": "tail -50 /var/log/auth.log 2>/dev/null || journalctl -u sshd -n 50 --no-pager",
        "Firewall rules": "iptables -L -n -v 2>/dev/null || nft list ruleset 2>/dev/null",
        "DNS resolution": "cat /etc/resolv.conf",
        "ARP table": "arp -a 2>/dev/null || ip neigh",
        "Route table": "ip route",
        "Disk usage": "df -h",
        "User accounts": "cat /etc/passwd | grep -v nologin | grep -v /bin/false",
        "Failed logins": "lastb 2>/dev/null | head -20 || echo 'No lastb'",
        "Kernel modules": "lsmod",
        "SUID binaries": "find / -perm -4000 2>/dev/null | head -30",
        "USB devices": "lsusb",
        "Network interfaces": "ip addr",
    }


