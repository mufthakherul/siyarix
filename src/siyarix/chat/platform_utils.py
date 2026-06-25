from __future__ import annotations
import logging
import platform as _platform
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from siyarix.config import get_config_dir
from siyarix._platform import (
    is_windows as _is_windows,
    is_termux as _is_termux,
    is_ish as _is_ish,
    get_platform_id,
    get_termux_prefix,
)

logger = logging.getLogger(__name__)


def is_kali_linux() -> bool:
    """Detect if running on Kali Linux (needs --break-system-packages for pip)."""
    if _platform.system() != "Linux":
        return False
    try:
        os_release = Path("/etc/os-release")
        if os_release.exists():
            for line in os_release.read_text().splitlines():
                if line.strip() == "ID=kali":
                    return True
    except (FileNotFoundError, OSError):
        pass
    return Path("/etc/kali-motd").exists()


def pip_install_args(package: str, *extra: str) -> list[str]:
    """Build pip install command args, adding --break-system-packages on Kali."""
    args = [sys.executable, "-m", "pip", "install", package, *extra]
    if is_kali_linux():
        args.append("--break-system-packages")
    return args


CROSS_PLATFORM_COMMANDS: dict[str, dict[str, str]] = {
    "nmap_scan": {
        "bash": "nmap -sV {target}",
        "powershell": "nmap -sV {target}",
        "cmd": "nmap -sV {target}",
        "termux": "nmap -sV {target}",
        "ish": "nmap -sV {target}",
    },
    "ping_host": {
        "bash": "ping -c 4 {target}",
        "powershell": "ping -n 4 {target}",
        "cmd": "ping -n 4 {target}",
        "termux": "ping -c 4 {target}",
        "ish": "ping -c 4 {target}",
    },
    "traceroute": {
        "bash": "traceroute {target}",
        "powershell": "tracert {target}",
        "cmd": "tracert {target}",
        "termux": "traceroute {target}",
        "ish": "traceroute {target}",
    },
    "dns_lookup": {
        "bash": "nslookup {target}",
        "powershell": "nslookup {target}",
        "cmd": "nslookup {target}",
        "termux": "nslookup {target}",
        "ish": "nslookup {target}",
    },
    "whois_query": {
        "bash": "whois {target}",
        "powershell": "whois {target}",
        "cmd": "whois {target}",
        "termux": "whois {target}",
        "ish": "whois {target}",
    },
    "netstat": {
        "bash": "netstat -tulpn",
        "powershell": "netstat -an",
        "cmd": "netstat -an",
        "termux": "netstat -tulpn",
        "ish": "netstat -tulpn",
    },
    "list_processes": {
        "bash": "ps aux",
        "powershell": "Get-Process | Format-Table",
        "cmd": "tasklist",
        "termux": "ps aux",
        "ish": "ps aux",
    },
    "disk_usage": {
        "bash": "df -h",
        "powershell": "Get-PSDrive | Where Used",
        "cmd": "wmic logicaldisk get size,freespace,caption",
        "termux": "df -h",
        "ish": "df -h",
    },
    "curl_request": {
        "bash": "curl -s {target}",
        "powershell": "curl -s {target}",
        "cmd": "curl {target}",
        "termux": "curl -s {target}",
        "ish": "curl -s {target}",
    },
    "dig_dns": {
        "bash": "dig {target}",
        "powershell": "Resolve-DnsName {target}",
        "cmd": "nslookup {target}",
        "termux": "dig {target}",
        "ish": "dig {target}",
    },
    "tcpdump": {
        "bash": "tcpdump -i any port {port}",
        "powershell": "Get-NetTCPConnection",
        "cmd": "netstat -an",
        "termux": "tcpdump -i any port {port}",
        "ish": "tcpdump -i any port {port}",
    },
    "ssh_connect": {
        "bash": "ssh {user}@{target}",
        "powershell": "ssh {user}@{target}",
        "cmd": "ssh {user}@{target}",
        "termux": "ssh {user}@{target}",
        "ish": "ssh {user}@{target}",
    },
    "check_firewall": {
        "bash": "iptables -L -n",
        "powershell": "netsh advfirewall show allprofiles",
        "cmd": "netsh advfirewall show allprofiles",
        "termux": "ip6tables -L -n 2>/dev/null || echo 'iptables unavailable on device'",
        "ish": "iptables -L -n 2>/dev/null || echo 'iptables unavailable'",
    },
    "enum_shares": {
        "bash": "smbclient -L {target}",
        "powershell": "Get-SmbShare",
        "cmd": "net view {target}",
        "termux": "smbclient -L {target} 2>/dev/null || echo 'smbclient not installed'",
        "ish": "smbclient -L {target} 2>/dev/null || echo 'smbclient not installed'",
    },
    "http_headers": {
        "bash": "curl -I {target}",
        "powershell": "curl -I {target}",
        "cmd": "curl -I {target}",
        "termux": "curl -I {target}",
        "ish": "curl -I {target}",
    },
}


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
    if _is_windows():
        return os.environ.get("COMSPEC", "cmd.exe")
    shell = os.environ.get("SHELL", "")
    if shell:
        return shell
    for sh in ("pwsh", "powershell", "bash", "zsh", "fish", "sh", "dash"):
        found = shutil.which(sh)
        if found:
            return found
    if _is_termux():
        return f"{get_termux_prefix()}/bin/bash"
    if _is_ish():
        return "/bin/sh"
    return "/bin/sh"


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

    Dangerous variables (PATH, LD_PRELOAD, PYTHONPATH, etc.) are also blocked.
    """
    _api_key_patterns = ("_API_KEY", "_SECRET", "_PASSWORD", "_TOKEN")
    _blocked_vars = {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "BASH_ENV",
        "IFS",
        "SHELLOPTS",
        "PERL5LIB",
        "RUBYLIB",
        "PYTHONHOME",
    }
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
            if key.upper() in _blocked_vars:
                logger.debug("Skipping blocked env var %s from .env", key)
                continue
            os.environ[key] = val


class _Shell:
    def __init__(self, value: str) -> None:
        self.value = value


def normalize_shell(shell: str) -> _Shell:
    return _Shell(shell)


def get_security_commands(shell: str = "") -> dict[str, str]:
    pid = get_platform_id()
    if pid == "windows":
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
    if pid == "android":
        return {
            "Listening ports": "ss -tulpn 2>/dev/null || netstat -tulpn",
            "Running processes": "ps aux",
            "Open files": "lsof -i 2>/dev/null || echo 'lsof not available'",
            "System logs": "logcat -d -t 100 2>/dev/null || dmesg | tail -100",
            "DNS resolution": "cat /etc/resolv.conf 2>/dev/null || getprop net.dns1 2>/dev/null",
            "ARP table": "ip neigh 2>/dev/null || cat /proc/net/arp",
            "Route table": "ip route 2>/dev/null || cat /proc/net/route",
            "Disk usage": "df -h",
            "Network interfaces": "ip addr 2>/dev/null || ifconfig",
            "Kernel info": "uname -a",
            "Battery": "termux-battery-status 2>/dev/null || echo 'termux-api not installed'",
            "Sensors": "termux-sensor -s 2>/dev/null || echo 'termux-api not installed'",
            "WiFi info": "termux-wifi-scaninfo 2>/dev/null || echo 'termux-api not installed'",
            "Cell location": "termux-location 2>/dev/null || echo 'termux-api not installed'",
        }
    if pid == "ios":
        return {
            "Listening ports": "netstat -tulpn 2>/dev/null || lsof -i",
            "Running processes": "ps aux",
            "Open files": "lsof -i 2>/dev/null || echo 'lsof partially available'",
            "System logs": "dmesg | tail -100 2>/dev/null || log show --last 5m 2>/dev/null | tail -100",
            "DNS resolution": "cat /etc/resolv.conf",
            "ARP table": "arp -a 2>/dev/null || ip neigh 2>/dev/null",
            "Route table": "netstat -rn 2>/dev/null || ip route 2>/dev/null",
            "Disk usage": "df -h",
            "Network interfaces": "ifconfig",
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
