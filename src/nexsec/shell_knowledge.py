"""NexSec Shell Knowledge — Cross-platform terminal command awareness.

Knows the commands for:
  • Linux / macOS (bash, zsh, sh)
  • Windows CMD
  • Windows PowerShell / pwsh
  • Fish shell

Provides:
  • Command translation between shells
  • Shell detection
  • Platform-appropriate execution suggestions
  • Security-relevant command patterns per platform
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from enum import StrEnum
from typing import Any


class ShellType(StrEnum):
    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"
    SH = "sh"
    POWERSHELL = "powershell"
    PWSH = "pwsh"
    CMD = "cmd"
    UNKNOWN = "unknown"


SHELL_ALIASES: dict[str, ShellType] = {
    "pwsh": ShellType.POWERSHELL,
    "powershell": ShellType.POWERSHELL,
    "sh": ShellType.BASH,
    "dash": ShellType.BASH,
    "ksh": ShellType.BASH,
}


def _shell_from_name(name: str) -> ShellType:
    alias = SHELL_ALIASES.get(name.lower())
    if alias is not None:
        return alias
    try:
        return ShellType(name.lower())
    except ValueError:
        return ShellType.UNKNOWN


def normalize_shell(shell: ShellType | str | None) -> ShellType:
    """Normalize shell aliases to the canonical shell used by command maps."""
    if shell is None:
        return ShellType.UNKNOWN
    if isinstance(shell, ShellType):
        return SHELL_ALIASES.get(shell.value, shell)
    return _shell_from_name(shell)


def shell_key(shell: ShellType | str | None) -> str:
    """Return the command-map key for a shell or shell-like string."""
    normalized = normalize_shell(shell)
    if normalized == ShellType.UNKNOWN:
        return "bash"
    return normalized.value


# ---------------------------------------------------------------------------
# Cross-platform equivalent command map
# command intent -> {shell: command}
# ---------------------------------------------------------------------------

CROSS_PLATFORM_COMMANDS: dict[str, dict[str, str]] = {
    "list_files": {
        "bash": "ls -la",
        "zsh": "ls -la",
        "fish": "ls -la",
        "powershell": "Get-ChildItem -Force",
        "cmd": "dir /a",
    },
    "list_processes": {
        "bash": "ps aux",
        "zsh": "ps aux",
        "fish": "ps aux",
        "powershell": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 30",
        "cmd": "tasklist /v",
    },
    "network_connections": {
        "bash": "ss -tulpn",
        "zsh": "ss -tulpn",
        "fish": "ss -tulpn",
        "powershell": "Get-NetTCPConnection | Where-Object State -eq Listen | Sort-Object LocalPort",
        "cmd": "netstat -ano",
    },
    "open_ports": {
        "bash": "ss -tlnp",
        "zsh": "ss -tlnp",
        "fish": "ss -tlnp",
        "powershell": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess",
        "cmd": "netstat -an | findstr LISTENING",
    },
    "routing_table": {
        "bash": "ip route",
        "zsh": "ip route",
        "fish": "ip route",
        "powershell": "Get-NetRoute | Where-Object DestinationPrefix -ne '::1/128'",
        "cmd": "route print",
    },
    "arp_table": {
        "bash": "arp -n",
        "zsh": "arp -n",
        "fish": "arp -n",
        "powershell": "Get-NetNeighbor",
        "cmd": "arp -a",
    },
    "dns_lookup": {
        "bash": "nslookup {target}",
        "zsh": "nslookup {target}",
        "fish": "nslookup {target}",
        "powershell": "Resolve-DnsName {target}",
        "cmd": "nslookup {target}",
    },
    "whoami": {
        "bash": "whoami && id",
        "zsh": "whoami && id",
        "fish": "whoami",
        "powershell": "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
        "cmd": "whoami /all",
    },
    "environment_vars": {
        "bash": "printenv | sort",
        "zsh": "printenv | sort",
        "fish": "set",
        "powershell": "Get-ChildItem Env: | Sort-Object Name",
        "cmd": "set",
    },
    "firewall_rules": {
        "bash": "iptables -L -n -v",
        "zsh": "iptables -L -n -v",
        "fish": "iptables -L -n -v",
        "powershell": "Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object Name,Direction,Action | Format-Table",
        "cmd": "netsh advfirewall firewall show rule name=all",
    },
    "scheduled_tasks": {
        "bash": "crontab -l && ls /etc/cron*",
        "zsh": "crontab -l && ls /etc/cron*",
        "fish": "crontab -l",
        "powershell": "Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName,TaskPath",
        "cmd": "schtasks /query /fo TABLE",
    },
    "services": {
        "bash": "systemctl list-units --type=service --state=running",
        "zsh": "systemctl list-units --type=service --state=running",
        "fish": "systemctl list-units --type=service --state=running",
        "powershell": "Get-Service | Where-Object Status -eq Running | Select-Object Name,DisplayName",
        "cmd": "sc query state= all",
    },
    "users": {
        "bash": "cat /etc/passwd | grep -v nologin | grep -v false",
        "zsh": "cat /etc/passwd | grep -v nologin | grep -v false",
        "fish": "cat /etc/passwd",
        "powershell": "Get-LocalUser | Select-Object Name,Enabled,LastLogon",
        "cmd": "net user",
    },
    "groups": {
        "bash": "cat /etc/group",
        "zsh": "cat /etc/group",
        "fish": "cat /etc/group",
        "powershell": "Get-LocalGroup | Select-Object Name,Description",
        "cmd": "net localgroup",
    },
    "installed_software": {
        "bash": "dpkg -l || rpm -qa",
        "zsh": "dpkg -l || rpm -qa",
        "fish": "dpkg -l",
        "powershell": "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher",
        "cmd": 'wmic product get name,version',
    },
    "system_info": {
        "bash": "uname -a && lsb_release -a",
        "zsh": "uname -a && lsb_release -a",
        "fish": "uname -a",
        "powershell": "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsHardwareAbstractionLayer",
        "cmd": "systeminfo",
    },
    "disk_usage": {
        "bash": "df -h",
        "zsh": "df -h",
        "fish": "df -h",
        "powershell": "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free",
        "cmd": "wmic logicaldisk get caption,freespace,size",
    },
    "file_hash": {
        "bash": "sha256sum {file}",
        "zsh": "sha256sum {file}",
        "fish": "sha256sum {file}",
        "powershell": "Get-FileHash {file} -Algorithm SHA256",
        "cmd": "certutil -hashfile {file} SHA256",
    },
    "find_suid": {
        "bash": "find / -perm -4000 -type f 2>/dev/null",
        "zsh": "find / -perm -4000 -type f 2>/dev/null",
        "fish": "find / -perm -4000 -type f 2>/dev/null",
        "powershell": "# SUID is a Linux concept; check privileged executables with: icacls C:\\Windows\\System32 /c",
        "cmd": "icacls C:\\Windows\\System32 /c 2>nul | findstr /i \"full control\"",
    },
    "registry_autoruns": {
        "bash": "# Linux: check /etc/init.d/ and systemctl",
        "zsh": "# Linux: check /etc/init.d/ and systemctl",
        "fish": "# Linux: check /etc/init.d/ and systemctl",
        "powershell": "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
        "cmd": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    "host_file": {
        "bash": "cat /etc/hosts",
        "zsh": "cat /etc/hosts",
        "fish": "cat /etc/hosts",
        "powershell": "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
        "cmd": "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    },
    "ping": {
        "bash": "ping -c 4 {target}",
        "zsh": "ping -c 4 {target}",
        "fish": "ping -c 4 {target}",
        "powershell": "Test-NetConnection -ComputerName {target} -InformationLevel Detailed",
        "cmd": "ping -n 4 {target}",
    },
    "traceroute": {
        "bash": "traceroute {target}",
        "zsh": "traceroute {target}",
        "fish": "traceroute {target}",
        "powershell": "Test-NetConnection -ComputerName {target} -TraceRoute",
        "cmd": "tracert {target}",
    },
}

# ---------------------------------------------------------------------------
# Security-relevant PowerShell commands (Windows red/blue team)
# ---------------------------------------------------------------------------

POWERSHELL_SECURITY_COMMANDS: dict[str, str] = {
    "Get open TCP connections": "Get-NetTCPConnection | Sort-Object State",
    "Check Windows Defender status": "Get-MpComputerStatus",
    "List startup programs": "Get-CimInstance Win32_StartupCommand",
    "Check SMB shares": "Get-SmbShare",
    "Audit event logs (last 50 errors)": "Get-EventLog -LogName System -EntryType Error -Newest 50",
    "Check WMI subscriptions": "Get-WMIObject -Namespace root\\subscription -Class __EventFilter",
    "Find world-writable dirs": "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -notmatch 'ReadOnly' }",
    "Dump LSASS (detect)": "Get-Process lsass | Select-Object Id,CPU,WorkingSet",
    "List local admins": "Get-LocalGroupMember -Group Administrators",
    "Check UAC level": "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "Find credential files": "Get-ChildItem -Path C:\\ -Recurse -Include *.xml,*.json,*.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password|passwd|credential'",
    "Check AppLocker policies": "Get-AppLockerPolicy -Effective | Format-List",
    "Enumerate AD users (if domain)": "Get-ADUser -Filter * -Properties * | Select-Object Name,SamAccountName,Enabled",
    "Check PowerShell logging": "Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
}

# ---------------------------------------------------------------------------
# Security-relevant Linux/bash commands
# ---------------------------------------------------------------------------

BASH_SECURITY_COMMANDS: dict[str, str] = {
    "Check SUID binaries": "find / -perm -4000 -type f 2>/dev/null",
    "Check SGID binaries": "find / -perm -2000 -type f 2>/dev/null",
    "World-writable files": "find / -perm -o+w -type f 2>/dev/null | grep -v proc",
    "Check sudo rights": "sudo -l",
    "SSH authorized keys": "cat ~/.ssh/authorized_keys",
    "Recently modified files": "find /etc /usr /var -mtime -7 -type f 2>/dev/null",
    "Running processes full": "ps auxf",
    "Cron jobs all users": "for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done",
    "Kernel exploits check": "uname -r && searchsploit linux kernel $(uname -r | cut -d. -f1,2)",
    "Open files by process": "lsof -i",
    "NFS shares": "showmount -e localhost 2>/dev/null",
    "Readable shadow": "ls -la /etc/shadow && cat /etc/shadow 2>/dev/null",
    "Capabilities": "getcap -r / 2>/dev/null",
    "Writable /etc/passwd": "ls -la /etc/passwd",
    "PATH writability": 'echo $PATH | tr ":" "\n" | xargs -I{} ls -ld {} 2>/dev/null | grep -v "^d[rwx-]*x[rwx-]*x[rwx-]* root"',
}

# ---------------------------------------------------------------------------
# Shell detection
# ---------------------------------------------------------------------------


def detect_shell() -> ShellType:
    """Detect the current shell as a ShellType."""
    # Check explicit env var first
    shell_env = os.getenv("SHELL", "")
    if shell_env:
        name = shell_env.split("/")[-1].lower()
        detected = _shell_from_name(name)
        if detected != ShellType.UNKNOWN:
            return detected

    # Windows detection
    if platform.system().lower() == "windows":
        # Check if running under pwsh or powershell
        psmodulepath = os.getenv("PSModulePath", "")
        if psmodulepath:
            pwsh = shutil.which("pwsh")
            if pwsh:
                return ShellType.PWSH
            return ShellType.POWERSHELL
        return ShellType.CMD

    # Try $0 from parent process
    try:
        ppid = os.getppid()
        result = subprocess.run(
            ["ps", "-p", str(ppid), "-o", "comm="],
            capture_output=True, text=True, timeout=3,
        )
        comm = result.stdout.strip().lstrip("-")
        detected = _shell_from_name(comm)
        if detected != ShellType.UNKNOWN:
            return detected
    except Exception:
        pass

    return ShellType.UNKNOWN


def get_shell_platform() -> str:
    """Return a human-friendly platform string."""
    sys_name = platform.system().lower()
    if sys_name == "windows":
        shell = detect_shell()
        if shell in (ShellType.POWERSHELL, ShellType.PWSH):
            return "Windows PowerShell"
        return "Windows CMD"
    elif sys_name == "darwin":
        shell = detect_shell()
        if shell in (ShellType.BASH, ShellType.ZSH, ShellType.SH, ShellType.FISH):
            return f"macOS ({shell.value})"
        return "macOS (zsh/bash)"
    else:
        shell = detect_shell()
        if shell in (ShellType.BASH, ShellType.ZSH, ShellType.SH, ShellType.FISH):
            return f"Linux ({shell.value})"
        return "Linux (bash)"


def translate_command(intent: str, target_shell: ShellType | None = None) -> str:
    """Translate a command intent to the appropriate shell command.

    Args:
        intent: Key from CROSS_PLATFORM_COMMANDS (e.g. "list_files")
        target_shell: Override shell; if None, auto-detects

    Returns:
        Shell-appropriate command string, or empty string if not found.
    """
    if target_shell is None:
        detected = detect_shell()
        target_shell = normalize_shell(detected)
    else:
        target_shell = normalize_shell(target_shell)

    shell_key = target_shell.value if target_shell != ShellType.UNKNOWN else "bash"
    entry = CROSS_PLATFORM_COMMANDS.get(intent, {})
    return entry.get(shell_key, entry.get("bash", ""))


def get_security_commands(shell: ShellType | None = None) -> dict[str, str]:
    """Return security-relevant commands for the given/detected shell."""
    if shell is None:
        shell = detect_shell()

    shell = normalize_shell(shell)

    if shell in (ShellType.POWERSHELL, ShellType.PWSH, ShellType.CMD):
        return POWERSHELL_SECURITY_COMMANDS
    return BASH_SECURITY_COMMANDS


def build_platform_context() -> dict[str, Any]:
    """Build a context dict describing the current execution environment."""
    shell = detect_shell()
    sys_name = platform.system()
    return {
        "platform": sys_name,
        "platform_lower": sys_name.lower(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "shell": shell.value,
        "shell_key": shell_key(shell),
        "shell_family": "windows" if sys_name.lower() == "windows" else "unix",
        "shell_platform": get_shell_platform(),
        "is_windows": sys_name.lower() == "windows",
        "is_linux": sys_name.lower() == "linux",
        "is_macos": sys_name.lower() == "darwin",
        "has_wsl": shutil.which("wsl") is not None,
        "available_intents": list(CROSS_PLATFORM_COMMANDS.keys()),
    }
