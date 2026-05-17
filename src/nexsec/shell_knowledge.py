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
import getpass
import socket
import shutil
import subprocess  # nosec B404
from pathlib import Path
from enum import StrEnum
from typing import Any, Mapping


class ShellType(StrEnum):
    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"
    SH = "sh"
    NUSHELL = "nushell"
    XONSH = "xonsh"
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
    "nu": ShellType.NUSHELL,
}


SUPPORTED_SHELLS: dict[ShellType, str] = {
    ShellType.BASH: "Tier 1",
    ShellType.ZSH: "Tier 1",
    ShellType.SH: "Tier 1",
    ShellType.POWERSHELL: "Tier 1",
    ShellType.CMD: "Tier 1",
    ShellType.FISH: "Tier 2",
    ShellType.NUSHELL: "Tier 2",
    ShellType.XONSH: "Tier 2",
}


def _device_type_from_system(sys_name: str) -> str:
    name = sys_name.lower()
    if name == "windows":
        return "windows"
    if name == "darwin":
        return "macos"
    if name == "linux":
        return "linux"
    return "unknown"


def detect_device_type(sys_name: str | None = None) -> str:
    """Detect the device OS type (windows/linux/macos)."""
    return _device_type_from_system(sys_name or platform.system())


def terminal_type_from_env(
    env: Mapping[str, str] | None = None,
    sys_name: str | None = None,
    shell: ShellType | None = None,
) -> str:
    """Detect terminal type from environment and OS signals."""
    env = env or os.environ
    sys_name = (sys_name or platform.system()).lower()
    shell = normalize_shell(shell or detect_shell())

    if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return "wsl"
    if env.get("CLOUD_SHELL") or env.get("AZUREPS_HOST_ENVIRONMENT"):
        return "cloud-shell"
    if env.get("CODESPACES") or env.get("GITHUB_CODESPACES_TOKEN"):
        return "codespaces"
    if env.get("VSCODE_PID") or env.get("TERM_PROGRAM", "").lower() == "vscode":
        return "vscode"

    term_program = env.get("TERM_PROGRAM", "").lower()
    if term_program in ("apple_terminal", "terminal.app"):
        return "mac-terminal"
    if term_program == "iterm.app":
        return "iterm"
    if env.get("WT_SESSION"):
        return "windows-terminal"
    if env.get("SSH_CONNECTION") or env.get("SSH_CLIENT") or env.get("SSH_TTY"):
        return "ssh"

    if sys_name == "windows":
        return "windows-console" if shell == ShellType.CMD else "powershell"
    return "posix-terminal"


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


def list_supported_shells() -> list[tuple[str, str]]:
    """Return supported shells with tier labels."""
    return sorted(((shell.value, tier) for shell, tier in SUPPORTED_SHELLS.items()))


# ---------------------------------------------------------------------------
# Cross-platform equivalent command map
# command intent -> {shell: command}
# ---------------------------------------------------------------------------

CROSS_PLATFORM_COMMANDS: dict[str, dict[str, str]] = {
    "current_directory": {
        "bash": "pwd",
        "zsh": "pwd",
        "fish": "pwd",
        "nushell": "pwd",
        "xonsh": "pwd",
        "powershell": "Get-Location",
        "cmd": "cd",
    },
    "list_files": {
        "bash": "ls -la",
        "zsh": "ls -la",
        "fish": "ls -la",
        "nushell": "ls -a",
        "xonsh": "ls -la",
        "powershell": "Get-ChildItem -Force",
        "cmd": "dir /a",
    },
    "list_processes": {
        "bash": "ps aux",
        "zsh": "ps aux",
        "fish": "ps aux",
        "nushell": "ps",
        "xonsh": "ps aux",
        "powershell": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 30",
        "cmd": "tasklist /v",
    },
    "process_tree": {
        "bash": "pstree -ap",
        "zsh": "pstree -ap",
        "fish": "pstree -ap",
        "nushell": "ps | sort-by cpu",
        "xonsh": "pstree -ap",
        "powershell": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50",
        "cmd": "tasklist /v",
    },
    "network_connections": {
        "bash": "ss -tulpn",
        "zsh": "ss -tulpn",
        "fish": "ss -tulpn",
        "nushell": "netstat -an",
        "xonsh": "ss -tulpn",
        "powershell": "Get-NetTCPConnection | Where-Object State -eq Listen | Sort-Object LocalPort",
        "cmd": "netstat -ano",
    },
    "open_ports": {
        "bash": "ss -tlnp",
        "zsh": "ss -tlnp",
        "fish": "ss -tlnp",
        "nushell": "netstat -an",
        "xonsh": "ss -tlnp",
        "powershell": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess",
        "cmd": "netstat -an | findstr LISTENING",
    },
    "network_interfaces": {
        "bash": "ip addr",
        "zsh": "ip addr",
        "fish": "ip addr",
        "nushell": "ip addr",
        "xonsh": "ip addr",
        "powershell": "Get-NetAdapter | Select-Object Name,Status,MacAddress,LinkSpeed",
        "cmd": "ipconfig /all",
    },
    "routing_table": {
        "bash": "ip route",
        "zsh": "ip route",
        "fish": "ip route",
        "nushell": "ip route",
        "xonsh": "ip route",
        "powershell": "Get-NetRoute | Where-Object DestinationPrefix -ne '::1/128'",
        "cmd": "route print",
    },
    "arp_table": {
        "bash": "arp -n",
        "zsh": "arp -n",
        "fish": "arp -n",
        "nushell": "arp -a",
        "xonsh": "arp -n",
        "powershell": "Get-NetNeighbor",
        "cmd": "arp -a",
    },
    "dns_lookup": {
        "bash": "nslookup {target}",
        "zsh": "nslookup {target}",
        "fish": "nslookup {target}",
        "nushell": "nslookup {target}",
        "xonsh": "nslookup {target}",
        "powershell": "Resolve-DnsName {target}",
        "cmd": "nslookup {target}",
    },
    "dns_cache": {
        "bash": "systemd-resolve --statistics || resolvectl statistics",
        "zsh": "systemd-resolve --statistics || resolvectl statistics",
        "fish": "systemd-resolve --statistics || resolvectl statistics",
        "nushell": "systemd-resolve --statistics || resolvectl statistics",
        "xonsh": "systemd-resolve --statistics || resolvectl statistics",
        "powershell": "Get-DnsClientCache",
        "cmd": "ipconfig /displaydns",
    },
    "whoami": {
        "bash": "whoami && id",
        "zsh": "whoami && id",
        "fish": "whoami",
        "nushell": "whoami",
        "xonsh": "whoami && id",
        "powershell": "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
        "cmd": "whoami /all",
    },
    "environment_vars": {
        "bash": "printenv | sort",
        "zsh": "printenv | sort",
        "fish": "set",
        "nushell": "env",
        "xonsh": "env | sort",
        "powershell": "Get-ChildItem Env: | Sort-Object Name",
        "cmd": "set",
    },
    "firewall_rules": {
        "bash": "iptables -L -n -v",
        "zsh": "iptables -L -n -v",
        "fish": "iptables -L -n -v",
        "nushell": "iptables -L -n -v",
        "xonsh": "iptables -L -n -v",
        "powershell": "Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object Name,Direction,Action | Format-Table",
        "cmd": "netsh advfirewall firewall show rule name=all",
    },
    "scheduled_tasks": {
        "bash": "crontab -l && ls /etc/cron*",
        "zsh": "crontab -l && ls /etc/cron*",
        "fish": "crontab -l",
        "nushell": "crontab -l",
        "xonsh": "crontab -l && ls /etc/cron*",
        "powershell": "Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName,TaskPath",
        "cmd": "schtasks /query /fo TABLE",
    },
    "services": {
        "bash": "systemctl list-units --type=service --state=running",
        "zsh": "systemctl list-units --type=service --state=running",
        "fish": "systemctl list-units --type=service --state=running",
        "nushell": "systemctl list-units --type=service --state=running",
        "xonsh": "systemctl list-units --type=service --state=running",
        "powershell": "Get-Service | Where-Object Status -eq Running | Select-Object Name,DisplayName",
        "cmd": "sc query state= all",
    },
    "users": {
        "bash": "cat /etc/passwd | grep -v nologin | grep -v false",
        "zsh": "cat /etc/passwd | grep -v nologin | grep -v false",
        "fish": "cat /etc/passwd",
        "nushell": "cat /etc/passwd",
        "xonsh": "cat /etc/passwd | grep -v nologin | grep -v false",
        "powershell": "Get-LocalUser | Select-Object Name,Enabled,LastLogon",
        "cmd": "net user",
    },
    "groups": {
        "bash": "cat /etc/group",
        "zsh": "cat /etc/group",
        "fish": "cat /etc/group",
        "nushell": "cat /etc/group",
        "xonsh": "cat /etc/group",
        "powershell": "Get-LocalGroup | Select-Object Name,Description",
        "cmd": "net localgroup",
    },
    "installed_software": {
        "bash": "dpkg -l || rpm -qa",
        "zsh": "dpkg -l || rpm -qa",
        "fish": "dpkg -l",
        "nushell": "dpkg -l || rpm -qa",
        "xonsh": "dpkg -l || rpm -qa",
        "powershell": "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher",
        "cmd": 'wmic product get name,version',
    },
    "package_managers": {
        "bash": "command -v apt || command -v dnf || command -v yum || command -v pacman",
        "zsh": "command -v apt || command -v dnf || command -v yum || command -v pacman",
        "fish": "type -q apt; or type -q dnf; or type -q yum; or type -q pacman",
        "nushell": "which apt; which dnf; which yum; which pacman",
        "xonsh": "type -a apt dnf yum pacman",
        "powershell": "Get-Command winget,choco,scoop -ErrorAction SilentlyContinue",
        "cmd": "where winget 2>nul && where choco 2>nul && where scoop 2>nul",
    },
    "system_info": {
        "bash": "uname -a && lsb_release -a",
        "zsh": "uname -a && lsb_release -a",
        "fish": "uname -a",
        "nushell": "uname -a",
        "xonsh": "uname -a && lsb_release -a",
        "powershell": "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsHardwareAbstractionLayer",
        "cmd": "systeminfo",
    },
    "disk_usage": {
        "bash": "df -h",
        "zsh": "df -h",
        "fish": "df -h",
        "nushell": "df",
        "xonsh": "df -h",
        "powershell": "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free",
        "cmd": "wmic logicaldisk get caption,freespace,size",
    },
    "disk_free": {
        "bash": "df -h --total",
        "zsh": "df -h --total",
        "fish": "df -h --total",
        "nushell": "df",
        "xonsh": "df -h --total",
        "powershell": "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Free",
        "cmd": "wmic logicaldisk get caption,freespace",
    },
    "file_hash": {
        "bash": "sha256sum {file}",
        "zsh": "sha256sum {file}",
        "fish": "sha256sum {file}",
        "nushell": "sha256sum {file}",
        "xonsh": "sha256sum {file}",
        "powershell": "Get-FileHash {file} -Algorithm SHA256",
        "cmd": "certutil -hashfile {file} SHA256",
    },
    "find_suid": {
        "bash": "find / -perm -4000 -type f 2>/dev/null",
        "zsh": "find / -perm -4000 -type f 2>/dev/null",
        "fish": "find / -perm -4000 -type f 2>/dev/null",
        "nushell": "find / -perm -4000 -type f 2>/dev/null",
        "xonsh": "find / -perm -4000 -type f 2>/dev/null",
        "powershell": "# SUID is a Linux concept; check privileged executables with: icacls C:\\Windows\\System32 /c",
        "cmd": "icacls C:\\Windows\\System32 /c 2>nul | findstr /i \"full control\"",
    },
    "registry_autoruns": {
        "bash": "# Linux: check /etc/init.d/ and systemctl",
        "zsh": "# Linux: check /etc/init.d/ and systemctl",
        "fish": "# Linux: check /etc/init.d/ and systemctl",
        "nushell": "# Linux: check /etc/init.d/ and systemctl",
        "xonsh": "# Linux: check /etc/init.d/ and systemctl",
        "powershell": "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
        "cmd": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    "host_file": {
        "bash": "cat /etc/hosts",
        "zsh": "cat /etc/hosts",
        "fish": "cat /etc/hosts",
        "nushell": "cat /etc/hosts",
        "xonsh": "cat /etc/hosts",
        "powershell": "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
        "cmd": "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    },
    "ping": {
        "bash": "ping -c 4 {target}",
        "zsh": "ping -c 4 {target}",
        "fish": "ping -c 4 {target}",
        "nushell": "ping -c 4 {target}",
        "xonsh": "ping -c 4 {target}",
        "powershell": "Test-NetConnection -ComputerName {target} -InformationLevel Detailed",
        "cmd": "ping -n 4 {target}",
    },
    "traceroute": {
        "bash": "traceroute {target}",
        "zsh": "traceroute {target}",
        "fish": "traceroute {target}",
        "nushell": "traceroute {target}",
        "xonsh": "traceroute {target}",
        "powershell": "Test-NetConnection -ComputerName {target} -TraceRoute",
        "cmd": "tracert {target}",
    },
    "git_status": {
        "bash": "git status -sb",
        "zsh": "git status -sb",
        "fish": "git status -sb",
        "nushell": "git status -sb",
        "xonsh": "git status -sb",
        "powershell": "git status -sb",
        "cmd": "git status -sb",
    },
    "git_branches": {
        "bash": "git branch -vv",
        "zsh": "git branch -vv",
        "fish": "git branch -vv",
        "nushell": "git branch -vv",
        "xonsh": "git branch -vv",
        "powershell": "git branch -vv",
        "cmd": "git branch -vv",
    },
    "docker_ps": {
        "bash": "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'",
        "zsh": "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'",
        "fish": "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'",
        "nushell": "docker ps",
        "xonsh": "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'",
        "powershell": "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'",
        "cmd": "docker ps",
    },
    "docker_images": {
        "bash": "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'",
        "zsh": "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'",
        "fish": "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'",
        "nushell": "docker images",
        "xonsh": "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'",
        "powershell": "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'",
        "cmd": "docker images",
    },
    "kubectl_get_pods": {
        "bash": "kubectl get pods -A",
        "zsh": "kubectl get pods -A",
        "fish": "kubectl get pods -A",
        "nushell": "kubectl get pods -A",
        "xonsh": "kubectl get pods -A",
        "powershell": "kubectl get pods -A",
        "cmd": "kubectl get pods -A",
    },
    "kubectl_contexts": {
        "bash": "kubectl config get-contexts",
        "zsh": "kubectl config get-contexts",
        "fish": "kubectl config get-contexts",
        "nushell": "kubectl config get-contexts",
        "xonsh": "kubectl config get-contexts",
        "powershell": "kubectl config get-contexts",
        "cmd": "kubectl config get-contexts",
    },
    "helm_list": {
        "bash": "helm list -A",
        "zsh": "helm list -A",
        "fish": "helm list -A",
        "nushell": "helm list -A",
        "xonsh": "helm list -A",
        "powershell": "helm list -A",
        "cmd": "helm list -A",
    },
    "terraform_plan": {
        "bash": "terraform plan",
        "zsh": "terraform plan",
        "fish": "terraform plan",
        "nushell": "terraform plan",
        "xonsh": "terraform plan",
        "powershell": "terraform plan",
        "cmd": "terraform plan",
    },
    "aws_identity": {
        "bash": "aws sts get-caller-identity",
        "zsh": "aws sts get-caller-identity",
        "fish": "aws sts get-caller-identity",
        "nushell": "aws sts get-caller-identity",
        "xonsh": "aws sts get-caller-identity",
        "powershell": "aws sts get-caller-identity",
        "cmd": "aws sts get-caller-identity",
    },
    "az_account": {
        "bash": "az account show",
        "zsh": "az account show",
        "fish": "az account show",
        "nushell": "az account show",
        "xonsh": "az account show",
        "powershell": "az account show",
        "cmd": "az account show",
    },
    "gcloud_auth": {
        "bash": "gcloud auth list",
        "zsh": "gcloud auth list",
        "fish": "gcloud auth list",
        "nushell": "gcloud auth list",
        "xonsh": "gcloud auth list",
        "powershell": "gcloud auth list",
        "cmd": "gcloud auth list",
    },
    "ssh_connect": {
        "bash": "ssh {user}@{target}",
        "zsh": "ssh {user}@{target}",
        "fish": "ssh {user}@{target}",
        "nushell": "ssh {user}@{target}",
        "xonsh": "ssh {user}@{target}",
        "powershell": "ssh {user}@{target}",
        "cmd": "ssh {user}@{target}",
    },
    "scp_copy": {
        "bash": "scp {path} {user}@{target}:{path}",
        "zsh": "scp {path} {user}@{target}:{path}",
        "fish": "scp {path} {user}@{target}:{path}",
        "nushell": "scp {path} {user}@{target}:{path}",
        "xonsh": "scp {path} {user}@{target}:{path}",
        "powershell": "scp {path} {user}@{target}:{path}",
        "cmd": "scp {path} {user}@{target}:{path}",
    },
    "rsync_copy": {
        "bash": "rsync -avz {path} {user}@{target}:{path}",
        "zsh": "rsync -avz {path} {user}@{target}:{path}",
        "fish": "rsync -avz {path} {user}@{target}:{path}",
        "nushell": "rsync -avz {path} {user}@{target}:{path}",
        "xonsh": "rsync -avz {path} {user}@{target}:{path}",
        "powershell": "rsync -avz {path} {user}@{target}:{path}",
        "cmd": "rsync -avz {path} {user}@{target}:{path}",
    },
    "python_version": {
        "bash": "python --version",
        "zsh": "python --version",
        "fish": "python --version",
        "nushell": "python --version",
        "xonsh": "python --version",
        "powershell": "python --version",
        "cmd": "python --version",
    },
    "node_version": {
        "bash": "node --version",
        "zsh": "node --version",
        "fish": "node --version",
        "nushell": "node --version",
        "xonsh": "node --version",
        "powershell": "node --version",
        "cmd": "node --version",
    },
    "pip_list": {
        "bash": "pip list --format=columns",
        "zsh": "pip list --format=columns",
        "fish": "pip list --format=columns",
        "nushell": "pip list",
        "xonsh": "pip list --format=columns",
        "powershell": "pip list --format=columns",
        "cmd": "pip list",
    },
}

INTENT_METADATA: dict[str, dict[str, Any]] = {
    "current_directory": {"category": "filesystem", "description": "Show current directory"},
    "list_files": {"category": "filesystem", "description": "List directory contents"},
    "list_processes": {"category": "process", "description": "Show running processes"},
    "process_tree": {"category": "process", "description": "Process tree/top consumers"},
    "network_connections": {"category": "network", "description": "Active network connections"},
    "open_ports": {"category": "network", "description": "Listening ports"},
    "network_interfaces": {"category": "network", "description": "Network interfaces"},
    "routing_table": {"category": "network", "description": "Routing table"},
    "arp_table": {"category": "network", "description": "ARP cache"},
    "dns_lookup": {"category": "network", "description": "DNS lookup", "placeholders": ["target"]},
    "dns_cache": {"category": "network", "description": "DNS cache"},
    "whoami": {"category": "identity", "description": "Current user and privileges"},
    "environment_vars": {"category": "system", "description": "Environment variables"},
    "firewall_rules": {"category": "security", "description": "Firewall rules"},
    "scheduled_tasks": {"category": "system", "description": "Scheduled tasks/cron jobs"},
    "services": {"category": "system", "description": "Running services"},
    "users": {"category": "identity", "description": "User accounts"},
    "groups": {"category": "identity", "description": "Groups"},
    "installed_software": {"category": "system", "description": "Installed software"},
    "package_managers": {"category": "system", "description": "Available package managers"},
    "system_info": {"category": "system", "description": "System information"},
    "disk_usage": {"category": "filesystem", "description": "Disk usage"},
    "disk_free": {"category": "filesystem", "description": "Disk free totals"},
    "file_hash": {"category": "filesystem", "description": "Compute file hash", "placeholders": ["file"]},
    "find_suid": {"category": "security", "description": "Find privileged executables"},
    "registry_autoruns": {"category": "security", "description": "Startup registry keys"},
    "host_file": {"category": "filesystem", "description": "Hosts file"},
    "ping": {"category": "network", "description": "Ping target", "placeholders": ["target"]},
    "traceroute": {"category": "network", "description": "Trace route", "placeholders": ["target"]},
    "git_status": {"category": "dev", "description": "Git status"},
    "git_branches": {"category": "dev", "description": "Git branches"},
    "docker_ps": {"category": "containers", "description": "Docker running containers"},
    "docker_images": {"category": "containers", "description": "Docker images"},
    "kubectl_get_pods": {"category": "infra", "description": "Kubernetes pods"},
    "kubectl_contexts": {"category": "infra", "description": "Kubernetes contexts"},
    "helm_list": {"category": "infra", "description": "Helm releases"},
    "terraform_plan": {"category": "infra", "description": "Terraform plan"},
    "aws_identity": {"category": "cloud", "description": "AWS caller identity"},
    "az_account": {"category": "cloud", "description": "Azure account"},
    "gcloud_auth": {"category": "cloud", "description": "GCP auth list"},
    "ssh_connect": {"category": "remote", "description": "SSH connect", "placeholders": ["user", "target"]},
    "scp_copy": {"category": "remote", "description": "SCP copy", "placeholders": ["user", "target", "path"]},
    "rsync_copy": {"category": "remote", "description": "Rsync copy", "placeholders": ["user", "target", "path"]},
    "python_version": {"category": "dev", "description": "Python version"},
    "node_version": {"category": "dev", "description": "Node version"},
    "pip_list": {"category": "dev", "description": "Python packages"},
}


def render_intent(intent: str, **kwargs: str) -> str:
    """Render a command intent with placeholder values."""
    entry = CROSS_PLATFORM_COMMANDS.get(intent, {})
    command = entry.get(shell_key(detect_shell()), entry.get("bash", ""))
    for key, value in kwargs.items():
        command = command.replace(f"{{{key}}}", value)
    return command

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

    # Modern shell signals
    if os.getenv("NU_VERSION"):
        return ShellType.NUSHELL
    if os.getenv("XONSH_VERSION"):
        return ShellType.XONSH

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
        result = subprocess.run(  # nosec B603 B607
            ["ps", "-p", str(ppid), "-o", "comm="],
            capture_output=True, text=True, timeout=3,
        )
        comm = result.stdout.strip().lstrip("-")
        detected = _shell_from_name(comm)
        if detected != ShellType.UNKNOWN:
            return detected
    except Exception:  # nosec B110
        pass

    return ShellType.UNKNOWN


def detect_terminal_type() -> str:
    """Detect the terminal type using environment signals."""
    return terminal_type_from_env()


def _safe_read(path: str, max_bytes: int = 2048) -> str:
    """Read a small text file safely and return an empty string on failure."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")[:max_bytes]
    except Exception:  # nosec B110
        return ""


def _linux_pretty_name() -> str:
    """Return PRETTY_NAME from /etc/os-release when available."""
    data = _safe_read("/etc/os-release")
    if not data:
        return ""
    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"')
            return value
    return ""


def _safe_loadavg() -> tuple[float, float, float] | None:
    """Return load average where available."""
    try:
        return os.getloadavg()
    except Exception:  # nosec B110
        return None


def _linux_memory_total_mb() -> int | None:
    """Parse MemTotal from /proc/meminfo when present."""
    meminfo = _safe_read("/proc/meminfo")
    if not meminfo:
        return None
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(int(parts[1]) / 1024)
    return None


def _detect_container(env: Mapping[str, str]) -> tuple[bool, str]:
    """Detect common container runtimes and return (is_container, runtime)."""
    if Path("/.dockerenv").exists():
        return True, "docker"
    cgroup = _safe_read("/proc/1/cgroup")
    lower = cgroup.lower()
    if "docker" in lower:
        return True, "docker"
    if "kubepods" in lower or env.get("KUBERNETES_SERVICE_HOST"):
        return True, "kubernetes"
    if "containerd" in lower:
        return True, "containerd"
    if env.get("CONTAINER"):
        return True, env.get("CONTAINER", "container")
    return False, "none"


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
        if shell in (ShellType.BASH, ShellType.ZSH, ShellType.SH, ShellType.FISH, ShellType.NUSHELL, ShellType.XONSH):
            return f"macOS ({shell.value})"
        return "macOS (zsh/bash)"
    else:
        shell = detect_shell()
        if shell in (ShellType.BASH, ShellType.ZSH, ShellType.SH, ShellType.FISH, ShellType.NUSHELL, ShellType.XONSH):
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
    env = os.environ
    shell = detect_shell()
    sys_name = platform.system()
    device_type = detect_device_type(sys_name)
    terminal_type = detect_terminal_type()
    normalized_shell = normalize_shell(shell)
    host = socket.gethostname()
    fqdn = socket.getfqdn()
    is_container, container_runtime = _detect_container(env)
    shell_env = env.get("SHELL", "")
    shell_executable = shell_env or shutil.which(normalized_shell.value) or ""
    load_avg = _safe_loadavg()
    linux_pretty = _linux_pretty_name() if sys_name.lower() == "linux" else ""
    memory_total_mb = _linux_memory_total_mb() if sys_name.lower() == "linux" else None
    cpu_count = os.cpu_count() or 0
    username = getpass.getuser()
    cwd = str(Path.cwd())
    home_dir = str(Path.home())

    return {
        "platform": sys_name,
        "platform_lower": sys_name.lower(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "platform_full": platform.platform(),
        "platform_pretty": linux_pretty or f"{sys_name} {platform.release()}",
        "device_type": device_type,
        "arch": platform.machine(),
        "processor": platform.processor() or "unknown",
        "hostname": host,
        "fqdn": fqdn,
        "username": username,
        "cwd": cwd,
        "home_dir": home_dir,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "python_version": platform.python_version(),
        "shell": shell.value,
        "shell_key": shell_key(shell),
        "shell_normalized": normalized_shell.value,
        "shell_executable": shell_executable,
        "shell_family": "windows" if sys_name.lower() == "windows" else "unix",
        "shell_platform": get_shell_platform(),
        "terminal_type": terminal_type,
        "term": env.get("TERM", ""),
        "colorterm": env.get("COLORTERM", ""),
        "term_program": env.get("TERM_PROGRAM", ""),
        "terminal_program_version": env.get("TERM_PROGRAM_VERSION", ""),
        "vscode_integrated_terminal": bool(env.get("VSCODE_PID")),
        "is_terminal_ssh": terminal_type == "ssh",
        "is_terminal_wsl": terminal_type == "wsl",
        "is_terminal_cloud": terminal_type in ("cloud-shell", "codespaces"),
        "is_codespaces": bool(env.get("CODESPACES")),
        "codespaces_name": env.get("CODESPACE_NAME", ""),
        "is_ci": bool(env.get("CI")),
        "is_container": is_container,
        "container_runtime": container_runtime,
        "is_windows": sys_name.lower() == "windows",
        "is_linux": sys_name.lower() == "linux",
        "is_macos": sys_name.lower() == "darwin",
        "has_wsl": shutil.which("wsl") is not None,
        "cpu_count": cpu_count,
        "memory_total_mb": memory_total_mb,
        "load_avg_1m": load_avg[0] if load_avg else None,
        "load_avg_5m": load_avg[1] if load_avg else None,
        "load_avg_15m": load_avg[2] if load_avg else None,
        "available_tools_count": len(CROSS_PLATFORM_COMMANDS),
        "available_intents": list(CROSS_PLATFORM_COMMANDS.keys()),
    }
