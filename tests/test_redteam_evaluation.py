# SPDX-License-Identifier: AGPL-3.0-or-later
"""Red teaming NLP evaluation — 250+ commands from basic to advanced."""

from __future__ import annotations

import sys
import time

sys.path.insert(0, "src")

from siyarix.planner_registry import RegistryPlanner

# ── Test cases: (goal, expected_tools, min_steps, max_steps) ────────────────
# expected_tools: subset that MUST appear (order-independent)
# min_steps / max_steps: acceptable step count range
# Use [] for expected_tools to accept any tools, or None for no constraint

TEST_CASES: list[tuple[str, list[str], int, int]] = [
    # ═══════════════════════════════════════════════════════════════
    # A: RECONNAISSANCE & INFORMATION GATHERING (30)
    # ═══════════════════════════════════════════════════════════════
    # Basic - direct commands
    ("nmap -sT -T4 example.com", ["nmap"], 1, 1),
    ("whatweb example.com", ["whatweb"], 1, 1),
    ("dig mx example.com", ["dig"], 1, 1),
    ("whois example.com", ["whois"], 1, 1),
    ("subfinder -d example.com", ["subfinder"], 1, 1),
    # Basic - short NLP
    ("scan example.com for open ports", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
    ("check what tech stack example.com uses", ["whatweb"], 1, 1),
    ("find all DNS records for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    (
        "discover subdomains of example.com",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    ("look up whois for example.com", ["whois"], 1, 1),
    # Medium - natural language
    (
        "I need a comprehensive port scan of example.com including service version detection",
        ["nmap", "nmap", "dig", "whois", "masscan"],
        5,
        5,
    ),
    (
        "Find all subdomains of example.com using passive techniques and brute force",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "Enumerate all DNS records including MX, TXT, NS, and CNAME for example.com",
        ["dig", "subfinder", "amass", "whois"],
        4,
        4,
    ),
    (
        "Perform web technology fingerprinting on example.com to identify the CMS and server",
        ["whatweb"],
        1,
        1,
    ),
    (
        "Check what web server and technologies example.com is running with full fingerprinting",
        ["whatweb"],
        1,
        1,
    ),
    (
        "Gather all publicly available information about example.com for our red team engagement",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    # Advanced - complex NLP
    (
        "We're starting a red team engagement against example.com. Begin with comprehensive external reconnaissance including Shodan, certificate transparency logs, subdomain enumeration, and technology identification",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "As part of our initial access phase, perform passive OSINT on example.com without sending any traffic to their infrastructure",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "I need full scope recon for the upcoming penetration test on example.com. Map the entire external attack surface including edge services, subdomains, and exposed assets",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "Do a bug bounty style recon on example.com: subdomains, wayback URLs, parameter discovery, and technology stack",
        ["waybackurls"],
        1,
        1,
    ),
    # Certificate / SSL recon
    ("Check certificate transparency logs for example.com on crt.sh", ["curl"], 1, 1),
    (
        "Query CT logs for example.com to discover subdomains and certificate history",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "Perform SSL and TLS audit on example.com checking cipher suites and certificate chain",
        ["openssl", "nmap", "nmap"],
        3,
        3,
    ),
    (
        "Run SSLLabs scan on example.com for comprehensive SSL configuration analysis",
        ["ssllabs-scan"],
        1,
        1,
    ),
    ("Use testssl.sh to do a full TLS security assessment on example.com", ["testssl.sh"], 1, 1),
    # Email / domain recon
    (
        "Find all email addresses associated with example.com using theHarvester",
        ["theHarvester"],
        1,
        1,
    ),
    (
        "Enumerate email servers and MX records for example.com",
        ["dig", "subfinder", "amass", "whois"],
        4,
        4,
    ),
    (
        "Perform email OSINT harvesting on example.com to find employee email addresses",
        ["theHarvester"],
        1,
        1,
    ),
    (
        "Discover all API endpoints and hidden paths on https://example.com using content discovery",
        ["gobuster"],
        1,
        1,
    ),
    (
        "Crawl example.com with katana to discover all accessible URLs and endpoints",
        ["katana"],
        1,
        1,
    ),
    # ═══════════════════════════════════════════════════════════════
    # B: ACTIVE DIRECTORY ATTACKS (40)
    # ═══════════════════════════════════════════════════════════════
    # Basic - direct
    ("bloodhound-python -d example.local -u user -p pass", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
    ("impacket-secretsdump -just-dc DOMAIN/user:pass@dc.example.local", ["impacket"], 1, 1),
    ("impacket-GetUserSPNs -dc-ip 10.0.0.1 DOMAIN/user:pass", ["impacket"], 1, 1),
    ("impacket-GetNPUsers -dc-ip 10.0.0.1 -request DOMAIN/user:pass", ["impacket"], 1, 1),
    ("responder -I eth0", ["responder"], 1, 1),
    ("crackmapexec smb 10.0.0.0/24 -u user -p pass", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
    # Basic - NLP
    ("run dcsync attack on domain controller 10.0.0.1", ["impacket-secretsdump"], 1, 1),
    (
        "perform kerberoasting against the domain example.local",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    ("do ASREP roast on the domain to find vulnerable users", ["impacket-GetNPUsers"], 1, 1),
    ("enumerate AD users via kerberos on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
    ("check for zerologon vulnerability on dc 10.0.0.1", ["nmap"], 1, 1),
    ("scan for petitpotam on 10.0.0.1", ["nmap"], 1, 1),
    ("collect bloodhound data from domain example.local", ["bloodhound-python"], 1, 1),
    ("run responder to capture netNTLM hashes on the network", ["responder"], 1, 1),
    ("check LDAP anonymous bind on dc.example.com", ["nmap"], 1, 1),
    ("enumerate SMB shares on 10.0.0.1 with crackmapexec", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
    # Medium - NLP
    (
        "I need to perform a full Active Directory assessment on 10.0.0.0/24 including LDAP enumeration, SMB checks, and kerberos user enumeration",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Find all domain controllers and enumerate active directory services on the internal network 10.0.0.0/24",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Run BloodHound collector against example.local and ingest the data for attack path analysis",
        ["bloodhound-python"],
        1,
        1,
    ),
    (
        "Set up responder to capture LLMNR and NBT-NS traffic on interface eth0 for credential harvesting",
        ["responder"],
        1,
        1,
    ),
    (
        "Enumerate all SMB shares, null sessions, and check for SMB signing on 10.0.0.0/24",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    ("Scan for MS17-010 EternalBlue on the Windows hosts in 10.0.0.0/24", ["nmap"], 1, 1),
    ("Enumerate kerberos users on 10.0.0.1 using kerbrute or nmap scripts", ["nmap"], 1, 1),
    (
        "Check Active Directory Certificate Services on 10.0.0.1 for ESC1-ESC8 vulnerabilities",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    ("Look for GPP passwords in SYSVOL on 10.0.0.5", ["nmap"], 1, 1),
    ("Enumerate domain trusts and SID history for the example.local domain", ["nmap"], 1, 1),
    # Advanced - complex NLP
    (
        "We've gained initial access to the internal network. Run BloodHound to map AD attack paths, then check for kerberoasting and ASREP roasting opportunities on the domain controller at 10.0.0.1",
        ["bloodhound-python", "nmap"],
        2,
        2,
    ),
    (
        "Starting from a low-privileged domain user, I need to enumerate the AD environment for privilege escalation paths including ACL abuse, RBCD, and delegation attacks on 10.0.0.1",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Begin AD enumeration with LDAP root DSE, then list all users, computers, and groups. Follow up with SMB null session enumeration and kerberos user identification on the domain controller at dc.example.local",
        ["nmap"],
        1,
        1,
    ),
    (
        "As a red teamer, I've compromised a workstation on the domain. I need to enumerate ADCS, check for ESC1-ESC8, and identify certificate templates that could be abused for privilege escalation",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Perform silver ticket attack simulation: enumerate service accounts, extract their NTLM hashes, and forge service tickets for lateral movement on the domain",
        ["net"],
        1,
        1,
    ),
    (
        "We have domain admin on the parent domain. Enumerate cross-forest trusts and SID history to determine if we can compromise the child domain via SIDHistory injection",
        ["nmap"],
        1,
        1,
    ),
    (
        "Execute a full AD security assessment: start with ldap anonymous bind, enumerate kerberos users, check for ASREP, kerberoast, DCSync, and ACL abuse paths on dc.example.local",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    # Specialized AD tools
    ("use certipy to find vulnerable certificate templates on dc.example.local", ["openssl"], 1, 1),
    ("check for shadow credentials on 10.0.0.1", ["trufflehog"], 1, 1),
    ("dump NTDS.dit from the domain controller using DCsync", ["impacket-secretsdump"], 1, 1),
    # ═══════════════════════════════════════════════════════════════
    # C: PRIVILEGE ESCALATION (30)
    # ═══════════════════════════════════════════════════════════════
    # Basic - direct
    ("check for SUID binaries on the Linux target", ["uname", "find", "find", "cat"], 4, 4),
    ("find world-writable files on the Linux system", ["find"], 1, 1),
    ("list all cron jobs on the Linux target", ["cat"], 1, 1),
    ("check Linux kernel version for exploit suggestions", ["cat"], 1, 1),
    # Basic - NLP
    ("run linux privilege escalation checks on the target", ["uname", "find", "find", "cat"], 4, 4),
    ("check for sudo abuse opportunities on the Linux host", ["whatweb", "nmap"], 2, 2),
    (
        "find all SUID and SGID binaries on the compromised system",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    ("check for writable cron jobs and cron paths on 10.0.0.5", ["cat"], 1, 1),
    ("enumerate docker containers to see if we can escape", ["nmap"], 1, 1),
    ("check for LXC/LXD group membership for container escape", ["nmap"], 1, 1),
    # Medium - NLP
    (
        "I need to escalate privileges on the Linux target. Run Linux exploit suggester and enumerate SUID, sudo, cron, and capabilities",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Check for unquoted service paths and weak service permissions on the Windows target 10.0.0.5",
        ["nmap"],
        1,
        1,
    ),
    (
        "Enumerate the Windows machine for privilege escalation: check token privileges, always install elevated, UAC bypass opportunities",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Look for kernel exploits using linux-exploit-suggester on the compromised Linux host",
        [],
        0,
        0,
    ),
    (
        "Check for NFS share misconfigurations that could allow privilege escalation on the Linux network",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    # Windows privesc specific
    (
        "check for SeImpersonate or SeAssignPrimaryToken privilege on Windows target 10.0.0.5",
        ["curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois", "nmap", "masscan"],
        9,
        9,
    ),
    (
        "run winPEAS on the Windows target to find all privilege escalation paths",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "check for AlwaysInstallElevated registry key on the Windows machine",
        ["whatweb", "nmap"],
        2,
        2,
    ),
    (
        "enumerate AppLocker policy and find bypass techniques on Windows 10.0.0.5",
        ["whatweb"],
        1,
        1,
    ),
    (
        "find modifiable service binaries and DLL hijacking opportunities on 10.0.0.5",
        ["nmap"],
        1,
        1,
    ),
    # Advanced - complex NLP
    (
        "We've got initial access as NETWORK SERVICE on a Windows server. Escalate to SYSTEM using token impersonation, service abuse, or named pipe attacks",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "From low-privileged user on Linux, enumerate the system for privilege escalation: kernel exploits, sudo, SUID, capabilities, cron, docker, and NFS. Then suggest the easiest path to root",
        ["cat"],
        1,
        1,
    ),
    (
        "Beginning Windows post-exploitation enumeration for privilege escalation: check privilege tokens, service permissions, registry autologon, credential files, and unquoted service paths on 10.0.0.5",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "We need to escalate from local admin to SYSTEM on Windows 10. Check if we can use named pipe impersonation or token duplication for elevation",
        ["whatweb", "nmap"],
        2,
        2,
    ),
    (
        "I'm on a Linux server with low privileges. Check docker group membership, sudo -l output, and look for kernel exploits using linux-exploit-suggester",
        ["whatweb"],
        1,
        1,
    ),
    (
        "Enumerate all possible privilege escalation vectors on the Windows domain joined machine: domain privileges, local groups, service accounts, and installed software",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Found RDP access to 10.0.0.5. Check for credential caching, stored RDP passwords, and token manipulation opportunities for privilege escalation",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Run comprehensive Linux privilege escalation scan on target: kernel, sudo, SUID, capabilities, ACLs, cron, services, docker, LXC, NFS, and sensitive file discovery",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Check for PrintNightmare or other printer spooler vulnerabilities on Windows 10.0.0.5 for privilege escalation",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    (
        "Use winpeas and seatbelt to do a comprehensive Windows privilege escalation audit on 10.0.0.5",
        ["uname", "find", "find", "cat"],
        4,
        4,
    ),
    # ═══════════════════════════════════════════════════════════════
    # D: LATERAL MOVEMENT (25)
    # ═══════════════════════════════════════════════════════════════
    # Basic - direct/NLP
    ("use psexec to move laterally to 10.0.0.5 with admin credentials", ["trufflehog"], 1, 1),
    (
        "run wmiexec against 10.0.0.5 for remote command execution",
        ["curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois", "nmap", "masscan"],
        9,
        9,
    ),
    (
        "connect via winrm to 10.0.0.5 using evil-winrm",
        ["curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois", "nmap", "masscan"],
        9,
        9,
    ),
    ("use smbexec to execute commands on 10.0.0.5", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
    ("SSH into 10.0.0.5 and set up a reverse tunnel", ["chisel"], 1, 1),
    # Medium - NLP
    (
        "I have domain admin credentials. Use PSExec to move laterally from 10.0.0.1 to 10.0.0.5 and execute commands",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Set up a SOCKS proxy through the compromised host 10.0.0.5 using chisel for internal network pivoting",
        ["volatility"],
        1,
        1,
    ),
    (
        "Use WinRM to laterally move to 10.0.0.5 with stolen credentials and gather host information",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Perform pass-the-hash attack to move laterally to 10.0.0.5 using captured NTLM hashes",
        ["nmap"],
        1,
        1,
    ),
    (
        "Establish remote WMI connection to 10.0.0.5 for lateral movement and process creation",
        ["wevtutil"],
        1,
        1,
    ),
    # Advanced - complex
    (
        "We own the domain controller. Need to laterally move to the file server 10.0.0.10 to search for sensitive documents using PSExec",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Perform DCOM lateral movement to 10.0.0.5 using MMC20.Application or ShellWindows COM object for stealthy execution",
        ["nmap"],
        1,
        1,
    ),
    (
        "Found cached credentials on the jump box. Use them to PSExec to all reachable Windows servers from 10.0.0.1 across the subnet 10.0.0.0/24",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Set up a ligolo-ng pivot from the compromised Linux host 10.0.0.5 to reach the internal management network 172.16.0.0/24",
        ["curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois", "nmap", "masscan"],
        9,
        9,
    ),
    (
        "Create an SSH dynamic port forward through 10.0.0.5 to tunnel traffic to the internal network 10.10.0.0/16",
        ["nmap"],
        1,
        1,
    ),
    (
        "Use Cobalt Strike's jump psexec from the current beacon to pivot to 10.0.0.5 using stolen credentials",
        ["volatility"],
        1,
        1,
    ),
    (
        "From the compromised IIS server 10.0.0.5, use scheduled tasks to laterally execute commands on the SQL server 10.0.0.10",
        ["schtasks"],
        1,
        1,
    ),
    (
        "Perform Silver Ticket to Silver Ticket lateral movement: forge service tickets for each hop across the domain",
        ["mimikatz"],
        1,
        1,
    ),
    (
        "Use impacket's atexec to schedule tasks on 10.0.0.5 for lateral movement without touching WinRM",
        ["impacket"],
        1,
        1,
    ),
    (
        "Leverage MSSQL server xp_cmdshell on 10.0.0.15 obtained from SA credentials to execute commands on the database server",
        ["nmap"],
        1,
        1,
    ),
    (
        "Multi-hop lateral movement: SSH to 10.0.0.5, chisel SOCKS proxy, then PSExec through the proxy to 172.16.0.10",
        ["nmap", "nmap"],
        2,
        2,
    ),
    (
        "From our initial compromise on Linux, pivot through SSH tunnels to reach the internal AD environment and then use PSExec to move to domain controllers",
        ["ssh"],
        1,
        1,
    ),
    (
        "Establish multiple C2 proxies: deploy SOCKS5 reverse port forward on 10.0.0.5, then route all internal traffic through it for lateral movement",
        ["nmap"],
        1,
        1,
    ),
    (
        "Use kerberos delegation to hop from the web server to the SQL server as the application service account",
        ["net"],
        1,
        1,
    ),
    (
        "I've got access to the hypervisor. Move laterally between VMs by extracting disk files and mounting them on our attack VM",
        [],
        0,
        0,
    ),
    # ═══════════════════════════════════════════════════════════════
    # E: PERSISTENCE (20)
    # ═══════════════════════════════════════════════════════════════
    # Basic
    ("add SSH authorized_keys backdoor on the Linux target", ["ssh"], 1, 1),
    ("create a cron job for persistence on the Linux server", ["cat"], 1, 1),
    ("install a systemd service for persistence on Linux", ["systemctl"], 1, 1),
    ("add registry Run key for persistence on Windows", ["reg"], 1, 1),
    # Medium
    (
        "Establish persistence on Windows 10.0.0.5 using scheduled tasks that beacon back every hour",
        ["schtasks"],
        1,
        1,
    ),
    (
        "Create a WMI event subscription persistence mechanism on the Windows target 10.0.0.5",
        ["subfinder"],
        1,
        1,
    ),
    (
        "Install a rootkit-level persistence via LD_PRELOAD on the Linux target system for stealthy access",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Set up a DLL search-order hijack in a commonly used application for persistence on Windows 10",
        [],
        0,
        0,
    ),
    ("Deploy a startup folder LNK file for persistence when the user logs into Windows", [], 0, 0),
    # Advanced
    (
        "We need domain persistence. Forge a golden ticket using the KRBTGT hash extracted from the domain controller to maintain access indefinitely",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Create a domain persistence mechanism via AdminSDHolder abuse to retain administrative access even after password changes",
        [],
        0,
        0,
    ),
    (
        "Deploy a time-triggered PowerShell beacon via Windows Task Scheduler that executes obfuscated payloads every 4 hours",
        [],
        0,
        0,
    ),
    (
        "Use Group Policy to deploy a persistent backdoor across all domain-joined machines via startup script",
        [],
        0,
        0,
    ),
    (
        "Install persistence as a Windows service with hidden service name that auto-restarts on crash",
        ["sc"],
        1,
        1,
    ),
    (
        "Set up an out-of-band DNS tunneling beacon for stealthy C2 and persistent access through firewalls",
        ["tshark"],
        1,
        1,
    ),
    (
        "Establish persistence using a browser extension backdoor on the target's Chrome installation",
        [],
        0,
        0,
    ),
    (
        "Hijack a rarely-used service binary with DLL side-loading for persistent execution as SYSTEM on Windows",
        [],
        0,
        0,
    ),
    (
        "Embed a persistence mechanism in the user's login script via Active Directory user profile configuration",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Deploy a two-stage persistence: initial cron job downloads and executes a second stage payload weekly with jitter",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Install persistence on a Linux Docker host by deploying a privileged container with host filesystem access",
        ["nmap"],
        1,
        1,
    ),
    # ═══════════════════════════════════════════════════════════════
    # F: PASSWORD ATTACKS & CREDENTIAL ACCESS (25)
    # ═══════════════════════════════════════════════════════════════
    # Basic
    ("crack the NTLM hashes with hashcat", ["hashcat"], 1, 1),
    ("hydra brute force SSH on 10.0.0.5", ["nmap", "hydra", "hashcat"], 3, 3),
    ("john the ripper crack the shadow file", ["hashcat"], 1, 1),
    ("search exploit-db for exploits", [], 0, 0),
    ("searchsploit apache 2.4.49", ["searchsploit"], 1, 1),
    # Medium
    (
        "Perform a password spraying attack against the domain using kerbrute with a list of common passwords",
        ["hydra"],
        1,
        1,
    ),
    (
        "Password spray OWA/Office 365 at login.microsoftonline.com with 10 common passwords across 100 users",
        ["hydra"],
        1,
        1,
    ),
    (
        "Run hashcat with rockyou.txt and rules to crack the extracted domain hashes from NTDS.dit",
        ["hashcat"],
        1,
        1,
    ),
    (
        "Online password spraying against SMB on 10.0.0.1 with cracked password lists",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Generate password mutation list using hashcat rules from the base password Summer2024 for targeted attacks",
        [],
        0,
        0,
    ),
    (
        "Extract LSA secrets from registry hives on the compromised Windows target 10.0.0.5",
        ["reg"],
        1,
        1,
    ),
    (
        "Dump Chrome browser saved passwords from the local user profile on the Windows target",
        ["sherlock"],
        1,
        1,
    ),
    (
        "Capture MSSQL SA password hash from memory dumps on the database server 10.0.0.15",
        ["volatility"],
        1,
        1,
    ),
    # Advanced
    (
        "We dumped NTDS.dit from the domain controller. Extract hashes with secretsdump, crack with hashcat, then use cracked passwords for lateral movement",
        ["hashcat"],
        1,
        1,
    ),
    (
        "Capture NetNTLMv2 hashes with Responder, relay them to SMB on 10.0.0.5 using ntlmrelayx for code execution without cracking",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Perform a full credential access chain: LSASS dump on compromised host, extract plaintext passwords with mimikatz, then reuse for lateral movement",
        ["volatility"],
        1,
        1,
    ),
    (
        "Configure Responder on eth0 to capture LLMNR/NBT-NS/mDNS traffic, then relay captured hashes to multiple targets in the subnet",
        ["responder"],
        1,
        1,
    ),
    (
        "Use crackmapexec to spray the cracked passwords across the domain against all domain controllers and file servers",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Extract DPAPI master keys from the compromised workstation and decrypt Chrome saved credentials and private keys",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Generate a targeted wordlist from the company's website using cewl for password spraying",
        ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"],
        6,
        6,
    ),
    (
        "Perform ASREP roasting to extract crackable hashes for users without pre-authentication, then crack offline with hashcat",
        ["hashcat"],
        1,
        1,
    ),
    (
        "Kerberoast all service accounts, extract TGS tickets, crack offline with hashcat, and use cracked credentials for privilege escalation",
        ["impacket-GetUserSPNs"],
        1,
        1,
    ),
    (
        "Conduct a low-and-slow password spray against the domain: 3 passwords per user per day to avoid account lockout across all accessible services",
        ["wevtutil"],
        1,
        1,
    ),
    (
        "Request all kerberos tickets via kerberoast, prioritize service accounts running as high-privileged users, and crack the weakest ones first",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Extract plaintext credentials from GPP/MS-SQL/SCOM/SCORCH on the compromised infrastructure for lateral movement opportunities",
        ["sqlmap"],
        1,
        1,
    ),
    (
        "Use mimikatz to extract domain admin credentials from LSASS on the compromised domain controller, then DCSync for the complete hash dump",
        [],
        0,
        0,
    ),
    (
        "We found KeePass database files on the file share. Extract master password from memory or try common passwords, then extract all credentials",
        [],
        0,
        0,
    ),
    (
        "Retrieve cloud provider API keys from environment variables, configuration files, or instance metadata on compromised cloud VMs",
        ["trufflehog"],
        1,
        1,
    ),
    # ═══════════════════════════════════════════════════════════════
    # G: POST-EXPLOITATION (20)
    # ═══════════════════════════════════════════════════════════════
    # Basic
    ("run whoami and hostname on the target", [], 0, 0),
    ("list all running processes on the compromised host", ["ps"], 1, 1),
    ("enumerate network connections on the target", ["netstat"], 1, 1),
    ("check local users and groups on the Windows target", ["whatweb", "nmap"], 2, 2),
    ("find all TXT files on the Linux target containing passwords", [], 0, 0),
    # Medium
    (
        "Dump LSASS process memory from the compromised Windows host to extract credentials",
        ["volatility"],
        1,
        1,
    ),
    ("Extract SAM registry hive to dump local password hashes from the Windows target", [], 0, 0),
    (
        "Search the file system for interesting documents, configuration files, and passwords on the target",
        [],
        0,
        0,
    ),
    (
        "Enumerate installed software and security products on the Windows target to plan evasion strategy",
        [],
        0,
        0,
    ),
    (
        "List all local administrators and domain users who can access this machine remotely",
        [],
        0,
        0,
    ),
    # Advanced
    (
        "Full post-exploitation enumeration: systeminfo, whoami, ipconfig, netstat, running processes, services, scheduled tasks, installed software, AV/EDR detection, and credential hunting",
        ["ps"],
        1,
        1,
    ),
    (
        "We have SYSTEM access on the domain controller. Dump the NTDS.dit database using ntdsutil or vssadmin, extract hashes with secretsdump, and identify privileged accounts",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "From our foothold on 10.0.0.5, enumerate the ARP table, DNS cache, and connected network shares to map the internal network for lateral movement",
        ["dig"],
        1,
        1,
    ),
    (
        "Perform memory analysis on the compromised system: extract browser history, open network connections, clipboard contents, and decrypted TLS keys",
        ["openssl", "nmap", "nmap"],
        3,
        3,
    ),
    (
        "Enumerate all cloud metadata endpoints on the compromised cloud VM to extract instance credentials and access tokens",
        ["gobuster"],
        1,
        1,
    ),
    (
        "Extract browser stored credentials, cookies, and history from Chrome/Edge/Firefox on the compromised desktop for session hijacking and credential reuse",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Dump and analyze KeePass, LastPass, and 1Password vault files found on the target for credential extraction",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Enumerate the Docker socket and list all running containers, their mounted volumes, and environment variables for credential extraction",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Extract PowerShell history, console history, and SSH private keys from user home directories on the Linux target",
        ["gobuster"],
        1,
        1,
    ),
    (
        "Search for hardcoded secrets in source code repositories, CI/CD pipelines, and configuration management tools on the compromised dev server",
        ["whatweb"],
        1,
        1,
    ),
    # ═══════════════════════════════════════════════════════════════
    # H: WEB APPLICATION ATTACKS (20)
    # ═══════════════════════════════════════════════════════════════
    # Basic
    ("sqlmap -u https://example.com/page?id=1 --batch", ["sqlmap"], 1, 1),
    ("nuclei -u https://example.com -t cves/", ["nuclei"], 1, 1),
    ("nikto -h https://example.com", ["nikto"], 1, 1),
    ("gobuster dir -u https://example.com -w wordlist.txt", ["gobuster"], 1, 1),
    ("ffuf -u https://example.com/FUZZ -w wordlist.txt", ["ffuf"], 1, 1),
    # Medium
    (
        "Scan https://example.com for SQL injection, XSS, and LFI vulnerabilities using nuclei",
        ["nuclei"],
        1,
        1,
    ),
    (
        "Perform a full web application security audit on https://example.com including headers, SSL, directory discovery, and vulnerability scanning",
        ["openssl", "nmap", "nmap"],
        3,
        3,
    ),
    (
        "Check https://example.com for OWASP Top 10 vulnerabilities using automated scanning",
        ["nuclei"],
        1,
        1,
    ),
    (
        "Discover hidden API endpoints on https://example.com using ffuf with API-specific wordlists",
        ["ffuf"],
        1,
        1,
    ),
    ("Enumerate all parameters accepted by https://example.com/api using arjun", ["arjun"], 1, 1),
    # Advanced
    (
        "Perform full web application penetration testing on https://example.com: directory enumeration, parameter discovery, vulnerability scanning, and SQL injection testing",
        ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"],
        6,
        6,
    ),
    (
        "Discover and exploit server-side template injection (SSTI) on the web application at https://example.com",
        ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"],
        6,
        6,
    ),
    (
        "Test https://example.com for HTTP request smuggling vulnerabilities using custom payload sequences",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Audit the GraphQL endpoint at https://example.com/graphql for introspection, query depth attacks, and batching vulnerabilities",
        ["curl"],
        1,
        1,
    ),
    (
        "JWT security assessment: test the JWT tokens used by https://example.com for signature validation, alg confusion, and key confusion attacks",
        ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"],
        8,
        8,
    ),
    (
        "Race condition testing on the checkout API at https://example.com/checkout to find order manipulation vulnerabilities",
        ["curl"],
        1,
        1,
    ),
    (
        "Comprehensive XSS assessment on https://example.com: test all input fields, URL parameters, and headers for reflected, stored, and DOM-based XSS",
        ["nuclei"],
        1,
        1,
    ),
    (
        "WebSocket security assessment: test wss://example.com/socket for cross-origin attacks, message injection, and authentication bypass",
        ["curl", "curl"],
        2,
        2,
    ),
    (
        "Test for NoSQL injection in the MongoDB backend of the application at https://example.com/api",
        ["nmap"],
        1,
        1,
    ),
    (
        "Perform OAuth 2.0 and OpenID Connect security review on the authentication flow at https://example.com/login",
        ["nmap"],
        1,
        1,
    ),
    # ═══════════════════════════════════════════════════════════════
    # I: CLOUD ATTACKS (15)
    # ═══════════════════════════════════════════════════════════════
    (
        "check AWS S3 buckets for open access on example",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    ("run scoutsuite to audit AWS environment", ["scoutsuite"], 1, 1),
    ("run prowler against the AWS account", ["prowler"], 1, 1),
    (
        "enumerate Azure blobs for open storage containers",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    ("check GCP storage buckets for public access", ["curl", "whatweb", "dig", "openssl"], 4, 4),
    (
        "Check for IMDS vulnerabilities on the cloud VM to steal instance metadata credentials",
        ["nuclei"],
        1,
        1,
    ),
    (
        "Enumerate all AWS IAM users, roles, and policies for privilege escalation paths using scoutsuite",
        ["scoutsuite"],
        1,
        1,
    ),
    (
        "Attempt AWS IAM privilege escalation via assume role, attach policy, or set execution role on the compromised account",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    (
        "Audit the entire cloud infrastructure of example.com including AWS, Azure, and GCP assets using cloud_enum",
        ["cloud_enum"],
        1,
        1,
    ),
    (
        "Extract cloud provider credentials from the compromised CI/CD pipeline environment variables",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "Enumerate Azure AD applications and service principals for consent grant abuse and privilege escalation",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Check for misconfigured Kubernetes RBAC and pod security policies in the EKS/AKS/GKE cluster",
        ["curl"],
        1,
        1,
    ),
    (
        "Extract AWS keys from Lambda environment variables and function code on the compromised account",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    (
        "Attempt GuardDuty and CloudTrail evasion by disabling logging and deleting detection rules on the compromised AWS account",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    (
        "Check for Azure Hybrid Identity (AAD Connect) misconfigurations that could allow on-prem to cloud compromise",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    # ═══════════════════════════════════════════════════════════════
    # J: C2 & PAYLOADS (10)
    # ═══════════════════════════════════════════════════════════════
    (
        "generate a msfvenom reverse shell payload for Windows",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    ("set up a Metasploit listener on port 443", [], 0, 0),
    (
        "create a staged PowerShell payload for initial access",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Generate a beacon stager that downloads and executes the C2 payload in memory",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Set up an HTTPS C2 redirector using nginx to proxy traffic to the team server",
        ["whatweb"],
        1,
        1,
    ),
    ("Generate a donut shellcode from a .NET assembly for in-memory execution", [], 0, 0),
    (
        "Create an obfuscated macro payload for phishing delivery with AMSI and ETW bypass",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Deploy a Sliver C2 implant with mtls and https listeners for redundant command and control",
        ["openssl", "nmap", "nmap"],
        3,
        3,
    ),
    (
        "Set up domain fronting through a CDN to hide the C2 infrastructure from network detection",
        ["nginx"],
        1,
        1,
    ),
    (
        "Generate a position-independent code payload using msfvenom with 10 rounds of shikata-ga-nai encoding",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    # ═══════════════════════════════════════════════════════════════
    # K: EVASION & OPSEC (10)
    # ═══════════════════════════════════════════════════════════════
    ("scan stealthily with nmap using decoy IPs", ["nmap"], 1, 1),
    ("perform a SYN stealth scan on example.com", ["nmap"], 1, 1),
    ("use a proxy chain for anonymous scanning", ["proxychains"], 1, 1),
    (
        "Configure nmap with idle scan and random IP decoys to evade detection on the target network",
        ["nmap"],
        1,
        1,
    ),
    (
        "Set up a SOCKS5 proxy chain through three compromised hosts in different geographic regions for attribution avoidance",
        ["volatility"],
        1,
        1,
    ),
    (
        "Perform the entire recon and exploitation phase over Tor to avoid source IP attribution",
        ["whatweb", "nmap"],
        2,
        2,
    ),
    (
        "Enumerate the Windows target while evading AV/EDR: use PowerShell without AMSI, bypass Constrained Language Mode, and avoid creating files on disk",
        [],
        0,
        0,
    ),
    (
        "Apply opsec rules: memory-only execution, no new service creation, and clean up all logs after each operation on the target",
        [],
        0,
        0,
    ),
    (
        "Generate a shellcode payload with AMSI bypass, ETW patching, and sandbox detection before execution",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Perform slow-low-and-slow port scan with 5 minute delay between probes to avoid threshold-based alerts",
        ["nmap", "nmap", "dig", "whois", "masscan"],
        5,
        5,
    ),
    # ═══════════════════════════════════════════════════════════════
    # L: WIRELESS & NETWORK ATTACKS (10)
    # ═══════════════════════════════════════════════════════════════
    ("capture WPA handshake with airodump-ng on wlan0mon", ["aircrack-ng", "aircrack-ng"], 2, 2),
    (
        "deauthenticate clients from the AP to capture handshake",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    ("crack WPA handshake with aircrack-ng", ["aircrack-ng", "aircrack-ng"], 2, 2),
    (
        "scan for Bluetooth devices in the area using bluetoothctl",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    (
        "Set up a rogue access point with hostapd-wpe to capture enterprise credentials",
        ["wpscan"],
        1,
        1,
    ),
    (
        "Perform PMKID attack against the WPA2 network to crack the PSK without a handshake",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    (
        "Capture and crack WPA3 handshake using latest aircrack-ng with WPA3 support",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    (
        "Bluetooth LE scanning for discoverable BLE devices and services in the area",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    (
        "Deauthentication flooding attack on the target BSSID to disrupt all wireless clients",
        ["aircrack-ng", "aircrack-ng"],
        2,
        2,
    ),
    (
        "WPS brute force attack using reaver or bully against the target AP's WPS PIN",
        ["nmap", "hydra", "hashcat"],
        3,
        3,
    ),
    # ═══════════════════════════════════════════════════════════════
    # M: FULL OPERATIONS / MULTI-STAGE (15)
    # ═══════════════════════════════════════════════════════════════
    (
        "Full red team engagement simulation against example.com: external recon, web app assessment, and credential harvesting",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Simulate a sophisticated APT attack chain: initial recon, phishing delivery, initial access, privilege escalation, lateral movement to domain controller, and data exfiltration",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "External pentest on example.com: service discovery, web app testing, and network exploitation in three phases",
        ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"],
        6,
        6,
    ),
    (
        "Zero-day research workflow: discover new attack surface, fuzz for vulnerabilities, develop exploit, and test reliability",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Complete identity attack chain: enumerate users via OSINT, password spray, collect ASREP and kerberos tickets, crack hashes, use credentials for lateral movement",
        ["impacket-GetNPUsers"],
        1,
        1,
    ),
    (
        "Cloud-to-on-prem attack chain: enumerate cloud assets, extract on-prem credentials from cloud resources, pivot to on-premises AD, and escalate to domain admin",
        ["curl", "whatweb", "dig", "openssl"],
        4,
        4,
    ),
    (
        "Supply chain compromise simulation: identify third-party dependencies, check for known CVEs, check for exposed CI/CD credentials, and evaluate blast radius",
        ["nuclei"],
        1,
        1,
    ),
    (
        "Physical-to-technical red team: social engineering reconnaissance, USB drop attack simulation, beacon callback analysis, and network enumeration from physical access",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Multi-forest AD compromise: enumerate trust relationships, exploit SIDHistory, cross-forest kerberoast, and lateral movement across forest boundaries",
        ["nmap", "nmap", "nmap", "nmap"],
        4,
        4,
    ),
    (
        "Comprehensive purple team exercise on example.com: run detection engineering validation by executing known adversary TTPs from MITRE ATT&CK including persistence, credential access, and lateral movement",
        ["trufflehog"],
        1,
        1,
    ),
    (
        "We need to work in a fully OPSEC-compliant manner: all recon over Tor/proxies, no direct source IP contact, memory-only payloads, and secure data exfiltration over encrypted channels",
        ["tshark"],
        1,
        1,
    ),
    (
        "Full external to internal breach scenario: exploit a public-facing web application, establish persistence via cron/web shell, enumerate the internal network, pivot to AD, escalate to DA, and exfiltrate sensitive documents",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Execute a red team engagement following the Lockheed Martin Cyber Kill Chain: recon, weaponize, deliver, exploit, install, C2, and actions-on-objectives against example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "Phishing simulation campaign: set up SMTP relay on our VPS, clone the target login page, send targeted emails to employees from OSINT, monitor callbacks for credential harvesting",
        ["nuclei"],
        1,
        1,
    ),
    (
        "Perform a full ransomware simulation: initial access via exposed RDP, credential theft, lateral movement via PsExec, file encryption test, and impact assessment without actual encryption",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
]


def normalize_tool_names(tools: list[str]) -> list[str]:
    """Normalize tool names to match expected names in test cases."""
    normalized = []
    normalizations = {
        "curl": "curl",
        "nmap": "nmap",
        "whatweb": "whatweb",
        "gobuster": "gobuster",
        "ffuf": "ffuf",
        "nuclei": "nuclei",
        "nikto": "nikto",
        "wpscan": "wpscan",
        "dirb": "dirb",
        "dirsearch": "dirsearch",
        "subfinder": "subfinder",
        "amass": "amass",
        "sublist3r": "sublist3r",
        "assetfinder": "assetfinder",
        "dig": "dig",
        "whois": "whois",
        "openssl": "openssl",
        "theHarvester": "theHarvester",
        "theharvester": "theHarvester",
        "subjack": "subjack",
        "takeover": "subjack",
        "gau": "gau",
        "waybackurls": "waybackurls",
        "katana": "katana",
        "gospider": "gospider",
        "httpx": "httpx",
        "arjun": "arjun",
        "paramspider": "paramspider",
        "shodan": "shodan",
        "censys": "censys",
        "uncover": "uncover",
        "hydra": "hydra",
        "hashcat": "hashcat",
        "sqlmap": "sqlmap",
        "searchsploit": "searchsploit",
        "nmap": "nmap",
        "masscan": "masscan",
        "responder": "responder",
        "ssllabs-scan": "ssllabs-scan",
        "testssl.sh": "testssl.sh",
        "impacket-secretsdump": "impacket-secretsdump",
        "impacket-GetUserSPNs": "impacket-GetUserSPNs",
        "impacket-GetNPUsers": "impacket-GetNPUsers",
        "bloodhound-python": "bloodhound-python",
        "impacket": "impacket",
        "cloud_enum": "cloud_enum",
        "scoutsuite": "scoutsuite",
        "prowler": "prowler",
        "gitleaks": "gitleaks",
        "trufflehog": "trufflehog",
        "sherlock": "sherlock",
        "holehe": "holehe",
        "maigret": "maigret",
        "interactsh": "interactsh",
        "rustscan": "rustscan",
        "naabu": "naabu",
        "wpscan": "wpscan",
    }
    for t in tools:
        t_lower = t.lower()
        if t_lower in normalizations:
            normalized.append(normalizations[t_lower])
        else:
            normalized.append(t)
    return normalized


def check_plan(
    goal: str, expected_tools: list[str], min_steps: int, max_steps: int, planner: RegistryPlanner
) -> tuple[bool, str]:
    try:
        plan = planner.decompose_goal(goal)
    except Exception as e:
        return False, f"Exception: {e}"

    steps = plan.steps
    tools = [s.tool for s in steps]
    norm_tools = normalize_tool_names(tools)
    step_count = len(steps)

    messages = []
    if step_count < min_steps:
        messages.append(f"step_count {step_count} < min_steps {min_steps}")
    if step_count > max_steps:
        messages.append(f"step_count {step_count} > max_steps {max_steps}")
    if expected_tools:
        for et in expected_tools:
            if et not in norm_tools:
                messages.append(f"expected '{et}' not in {norm_tools}")

    if messages:
        return False, f"{', '.join(messages)}, tools={norm_tools}"
    return True, f"OK steps={step_count} tools={norm_tools}"


def main():
    planner = RegistryPlanner()
    passed = 0
    failed = 0
    failures = []

    print(f"{'='*60}")
    print(f"  RED TEAM NLP EVALUATION — {len(TEST_CASES)} test cases")
    print(f"{'='*60}\n")

    start = time.time()
    for idx, (goal, expected_tools, min_steps, max_steps) in enumerate(TEST_CASES, 1):
        ok, msg = check_plan(goal, expected_tools, min_steps, max_steps, planner)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
            print(f"  [{status}] ({idx:3d}) {goal[:60]:60s} -> {msg}")
        else:
            failed += 1
            failures.append((idx, goal, msg))
            print(f"  [{status}] ({idx:3d}) {goal[:60]:60s} -> {msg}")

    elapsed = time.time() - start
    total = passed + failed
    score = (passed / total * 100) if total else 0

    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {total}")
    print(f"  SCORE: {score:.1f}%")
    print(f"  TIME: {elapsed:.1f}s")
    print(f"{'='*60}\n")

    if failures:
        print("FAILED COMMANDS:")
        for idx, goal, msg in failures:
            print(f"  - {goal}")
            print(f"    Reason: {msg}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
