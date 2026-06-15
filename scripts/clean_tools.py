import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

json_path = r"D:\Miraz_Work\siyarix\src\siyarix\data\cyber_tools.json"

with open(json_path, "r", encoding="utf-8") as f:
    tools = json.load(f)

# ── 1. GENERIC UTILITIES TO REMOVE ──────────────────────────────────────────
generic_utilities = {
    # Coreutils / base system
    "kill", "pkill", "pgrep", "pidof", "renice", "nice", "nohup", "taskset",
    "fdisk", "parted", "mkfs", "blkid", "lsblk", "chmod", "chown", "chgrp",
    "date", "cal", "hostname", "uptime", "last", "lastlog", "who", "w", "id",
    "groups", "users", "logname", "finger", "shutdown", "reboot",
    "modprobe", "lsmod", "insmod", "rmmod", "depmod", "sysctl", "udevadm",
    "ltrace", "time", "script", "scriptreplay", "logger",
    "bc", "dc", "expr", "factor", "numfmt", "seq", "yes",
    "tr", "iconv", "expand", "unexpand", "fold", "fmt", "pr", "nl", "od",
    "column", "paste", "join", "comm", "cut", "sort", "uniq", "wc",
    "head", "tail", "less", "tee",
    "mkdir", "cp", "mv", "rm", "ln", "readlink", "realpath",
    "dirname", "basename", "mktemp", "touch", "rename",
    "nproc", "type", "whereis", "locate", "updatedb",
    "mesg", "write", "wall", "pinky", "stdbuf", "env", "printenv", "set",
    # File transfer (generic)
    "scp", "ftp", "lftp", "aria2c", "axel",
    # Filesystem / disk
    "mount", "umount", "df", "du", "stat",
    # System monitoring
    "ps", "top", "sar", "iostat", "vmstat", "mpstat",
    # Network config
    "ip", "route", "ifconfig", "iwconfig", "iwlist", "iw", "ethtool", "nmcli",
    # Hardware / system info
    "uname", "systemctl", "journalctl", "dmesg", "lspci", "lsusb",
    "lscpu", "lshw", "dmidecode", "sensors",
    # Shells / interpreters
    "bash", "powershell", "python", "ruby", "golang",
    # Text editors / viewers
    "nano", "vim",
    # Text processing
    "cat", "find", "grep", "awk", "sed", "xxd", "hexdump", "watch", "file", "which",
    # Compression / archive
    "7z", "gzip", "unzip",
    # Terminal multiplexers
    "screen", "tmux",
    # Process / system monitoring (generic)
    "htop", "iotop", "iperf3", "ncdu", "tree", "bmon", "nload", "iftop", "nethogs",
    "darkstat", "jnettop",
    # Build / dev tools
    "timeout", "xargs", "parallel", "entr", "make", "cmake", "ninja",
    "pkg-config", "patch", "diff", "colordiff",
    # Non-security miscellaneous
    "cockpit", "librecad", "ltp", "neofetch", "ola", "peach", "riak",
    "torbrowser", "virtualbox", "screenedgeutil", "jcat",
    # Generic network monitoring
    "bpf", "libpcap",
    # Database clients (generic)
    "redis-cli", "mongosh", "mysql", "psql", "sqlite3",
    # These are too generic
    "ss", "nmap"  # NO - nmap is essential. Leave it.
}

# Re-add essential ones accidentally included
generic_utilities.discard("nmap")
generic_utilities.discard("strings")  # useful in forensics

# ── 2. TOOLS TO KEEP (overrides - even if name sounds generic) ──────────────
force_keep = {
    "curl", "wget", "jq", "rsync", "ssh", "svn", "gpg", "openssl",
    "strings", "base64", "hashdeep", "dcfldd", "dd",
    "bandit", "gitleaks", "bundle-audit", "depshield",
    "suicide",  # secure deletion wrapper
    "ss",       # socket statistics (useful in network recon)
    "strace",
}

# ── 3. CATEGORY CORRECTIONS ─────────────────────────────────────────────────
category_fixes = {
    "bloodhound": "recon",
    "crackmapexec": "post_exploit",
    "certipy-ad": "exploitation",
    "smbclient": "exploitation",
    "rpcclient": "exploitation",
    "ldapdomaindump": "exploitation",
    "adidnsdump": "exploitation",
    "linpeas": "recon",
    "winpeas": "recon",
    "pspy": "recon",
    "enum4linux-ng": "recon",
    "showmount": "recon",
    "snmp-check": "recon",
    "smb-security-mode": "recon",
    "rdp-sec-check": "recon",
    "ciscot7": "crypto",
    "heartbleed": "network",
    "shellshock": "exploitation",
    "linux-exploit-suggester": "exploitation",
    "windows-exploit-suggester": "exploitation",
    "clamscan": "forensics",
    "freshclam": "utility",
    "stig-viewer": "utility",
    "pop3-bruteforce": "exploitation",
    "imap-bruteforce": "exploitation",
    "cisco-auditing-tool": "network",
    "cisco-scanner": "network",
    "nfs-ls": "recon",
    "rpc-scan": "recon",
    "braa": "network",
    "snmpwalk": "network",
    "snmpbulkwalk": "network",
    "onesixtyone": "network",
    "snmpenum": "network",
    "ossec": "network",
    "bandit": "devsecops",
    "gitleaks": "devsecops",
    "bundle-audit": "devsecops",
    "depshield": "devsecops",
    "s3scanner": "recon",
    "lazys3": "cloud",
    "s3-inspector": "cloud",
    "ssllabs-scan": "crypto",
    "hash-identifier": "crypto",
    "hashid": "crypto",
    "wpscan": "web",
    "joomscan": "web",
    "wafw00f": "web",
    "docker": "container",
    "docker-bench-security": "container",
    "rkhunter": "forensics",
    "chkrootkit": "forensics",
}

# ── 4. DATA ERROR FIXES ─────────────────────────────────────────────────────
risk_level_fixes = {
    "snmpwalk": "low",
    "nbtscan": "low",
    "smbclient": "medium",
    "rpcclient": "medium",
    "ldapdomaindump": "high",
    "adidnsdump": "high",
}

# ── 5. DUPLICATES TO REMOVE ─────────────────────────────────────────────────
duplicates_to_remove = {
    "hashid",          # duplicate of hash-identifier
    "searchsploit",    # duplicate of exploitdb
    "proxychains4",    # duplicate of proxychains
    "reaver-wps",      # duplicate of reaver
    "az-cli",          # duplicate of az
    "gcloud-cli",      # duplicate of gcloud
    "veil-evasion",    # sub-component of veil
    "samba",           # generic SMB implementation, not a security tool
}

# ── 6. MISSING TOOLS TO ADD ─────────────────────────────────────────────────
missing_tools = {
    # Reconnaissance
    "aquatone": {
        "name": "aquatone", "category": "recon",
        "description": "Visual web page screenshot and inspection tool",
        "risk_level": "low", "aliases": [], "binary": "aquatone",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "eyewitness": {
        "name": "eyewitness", "category": "recon",
        "description": "Web application screenshot and discovery tool",
        "risk_level": "low", "aliases": [], "binary": "eyewitness",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "trufflehog": {
        "name": "trufflehog", "category": "devsecops",
        "description": "Secrets scanning across git repositories and filesystems",
        "risk_level": "low", "aliases": [], "binary": "trufflehog",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam", "devsecops"]
    },
    "metagoofil": {
        "name": "metagoofil", "category": "recon",
        "description": "Metadata extraction and document analysis tool",
        "risk_level": "low", "aliases": [], "binary": "metagoofil",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "dmitry": {
        "name": "dmitry", "category": "recon",
        "description": "Deepmagic Information Gathering - domain, whois, and subdomain enumeration",
        "risk_level": "low", "aliases": [], "binary": "dmitry",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "reconftw": {
        "name": "reconftw", "category": "recon",
        "description": "All-in-one reconnaissance framework with multiple subdomain tools",
        "risk_level": "low", "aliases": [], "binary": "reconftw",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    # Exploitation
    "ysoserial": {
        "name": "ysoserial", "category": "exploitation",
        "description": "Java deserialization payload generator for security testing",
        "risk_level": "critical", "aliases": [], "binary": "ysoserial",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "sliver": {
        "name": "sliver", "category": "exploitation",
        "description": "Modern cross-platform C2 framework by BishopFox",
        "risk_level": "critical", "aliases": [], "binary": "sliver",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "mythic": {
        "name": "mythic", "category": "exploitation",
        "description": "Cross-platform post-exploitation C2 framework with web UI",
        "risk_level": "critical", "aliases": [], "binary": "mythic",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "donut": {
        "name": "donut", "category": "exploitation",
        "description": "Shellcode generator for .NET and PE file injection",
        "risk_level": "critical", "aliases": [], "binary": "donut",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "covenant": {
        "name": "covenant", "category": "exploitation",
        "description": ".NET command and control framework for red team operations",
        "risk_level": "critical", "aliases": [], "binary": "covenant",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    # Network / Wireless
    "zmap": {
        "name": "zmap", "category": "network",
        "description": "Internet-wide port scanner for large-scale network discovery",
        "risk_level": "medium", "aliases": [], "binary": "zmap",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "zgrab": {
        "name": "zgrab", "category": "network",
        "description": "Application layer protocol scanner for banner grabbing",
        "risk_level": "low", "aliases": [], "binary": "zgrab",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "wifiphisher": {
        "name": "wifiphisher", "category": "network",
        "description": "Evil twin WiFi phishing framework for security testing",
        "risk_level": "high", "aliases": [], "binary": "wifiphisher",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "yersinia": {
        "name": "yersinia", "category": "network",
        "description": "Layer 2 network attack framework - CDP, STP, DTP, VLAN hopping",
        "risk_level": "high", "aliases": [], "binary": "yersinia",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "arping": {
        "name": "arping", "category": "network",
        "description": "ARP-level ping for host discovery on local networks",
        "risk_level": "low", "aliases": [], "binary": "arping",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam", "blueteam"]
    },
    # Password / Crypto
    "crunch": {
        "name": "crunch", "category": "crypto",
        "description": "Wordlist generator for password cracking and dictionary attacks",
        "risk_level": "medium", "aliases": [], "binary": "crunch",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "ophcrack": {
        "name": "ophcrack", "category": "crypto",
        "description": "Windows password cracker using LM/NTLM hashes and rainbow tables",
        "risk_level": "high", "aliases": [], "binary": "ophcrack",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "pypykatz": {
        "name": "pypykatz", "category": "crypto",
        "description": "Python implementation of Mimikatz for credential extraction",
        "risk_level": "critical", "aliases": [], "binary": "pypykatz",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam", "forensics"]
    },
    "samdump2": {
        "name": "samdump2", "category": "crypto",
        "description": "Windows SAM registry hive hash extraction tool",
        "risk_level": "high", "aliases": [], "binary": "samdump2",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    # Web Application
    "arjun": {
        "name": "arjun", "category": "web",
        "description": "HTTP parameter discovery and brute-forcing tool",
        "risk_level": "low", "aliases": [], "binary": "arjun",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "interactsh": {
        "name": "interactsh", "category": "web",
        "description": "OOB interaction and callback server for blind vulnerabilities",
        "risk_level": "low", "aliases": [], "binary": "interactsh",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    # Cloud
    "stratus-red-team": {
        "name": "stratus-red-team", "category": "cloud",
        "description": "Cloud attack simulation tool for AWS/Azure/GCP",
        "risk_level": "high", "aliases": [], "binary": "stratus-red-team",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam", "cloud"]
    },
    "cloudsplaining": {
        "name": "cloudsplaining", "category": "cloud",
        "description": "AWS IAM privilege escalation and policy analysis scanner",
        "risk_level": "medium", "aliases": [], "binary": "cloudsplaining",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "devsecops", "cloud"]
    },
    "peirates": {
        "name": "peirates", "category": "container",
        "description": "Kubernetes penetration testing and privilege escalation tool",
        "risk_level": "critical", "aliases": [], "binary": "peirates",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam", "cloud"]
    },
    # Forensics
    "velociraptor": {
        "name": "velociraptor", "category": "forensics",
        "description": "Endpoint visibility, digital forensics, and incident response platform",
        "risk_level": "low", "aliases": [], "binary": "velociraptor",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["forensics", "blueteam"]
    },
    "hayabusa": {
        "name": "hayabusa", "category": "forensics",
        "description": "Fast Windows event log forensics and threat hunting tool",
        "risk_level": "low", "aliases": [], "binary": "hayabusa",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["forensics", "blueteam"]
    },
    "chainsaw": {
        "name": "chainsaw", "category": "forensics",
        "description": "Windows event log hunting and analysis with Sigma rules",
        "risk_level": "low", "aliases": [], "binary": "chainsaw",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["forensics", "blueteam"]
    },
    # DevSecOps / SAST
    "snyk": {
        "name": "snyk", "category": "devsecops",
        "description": "Developer-first dependency vulnerability scanning and fix tool",
        "risk_level": "low", "aliases": [], "binary": "snyk",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["devsecops", "blueteam"]
    },
    "checkov": {
        "name": "checkov", "category": "devsecops",
        "description": "Infrastructure as Code static analysis for security misconfigurations",
        "risk_level": "low", "aliases": [], "binary": "checkov",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["devsecops", "cloud"]
    },
    "semgrep": {
        "name": "semgrep", "category": "devsecops",
        "description": "Static analysis security testing for code and infrastructure",
        "risk_level": "low", "aliases": [], "binary": "semgrep",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["devsecops", "blueteam"]
    },
    "kubescape": {
        "name": "kubescape", "category": "container",
        "description": "Kubernetes security and compliance scanner",
        "risk_level": "low", "aliases": [], "binary": "kubescape",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["devsecops", "blueteam", "cloud"]
    },
    # Tunneling / Pivoting
    "dns2tcp": {
        "name": "dns2tcp", "category": "network",
        "description": "DNS tunneling tool for exfiltration and C2 communication",
        "risk_level": "high", "aliases": [], "binary": "dns2tcp",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "iodine": {
        "name": "iodine", "category": "network",
        "description": "IPv4 over DNS tunnel for bypassing network restrictions",
        "risk_level": "high", "aliases": [], "binary": "iodine",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "ptunnel": {
        "name": "ptunnel", "category": "network",
        "description": "ICMP tunnel for covert data exfiltration",
        "risk_level": "high", "aliases": [], "binary": "ptunnel",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "proxytunnel": {
        "name": "proxytunnel", "category": "network",
        "description": "SSH proxy tunnel for HTTP CONNECT proxies",
        "risk_level": "medium", "aliases": [], "binary": "proxytunnel",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    # Additional Kali essentials
    "isr-evilgrade": {
        "name": "isr-evilgrade", "category": "exploitation",
        "description": "Fake update server framework for MITM attacks",
        "risk_level": "critical", "aliases": [], "binary": "isr-evilgrade",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
    "backdoor-factory": {
        "name": "backdoor-factory", "category": "exploitation",
        "description": "PE binary backdoor injection and shellcode patching",
        "risk_level": "critical", "aliases": [], "binary": "backdoor-factory",
        "version_args": ["--version"], "version_pattern": "",
        "personas": ["pentester", "redteam"]
    },
}

# ── APPLY TRANSFORMATIONS ───────────────────────────────────────────────────

# Track removed tools for reporting
removed = []
fixed_categories = []
fixed_risk_levels = []
added = []
kept_override = []

# Filter out generic utilities (unless in force_keep)
filtered = {}
for key, val in tools.items():
    if key in duplicates_to_remove:
        removed.append(f"duplicate:{key}")
        continue
    if key in generic_utilities and key not in force_keep:
        removed.append(f"generic:{key}")
        continue
    if key in force_keep:
        kept_override.append(key)
    filtered[key] = val

# Apply category fixes
for key, new_cat in category_fixes.items():
    if key in filtered:
        old = filtered[key].get("category", "?")
        filtered[key]["category"] = new_cat
        fixed_categories.append(f"{key}: {old} → {new_cat}")

# Apply risk_level fixes
for key, new_rl in risk_level_fixes.items():
    if key in filtered:
        old = filtered[key].get("risk_level", "?")
        filtered[key]["risk_level"] = new_rl
        fixed_risk_levels.append(f"{key}: {old} → {new_rl}")

# Add missing tools
for key, val in missing_tools.items():
    if key not in filtered:
        filtered[key] = val
        added.append(key)

# ── WRITE OUTPUT ────────────────────────────────────────────────────────────
output_path = json_path  # overwrite in place

# Sort keys for consistent output
sorted_tools = dict(sorted(filtered.items()))

with open(output_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(sorted_tools, f, indent=2, ensure_ascii=False)

# ── REPORT ──────────────────────────────────────────────────────────────────
print("=== Cleanup Complete ===")
print(f"Tools removed:          {len(removed)}")
for r in removed:
    print(f"  - {r}")
print(f"Categories fixed:       {len(fixed_categories)}")
for f in fixed_categories:
    print(f"  - {f}")
print(f"Risk levels fixed:      {len(fixed_risk_levels)}")
for f in fixed_risk_levels:
    print(f"  - {f}")
print(f"Tools added:            {len(added)}")
for a in added:
    print(f"  + {a} ({missing_tools[a]['category']})")
print(f"Kept despite generic:   {len(kept_override)}")
for k in kept_override:
    print(f"  ~ {k}")
print(f"\nFinal tool count: {len(sorted_tools)}")
