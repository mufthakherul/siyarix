# SPDX-License-Identifier: AGPL-3.0-or-later
"""Natural Language Processing Engine for Offline Heuristic Planning.

Provides advanced intent scoring, entity extraction, semantic parameter
extraction, and TF-IDF based keyword weighting without heavy machine learning dependencies.
"""

from __future__ import annotations

import re
import math
import difflib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedIntent:
    target: str = ""
    target_type: str = ""  # e.g., 'url', 'ipv4', 'domain', 'email', 'mac'
    tool_name: str | None = None
    template_name: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    tokens: list[str] = field(default_factory=list)
    raw_text: str = ""
    all_entities: dict[str, list[str]] = field(default_factory=dict)
    negated: bool = False
    conjunctive_goal: bool = False
    normalized_confidence: float = 0.0


class NaturalLanguageParser:
    """An advanced, zero-dependency NLP engine for intent mapping and semantic parsing."""

    # Comprehensive English stopwords to filter out noise
    STOPWORDS: frozenset[str] = frozenset(
        {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "from",
            "up",
            "about",
            "into",
            "over",
            "after",
            "please",
            "can",
            "you",
            "do",
            "i",
            "want",
            "need",
            "could",
            "would",
            "run",
            "execute",
            "perform",
            "start",
            "initiate",
            "make",
            "give",
            "me",
            "show",
            "find",
            "get",
            "tell",
            "is",
            "are",
            "was",
            "were",
            "be",
            "been",
            "have",
            "has",
            "had",
            "what",
            "which",
            "who",
            "where",
            "why",
            "how",
            "all",
            "any",
            "some",
            "every",
            "just",
            "now",
            "then",
            "like",
        }
    )

    # Regex patterns for Entity Extraction
    PATTERNS = {
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
        "aws_s3": r"\b(?:[a-zA-Z0-9.\-_]{3,63}\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)\b",
        "azure_blob": r"\b(?:[a-z0-9]{3,24}\.blob\.core\.windows\.net)\b",
        "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
        "cidr": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-2]?[0-9]|3[0-2])\b",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "mac": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
        "sha256": r"\b[A-Fa-f0-9]{64}\b",
        "sha1": r"\b[A-Fa-f0-9]{40}\b",
        "md5": r"\b[A-Fa-f0-9]{32}\b",
        "asn": r"\bAS\d{1,6}\b",
        "windows_path": r"\b[a-zA-Z]:\\[^:\*\?\"<>\|\s]+\b",
        "linux_path": r"(?<!\w)(?:/[a-zA-Z0-9_\-\.]+)+\b",
        "github_repo": r"\b(?:https?://github\.com/)?(?:[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)\b",
        "ntlm": r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b",
        "gcp_bucket": r"\b(?:[a-z0-9\-_]{3,63}\.storage\.googleapis\.com)\b",
    }

    # Suffixes for lightweight stemming - ordered longest to shortest to prevent over-stemming
    SUFFIXES = [
        "ation",
        "tion",
        "ness",
        "ment",
        "able",
        "ible",
        "ity",
        "ing",
        "ly",
        "ed",
        "es",
        "s",
    ]

    # PHRASE_SYNONYMS applied before tokenization
    PHRASE_SYNONYMS: dict[str, str] = {
        "pass the hash": "pth",
        "pass the ticket": "ptt",
        "pass-the-hash": "pth",
        "pass-the-ticket": "ptt",
        "living off the land": "lolbas",
        "living-off-the-land": "lolbas",
        "golden ticket": "golden_ticket",
        "silver ticket": "silver_ticket",
        "diamond ticket": "diamond_ticket",
        "lateral movement": "pivoting",
        "privilege escalation": "privesc",
        "command and control": "c2",
        "out of band": "oob",
        "out-of-band": "oob",
        "man in the middle": "mitm",
        "man-in-the-middle": "mitm",
        "denial of service": "dos",
        "sql injection": "sqli",
        "cross site scripting": "xss",
        "cross-site scripting": "xss",
        "remote code execution": "rce",
        "local file inclusion": "lfi",
        "remote file inclusion": "rfi",
        "server side request forgery": "ssrf",
        "server-side request forgery": "ssrf",
        "insecure direct object reference": "idor",
        "security misconfiguration": "misconfig",
        "broken access control": "bac",
        "open redirect": "redirect",
        "evil twin": "evil_twin",
        "rogue ap": "evil_twin",
        "rogue access point": "evil_twin",
        "spear phishing": "spearphish",
        "supply chain": "supplychain",
        "dependency confusion": "depconfusion",
        "token impersonation": "token_impersonation",
        "process injection": "injection",
        "code injection": "injection",
        "heap spray": "heapspray",
        "rop chain": "ropchain",
        "format string": "formatstring",
        "use after free": "uaf",
        "buffer overflow": "bof",
        "stack overflow": "bof",
        "integer overflow": "intoverflow",
        "type confusion": "typeconfusion",
        "race condition": "racecondition",
        "time of check": "toctou",
        "atomic red team": "art",
        "attack simulation": "purpleteam",
        "threat hunting": "threathunting",
        "incident response": "ir",
        "azure active directory": "azuread",
        "azure ad": "azuread",
        "active directory": "activedirectory",
        "domain controller": "dc",
        "service principal": "sp",
        "managed identity": "managedidentity",
        "kubernetes attack": "k8s_attack",
        "container escape": "containerescape",
        "firmware analysis": "firmware",
        "iot device": "iot",
        "ics network": "ics",
        "scada system": "scada",
        "ssl pinning": "sslpinning",
        "certificate pinning": "sslpinning",
        "root detection": "rootdetection",
        "jailbreak detection": "jailbreakdetection",
        "amsi bypass": "amsibypass",
        "etw bypass": "etwbypass",
        "av bypass": "avbypass",
        "edr bypass": "edrbypass",
        "defense evasion": "evasion",
        "dns exfiltration": "dnsexfil",
        "icmp tunnel": "icmptunnel",
        "covert channel": "covertchannel",
        "bug bounty": "bugbounty",
        "responsible disclosure": "bugbounty",
        "capture the flag": "ctf",
        "padding oracle": "paddingoracle",
        "hash cracking": "hashcrack",
        "rainbow table": "rainbowtable",
    }

    # Extended Ontology mapping synonyms to canonical forms (including MITRE tactics)
    DEFAULT_SYNONYMS = {
        "bug": "vuln",
        "cve": "vuln",
        "exploit": "vuln",
        "hack": "vuln",
        "weakness": "vuln",
        "flaw": "vuln",
        "dirbust": "directory",
        "enum": "enumeration",
        "discover": "recon",
        "subdomain": "recon",
        "passwords": "brute",  # pragma: allowlist secret
        "creds": "brute",
        "credentials": "brute",
        "sql": "sqli",
        "injection": "sqli",
        "xss": "cross-site",
        "mitm": "intercept",
        "sniff": "intercept",
        "phish": "social",
        # MITRE ATT&CK & Advanced Slang mappings
        "reconnaissance": "recon",
        "weaponize": "exploit",
        "delivery": "phish",
        "lateral": "pivoting",
        "movement": "pivoting",
        "exfiltration": "exfil",
        "dump": "brute",
        "hashdump": "brute",
        "privesc": "escalation",
        "osint": "recon",
        "fuzz": "fuzzing",
        "dos": "denial",
        "ddos": "denial",
        "sam": "credentials",
        "ntds": "credentials",
        "lsass": "credentials",
        "rce": "exploit",
        "shell": "exploit",
        "root": "escalation",
        "system": "escalation",
        "smb": "smb",
        "rdp": "rdp",
        "ssh": "ssh",
        "ftp": "ftp",
        "dns": "dns",
        "header": "headers",
        "tech": "technology",
        "os": "operating_system",
        "mail": "email",
        "mx": "dns",
        "txt": "dns",
        "soa": "dns",
        "api": "endpoint",
        "rest": "endpoint",
        "container": "docker",
        "kubernetes": "k8s",
        "kube": "k8s",
        "waf": "firewall",
        "proxy": "network",
        "vpn": "network",
        "firewall": "acl",
        "acl": "acl",
        "cert": "tls",
        "certificate": "tls",
        "cloudfront": "cdn",
        "cdn": "cdn",
        "loadbalancer": "lb",
        "git": "vcs",
        "jenkins": "ci",
        "ci": "ci",
        "jira": "ticket",
        "confluence": "wiki",
        "ldap": "ldap",
        "ntlm": "ntlm",
        "kerberos": "kerberos",
        "ad": "activedirectory",
        "bust": "dirbust",
        "busting": "dirbust",
        "log4j": "cve",
        "log4shell": "cve",
        "heartbleed": "cve",
        "shellshock": "cve",
        "shellsock": "cve",
        "spring4shell": "cve",
        "springshell": "cve",
        "struts": "cve",
        "traceroute": "tracert",
        "tracert": "tracert",
        "wpa": "wifi",
        "wpa2": "wifi",
        "wep": "wifi",
        "handshake": "wifi",
        "beacon": "wifi",
        "wireless": "wifi",
        "bloodhound": "activedirectory",
        "responder": "activedirectory",
        "impacket": "activedirectory",
        "zerologon": "activedirectory",
        "petitpotam": "activedirectory",
        "ntlmrelay": "activedirectory",
        "dcsync": "activedirectory",
        "golden ticket": "activedirectory",
        "silver ticket": "activedirectory",
        "pass the hash": "pth",
        "pth": "pth",
        "overpass": "activedirectory",
        "kerberoast": "activedirectory",
        "asrep": "activedirectory",
        "ipmi": "bmc",
        "bmc": "bmc",
        "snmp": "snmp",
        "smtp": "email",
        "imap": "email",
        "pop3": "email",
        "wordpress": "cms",
        "joomla": "cms",
        "drupal": "cms",
        "magento": "cms",
        "tomcat": "web_server",
        "iis": "web_server",
        "nginx": "web_server",
        "apache": "web_server",
        "s3": "cloud",
        "ec2": "cloud",
        "lambda": "cloud",
        "cloudformation": "cloud",
        "k8s": "kubernetes",
        "pod": "kubernetes",
        "compose": "docker",
        "dockerfile": "docker",
        "esxi": "vmware",
        "vcenter": "vmware",
        "vsphere": "vmware",
        "vmware": "vmware",
        "virtualbox": "hypervisor",
        "hyperv": "hypervisor",
        "qemu": "hypervisor",
        "redis": "database",
        "mongodb": "database",
        "mysql": "database",
        "mariadb": "database",
        "postgres": "database",
        "postgresql": "database",
        "mssql": "database",
        "cassandra": "database",
        "elasticsearch": "elastic",
        "memcached": "cache",
        "varnish": "cache",
        "rabbitmq": "queue",
        "activemq": "queue",
        "kafka": "queue",
        "graphql": "api",
        "swagger": "api",
        "openapi": "api",
        "restapi": "api",
        "soap": "api",
        "grpc": "api",
        "websocket": "api",
        "oauth": "auth",
        "saml": "auth",
        "jwt": "auth",
        # Recon & OSINT tools
        "shodan": "shodan",
        "censys": "censys",
        "crtsh": "crtsh",
        "certificate_transparency": "crtsh",
        "theharvester": "osint",
        "the harvester": "osint",
        "gau": "wayback",
        "wayback": "wayback",
        "waybackurls": "wayback",
        "httpx": "httpx",
        "probe": "httpx",
        "katana": "crawler",
        "crawler": "crawler",
        "spider": "crawler",
        "gospider": "crawler",
        "uncover": "uncover",
        "subjack": "takeover",
        "subdomain_takeover": "takeover",
        "trufflehog": "secrets",
        "gitleaks": "secrets",
        "secret_scan": "secrets",  # pragma: allowlist secret
        "sherlock": "username",
        "holehe": "osint",
        "maigret": "username",
        "social": "username",
        "dnsx": "dns",
        "massdns": "dns",
        "puredns": "dns",
        "dnsvalidator": "dns",
        "arjun": "parameter",
        "paramspider": "parameter",
        "param_discovery": "parameter",
        "cloud_enum": "cloud",
        "scoutsuite": "cloud",
        "prowler": "cloud",
        "cloudmapper": "cloud",
        "interactsh": "oob",
        "oob": "oob",
        "collaborator": "oob",
        "notify": "notification",
        "chaos": "dns_dataset",
        "dns_dataset": "dns_dataset",
        "alterx": "subdomain_permute",
        "permutation": "subdomain_permute",
        "ffuf": "fuzzing",
        "gobuster": "directory",
        "dirsearch": "directory",
        "dirb": "directory",
        "jsubfinder": "javascript",
        "subjs": "javascript",
        "linkfinder": "javascript",
        "js": "javascript",
        "waymore": "wayback",
        "uro": "url_filter",
        "qsreplace": "parameter",
        "kxss": "xss",
        "dalfox": "xss",
        "pwncat": "shell",
        "metasploit": "exploit",
        "msf": "exploit",
        "empire": "exploit",
        "covenant": "exploit",
        "mythic": "exploit",
        "sliver": "exploit",
        "havoc": "exploit",
        "bruteratel": "exploit",
        "nishang": "exploit",
        "powerview": "activedirectory",
        "crackmapexec": "activedirectory",
        "cme": "activedirectory",
        "netexec": "activedirectory",
        "nxc": "activedirectory",
        "ldapdomaindump": "activedirectory",
        "adidnsdump": "activedirectory",
        "gpppassword": "activedirectory",  # pragma: allowlist secret
        "group3r": "activedirectory",
        "pingcastle": "activedirectory",
        "purpleknight": "activedirectory",
        "certipy": "activedirectory",
        "adcs": "activedirectory",
        "esc1": "activedirectory",
        "esc8": "activedirectory",
        "coerce": "activedirectory",
        "shadowcred": "activedirectory",
        "rbcd": "activedirectory",
        "delegation": "activedirectory",
        "constrained_delegation": "activedirectory",
        "unconstrained_delegation": "activedirectory",
        "resource_based_delegation": "activedirectory",
        "dcenum": "activedirectory",
        "enum4linux": "activedirectory",
        "enum4linux-ng": "activedirectory",
        "ldapsearch": "activedirectory",
        "samba": "smb",
        "wmiexec": "activedirectory",
        "wmic": "activedirectory",
        "psexec": "activedirectory",
        "smbexec": "activedirectory",
        "atexec": "activedirectory",
        "dcomexec": "activedirectory",
        "secretsdump": "activedirectory",  # pragma: allowlist secret
        "ticketer": "activedirectory",
        "goldenticket": "activedirectory",
        "silver_ticket": "activedirectory",
        "diamond_ticket": "activedirectory",
        "sapphire_ticket": "activedirectory",
        "skeleton_key": "activedirectory",
        "dsync": "activedirectory",
        "gmsa": "activedirectory",
        "gmsapassword": "activedirectory",  # pragma: allowlist secret
        "lapspassword": "activedirectory",  # pragma: allowlist secret
        "laps": "activedirectory",
        "krbtgt": "activedirectory",
        "ntds_dit": "activedirectory",
        "domain_backup": "activedirectory",
        "domain_exfiltration": "activedirectory",
        "aclpwn": "activedirectory",
        "smbmap": "smb",
        "smbclient": "smb",
        "rpcclient": "activedirectory",
        "rpcdump": "activedirectory",
        "snmpenum": "snmp",
        "snmpscan": "snmp",
        "snmplist": "snmp",
        "snmpwalk": "snmp",
        "onesixtyone": "snmp",
        "ike": "vpn",
        "ike_scan": "vpn",
        "ipsec": "vpn",
        "cisco_scan": "network",
        "cdp": "network",
        "lldp": "network",
        "stp": "network",
        "dtls": "tls",
        "starttls": "tls",
        "srvinfo": "smb",
        "nbtscan": "netbios",
        "netbios": "netbios",
        "nbtstat": "netbios",
        "nmap_vulners": "vuln",
        "vulscan": "vuln",
        "vulners": "vuln",
        "amass": "recon",
        "assetfinder": "recon",
        "sublist3r": "recon",
        "findomain": "recon",
        "domain": "recon",
        "subfinder": "recon",
        "recon-ng": "recon",
        "reconftw": "recon",
        "lazyrecon": "recon",
        "bbrf": "recon",
        "projectdiscovery": "recon",
        "pd": "recon",
        # Post-Exploitation / C2
        "shellcode": "exploit",
        "payload": "exploit",
        "stager": "exploit",
        "dropper": "exploit",
        "loader": "exploit",
        "implant": "c2",
        "agent": "c2",
        "listener": "c2",
        "handler": "c2",
        "meterpreter": "exploit",
        # Privilege Escalation
        "winpeas": "winpeas",
        "linpeas": "linpeas",
        "powerup": "winpeas",
        "seatbelt": "winpeas",
        "sharpup": "winpeas",
        "juicypotato": "winpeas",
        "roguewinrm": "winpeas",
        "printspoofer": "winpeas",
        "godpotato": "winpeas",
        "seimpersonateprivilege": "winpeas",
        "sweetpotato": "winpeas",
        "tokenvator": "winpeas",
        "incognito": "winpeas",
        "capabilities": "linpeas",
        "linenum": "linpeas",
        "pspy": "linpeas",
        "gtfobins": "linpeas",
        "lolbas": "lolbas",
        "lolbin": "lolbas",
        # Lateral Movement
        "chisel": "pivoting",
        "ligolo": "pivoting",
        "socat": "pivoting",
        "proxychains": "pivoting",
        "socks5": "pivoting",
        "plink": "pivoting",
        "stunnel": "pivoting",
        # Persistence
        "backdoor": "persistence",
        "rootkit": "persistence",
        "webshell": "persistence",
        "crontab": "persistence",
        "autoruns": "persistence",
        "regrun": "persistence",
        # Defense Evasion
        "amsi": "evasion",
        "etw": "evasion",
        "obfuscate": "evasion",
        "veil": "evasion",
        "shellter": "evasion",
        "donut": "evasion",
        "srdi": "evasion",
        # Exfiltration
        "exfil": "exfiltration",
        "dnsexfil": "exfiltration",
        "icmptunnel": "exfiltration",
        "covertchannel": "exfiltration",
        "iodine": "exfiltration",
        # Social Engineering
        "spearphish": "phishing",
        "vish": "phishing",
        "smish": "phishing",
        "pretexting": "phishing",
        "gophish": "phishing",
        "evilginx": "phishing",
        "modlishka": "phishing",
        "setools": "phishing",
        # IoT / Embedded
        "firmware": "iot",
        "jtag": "iot",
        "uart": "iot",
        "bootloader": "iot",
        "flashrom": "iot",
        "openocd": "iot",
        "avrdude": "iot",
        "i2c": "iot",
        "spi": "iot",
        "firmwalker": "iot",
        "unblob": "iot",
        # OT / ICS / SCADA
        "modbus": "ics",
        "dnp3": "ics",
        "profibus": "ics",
        "profinet": "ics",
        "plc": "ics",
        "hmi": "ics",
        "mbtget": "ics",
        "plcscan": "ics",
        # Mobile
        "apk": "android",
        "adb": "android",
        "frida": "mobile",
        "objection": "mobile",
        "mobsf": "mobile",
        "apkleaks": "android",
        "jadx": "android",
        "dex2jar": "android",
        "apkid": "android",
        "ipa": "ios",
        "idb": "ios",
        "clutch": "ios",
        "cycript": "ios",
        "sslpinning": "mobile",
        "jailbreak": "ios",
        "rootdetection": "android",
        # Cloud Attack
        "azuread": "cloud",
        "aadinternals": "cloud",
        "powerzure": "cloud",
        "roadtools": "cloud",
        "stormspotter": "cloud",
        "azurehound": "cloud",
        "microburst": "cloud",
        "gcpbucketbrute": "cloud",
        "imds": "cloud",
        "metadata_service": "cloud",
        # Kubernetes / Container
        "containerescape": "kubernetes",
        "cdk": "kubernetes",
        "kubesec": "kubernetes",
        "kube-hunter": "kubernetes",
        "kube-bench": "kubernetes",
        "etcd": "kubernetes",
        "rbac": "kubernetes",
        # Cryptography / CTF
        "hashcrack": "crypto",
        "rainbowtable": "crypto",
        "rsactftool": "crypto",
        "paddingoracle": "crypto",
        "xorcrack": "crypto",
        "hashid": "crypto",
        "nth": "crypto",
        # CTF Pwn
        "pwn": "pwn",
        "ropchain": "pwn",
        "heapspray": "pwn",
        "bof": "pwn",
        "pwndbg": "pwn",
        "ropgadget": "pwn",
        "pwntools": "pwn",
        "checksec": "pwn",
        "gef": "pwn",
        "peda": "pwn",
        "formatstring": "pwn",
        "uaf": "pwn",
        # CTF Steganography / Forensics
        "steghide": "stego",
        "stegcracker": "stego",
        "zsteg": "stego",
        "stegsolve": "stego",
        "outguess": "stego",
        "steganography": "stego",
        # Purple Team / Threat Intel
        "art": "purpleteam",
        "caldera": "purpleteam",
        "vectr": "purpleteam",
        "mitre": "purpleteam",
        "ttp": "purpleteam",
        "ioc": "threathunting",
        "edr": "threathunting",
        "xdr": "threathunting",
        "soar": "threathunting",
        "soc": "threathunting",
        "playbook": "threathunting",
        "threathunting": "threathunting",
        # Bug Bounty
        "bugbounty": "bugbounty",
        "vdp": "bugbounty",
        "hackerone": "bugbounty",
        "bugcrowd": "bugbounty",
        # Wireless extensions
        "pmkid": "wifi",
        "evil_twin": "wifi",
        "hcxtools": "wifi",
        "wifite": "wifi",
        "kismet": "wifi",
        "bettercap": "wifi",
        "hostapd": "wifi",
        "ble": "bluetooth",
        "zigbee": "iot",
        "zwave": "iot",
        "nfc": "rfid",
        "rfid": "rfid",
        # Cryptography
        "padbuster": "crypto",
        "john": "hashcrack",
        "cewl": "wordlist",
        "crunch": "wordlist",
        "swaks": "phishing",
        "dnscat": "exfiltration",
        "dnscat2": "exfiltration",
        "ptunnel": "exfiltration",
        "weevely": "webshell",
        "rubeus": "activedirectory",
        "mimikatz": "activedirectory",
        "pypykatz": "activedirectory",
        "nanodump": "activedirectory",
        "lsassy": "activedirectory",
        "msfvenom": "exploit",
        "msfconsole": "exploit",
        "villain": "exploit",
        "scythe": "exploit",
        "nighthawk": "exploit",
        "deimos": "exploit",
        "xfreerdp": "rdp",
        "rdesktop": "rdp",
        "pip-audit": "supplychain",
        "confused": "supplychain",
        "supplychain": "supplychain",
        "depconfusion": "supplychain",
    }

    def __init__(self, custom_synonyms: dict[str, str] | None = None) -> None:
        self._tool_corpus: dict[str, list[str]] = {}
        self._template_corpus: dict[str, list[str]] = {}

        # IDF (Inverse Document Frequency) components
        self._doc_frequencies: dict[str, int] = defaultdict(int)
        self._total_docs: int = 0

        self.synonyms = self.DEFAULT_SYNONYMS.copy()
        if custom_synonyms:
            self.synonyms.update(custom_synonyms)

        self._tokenize_cache: dict[str, list[str]] = {}

    def _recalculate_idf(self) -> None:
        """Calculate document frequencies for IDF weighting."""
        self._doc_frequencies.clear()
        self._total_docs = len(self._tool_corpus) + len(self._template_corpus)

        for tokens in self._tool_corpus.values():
            for t in set(tokens):
                self._doc_frequencies[t] += 1

        for tokens in self._template_corpus.values():
            for t in set(tokens):
                self._doc_frequencies[t] += 1

    def train_tools(self, tools_metadata: list[dict[str, Any]]) -> None:
        """Feed tool descriptions to the parser to build semantic corpus."""
        for t in tools_metadata:
            name = t.get("name", "")
            desc = t.get("description", "")
            tags = " ".join(t.get("tags", []))
            category = str(t.get("category", ""))
            # Combine all semantic clues
            text = f"{name} {desc} {tags} {category}".lower()
            self._tool_corpus[name] = self.tokenize(text)
        self._recalculate_idf()

    def train_templates(self, templates_metadata: dict[str, str]) -> None:
        """Feed workflow templates to the parser."""
        for name, desc in templates_metadata.items():
            text = f"{name.replace('_', ' ')} {desc}".lower()
            self._template_corpus[name] = self.tokenize(text)
        self._recalculate_idf()

    # ── CLS injection API ───────────────────────────────────────────────

    def inject_learned_synonyms(self, synonyms: dict[str, str]) -> None:
        """Merge CLS-learned keyword→tool mappings into the active synonym map.

        New synonyms take precedence only if the key is not already defined
        by the hard-coded :attr:`DEFAULT_SYNONYMS` table so that the core NLP
        vocabulary is never overwritten by learned data.
        """
        for keyword, canonical in synonyms.items():
            if keyword and canonical and keyword not in self.DEFAULT_SYNONYMS:
                self.synonyms[keyword] = canonical

    def inject_learned_corpus(self, skill_id: str, intent_pattern: str, tokens: list[str]) -> None:
        """Add a CLS-learned skill pattern as a corpus document for intent scoring.

        The pattern is stored under a ``__cls_<skill_id>`` key so it does not
        conflict with tool or template entries. IDF weights are recalculated
        after insertion to keep scoring accurate.
        """
        if tokens:
            corpus_key = f"__cls_{skill_id[:8]}"
            self._template_corpus[corpus_key] = tokens
            self._recalculate_idf()

    def stem_word(self, word: str) -> str:
        """Lightweight Porter-style suffix stripping."""
        for suffix in self.SUFFIXES:
            if word.endswith(suffix) and len(word) - len(suffix) >= 3:
                stem = word[: -len(suffix)]
                if len(stem) > 2 and stem[-1] == stem[-2]:
                    return stem[:-1]
                return stem
        return word

    def tokenize(self, text: str) -> list[str]:
        """Convert raw text into normalized semantic tokens including N-Grams."""
        cached = self._tokenize_cache.get(text)
        if cached is not None:
            return cached
        result = self._do_tokenize(text)
        if len(self._tokenize_cache) < 512:
            self._tokenize_cache[text] = result
        return result

    def _do_tokenize(self, text: str) -> list[str]:
        """Internal tokenization logic (uncached)."""
        text_lower = text.lower()
        # Apply phrase synonyms before single-word processing
        for phrase, canonical in self.PHRASE_SYNONYMS.items():
            text_lower = text_lower.replace(phrase, canonical)
        # Remove punctuation except hyphens
        text_normalized = re.sub(r"[^\w\s-]", " ", text_lower)
        words = text_normalized.split()
        tokens: list[str] = []
        clean_words: list[str] = []
        for w in words:
            if w and w not in self.STOPWORDS and len(w) > 1:
                stemmed = self.stem_word(w)
                mapped = self.synonyms.get(stemmed, stemmed)
                clean_words.append(mapped)
                tokens.append(mapped)
        # Generate Bigrams
        for i in range(len(clean_words) - 1):
            tokens.append(f"{clean_words[i]}_{clean_words[i + 1]}")
        # Generate Trigrams
        for i in range(len(clean_words) - 2):
            tokens.append(f"{clean_words[i]}_{clean_words[i + 1]}_{clean_words[i + 2]}")
        return tokens

    def extract_entities(self, text: str) -> tuple[str, str]:
        """Extract the primary target entity, using a strict priority ordering.

        Collects ALL matched entity types and returns the single highest-priority
        one. Priority (high -> low):
        url > cidr > ipv4 > ipv6 > mac > cve > sha256 > sha1 > md5 > ntlm > asn
        > aws_s3 > azure_blob > gcp_bucket > github_repo > windows_path
        > linux_path > email > domain
        """
        found = self.extract_all_entities(text)
        # Priority ordering
        for etype in (
            "url",
            "cidr",
            "ipv4",
            "ipv6",
            "mac",
            "cve",
            "sha256",
            "sha1",
            "md5",
            "ntlm",
            "asn",
            "aws_s3",
            "azure_blob",
            "gcp_bucket",
            "github_repo",
            "windows_path",
            "linux_path",
            "email",
            "domain",
        ):
            if etype in found:
                return found[etype][0], etype
        return "", ""

    def extract_all_entities(self, text: str) -> dict[str, list[str]]:
        """Extract ALL entity types found in the text, returned as a dict."""
        found: dict[str, list[str]] = {}
        for entity_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                if entity_type == "domain":
                    valid = [
                        m
                        for m in matches
                        if len(m) > 4
                        and not m.startswith("e.g")
                        and not re.match(r"^[v\d]+[\d.]+$", m)
                        and m.count(".") >= 1
                        and not re.match(r"^\d+\.\d+\.\d+\.\d+$", m)
                    ]
                    if valid:
                        found[entity_type] = valid
                else:
                    found[entity_type] = list(matches)
        return found

    def extract_parameters(self, text: str) -> dict[str, str]:
        """Extract modifier arguments with Negation Context Handling."""
        params = {}
        text_lower = text.lower()

        is_negated = any(
            neg in text_lower
            for neg in ["not ", "no ", "without ", "skip ", "exclude ", "don't ", "dont ", "avoid "]
        )

        port_match = re.search(r"(?:\bports?|-p)\s*([0-9,\-]+)\b", text_lower)
        if port_match:
            params["ports"] = port_match.group(1)
        elif "all ports" in text_lower or "full ports" in text_lower:
            params["ports"] = "all"

        is_fast = any(word in text_lower for word in ["fast", "quick", "speedy", "rapid"])
        is_stealth = any(
            word in text_lower for word in ["stealth", "slow", "sneaky", "quiet", "evasive"]
        )
        is_aggressive = any(word in text_lower for word in ["aggressive", "intense", "heavy"])

        if is_negated:
            if is_fast or is_aggressive:
                params["speed"] = "stealth"
            elif is_stealth:
                params["speed"] = "fast"
        else:
            if is_fast:
                params["speed"] = "fast"
            elif is_stealth:
                params["speed"] = "stealth"
            elif is_aggressive:
                params["speed"] = "aggressive"

        # Time / Duration extraction
        time_match = re.search(r"\b(?:timeout|max time|run for)\s*(\d+[smhd])\b", text_lower)
        if time_match:
            params["timeout"] = time_match.group(1)

        # Severity extraction (for vuln scanners)
        severities = []
        if "critical" in text_lower:
            severities.append("critical")
        if "high" in text_lower:
            severities.append("high")
        if "medium" in text_lower:
            severities.append("medium")
        if "low" in text_lower:
            severities.append("low")
        if severities:
            if is_negated and "low" in severities:
                params["severity"] = "high,critical"
            else:
                params["severity"] = ",".join(severities)

        # Output Format extraction
        if "json" in text_lower:
            params["format"] = "json"
        elif "xml" in text_lower:
            params["format"] = "xml"
        elif "markdown" in text_lower or " md " in text_lower:
            params["format"] = "markdown"

        # Protocol extraction
        if "udp" in text_lower:
            params["protocol"] = "tcp" if is_negated else "udp"
        elif "tcp" in text_lower:
            params["protocol"] = "udp" if is_negated else "tcp"

        # Output verbosity
        if any(word in text_lower for word in ["verbose", "detail", "detailed"]):
            if not is_negated:
                params["verbose"] = "true"

        # Wordlist extraction
        wordlist_match = re.search(r"\bwordlist\s*([a-zA-Z0-9_./\-]+)\b", text_lower)
        if wordlist_match:
            params["wordlist"] = wordlist_match.group(1)

        # Concurrency / Threads extraction
        threads_match = re.search(r"\b(?:threads|rate|connections|workers)\s*(\d+)\b", text_lower)
        if threads_match:
            params["threads"] = threads_match.group(1)

        # Auth extraction (Username / Password)
        user_match = re.search(r"\b(?:user|username)\s+([a-zA-Z0-9_.\-]+)\b", text_lower)
        if user_match:
            params["username"] = user_match.group(1)

        pass_match = re.search(r"\b(?:pass|password)\s+([a-zA-Z0-9_.\-!@#$%^&*]+)\b", text_lower)
        if pass_match:
            params["password"] = pass_match.group(1)

        # Module / Plugin extraction
        module_match = re.search(r"\b(?:module|plugin|script)\s+([a-zA-Z0-9_.\-]+)\b", text_lower)
        if module_match:
            params["module"] = module_match.group(1)

        # Rate Limiting / Rate parameter extraction
        rate_match = re.search(r"\b(?:rate|--rate)\s*(\d+)\b", text_lower)
        if rate_match:
            params["rate"] = rate_match.group(1)

        # Output file
        output_match = re.search(
            r"\b(?:save\s+to|output\s+to|write\s+to|out(?:put)?\s+file)\s+([a-zA-Z0-9_.\-/\\]+)\b",
            text_lower,
        )
        if output_match:
            params["output"] = output_match.group(1)

        # Recursion depth
        depth_match = re.search(r"\b(?:depth|level|recursion)\s*(\d+)\b", text_lower)
        if depth_match:
            params["depth"] = depth_match.group(1)

        # Proxy
        proxy_match = re.search(
            r"\b(?:via|through|using)?\s*proxy\s+([a-zA-Z0-9:./\-]+)\b", text_lower
        )
        if proxy_match:
            params["proxy"] = proxy_match.group(1)

        # Auth token / API key
        token_match = re.search(
            r"\b(?:with\s+token|api[_\s]?key|bearer|authorization\s+token)\s+([a-zA-Z0-9_.\-]+)\b",
            text_lower,
        )
        if token_match:
            params["token"] = token_match.group(1)

        # Target list from file
        targetlist_match = re.search(
            r"\b(?:from\s+file|targets?\s+(?:from|in)|input\s+file|target\s+list)\s+([a-zA-Z0-9_.\-/\\]+)\b",
            text_lower,
        )
        if targetlist_match:
            params["target_list"] = targetlist_match.group(1)

        # Exclude
        exclude_match = re.search(
            r"\b(?:exclude|ignore|blacklist)\s+([a-zA-Z0-9_.\-/,]+)\b", text_lower
        )
        if exclude_match:
            params["exclude"] = exclude_match.group(1)

        # Time range
        time_range_match = re.search(r"\blast\s+(\d+)\s*(day|hour|week|month)s?\b", text_lower)
        if time_range_match:
            n, unit = time_range_match.group(1), time_range_match.group(2)
            unit_map = {"hour": "h", "day": "d", "week": "w", "month": "m"}
            params["time_range"] = f"{n}{unit_map.get(unit, unit[0])}"

        # Threads / Concurrency
        threads_match = re.search(r"\b(?:threads|--threads|-t)\s*(\d+)\b", text_lower)
        if threads_match:
            params["threads"] = threads_match.group(1)

        # User-Agent string
        ua_match = re.search(r"\b(?:user-agent|ua)\s+['\"]([^'\"]+)['\"]", text_lower)
        if not ua_match:
            ua_match = re.search(r"\b(?:user-agent|ua)\s+([a-zA-Z0-9_.\-\/:()]+)\b", text_lower)
        if ua_match:
            params["user_agent"] = ua_match.group(1)

        # Cookie header
        cookie_match = re.search(r"\b(?:cookie|cookies)\s+['\"]([^'\"]+)['\"]", text_lower)
        if not cookie_match:
            cookie_match = re.search(r"\b(?:cookie|cookies)\s+([a-zA-Z0-9_.\-=\/;]+)\b", text_lower)
        if cookie_match:
            params["cookie"] = cookie_match.group(1)

        # Verbosity level
        verbosity_match = re.search(
            r"\b(?:verbose|verbosity|level)\s+(low|medium|high|debug|\d)\b", text_lower
        )
        if verbosity_match:
            params["verbosity"] = verbosity_match.group(1)

        return params

    def get_idf(self, token: str) -> float:
        """Calculate Inverse Document Frequency for a token."""
        df = self._doc_frequencies.get(token, 0)
        if df == 0 or self._total_docs == 0:
            return 1.0  # Unknown words have high IDF
        return math.log(self._total_docs / (1 + df)) + 1.0

    def _phonetic_simplify(self, word: str) -> str:
        """Lightweight phonetic normalizer for cybersecurity typos."""
        w = word.lower()
        # Remove consecutive duplicates (e.g. 'ffuf' -> 'fuf', 'dirbuster' -> 'dirbuster')
        w = re.sub(r"(.)\1+", r"\1", w)
        # Basic phonetic substitutions
        w = w.replace("ph", "f").replace("y", "i").replace("c", "k")
        return w

    def _get_char_bigrams(self, word: str) -> set[str]:
        if len(word) < 2:
            return {word}
        return set(word[i : i + 2] for i in range(len(word) - 1))

    def fuzzy_match(self, token: str, corpus_tokens: list[str]) -> bool:
        """Check if a token fuzzy-matches any corpus token using Jaccard N-Gram similarity."""
        if not corpus_tokens:
            return False
        if len(token) < 5:
            return token in corpus_tokens

        token_phonetic = self._phonetic_simplify(token)
        token_bigrams = self._get_char_bigrams(token_phonetic)

        for c_token in corpus_tokens:
            if len(c_token) < 5:
                if token == c_token:
                    return True
                continue

            # Fast difflib check for transpositions (like direcotry -> directory)
            if difflib.get_close_matches(token, [c_token], n=1, cutoff=0.75):
                return True

            c_token_phonetic = self._phonetic_simplify(c_token)
            c_bigrams = self._get_char_bigrams(c_token_phonetic)

            # Calculate Jaccard similarity for phonetic replacements
            intersection = len(token_bigrams.intersection(c_bigrams))
            union = len(token_bigrams.union(c_bigrams))
            if union == 0:
                continue

            similarity = intersection / union
            if similarity >= 0.50:  # 50% overlap in phonetic bigrams is robust for typos
                return True

        return False

    def score_intent(
        self, tokens: list[str], corpus: dict[str, list[str]]
    ) -> tuple[str | None, float]:
        """Calculate Okapi BM25 similarity to find the best matching intent.

        BM25 improves upon TF-IDF by capping term frequency saturation and properly
        normalizing based on average document length, making it the industry standard
        for information retrieval.
        """
        best_match = None
        highest_score = 0.0

        # Calculate average document length for BM25
        avgdl = sum(len(doc) for doc in corpus.values()) / max(1, len(corpus))
        k1 = 1.5  # Term frequency saturation parameter
        b = 0.75  # Length normalization parameter

        for name, doc_tokens in corpus.items():
            score = 0.0
            doc_len = len(doc_tokens)

            # Count term frequencies in the document
            doc_tf: dict[str, int] = defaultdict(int)
            for t in doc_tokens:
                doc_tf[t] += 1

            for token_idx, token in enumerate(tokens):
                idf = self.get_idf(token)
                term_freq = 0

                # Positional boost: first 3 query tokens carry more intent signal
                positional_multiplier = 1.25 if token_idx < 3 else 1.0

                if "_" in token:
                    # N-grams
                    if token in doc_tokens:
                        term_freq = 3  # Boost N-gram matches
                elif self.fuzzy_match(token, doc_tokens):
                    if token == name:
                        term_freq = 6  # Huge boost for exact name match
                    else:
                        term_freq = doc_tf.get(token, 1)

                if term_freq > 0:
                    # Okapi BM25 scoring formula
                    numerator = term_freq * (k1 + 1)
                    denominator = term_freq + k1 * (1 - b + b * (doc_len / max(1.0, avgdl)))
                    score += idf * (numerator / denominator) * positional_multiplier

            if score > highest_score:
                highest_score = score
                best_match = name

        return best_match, highest_score

    def normalize_target(self, target: str, target_type: str) -> str:
        """Sanitize and normalize extracted target entities."""
        if not target:
            return ""
        target = target.strip()
        if target_type == "url":
            target = target.rstrip("/")
        elif target_type == "domain":
            target = target.lower().strip(".")
        elif target_type in ("ipv4", "ipv6"):
            target = target.strip("[]")
        return target

    def parse(self, text: str) -> ParsedIntent:
        """Parse natural language into a structured intent representation."""
        intent = ParsedIntent(raw_text=text)

        # 1. Target Extraction
        raw_target, intent.target_type = self.extract_entities(text)
        intent.target = self.normalize_target(raw_target, intent.target_type)
        intent.all_entities = self.extract_all_entities(text)

        # Strip the target from text to prevent it from confusing intent matching
        clean_text = text.replace(raw_target, "") if raw_target else text

        # 2. Tokenization
        intent.tokens = self.tokenize(clean_text)

        # 3. Parameter Extraction
        intent.parameters = self.extract_parameters(clean_text)

        # Detect negation
        intent.negated = any(
            neg in text.lower()
            for neg in ["not ", "no ", "without ", "skip ", "don't ", "dont ", "avoid "]
        )

        # 4. Intent Scoring
        if intent.tokens:
            tpl_match, tpl_score = self.score_intent(intent.tokens, self._template_corpus)
            tool_match, tool_score = self.score_intent(intent.tokens, self._tool_corpus)

            # Templates usually capture complex intents better, slightly favor them (+20% bonus)
            if tpl_score > 0 and (tpl_score * 1.2) >= tool_score:
                intent.template_name = tpl_match
                intent.confidence = tpl_score
            elif tool_score > 0:
                intent.tool_name = tool_match
                intent.confidence = tool_score

        # Normalized confidence: sigmoid-like mapping to 0-1 scale
        if intent.confidence > 0:
            k = 5.0
            intent.normalized_confidence = intent.confidence / (intent.confidence + k)

        # Minimum confidence threshold — garbled/unrecognised input drops to None
        if intent.confidence < 0.15:
            intent.tool_name = None
            intent.template_name = None
            intent.confidence = 0.0

        return intent

    def parse_multi(self, text: str) -> list[ParsedIntent]:
        """Parse natural language into multiple structured intents if conjunctions exist."""
        # Split text by unambiguous multi-step conjunctions and separators
        split_pattern = (
            r"\b(?:"
            r"and\s+then"
            r"|followed\s+by"
            r"|&&"
            r"|,\s*then"
            r"|then"
            r"|after\s+that"
            r"|next"
            r"|subsequently"
            r"|finally"
            r"|lastly"
            r"|also\s+run"
            r"|also\s+do"
            r")\b"
            r"|;\s*"
        )
        parts = re.split(split_pattern, text, flags=re.IGNORECASE)

        intents = []
        first_target = ""
        first_target_type = ""
        for i, part in enumerate(parts):
            part = part.strip() if part else ""
            if len(part) >= 2:
                parsed = self.parse(part)
                # Propagate target from first intent to subsequent targetless intents
                if i == 0:
                    first_target = parsed.target
                    first_target_type = parsed.target_type
                elif not parsed.target and first_target:
                    parsed.target = first_target
                    parsed.target_type = first_target_type
                parsed.conjunctive_goal = len(parts) > 1
                intents.append(parsed)
        return intents
