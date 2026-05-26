#!/usr/bin/env python3
"""Generate tool_metadata.json — capability metadata for known security tools.

Run on Kali Linux to produce a comprehensive metadata file. On other
distros it still produces useful data via --help inference.

Usage:
    python scripts/generate_tool_metadata.py           # hardcoded base + scan PATH
    python scripts/generate_tool_metadata.py --update   # merge with existing
    python scripts/generate_tool_metadata.py --scan-only  # PATH scan only (no hardcoded)
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "phalanx" / "data"
OUTPUT = DATA_DIR / "tool_metadata.json"


# ── Comprehensive hardcoded metadata base (200+ tools) ──────────────────
# Covers Kali Linux default tool categories. Users can regenerate with
# --update on their own system to add locally installed tools.
_KNOWN_METADATA: dict[str, dict] = {
    # ── recon ─────────────────────────────────────────────────────────────
    "nmap": {"capabilities": ["port_scan","service_detect","os_detect","network_recon"], "category": "recon", "description": "Network exploration and port scanner"},
    "masscan": {"capabilities": ["fast_port_scan","network_recon"], "category": "recon", "description": "Internet-scale port scanner"},
    "rustscan": {"capabilities": ["fast_port_scan","network_recon"], "category": "recon", "description": "Fast port scanner written in Rust"},
    "unicornscan": {"capabilities": ["port_scan","network_recon"], "category": "recon", "description": "Distributed port scanner"},
    "zenmap": {"capabilities": ["port_scan","service_detect","os_detect","network_recon"], "category": "recon", "description": "Nmap GUI frontend"},
    "naabu": {"capabilities": ["fast_port_scan","network_recon"], "category": "recon", "description": "Fast port scanner"},
    "dnsrecon": {"capabilities": ["dns_recon","subdomain_enum","dns_brute"], "category": "recon", "description": "DNS enumeration tool"},
    "dnsenum": {"capabilities": ["dns_recon","subdomain_enum","dns_brute"], "category": "recon", "description": "DNS enumeration utility"},
    "dnsmap": {"capabilities": ["dns_recon","subdomain_enum"], "category": "recon", "description": "DNS domain brute-forcer"},
    "dnsx": {"capabilities": ["dns_recon","dns_brute"], "category": "recon", "description": "DNS query tool"},
    "subfinder": {"capabilities": ["subdomain_enum","dns_recon"], "category": "recon", "description": "Passive subdomain discovery"},
    "amass": {"capabilities": ["subdomain_enum","dns_recon","osint"], "category": "recon", "description": "Network mapping and external recon"},
    "assetfinder": {"capabilities": ["subdomain_enum","osint"], "category": "recon", "description": "Subdomain discovery tool"},
    "findomain": {"capabilities": ["subdomain_enum","osint"], "category": "recon", "description": "Subdomain enumeration"},
    "sublist3r": {"capabilities": ["subdomain_enum","osint"], "category": "recon", "description": "Fast subdomain enumeration"},
    "theHarvester": {"capabilities": ["email_harvest","osint","domain_recon"], "category": "recon", "description": "Email and domain intelligence gathering"},
    "h8mail": {"capabilities": ["email_harvest","osint"], "category": "recon", "description": "Email OSINT and breach hunting"},
    "whois": {"capabilities": ["osint","domain_recon"], "category": "recon", "description": "WHOIS domain lookup"},
    "shodan": {"capabilities": ["osint","network_recon","service_detect"], "category": "recon", "description": "Shodan search and query"},
    "recon-ng": {"capabilities": ["osint","passive_recon","domain_recon"], "category": "recon", "description": "Web reconnaissance framework"},
    "spiderfoot": {"capabilities": ["osint","passive_recon","domain_recon"], "category": "recon", "description": "OSINT automation tool"},
    "maltego": {"capabilities": ["osint","passive_recon","domain_recon"], "category": "recon", "description": "Link analysis and OSINT"},
    "sn0int": {"capabilities": ["osint","passive_recon","domain_recon"], "category": "recon", "description": "Semi-automatic OSINT framework"},
    "holehe": {"capabilities": ["osint","email_harvest"], "category": "recon", "description": "Email OSINT verification"},
    "whatweb": {"capabilities": ["web_scan","tech_detect"], "category": "recon", "description": "Website technology detection"},
    "wappalyzer": {"capabilities": ["tech_detect","web_scan"], "category": "recon", "description": "Technology profiler"},
    "httpx": {"capabilities": ["http_probe","tech_detect","alive_check","status_check"], "category": "recon", "description": "HTTP probe and analysis"},
    "httprobe": {"capabilities": ["http_probe","alive_check"], "category": "recon", "description": "HTTP/HTTPS probe"},
    "gau": {"capabilities": ["url_gather","osint"], "category": "recon", "description": "Get all URLs from URLs"},
    "waybackurls": {"capabilities": ["url_gather","osint"], "category": "recon", "description": "Wayback Machine URL harvesting"},
    "katana": {"capabilities": ["crawler","spider","url_gather"], "category": "recon", "description": "Web crawling and URL extraction"},
    "hakrawler": {"capabilities": ["crawler","url_gather"], "category": "recon", "description": "Web crawler"},
    "gospider": {"capabilities": ["crawler","spider","url_gather"], "category": "recon", "description": "Fast web spider"},
    "unfurl": {"capabilities": ["url_analyze","osint"], "category": "recon", "description": "URL extract and analyze"},
    "trufflehog": {"capabilities": ["secret_scan","git_scan","credentials_detect"], "category": "recon", "description": "Secret scanner for git repos"},
    "gitleaks": {"capabilities": ["secret_scan","git_scan","credentials_detect"], "category": "recon", "description": "Git secret scanner"},
    "netcat": {"capabilities": ["banner_grab","network_recon","port_scan"], "category": "recon", "description": "TCP/IP swiss army knife"},
    "socat": {"capabilities": ["banner_grab","network_recon","proxy"], "category": "recon", "description": "Multipurpose relay"},
    "tshark": {"capabilities": ["packet_sniff","protocol_analyze","traffic_dump"], "category": "recon", "description": "CLI Wireshark"},
    "tcpdump": {"capabilities": ["packet_sniff","protocol_analyze","traffic_dump"], "category": "recon", "description": "Packet analyzer"},
    "nmap-parse-output": {"capabilities": ["port_scan","service_detect"], "category": "recon", "description": "Nmap output parser"},
    "arp-scan": {"capabilities": ["network_recon","network_sniff"], "category": "recon", "description": "ARP discovery scanner"},
    "nbtscan": {"capabilities": ["netbios_recon","network_recon"], "category": "recon", "description": "NetBIOS scanner"},
    "ike-scan": {"capabilities": ["network_recon","vpn_scan"], "category": "recon", "description": "IPsec VPN scanner"},
    "dnstwist": {"capabilities": ["dns_recon","osint","domain_recon"], "category": "recon", "description": "DNS typosquatting detector"},
    "fierce": {"capabilities": ["dns_recon","subdomain_enum"], "category": "recon", "description": "DNS reconnaissance tool"},
    "lbd": {"capabilities": ["dns_recon","network_recon"], "category": "recon", "description": "Load balancer detector"},
    "wafw00f": {"capabilities": ["web_scan","tech_detect"], "category": "recon", "description": "WAF fingerprinting"},
    "aquatone": {"capabilities": ["http_probe","tech_detect","web_scan"], "category": "recon", "description": "Web screenshot and inspection"},
    "eyewitness": {"capabilities": ["http_probe","web_scan"], "category": "recon", "description": "Web application screenshots"},
    "photon": {"capabilities": ["crawler","url_gather","osint"], "category": "recon", "description": "Web crawler for OSINT"},
    "paramspider": {"capabilities": ["url_gather","parameter_fuzzing"], "category": "recon", "description": "Parameter discovery"},
    # ── web ──────────────────────────────────────────────────────────────
    "gobuster": {"capabilities": ["dir_enum","dns_enum","vhost_enum"], "category": "web", "description": "Directory/file/DNS busting"},
    "ffuf": {"capabilities": ["fuzzing","dir_enum","parameter_fuzzing"], "category": "web", "description": "Fast web fuzzer"},
    "feroxbuster": {"capabilities": ["dir_enum","fuzzing"], "category": "web", "description": "Recursive content discovery"},
    "dirb": {"capabilities": ["dir_enum","web_scan"], "category": "web", "description": "Web content scanner"},
    "dirbuster": {"capabilities": ["dir_enum","web_scan"], "category": "web", "description": "Directory brute-force"},
    "wfuzz": {"capabilities": ["fuzzing","parameter_fuzzing","web_scan"], "category": "web", "description": "Web application fuzzer"},
    "nikto": {"capabilities": ["web_scan","server_audit","vuln_detect"], "category": "web", "description": "Web server scanner"},
    "wpscan": {"capabilities": ["wordpress_scan","plugin_enum","theme_enum","vuln_detect"], "category": "web", "description": "WordPress security scanner"},
    "joomscan": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "Joomla vulnerability scanner"},
    "droopescan": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "Drupal/WordPress/Joomla scanner"},
    "sqlmap": {"capabilities": ["sqli","db_enum","data_extract"], "category": "web", "description": "SQL injection automation"},
    "nosqli": {"capabilities": ["sqli","db_enum"], "category": "web", "description": "NoSQL injection scanner"},
    "xsstrike": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "XSS detection and exploitation"},
    "dalfox": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "XSS parameter scanner"},
    "commix": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "Command injection finder"},
    "jwt_tool": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "JWT security testing toolkit"},
    "zap": {"capabilities": ["web_scan","api_scan","dast","proxy","vuln_detect"], "category": "web", "description": "OWASP ZAP web proxy"},
    "zap.sh": {"capabilities": ["web_scan","api_scan","dast","proxy","vuln_detect"], "category": "web", "description": "OWASP ZAP launcher"},
    "burpsuite": {"capabilities": ["web_scan","proxy","intruder","web_proxy","vuln_detect"], "category": "web", "description": "Burp Suite web security testing"},
    "interactsh": {"capabilities": ["oob_detect","dns_callback","http_callback"], "category": "web", "description": "OOB interaction detection"},
    "arachni": {"capabilities": ["web_scan","vuln_detect","dast"], "category": "web", "description": "Web application security scanner"},
    "wapiti": {"capabilities": ["web_scan","vuln_detect","dast"], "category": "web", "description": "Web application vulnerability scanner"},
    "skipfish": {"capabilities": ["web_scan","vuln_detect"], "category": "web", "description": "Web security scanner"},
    "cadaver": {"capabilities": ["web_scan"], "category": "web", "description": "WebDAV client"},
    "davtest": {"capabilities": ["web_scan"], "category": "web", "description": "WebDAV scanner"},
    "http-enum": {"capabilities": ["web_scan","dir_enum"], "category": "web", "description": "Web enumeration"},
    # ── vuln ─────────────────────────────────────────────────────────────
    "nuclei": {"capabilities": ["template_scan","cve_scan","vuln_detect"], "category": "vuln", "description": "Template-based vulnerability scanner"},
    "vulners": {"capabilities": ["cve_scan","vuln_detect"], "category": "vuln", "description": "Vulnerability database lookup"},
    "searchsploit": {"capabilities": ["vuln_detect","exploitation","cve_scan"], "category": "vuln", "description": "Exploit-DB search tool"},
    "cve-bin-tool": {"capabilities": ["cve_scan","vuln_detect"], "category": "vuln", "description": "CVE binary scanner"},
    "lynis": {"capabilities": ["vuln_detect","server_audit"], "category": "vuln", "description": "Security auditing tool"},
    "openvas": {"capabilities": ["vuln_detect","cve_scan","port_scan","service_detect"], "category": "vuln", "description": "OpenVAS vulnerability scanner"},
    "greenbone-nvt-sync": {"capabilities": ["vuln_detect"], "category": "vuln", "description": "Greenbone NVT feed sync"},
    "legion": {"capabilities": ["vuln_detect","web_scan","port_scan"], "category": "vuln", "description": "Automated security scanner"},
    "nikto": {"capabilities": ["vuln_detect","web_scan"], "category": "vuln", "description": "Web server vulnerability scanner"},
    # ── exploit ──────────────────────────────────────────────────────────
    "hydra": {"capabilities": ["brute_force","password_attack","credential_test"], "category": "exploit", "description": "Network login cracker"},
    "john": {"capabilities": ["password_crack","hash_crack"], "category": "exploit", "description": "John the Ripper password cracker"},
    "hashcat": {"capabilities": ["password_crack","hash_crack","gpu_crack"], "category": "exploit", "description": "Hashcat GPU password cracker"},
    "hashid": {"capabilities": ["password_crack"], "category": "exploit", "description": "Hash type identifier"},
    "hash-identifier": {"capabilities": ["password_crack"], "category": "exploit", "description": "Hash type identification"},
    "medusa": {"capabilities": ["brute_force","password_attack"], "category": "exploit", "description": "Parallel network login cracker"},
    "crowbar": {"capabilities": ["brute_force","password_attack"], "category": "exploit", "description": "SSH/RDP brute-force"},
    "ncrack": {"capabilities": ["brute_force","password_attack"], "category": "exploit", "description": "Network authentication cracker"},
    "cewl": {"capabilities": ["password_attack","osint"], "category": "exploit", "description": "Custom wordlist generator"},
    "crunch": {"capabilities": ["password_attack"], "category": "exploit", "description": "Wordlist generator"},
    "rsmangler": {"capabilities": ["password_attack"], "category": "exploit", "description": "Wordlist mutation tool"},
    "msfconsole": {"capabilities": ["exploitation","payload_gen","post_exploit","auxiliary_scan"], "category": "exploit", "description": "Metasploit Framework console"},
    "msfvenom": {"capabilities": ["payload_gen","exploitation"], "category": "exploit", "description": "Payload generator"},
    "metasploit": {"capabilities": ["exploitation","payload_gen","post_exploit","auxiliary_scan"], "category": "exploit", "description": "Metasploit alias"},
    "bettercap": {"capabilities": ["mitm","arp_spoof","dns_spoof","http_proxy","sniff"], "category": "exploit", "description": "MITM framework"},
    "ettercap": {"capabilities": ["mitm","arp_poison","dns_spoof","packet_sniff"], "category": "exploit", "description": "MITM attack toolkit"},
    "yersinia": {"capabilities": ["mitm","network_recon"], "category": "exploit", "description": "Layer 2 attack tool"},
    "impacket": {"capabilities": ["smb_recon","kerberoast","wmi_exec","pass_the_hash","dc_sync"], "category": "exploit", "description": "Impacket SMB protocol suite"},
    "bloodhound": {"capabilities": ["ad_recon","acl_analyze","attack_path"], "category": "exploit", "description": "Active Directory graph analysis"},
    "bloodhound-python": {"capabilities": ["ad_recon","acl_analyze"], "category": "exploit", "description": "BloodHound Python ingestor"},
    "responder": {"capabilities": ["llmnr_poison","ntlm_relay","smb_recon"], "category": "exploit", "description": "NBT-NS/LLMNR responder"},
    "crackmapexec": {"capabilities": ["smb_recon","winrm_exec","credential_test","pass_the_hash"], "category": "exploit", "description": "Post-exploitation toolkit"},
    "netexec": {"capabilities": ["smb_recon","winrm_exec","credential_test"], "category": "exploit", "description": "Network execution (nxc successor)"},
    "evil-winrm": {"capabilities": ["winrm_shell","post_exploit"], "category": "exploit", "description": "WinRM shell"},
    "empire": {"capabilities": ["c2","stager_gen","power_shell","post_exploit"], "category": "exploit", "description": "PowerShell Empire post-exploitation"},
    "pwncat": {"capabilities": ["reverse_shell","file_transfer","privilege_esc","post_exploit"], "category": "exploit", "description": "Reverse shell handler"},
    "pwncat-cs": {"capabilities": ["reverse_shell","file_transfer","c2"], "category": "exploit", "description": "Pwncat command-and-control"},
    "certipy": {"capabilities": ["ad_cert_abuse","esc_attack","ad_recon"], "category": "exploit", "description": "Active Directory certificate abuse"},
    "chisel": {"capabilities": ["tunnel","proxy","port_forward","pivot"], "category": "exploit", "description": "Fast TCP tunnel"},
    "ligolo-ng": {"capabilities": ["tunnel","proxy","pivot"], "category": "exploit", "description": "Tunneling/pivoting agent"},
    "sshuttle": {"capabilities": ["proxy","tunnel","pivot"], "category": "exploit", "description": "VPN over SSH"},
    "proxychains": {"capabilities": ["proxy","relay","proxying"], "category": "exploit", "description": "Proxy chaining"},
    "socat": {"capabilities": ["port_forward","relay","proxy"], "category": "exploit", "description": "Port forwarding and relay"},
    "stunnel": {"capabilities": ["proxy","tunnel"], "category": "exploit", "description": "SSL tunnel"},
    "autobloody": {"capabilities": ["ad_recon","attack_path"], "category": "exploit", "description": "BloodHound attack path automation"},
    "coercer": {"capabilities": ["smb_recon","ad_recon"], "category": "exploit", "description": "Coerce authentication"},
    "kerbrute": {"capabilities": ["brute_force","ad_recon","kerberoast"], "category": "exploit", "description": "Kerberos enumeration"},
    "pcredz": {"capabilities": ["credential_dump","sniff"], "category": "exploit", "description": "Credential sniffer"},
    "smbmap": {"capabilities": ["smb_recon","enum","credential_test"], "category": "exploit", "description": "SMB enumeration"},
    "enum4linux": {"capabilities": ["smb_recon","ad_recon","enum"], "category": "exploit", "description": "Windows/Samba enumeration"},
    "enum4linux-ng": {"capabilities": ["smb_recon","ad_recon","enum"], "category": "exploit", "description": "SMB/CIFS enumeration"},
    "ldapsearch": {"capabilities": ["ad_recon","enum"], "category": "exploit", "description": "LDAP search utility"},
    "ldapdomaindump": {"capabilities": ["ad_recon","enum"], "category": "exploit", "description": "AD LDAP dump"},
    "rpcclient": {"capabilities": ["ad_recon","smb_recon"], "category": "exploit", "description": "SMB RPC client"},
    "sprayhound": {"capabilities": ["ad_recon","brute_force"], "category": "exploit", "description": "AD password spray"},
    "pre2k": {"capabilities": ["ad_recon"], "category": "exploit", "description": "Pre-Windows 2000 computer discovery"},
    # ── wireless ─────────────────────────────────────────────────────────
    "aircrack-ng": {"capabilities": ["wireless_attack","wpa_crack","packet_capture","deauth"], "category": "wireless", "description": "Wireless security assessment suite"},
    "reaver": {"capabilities": ["wireless_attack","wps_attack","pin_brute"], "category": "wireless", "description": "WPS brute-force tool"},
    "wifite": {"capabilities": ["wireless_attack","wpa_crack","deauth"], "category": "wireless", "description": "Automated wireless auditor"},
    "kismet": {"capabilities": ["wireless_audit","wireless_detect","packet_sniff"], "category": "wireless", "description": "Wireless network detector"},
    "airgeddon": {"capabilities": ["wireless_attack","mitm","deauth"], "category": "wireless", "description": "Multi-purpose wireless attack tool"},
    "bully": {"capabilities": ["wireless_attack","wps_attack","pin_brute"], "category": "wireless", "description": "WPS brute-force"},
    "pixiewps": {"capabilities": ["wireless_attack","wps_attack"], "category": "wireless", "description": "WPS offline brute-force"},
    "mdk4": {"capabilities": ["wireless_attack","deauth","dos"], "category": "wireless", "description": "802.11 attack tool"},
    "hcxdumptool": {"capabilities": ["wireless_attack","packet_capture"], "category": "wireless", "description": "Raw packet capture for WPA cracking"},
    "hcxpcapngtool": {"capabilities": ["wireless_attack","packet_capture"], "category": "wireless", "description": "Hashcat pcap converter"},
    "horst": {"capabilities": ["wireless_audit","packet_sniff"], "category": "wireless", "description": "802.11 analyzer"},
    "wash": {"capabilities": ["wireless_detect","wps_attack"], "category": "wireless", "description": "WPS scanner"},
    # ── social ───────────────────────────────────────────────────────────
    "setoolkit": {"capabilities": ["social_engineering","phishing","credential_harvest","browser_exploit"], "category": "social", "description": "Social Engineering Toolkit"},
    "beef": {"capabilities": ["browser_exploit","social_engineering","phishing"], "category": "social", "description": "Browser exploitation framework"},
    "gophish": {"capabilities": ["phishing","campaign_manage","credential_harvest"], "category": "social", "description": "Phishing framework"},
    "ghost-phisher": {"capabilities": ["phishing","credential_harvest","social_engineering"], "category": "social", "description": "Phishing attack toolkit"},
    "king-phisher": {"capabilities": ["phishing","campaign_manage","email_track"], "category": "social", "description": "Phishing campaign toolkit"},
    "evilginx": {"capabilities": ["phishing","proxy","social_engineering"], "category": "social", "description": "Phishing reverse proxy"},
    "modlishka": {"capabilities": ["phishing","proxy","social_engineering"], "category": "social", "description": "Phishing proxy"},
    "hiddeneye": {"capabilities": ["phishing","social_engineering"], "category": "social", "description": "Phishing attack tool"},
    "socialfish": {"capabilities": ["phishing","credential_harvest"], "category": "social", "description": "Credential harvesting"},
    # ── cloud ────────────────────────────────────────────────────────────
    "aws": {"capabilities": ["cloud_enum","aws_recon"], "category": "cloud", "description": "AWS CLI"},
    "az": {"capabilities": ["cloud_enum","azure_recon"], "category": "cloud", "description": "Azure CLI"},
    "gcloud": {"capabilities": ["cloud_enum","gcp_recon"], "category": "cloud", "description": "Google Cloud CLI"},
    "s3scanner": {"capabilities": ["cloud_enum"], "category": "cloud", "description": "S3 bucket scanner"},
    "pacu": {"capabilities": ["cloud_enum","aws_recon","exploitation"], "category": "cloud", "description": "AWS exploitation framework"},
    "scoutsuite": {"capabilities": ["cloud_enum","aws_recon","azure_recon","gcp_recon"], "category": "cloud", "description": "Multi-cloud security auditing"},
    "cloudsploit": {"capabilities": ["cloud_enum","aws_recon"], "category": "cloud", "description": "Cloud security scanner"},
    "s3-inspector": {"capabilities": ["cloud_enum"], "category": "cloud", "description": "S3 bucket permission checker"},
    "steampipe": {"capabilities": ["cloud_enum"], "category": "cloud", "description": "Cloud infrastructure query"},
    # ── infra ────────────────────────────────────────────────────────────
    "docker": {"capabilities": ["container_runtime","image_manage"], "category": "infra", "description": "Container runtime"},
    "podman": {"capabilities": ["container_runtime","image_manage"], "category": "infra", "description": "Rootless container runtime"},
    "kubectl": {"capabilities": ["k8s_manage","cluster_recon"], "category": "infra", "description": "Kubernetes CLI"},
    "helm": {"capabilities": ["k8s_manage","k8s_package"], "category": "infra", "description": "Kubernetes package manager"},
    "terraform": {"capabilities": ["iac_plan","infra_manage"], "category": "infra", "description": "Infrastructure as Code"},
    "ansible": {"capabilities": ["automation","config_manage","infra_manage"], "category": "infra", "description": "Configuration management and automation"},
    "cloudflared": {"capabilities": ["tunnel","proxy"], "category": "infra", "description": "Cloudflare tunnel"},
    "vagrant": {"capabilities": ["infra_manage","automation"], "category": "infra", "description": "VM environment manager"},
    "packer": {"capabilities": ["iac_plan","infra_manage"], "category": "infra", "description": "Machine image builder"},
    # ── forensics ────────────────────────────────────────────────────────
    "volatility": {"capabilities": ["memory_forensics","process_dump","registry_analyze"], "category": "forensics", "description": "Memory forensics framework"},
    "autopsy": {"capabilities": ["disk_forensics","file_carve","timeline_analyze"], "category": "forensics", "description": "Digital forensics platform"},
    "sleuthkit": {"capabilities": ["disk_forensics","filesystem_analyze","file_carve"], "category": "forensics", "description": "Filesystem analysis toolkit"},
    "binwalk": {"capabilities": ["firmware_analyze","file_extract","entropy_scan"], "category": "forensics", "description": "Firmware analysis tool"},
    "foremost": {"capabilities": ["file_carve","data_extract"], "category": "forensics", "description": "File carving tool"},
    "scalpel": {"capabilities": ["file_carve","data_extract"], "category": "forensics", "description": "File carving utility"},
    "testdisk": {"capabilities": ["disk_forensics","filesystem_analyze"], "category": "forensics", "description": "Partition recovery"},
    "photorec": {"capabilities": ["file_carve","data_extract"], "category": "forensics", "description": "File recovery"},
    "guymager": {"capabilities": ["disk_forensics"], "category": "forensics", "description": "Disk imaging tool"},
    "dcfldd": {"capabilities": ["disk_forensics"], "category": "forensics", "description": "Forensic dd"},
    "ddrescue": {"capabilities": ["disk_forensics"], "category": "forensics", "description": "Data rescue tool"},
    "afflib-tools": {"capabilities": ["disk_forensics"], "category": "forensics", "description": "Advanced forensics format tools"},
    "ewf-tools": {"capabilities": ["disk_forensics"], "category": "forensics", "description": "Expert witness format tools"},
    "xplico": {"capabilities": ["packet_sniff","protocol_analyze","network_forensics"], "category": "forensics", "description": "Network forensics analysis"},
    "strings": {"capabilities": ["data_extract"], "category": "forensics", "description": "Extract printable strings"},
    "hexdump": {"capabilities": ["data_extract"], "category": "forensics", "description": "Hex dump viewer"},
    "xxd": {"capabilities": ["data_extract"], "category": "forensics", "description": "Hex dump tool"},
    "exiftool": {"capabilities": ["data_extract","metadata_analyze"], "category": "forensics", "description": "Metadata extraction"},
    "steghide": {"capabilities": ["data_extract","stego"], "category": "forensics", "description": "Steganography tool"},
    "stegseek": {"capabilities": ["data_extract","stego"], "category": "forensics", "description": "Steganography brute-force"},
    "outguess": {"capabilities": ["stego","data_extract"], "category": "forensics", "description": "Steganography tool"},
    "steghide": {"capabilities": ["stego","data_extract"], "category": "forensics", "description": "Steganography tool"},
    "zsteg": {"capabilities": ["stego","data_extract"], "category": "forensics", "description": "PNG/BMP steganography"},
    # ── c2 / post-exploit ────────────────────────────────────────────────
    "cobaltstrike": {"capabilities": ["c2","stager_gen","post_exploit"], "category": "c2", "description": "Cobalt Strike C2 framework"},
    "sliver": {"capabilities": ["c2","stager_gen","post_exploit"], "category": "c2", "description": "Sliver C2 framework"},
    "havoc": {"capabilities": ["c2","stager_gen"], "category": "c2", "description": "Havoc C2 framework"},
    "mythic": {"capabilities": ["c2","stager_gen","post_exploit"], "category": "c2", "description": "Mythic C2 framework"},
    "bruteratel": {"capabilities": ["c2","post_exploit"], "category": "c2", "description": "Brute Ratel C2"},
    "nimplant": {"capabilities": ["c2","stager_gen"], "category": "c2", "description": "Nimplant C2 implant"},
    "phoenixc2": {"capabilities": ["c2","stager_gen"], "category": "c2", "description": "Phoenix C2 framework"},
    # ── hardware / iot ───────────────────────────────────────────────────
    "openocd": {"capabilities": ["hardware_debug","firmware_flash"], "category": "hardware", "description": "OpenOCD debugger"},
    "flashrom": {"capabilities": ["firmware_flash","hardware_debug"], "category": "hardware", "description": "BIOS/SPI flash utility"},
    "chipsec": {"capabilities": ["hardware_debug","firmware_analyze"], "category": "hardware", "description": "Platform security assessment"},
    "pixie": {"capabilities": ["hardware_debug"], "category": "hardware", "description": "PixieDust WPS attack"},
    "radare2": {"capabilities": ["binary_analysis","reverse_engineering","firmware_analyze"], "category": "reverse", "description": "Reverse engineering framework"},
    "r2": {"capabilities": ["binary_analysis","reverse_engineering"], "category": "reverse", "description": "Radare2 alias"},
    "ghidra": {"capabilities": ["binary_analysis","reverse_engineering","firmware_analyze"], "category": "reverse", "description": "Reverse engineering platform"},
    "objdump": {"capabilities": ["binary_analysis","reverse_engineering"], "category": "reverse", "description": "Binary object analysis"},
    "readelf": {"capabilities": ["binary_analysis","reverse_engineering"], "category": "reverse", "description": "ELF analysis"},
    "strace": {"capabilities": ["binary_analysis"], "category": "reverse", "description": "System call tracer"},
    "ltrace": {"capabilities": ["binary_analysis"], "category": "reverse", "description": "Library call tracer"},
    "dnspy": {"capabilities": ["binary_analysis","reverse_engineering"], "category": "reverse", "description": ".NET debugger"},
    # ── info gathering / misc ────────────────────────────────────────────
    "dig": {"capabilities": ["dns_recon"], "category": "recon", "description": "DNS lookup utility"},
    "nslookup": {"capabilities": ["dns_recon"], "category": "recon", "description": "DNS query tool"},
    "host": {"capabilities": ["dns_recon"], "category": "recon", "description": "DNS lookup"},
    "curl": {"capabilities": ["http_probe","web_scan","url_analyze"], "category": "recon", "description": "HTTP client"},
    "wget": {"capabilities": ["http_probe","web_scan"], "category": "recon", "description": "HTTP downloader"},
    "jq": {"capabilities": ["data_extract","json_parse"], "category": "recon", "description": "JSON query tool"},
    "openssl": {"capabilities": ["certificate_scan","tls_scan","crypto"], "category": "recon", "description": "SSL/TLS toolkit"},
    "testssl": {"capabilities": ["certificate_scan","tls_scan","vuln_detect"], "category": "recon", "description": "TLS/SSL security scanner"},
    "sslyze": {"capabilities": ["certificate_scan","tls_scan"], "category": "recon", "description": "SSL configuration scanner"},
    "ike-scan": {"capabilities": ["vpn_scan","network_recon"], "category": "recon", "description": "IPsec VPN scanner"},
    "nmap-parse": {"capabilities": ["port_scan","service_detect"], "category": "recon", "description": "Nmap output parser"},
}


# ── Capability keywords matched against --help output ───────────────────
_HELP_CAP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"port\s*scan|nmap|masscan"), "port_scan"),
    (re.compile(r"service\s*(detect|version|probe)"), "service_detect"),
    (re.compile(r"os\s*(detect|fingerprint|identify)"), "os_detect"),
    (re.compile(r"dns|domain|subdomain|resolv|dig|nslookup"), "dns_recon"),
    (re.compile(r"subdomain|subdomain_enum|enum.*sub"), "subdomain_enum"),
    (re.compile(r"whois|osint|passive|recon|gather"), "osint"),
    (re.compile(r"vuln|vulnerability|cve|cvss|exploit-db"), "vuln_detect"),
    (re.compile(r"web\s*(scan|app|server|audit|crawl)"), "web_scan"),
    (re.compile(r"dir.*(enum|bust|scan)|gobuster|dirb"), "dir_enum"),
    (re.compile(r"fuzz|ffuf|wfuzz|param"), "fuzzing"),
    (re.compile(r"sql|sqli|injection|database"), "sqli"),
    (re.compile(r"brute|bruteforce|hydra|crack|hashcat"), "brute_force"),
    (re.compile(r"password|credential|hash|john"), "password_crack"),
    (re.compile(r"exploit|exploitation|msf|metasploit"), "exploitation"),
    (re.compile(r"post.*exploit|post_exploit"), "post_exploit"),
    (re.compile(r"mitm|arp|spoof|ettercap|bettercap"), "mitm"),
    (re.compile(r"sniff|packet|tcpdump|tshark|wireshark"), "packet_sniff"),
    (re.compile(r"wireless|wifi|aircrack|reaver|kismet"), "wireless_attack"),
    (re.compile(r"cloud|aws|azure|gcp|s3|bucket"), "cloud_enum"),
    (re.compile(r"container|docker|podman"), "container_runtime"),
    (re.compile(r"k8s|kubernetes|kubectl|helm"), "k8s_manage"),
    (re.compile(r"iac|terraform|ansible|pulumi"), "iac_plan"),
    (re.compile(r"social.*eng|phish|setoolkit|gophish"), "social_engineering"),
    (re.compile(r"reverse.*shell|shell|payload"), "reverse_shell"),
    (re.compile(r"proxy|tunnel|chisel|ngrok"), "proxy"),
    (re.compile(r"forensic|volatility|autopsy|sleuth"), "forensics"),
    (re.compile(r"secret|gitleaks|trufflehog|credential"), "secret_scan"),
    (re.compile(r"smtp|email|sendmail|harvest"), "email_harvest"),
    (re.compile(r"ldap|kerberos|ad\s*recon|bloodhound"), "ad_recon"),
    (re.compile(r"samba|smb|cifs|netbios"), "smb_recon"),
    (re.compile(r"router|switch|snmp|network.*device"), "network_recon"),
    (re.compile(r"cert|tls|ssl|https|pki"), "certificate_scan"),
    (re.compile(r"api|rest|graphql|endpoint"), "api_scan"),
    (re.compile(r"backup|exfil|transfer|data"), "file_transfer"),
]

_HELP_EXCLUDE_PATTERNS = [
    re.compile(r"usage:\s+python|python3\s+-m", re.I),
    re.compile(r"no\s+help|unrecognized|invalid\s+option", re.I),
]

# ── Inferred category from capabilities ────────────────────────────────
_CAP_TO_CATEGORY: dict[str, str] = {
    "port_scan": "recon",
    "service_detect": "recon",
    "os_detect": "recon",
    "dns_recon": "recon",
    "subdomain_enum": "recon",
    "osint": "recon",
    "whois": "recon",
    "web_scan": "web",
    "dir_enum": "web",
    "fuzzing": "web",
    "sqli": "web",
    "vuln_detect": "vuln",
    "cve_scan": "vuln",
    "brute_force": "exploit",
    "password_crack": "exploit",
    "exploitation": "exploit",
    "post_exploit": "exploit",
    "mitm": "exploit",
    "social_engineering": "social",
    "wireless_attack": "wireless",
    "packet_sniff": "recon",
    "cloud_enum": "cloud",
    "container_runtime": "infra",
    "k8s_manage": "infra",
    "iac_plan": "infra",
    "forensics": "forensics",
    "secret_scan": "web",
    "ad_recon": "exploit",
    "smb_recon": "exploit",
    "reverse_shell": "exploit",
    "proxy": "exploit",
    "api_scan": "web",
    "certificate_scan": "recon",
    "file_transfer": "exploit",
    "email_harvest": "recon",
}


def infer_from_help(binary: str) -> dict:
    """Run --help / -h and infer capabilities from output text."""
    caps: set[str] = set()
    for flag in ("--help", "-h"):
        try:
            r = subprocess.run([binary, flag], capture_output=True, text=True, timeout=8)
            text = (r.stdout + r.stderr).lower()
            if any(p.search(text) for p in _HELP_EXCLUDE_PATTERNS):
                continue
            for pattern, cap in _HELP_CAP_PATTERNS:
                if pattern.search(text):
                    caps.add(cap)
            if not caps:
                # Generic: if --help produced real output, tag it
                stripped = text.strip()
                if len(stripped) > 50:
                    caps.add("cli_tool")
            break
        except (OSError, subprocess.TimeoutExpired):
            continue
    if not caps:
        return {}
    category = _pick_category(caps)
    desc = f"{binary} — auto-inferred from --help"
    return {"capabilities": sorted(caps), "category": category, "description": desc}


def _pick_category(caps: set[str]) -> str:
    for cap in caps:
        cat = _CAP_TO_CATEGORY.get(cap)
        if cat:
            return cat
    return "tool"


def scan_path_tools() -> dict[str, dict]:
    """Scan PATH and infer metadata for every executable."""
    metadata: dict[str, dict] = {}
    seen: set[str] = set()
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for d in path_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                full = os.path.join(d, entry)
                name, ext = os.path.splitext(entry)
                binary = name.lower()
                if binary in seen or not os.path.isfile(full):
                    continue
                if os.name == "nt":
                    if ext.lower() not in (".exe", ".bat", ".ps1", ".cmd"):
                        continue
                elif not os.access(full, os.X_OK):
                    continue
                seen.add(binary)
                inferred = infer_from_help(binary)
                if inferred:
                    metadata[binary] = inferred
        except PermissionError:
            continue
    return metadata


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = {}
    scan_only = "--scan-only" in sys.argv

    if OUTPUT.exists() and "--update" in sys.argv:
        existing = json.loads(OUTPUT.read_text(encoding="utf-8"))
        print(f"Loaded existing metadata: {len(existing)} entries")

    # Start with hardcoded base unless --scan-only
    if scan_only:
        base: dict[str, dict] = {}
        print("--scan-only mode: no hardcoded base")
    else:
        base = dict(_KNOWN_METADATA)
        print(f"Hardcoded base: {len(base)} tools")

    print("Scanning PATH and inferring capabilities from --help ...")
    scanned = scan_path_tools()
    print(f"  Found {len(scanned)} tools with inferable metadata")

    merged = dict(existing)
    # Priority: existing (--update) > scanned > hardcoded base
    merged.update(base)
    merged.update(scanned)

    # Sort by category then name
    def _sort_key(item):
        meta = item[1]
        return (meta.get("category", "z"), item[0])

    merged = dict(sorted(merged.items(), key=_sort_key))

    OUTPUT.write_text(json.dumps(merged, indent=2, encoding="utf-8"))
    print(f"\nWrote {len(merged)} entries to {OUTPUT}")


if __name__ == "__main__":
    main()
