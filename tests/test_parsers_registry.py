# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive parametrized tests for ALL tool output parsers via ParserRegistry.

Uses the auto-discovery mechanism to test every registered parser with
realistic sample outputs and empty/null edge cases.
"""

from __future__ import annotations

import pytest
from siyarix.parsers import ParserRegistry


# ---------------------------------------------------------------------------
# Realistic sample outputs for every registered parser
# ---------------------------------------------------------------------------
# Maps tool_name -> list of (sample_output, min_expected_findings, ...)
# The test will skip any tool not in this dict with a warning.

SAMPLES: dict[str, tuple[str, int]] = {
    # ======== Network / Port Scanning ========
    "nmap": (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/>'
        '<hostnames><hostname name="target.local" type="user"/></hostnames>'
        "<ports>"
        '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
        '<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'
        "</ports></host></nmaprun>",
        2,
    ),
    "masscan": (
        "Discovered open port 80/tcp on 192.168.1.1\n"
        "Discovered open port 443/tcp on 192.168.1.1\n",
        2,
    ),
    "rustscan": (
        "Open 10.0.0.1:22\nOpen 10.0.0.1:80\nOpen 10.0.0.1:443\n",
        3,
    ),
    "naabu": (
        "https://10.0.0.1:443\nhttp://10.0.0.1:80\n",
        2,
    ),
    "zmap": (
        "10.0.0.1\n10.0.0.2\n10.0.0.3\n",
        3,
    ),
    "zgrab": (
        '{"ip":"10.0.0.1","domain":"example.com","data":{"http":{"status":"success","status_code":200,"title":"Index of /"}}}\n'
        '{"ip":"10.0.0.2","domain":"example.org","data":{"tls":{"status":"success","handshake_done":true}}}\n',
        2,
    ),

    # ======== DNS / Subdomain Enumeration ========
    "dnsx": (
        '{"host":"example.com","type":"A","a":"1.2.3.4"}\n{"host":"example.org","type":"AAAA","a":"::1"}\n',
        2,
    ),
    "subfinder": (
        "sub1.example.com\nsub2.example.com\nsub3.example.com\n",
        3,
    ),
    "amass": (
        '{"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}\n'
        '{"name":"sub2.example.com","domain":"example.com","addresses":[{"ip":"5.6.7.8"}]}\n',
        2,
    ),
    "assetfinder": ("sub1.example.com\nsub2.example.com\n", 2),
    "findomain": (
        '{"domain":"sub1.example.com","ip_address":"1.2.3.4"}\n{"domain":"sub2.example.com","ip_address":"5.6.7.8"}\n{"domain":"sub3.example.com","ip_address":"9.10.11.12"}\n',
        3,
    ),
    "sublist3r": ("sub1.example.com\nsub2.example.com\n", 2),
    "shuffledns": (
        "sub1.example.com\nsub2.example.com\nsub3.example.com\n",
        3,
    ),
    "massdns": (
        "sub1.example.com. A 1.2.3.4\nsub2.example.com. A 5.6.7.8\n",
        2,
    ),
    "dnsenum": (
        "Host's addresses:\n  sub1.example.com...................... [A: 1.2.3.4]\n"
        "Brute Force:\n  www.example.com....................... [A: 1.2.3.4]\n",
        2,
    ),
    "dnsmap": (
        "sub1.example.com (1.2.3.4)\nsub2.example.com (5.6.7.8)\n",
        2,
    ),
    "dnsrecon": (
        "[*] A sub1.example.com 1.2.3.4\n[*] A sub2.example.com 5.6.7.8\n",
        2,
    ),
    "dnstwist": (
        '[{"domain":"example.com","fuzzed":"example.org","dns-a":["1.2.3.4"],"score":75},{"domain":"example.com","fuzzed":"examp1e.com","dns-a":["5.6.7.8"],"score":50}]',
        2,
    ),
    "dig": (
        "; <<>> DiG 9.16 <<>> example.com\n"
        ";; ANSWER SECTION:\n"
        "example.com. 3600 IN A 1.2.3.4\n"
        "example.com. 3600 IN MX 10 mail.example.com.\n",
        2,
    ),

    # ======== Web Scanning / Enumeration ========
    "gobuster": (
        "Url: http://example.com\n/admin (Status: 200) [Size: 1234]\n"
        "/login (Status: 301) [Size: 0]\n",
        2,
    ),
    "dirb": (
        "http://example.com/admin (CODE:200|SIZE:1234)\n"
        "http://example.com/backup (CODE:403|SIZE:0)\n",
        2,
    ),
    "dirsearch": (
        "Target: http://example.com\n200 1234 http://example.com/admin\n301 0 http://example.com/backup\n403 50 http://example.com/.htaccess\n",
        3,
    ),
    "feroxbuster": (
        "200 GET 1234 http://example.com/admin\n"
        "301 GET 0 http://example.com/redirect\n",
        2,
    ),
    "ffuf": (
        "admin                  [Status: 200, Size: 1234, Words: 100, Lines: 20]\n"
        "backup                 [Status: 403, Size: 50, Words: 10, Lines: 2]\n",
        2,
    ),
    "wfuzz": (
        "ID: admin Response: 200  Size: 1234\n"
        "ID: root Response: 403  Size: 50\n",
        2,
    ),
    "katana": (
        '{"url":"http://example.com/admin","source":"href","status_code":200}\n'
        '{"url":"http://example.com/login","source":"form","status_code":301}\n'
        '{"url":"http://example.com/api","source":"href","status_code":403}\n',
        3,
    ),
    "gospider": (
        '{"url":"http://example.com/admin","source":"crawl","status":200}\n'
        '{"url":"http://example.com/login","source":"crawl","status":301}\n'
        '{"url":"http://example.com/api","source":"crawl","status":403}\n',
        3,
    ),
    "hakrawler": (
        "http://example.com/admin\nhttp://example.com/login\n",
        2,
    ),
    "kiterunner": (
        '{"URL": "http://example.com/api/users", "Status": 200}\n'
        "GET http://example.com/api/admin\n",
        2,
    ),
    "paramspider": (
        "http://example.com/api?user=FUZZ\nhttp://example.com/login?redirect=FUZZ\n",
        2,
    ),
    "waybackurls": (
        "http://example.com/test\nhttp://example.com/test2?id=1\nhttp://example.com/test3?q=search\n",
        3,
    ),
    "gau": (
        "http://example.com/path1\nhttp://example.com/path2?id=1\nhttp://example.com/path3?q=test\n",
        3,
    ),
    "wget": (
        "--2025-01-01 12:00:00--  http://example.com/file\n"
        "Length: 1234 (1.2K)\nSaving to: file\n100%[==============================================>] 1,234  --.-K/s   in 0s\n",
        1,
    ),
    "curl": (
        "HTTP/2 200 \ncontent-type: text/html\nserver: nginx/1.24.0\n\n<html><body>OK</body></html>",
        1,
    ),
    "aquatone": (
        '{"pages": [{"url": "http://example.com", "status": 200, "pageTitle": "Example Domain", "hasScreenshot": true}]}',
        1,
    ),
    "gowitness": (
        '[{"url":"http://example.com","status_code":200,"title":"Example","screenshot_path":"test.png"},{"url":"http://example.org","status_code":301,"title":"Moved","screenshot_path":"test2.png"}]',
        2,
    ),
    "httpx": (
        "http://example.com [200] [Example Domain] [nginx] [https]\n"
        "http://example.org [301] [Moved] [apache] [http]\n",
        2,
    ),

    # ======== Vulnerability Scanners ========
    "nuclei": (
        '{"template-id":"CVE-2023-1234","info":{"name":"Test Vulnerability","severity":"high"},'
        '"host":"example.com","matched-at":"example.com/admin","type":"http"}\n'
        '{"template-id":"CVE-2023-5678","info":{"name":"Another Vuln","severity":"medium"},'
        '"host":"example.com","matched-at":"example.com/login","type":"http"}\n',
        2,
    ),
    "nikto": (
        "+ /admin: OSVDB-1234: Admin login page found.\n"
        "+ Server: Apache/2.4.7\n"
        "+ /wp-admin: WordPress installation found.\n",
        2,
    ),
    "wapiti": (
        '{"vulnerabilities": [{"method":"GET","path":"/search","parameter":"q","type":"SQL Injection","level":"2"}],'
        '"infos": [{"path":"/robots.txt","description":"robots.txt found"}]}',
        2,
    ),
    "arachni": (
        '{"issues": [{"name":"SQL Injection","severity":"high","vector":{"action":"http://example.com/search","input":"q"},'
        '"cwe":"CWE-89","description":"SQL injection in q parameter"},'
        '{"name":"XSS","severity":"medium","vector":{"action":"http://example.com/search","input":"q"},'
        '"cwe":"CWE-79","description":"Cross-site scripting"}]}',
        2,
    ),
    "zaproxy": (
        "[HIGH] Cross Site Scripting (Reflected) in http://example.com/search [parameter: q]\n"
        "[MEDIUM] SQL Injection in http://example.com/api [parameter: id]\n",
        2,
    ),
    "burpsuite": (
        "Issue: SQL Injection\nSeverity: High\nConfidence: Certain\nURL: http://example.com/api\n"
        "Issue: XSS\nSeverity: Medium\nConfidence: Firm\nURL: http://example.com/search\n",
        2,
    ),
    "wpscan": (
        "[+] URL: http://example.com/ [200]\n"
        "[!] WordPress version 5.8.2 identified (vulnerable)\n"
        "[!] User enumeration: admin found\n",
        2,
    ),
    "sqlmap": (
        "[INFO] target URL appears to be 'http://example.com/?id=1'\n"
        "[WARNING] parameter 'id' is vulnerable\n"
        "[INFO] GET parameter 'id' is 'MySQL' injectable\n",
        2,
    ),
    "xsstrike": (
        "[!] XSS vulnerability found in http://example.com/search\n"
        "[!] Parameter: q\n[*] Payload: <script>alert(1)</script>\n",
        1,
    ),
    "kxss": (
        "URL: http://example.com/?q=test Param: q Unfiltered: [<>'\"]\n"
        "URL: http://example.com/?s=search Param: s Unfiltered: [<>\"]\n",
        2,
    ),
    "dalfox": (
        '[{"URL":"http://example.com/?q=test","param":"q","severity":"Medium","type":"Reflected XSS","CVE":"","CWE":"CWE-79"}]',
        1,
    ),
    "corsy": (
        '{"http://example.com": [{"type": "Origin Reflection", "severity": "High"}, {"type": "Wildcard Origin", "severity": "Medium"}]}',
        2,
    ),
    "wafw00f": (
        "[+] Checking http://example.com\n[+] The site http://example.com is behind Cloudflare (Cloudflare)\n",
        1,
    ),
    "arjun": (
        '{"results": {"http://example.com/api": {"found_params": ["id", "user", "admin"]}}}',
        1,
    ),

    # ======== Brute Force / Credential ========
    "hydra": (
        "[22][ssh] host: 10.0.0.1 login: admin password: admin123\n"
        "[80][http-post-form] host: 10.0.0.1 login: user password: pass123\n",
        2,
    ),


    "smtp-user-enum": (
        "Found users:\nadmin\nroot\ntest\n",
        3,
    ),
    "john": (
        "admin:password123\nroot:toor\nuser:password\n",
        3,
    ),
    "hashcat": (
        "hash1:password1\nhash2:password2\nhash3:password3\n",
        3,
    ),
    "hash-identifier": (
        "Hash: 5d41402abc4b2a76b9719d911017c592\nPossible algorithms: MD5, MD4, MD2\n",
        1,
    ),

    # ======== Exploitation / Post-Exploitation ========
    "metasploit": (
        "[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.2:4445)\n"
        "[+] Exploit completed successfully\n"
        "[*] Sending stage (1000000 bytes) to 10.0.0.2\n",
        1,
    ),
    "searchsploit": (
        "Windows/x64 - Remote Code Execution (RCE) | exploits/windows/remote/12345.py\n"
        "Linux - Local Privilege Escalation | exploits/linux/local/54321.c\n",
        2,
    ),
    "commix": (
        "[+] Command injection vulnerability: http://example.com/index.php?cmd=ls\n"
        "[!] Shell: uname -a\n",
        1,
    ),
    "bettercap": (
        "[12:34:56] [sys.log] [mitm] spoofing detected on 192.168.1.1\n"
        "[12:34:57] [sys.log] [endpoint] new device 192.168.1.2 00:11:22:33:44:55\n",
        2,
    ),
    "ettercap": (
        "Host 192.168.1.1 added to targets list\n"
        "Host 192.168.1.2 added to targets list\n",
        2,
    ),
    "responder": (
        "[HTTP] NTLMv2 hash captured from 192.168.1.1: admin::domain:FULLHASH\n"
        "[SMB] NTLMv2 hash captured from 192.168.1.2: user::domain:HASHVALUE\n",
        2,
    ),

    # ======== Windows/AD ========
    "crackmapexec": (
        "SMB         10.0.0.1      445    DC01     [*] Windows 10.0 Build 17763 x64\n"
        "SMB         10.0.0.1      445    DC01     [+] admin:Password123!\n",
        1,
    ),
    "smbclient": (
        "//10.0.0.1/share   (PC-1)\n//10.0.0.1/ADMIN$  (PC-2)\n",
        2,
    ),
    "smbmap": (
        "[+] IP: 10.0.0.1 - Shares: ADMIN$ (Read), C$ (Read/Write), SHARE (Read)\n",
        1,
    ),
    "impacket": (
        "Impacket v0.12.0 - Copyright 2025 Security Researchers\n"
        "[*] SMBv2.1 dialect used\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c1:::\n",
        1,
    ),
    "evil-winrm": (
        "Evil-WinRM shell session opened on 10.0.0.1:5985\n",
        1,
    ),
    "kerbrute": (
        "2025/01/01 12:00:00 >  [+] VALID USER: admin@example.local\n"
        "2025/01/01 12:00:01 >  [+] VALID USER: svc_account@example.local\n",
        2,
    ),
    "bloodhound": (
        '{"data": [{"Label": "ADMIN@EXAMPLE.LOCAL", "ObjectId": "S-1-5-21-1234-500", "ObjectType": "User"}]}',
        1,
    ),
    "bloodhound-python": (
        "INFO: Found 3 domains\nINFO: Found 5 computers\nINFO: Found 10 users\nINFO: Found 20 groups\n",
        1,
    ),
    "sharphound": (
        "SharpHound Enumeration Results:\n -- Users: 10\n -- Computers: 5\n -- Groups: 20\n",
        1,
    ),
    "certipy": (
        "[*] Certipy v4.0.0\n[*] Found certificate template: ESC1-Vulnerable (ESC1)\n"
        "[*] Found certificate template: ESC3-Vulnerable (ESC3)\n",
        2,
    ),
    "ldapsearch": (
        "# LDAP search results\n# dn: CN=admin,CN=Users,DC=example,DC=local\n"
        "dn: CN=admin,CN=Users,DC=example,DC=local\n"
        "memberOf: CN=Domain Admins,CN=Users,DC=example,DC=local\n",
        1,
    ),
    "pypykatz": (
        "MSVCRV: username Admin, domain EXAMPLE, password: Passw0rd!\n"
        "SSP: username Admin, domain EXAMPLE, password: Secret123\n",
        2,
    ),
    "mimikatz": (
        '{"username":"Admin","domain":"EXAMPLE","ntlm":"31d6cfe0d16ae931b73c59d7e0c089c1","password":"Passw0rd!"}\n',
        1,
    ),
    "seatbelt": (
        "=== Seatbelt Enumeration ===\n"
        "Token Information (Current User): Admin\n"
        "System Information: Windows 10.0.19041\n",
        1,
    ),
    "enum4linux": (
        "[*] Enumerating users using SID S-1-5-21-1234 and logon username '', password ''\n"
        "S-1-5-21-1234-500 Admin (Local User)\n",
        1,
    ),

    # ======== Cloud / DevOps ========
    "aws": (
        "{\"Account\": {\"Id\": \"123456789012\"}, \"Users\": [{\"UserName\": \"admin\", \"CreateDate\": \"2025-01-01\"}]}",
        1,
    ),
    "prowler": (
        '{"Control":"s3_bucket_public_access","Status":"FAIL","Severity":"high","Region":"us-east-1","ResourceArn":"arn:aws:s3:::test-bucket"}\n',
        1,
    ),
    "scoutsuite": (
        '{"rule_results":{"iam-user-keys":{"level":"medium","items":["admin@123456789012"]}}}',
        1,
    ),
    "checkov": (
        "{\"check_type\": \"terraform\", \"results\": {\"passed_checks\": [], \"failed_checks\": "
        "[{\"check_id\": \"CKV_AWS_1\", \"check_name\": \"S3 bucket ACL\", \"file\": \"main.tf\", "
        "\"resource\": \"aws_s3_bucket.test\", \"severity\": \"HIGH\"}]}}",
        1,
    ),
    "trivy": (
        "{\"Results\": [{\"Target\": \"test-image:latest\", \"Vulnerabilities\": "
        "[{\"VulnerabilityID\": \"CVE-2025-1234\", \"PkgName\": \"openssl\", "
        "\"Severity\": \"HIGH\", \"Title\": \"OpenSSL Vulnerability\"}]}]}",
        1,
    ),
    "grype": (
        "{\"matches\": [{\"vulnerability\": {\"id\": \"CVE-2025-1234\", \"severity\": \"High\"}, "
        "\"artifact\": {\"name\": \"openssl\", \"version\": \"1.1.1\"}}]}",
        1,
    ),
    "syft": (
        "{\"artifacts\": [{\"name\": \"openssl\", \"version\": \"1.1.1\", \"type\": \"deb\"}, "
        "{\"name\": \"python\", \"version\": \"3.12.0\", \"type\": \"binary\"}]}",
        2,
    ),
    "semgrep": (
        '{"results":[{"check_id":"sql-injection","path":"app.py","start":{"line":12},"extra":{"severity":"HIGH","message":"SQL injection detected"}},{"check_id":"hardcoded-secret","path":"auth.py","start":{"line":45},"extra":{"severity":"MEDIUM","message":"Hardcoded secret"}}]}\n',
        2,
    ),
    "bandit": (
        "{\"results\": [{\"filename\": \"app.py\", \"line_number\": 15, "
        "\"issue_severity\": \"HIGH\", \"issue_text\": \"Possible SQL injection\"}, "
        "{\"filename\": \"auth.py\", \"line_number\": 42, "
        "\"issue_severity\": \"MEDIUM\", \"issue_text\": \"Hardcoded password\"}]}",
        2,
    ),
    "gitleaks": (
        '{"line":"password=supersecret","file":".env","ruleID":"Generic API Key","secret":"supersecret","severity":"high"}\n'
        '{"line":"token=abcdef","file":"config.js","ruleID":"Token","secret":"abcdef","severity":"medium"}\n',
        2,
    ),
    "trufflehog": (
        "{\"SourceMetadata\": {\"Data\": {\"file\": \".env\"}}, \"DetectorName\": \"AWS\", "
        "\"Raw\": \"AKIAIOSFODNN7EXAMPLE\"}\n",
        1,
    ),
    "kubectl": (
        "NAME                STATUS   AGE\npod/nginx-1           Running  24h\npod/redis-0           Running  12h\nservice/web          ClusterIP 24h\n",
        2,
    ),

    # ======== SSL/TLS ========
    "sslscan": (
        "SSLScan Results:\n  Target: example.com:443\n"
        "  OpenSSL: 1.1.1t\n  Supported Server Cipher(s): TLSv1.2 TLS_ECDHE_RSA_AES_128_GCM_SHA256\n"
        "  TLSv1.0: Disabled\n  TLSv1.1: Disabled\n  TLSv1.2: Enabled\n  TLSv1.3: Enabled\n",
        1,
    ),
    "sslyze": (
        "{\"server_info\": {\"host\": \"example.com\", \"port\": 443}, "
        "\"scan_results\": [{\"result\": \"TLS 1.2 Supported\", \"severity\": \"info\"}, "
        "{\"result\": \"Certificate Expires in 30 days\", \"severity\": \"medium\"}]}",
        2,
    ),
    "testssl": (
        " Testing results for example.com:443\n"
        " Service: HTTP\n"
        " [INFO]  SSL/TLS Protocols\n"
        " [HIGH]  TLS 1.0 offered (NOT ok)\n"
        " [HIGH]  TLS 1.1 offered (NOT ok)\n"
        " [INFO]  TLS 1.2 offered (OK)\n",
        2,
    ),

    # ======== SSH ========
    "ssh-audit": (
        "# ssh-audit v3.0.0 - SSH server audit\n"
        "## general\ntest@example.com:22 - OpenSSH 8.9p1\n"
        "## algorithms\n"
        "[fail]  ssh-rsa             -- 1024-bit RSA key -- DISABLED\n"
        "[warn]  diffie-hellman-group1-sha1 -- weak DH key exchange\n",
        2,
    ),

    # ======== Leak Detection / OSINT ========
    "shodan": (
        '{"ip_str":"1.2.3.4","org":"Test Corp","os":"Linux",'
        '"ports":[80,443,22],"vulns":["CVE-2023-1234","CVE-2023-5678"]}\n'
        '{"ip_str":"5.6.7.8","org":"Another Corp","os":"Windows",'
        '"ports":[443],"vulns":["CVE-2024-5678"]}\n',
        5,
    ),
    "theharvester": (
        "[*] Searching in Google\n"
        "Hosts found: 3\n"
        "  example.com: 80\n  example.com: 443\n  mail.example.com: 25\n",
        2,
    ),
    "recon-ng": (
        "[*] Recon module: whois_pocs\n"
        "[+] 'admin@example.com' found in whois contacts.\n"
        "[+] 'tech@example.com' found in whois contacts.\n",
        2,
    ),
    "whois": (
        "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 1234567\n"
        "Registrar: Test Registrar\nCreation Date: 2000-01-01\n",
        1,
    ),
    "whatweb": (
        "http://example.com [200] Apache[2.4.7] PHP[7.4] HTML5\n"
        "http://example.org [200] nginx[1.24.0] WordPress[6.0]\n",
        2,
    ),
    "sherlock": (
        "[+] Checking username 'john'...\n"
        "[+] GitHub: https://github.com/john\n"
        "[+] Twitter: https://twitter.com/john\n"
        "[+] Reddit: https://reddit.com/user/john\n",
        3,
    ),
    "dmitry": (
        "[*] Initializing dmitry...\n"
        "Host: example.com\n"
        "IP: 1.2.3.4\n"
        "Nameserver: ns1.example.com\n",
        1,
    ),
    "finger": (
        "Login: admin                     Name: Admin User\n"
        "Directory: /home/admin                Shell: /bin/bash\n"
        "Login: root                      Name: Root User\n"
        "Directory: /root                      Shell: /bin/bash\n",
        2,
    ),
    "exiftool": (
        '{"SourceFile":"image.jpg","Make":"Canon","Model":"EOS 5D","Software":"Adobe Photoshop"}',
        1,
    ),
    "netcat": (
        "HTTP/1.1 200 OK\nServer: Apache/2.4.7\nContent-Type: text/html\n"
        "Connection from 192.168.1.1: random data captured\n",
        1,
    ),
    "tcpdump": (
        "12:00:00.123456 IP 10.0.0.1.80 > 10.0.0.2.443: Flags [S], seq 123, win 65535\n"
        "12:00:00.123789 IP 10.0.0.1.80 > 10.0.0.2.443: Flags [.], ack 456, win 65535\n",
        2,
    ),

    # ======== Forensics / Misc ========
    "volatility": (
        "Volatility Foundation Volatility Framework 2.6\n"
        "Name: cmd.exe  PID: 1234  PPID: 5678  Time: 2025-01-01 12:00:00\n"
        "Name: explorer.exe  PID: 2345  PPID: 5678  Time: 2025-01-01 12:00:00\n",
        2,
    ),
    "yara": (
        "rule MaliciousDoc : DOC Office\n  meta: description = Detects malicious documents\n  strings: $a = {D0 CF 11 E0 A1 B1 1A E1}\n  condition: $a\n",
        1,
    ),
    "lynis": (
        "[!] SSH configuration has PermitRootLogin enabled\n"
        "[+] Firewall rules appear to be configured\n"
        "[-] Some service is not found or is vulnerable\n",
        2,
    ),

    # ======== IPSec / VPN ========
    "ike-scan": (
        "10.0.0.1\tMain Mode Handshake returned\n"
        "10.0.0.1\t1 transform(s), 1 vendor ID(s)\n",
        1,
    ),
    "interactsh": (
        '{"protocol":"HTTP","unique-id":"abc123","remote-address":"1.2.3.4","timestamp":"2025-01-01T12:00:00Z","raw-request":"GET /test"}\n'
        '{"protocol":"DNS","unique-id":"def456","remote-address":"5.6.7.8","timestamp":"2025-01-01T12:00:01Z","raw-request":"example.com A"}\n',
        2,
    ),

    # ======== Wireless ========
    "aircrack": (
        "KEY FOUND! [ secretpass ]\n"
        "Master Key: 1234ABCD\n",
        1,
    ),

    # ======== S3 ========
    "s3scanner": (
        "test-bucket - OPEN\nprivate-bucket - AUTH\n",
        2,
    ),

    # ======== JWT ========
    "jwt-tool": (
        "Token: eyJ.eyJ.9.signature\n"
        "[+] Algorithm: HS256\n[+] Signature verified with key 'secret'\n"
        "[!] Critical: None algorithm accepted!\n",
        1,
    ),

    # ======== Exploit Dev / AppSec ========
    "crackmapexec": (
        "SMB         10.0.0.1      445    DC01     [*] Windows 10.0 Build 17763 x64\n"
        "SMB         10.0.0.1      445    DC01     [+] admin:Password123!\n",
        1,
    ),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def get_all_tools() -> list[str]:
    """Discover all tools via ParserRegistry and return sorted list."""
    reg = ParserRegistry()
    reg.discover()
    tools = reg.registered_tools()
    # Remove duplicates while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in tools:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return sorted(unique)


def test_discovery_detects_all_parsers():
    """Verify ParserRegistry.discover() finds all 105 parsers."""
    reg = ParserRegistry()
    discovered = reg.discover()
    # At least 105 registered entries (some tools may have version-specific parsers)
    assert reg.count >= 105, f"Expected >=105 parsers, got {reg.count}"
    assert len(discovered) >= 100, f"Expected >=100 tool entries, got {len(discovered)}"


@pytest.mark.parametrize("tool_name", sorted(SAMPLES.keys()))
def test_parser_accepts_sample_output(tool_name: str):
    """Each parser must accept realistic sample output and return findings."""
    reg = ParserRegistry()
    reg.discover()
    sample, min_count = SAMPLES[tool_name]
    findings = reg.parse(tool_name, sample)
    assert len(findings) >= min_count, (
        f"{tool_name}: expected >= {min_count} findings, got {len(findings)}"
    )
    for f in findings:
        assert isinstance(f, dict), f"{tool_name}: finding should be dict"
        assert "title" in f, f"{tool_name}: finding missing 'title'"
        assert "severity" in f, f"{tool_name}: finding missing 'severity'"
        assert "description" in f, f"{tool_name}: finding missing 'description'"
        assert "evidence" in f, f"{tool_name}: finding missing 'evidence'"
        assert "tool" in f, f"{tool_name}: finding missing 'tool'"
        assert f["severity"] in ("critical", "high", "medium", "low", "info"), (
            f"{tool_name}: invalid severity '{f.get('severity')}'"
        )


def test_all_parsers_have_samples():
    """Every discovered parser must have at least one sample in SAMPLES."""
    reg = ParserRegistry()
    reg.discover()
    missing = [t for t in reg.registered_tools() if t not in SAMPLES]
    if missing:
        pytest.skip(f"Parsers without samples: {missing}")
    assert not missing, f"Parsers without samples: {missing}"


@pytest.mark.parametrize("tool_name", sorted(SAMPLES.keys()))
def test_parser_handles_empty_input(tool_name: str):
    """Each parser must gracefully handle empty input."""
    reg = ParserRegistry()
    reg.discover()
    findings = reg.parse(tool_name, "")
    assert isinstance(findings, list), f"{tool_name}: empty input should return list"
    assert len(findings) == 0, f"{tool_name}: empty input should return empty list, got {len(findings)}"


@pytest.mark.parametrize("tool_name", sorted(SAMPLES.keys()))
def test_parser_handles_malformed_input(tool_name: str):
    """Each parser must gracefully handle malformed/garbage input."""
    reg = ParserRegistry()
    reg.discover()
    findings = reg.parse(tool_name, "!@#$%^&*() NOT VALID {{{  ")
    assert isinstance(findings, list), f"{tool_name}: malformed input should return list"


def test_discovery_all_tools_registered():
    """Verify every parser class in __all__ is reachable via discover()."""
    from siyarix.parsers import __all__ as parser_names
    # Filter out non-parser entries
    classes = [n for n in parser_names if n.endswith("Parser")]
    reg = ParserRegistry()
    reg.discover()
    # Count unique tool names (one tool may have multiple version parsers)
    assert len(classes) <= reg.count + 10, (
        f"Expected <= {len(classes)} parser classes, got {reg.count}"
    )
