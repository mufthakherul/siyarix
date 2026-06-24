"""Evaluation: 150+ reconnaissance commands from basic to advanced."""

from siyarix import RegistryPlanner

AVAILABLE_TOOLS = [
    "nmap", "masscan", "rustscan", "naabu",
    "gobuster", "ffuf", "dirb", "dirsearch",
    "whatweb", "wappalyzer", "builtwith",
    "nuclei", "nikto", "wapiti", "skipfish",
    "hydra", "medusa", "ncrack", "patator",
    "subfinder", "amass", "sublist3r", "assetfinder",
    "curl", "wget", "httpie",
    "dig", "nslookup", "host",
    "aircrack-ng", "hashcat", "john",
    "sqlmap", "jSQL", "sqlninja",
    "whois", "openssl", "eyewitness",
    "tracert", "traceroute", "responder",
    "impacket", "impacket-secretsdump", "impacket-GetUserSPNs", "impacket-GetNPUsers",
    "bloodhound-python", "searchsploit",
    "shodan", "censys",
    "theHarvester", "gau", "waybackurls",
    "httpx", "katana", "gospider",
    "uncover", "subjack",
    "trufflehog", "gitleaks",
    "sherlock", "holehe", "maigret",
    "dnsx", "massdns", "puredns",
    "arjun", "paramspider",
    "cloud_enum", "scoutsuite", "prowler",
    "interactsh", "testssl.sh", "ssllabs-scan",
    "bluetoothctl", "crackmapexec", "netexec", "enum4linux",
]


def check_plan(goal: str, expected_tools: list[str], min_steps: int = 1,
               max_steps: int | None = None) -> bool:
    p = RegistryPlanner()
    p.build_index(AVAILABLE_TOOLS)
    plan = p.decompose_goal(goal)
    actual_tools = [s.tool for s in plan.steps]
    step_count = len(plan.steps)
    if step_count < min_steps:
        return False
    if max_steps and step_count > max_steps:
        return False
    for et in expected_tools:
        if et not in actual_tools:
            return False
    return True


def run_tests():
    passed = 0
    failed = 0
    failures = []

    # Format: (command, [expected tools], min_steps, max_steps)

    tests = [
        # ============ SECTION 1: BASIC RECON (20) ============
        ("check headers of https://example.com", ["curl"], 1, 1),
        ("scan ports on 10.0.0.1", ["nmap"], 1, 1),
        ("dns enumeration on example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("whois lookup for example.com", ["whois"], 1, 1),
        ("find tech stack on example.com", ["whatweb"], 1, 1),
        ("check http://example.com security headers", ["curl", "openssl"], 2, 2),
        ("wordpress scan on https://example.com", ["wpscan"], 1, 1),
        ("cms detection on https://example.com", ["whatweb"], 1, 1),
        ("enumerate directories on https://example.com", ["gobuster"], 1, 1),
        ("fuzz endpoints on https://example.com", ["ffuf"], 1, 1),
        ("ping sweep on 10.0.0.0/24", ["nmap"], 1, 1),
        ("find live hosts on 192.168.1.0/24", ["nmap"], 1, 1),
        ("tcp scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("udp scan on 10.0.0.1", ["nmap"], 1, 1),
        ("service version scan on 10.0.0.1", ["nmap"], 1, 1),
        ("ssl check on https://example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("tls cipher scan on example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("certificate info for https://example.com", ["openssl"], 1, 1),
        ("mx record lookup for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("dns resolution for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),

        # ============ SECTION 2: WEB RECON (20) ============
        ("cors check on https://example.com", ["curl", "curl"], 2, 2),
        ("cookie analysis on https://example.com", ["curl"], 1, 1),
        ("redirect chain for https://example.com", ["curl"], 1, 1),
        ("waf detection on https://example.com", ["nmap"], 1, 1),
        ("cdn detection for https://example.com", ["curl"], 1, 1),
        ("api endpoint check on https://example.com", ["curl"], 1, 1),
        ("graphql introspection on https://example.com", ["curl"], 1, 1),
        ("swagger discovery on https://example.com", ["curl"], 1, 1),
        ("websocket upgrade check on https://example.com", ["curl"], 1, 1),
        ("check for exposed .git on https://example.com", ["curl"], 1, 1),
        ("check oauth endpoints on https://example.com", ["nmap"], 1, 1),
        ("exposed panel scan on https://example.com", ["nuclei"], 1, 1),
        ("ssrf check on https://example.com", ["nuclei"], 1, 1),
        ("idor scan on https://example.com/api", ["nuclei"], 1, 1),
        ("lfi scan on https://example.com/page", ["nuclei"], 1, 1),
        ("rfi scan on https://example.com/page", ["nuclei"], 1, 1),
        ("clickjacking test on https://example.com", ["curl"], 1, 1),
        ("deserialization check on https://example.com", ["nuclei"], 1, 1),
        ("open redirect scan on https://example.com", ["nuclei"], 1, 1),
        ("broken access control check on https://example.com", ["nuclei"], 1, 1),

        # ============ SECTION 3: DNS RECON (15) ============
        ("full dns recon on example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("dns zone transfer on example.com", ["dig"], 1, 1),
        ("axfr query for example.com", ["dig"], 1, 1),
        ("nameserver lookup for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("subdomain enumeration on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),
        ("amass subdomain brute on example.com", ["amass"], 1, 1),
        ("dns record check for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("subdomain discovery for example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),
        ("dnsrecon on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),
        ("dns resolution check on example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("reverse dns lookup on 8.8.8.8", ["dig"], 1, 1),
        ("dns probe with dnsx on example.com", ["dnsx"], 1, 1),
        ("massdns on example.com with resolvers", ["massdns"], 1, 1),
        ("puredns resolve for example.com", ["puredns"], 1, 1),
        ("passive subdomain enum on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),

        # ============ SECTION 4: NETWORK RECON (15) ============
        ("full port scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("stealth scan on 10.0.0.1", ["nmap"], 1, 1),
        ("host discovery on 192.168.1.0/24", ["nmap"], 1, 1),
        ("snmp enumeration on 10.0.0.1", ["nmap"], 1, 1),
        ("smtp server enum on mail.example.com", ["nmap"], 1, 1),
        ("imap enumeration on 10.0.0.1", ["nmap"], 1, 1),
        ("traceroute to example.com", ["tracert"], 1, 1),
        ("tracert to 8.8.8.8", ["tracert"], 1, 1),
        ("masscan full sweep on 10.0.0.0/16", ["masscan"], 1, 1),
        ("fast port scan on 10.0.0.1 top 1000", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("aggressive scan on 10.0.0.1 all ports", ["nmap"], 1, 1),
        ("ipmi recon on 10.0.0.1", ["nmap"], 1, 1),
        ("live host discovery on 10.0.0.0/24", ["nmap"], 1, 1),
        ("check open ports on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("up hosts scan on 172.16.0.0/24", ["nmap"], 1, 1),

        # ============ SECTION 5: SSL/TLS RECON (10) ============
        ("full ssl audit on https://example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("tls cipher suite check on example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("heartbleed check on https://example.com", ["nmap"], 1, 1),
        ("ssl certificate chain validation for example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("ssl labs scan for example.com", ["ssllabs-scan"], 1, 1),
        ("testssl full check on example.com", ["testssl.sh"], 1, 1),
        ("certificate transparency search for example.com", ["curl"], 1, 1),
        ("crtsh lookup for example.com", ["curl"], 1, 1),
        ("crt.sh certificate search for example.com", ["curl"], 1, 1),
        ("ssl cipher enum on example.com:443", ["openssl", "nmap", "nmap"], 3, 3),

        # ============ SECTION 6: OSINT & EXTERNAL RECON (20) ============
        ("full osint recon on example.com", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 7, 7),
        ("open source recon on example.com", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 7, 7),
        ("theHarvester email osint on example.com", ["theHarvester"], 1, 1),
        ("shodan internet search for example.com", ["shodan"], 1, 1),
        ("censys search for example.com", ["censys"], 1, 1),
        ("the harvester recon for example.com", ["theHarvester"], 1, 1),
        ("external attack surface recon on example.com", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 6, 6),
        ("passive reconnaissance on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 5, 5),
        ("passive scan on 10.0.0.1", ["whatweb", "subfinder", "dig", "whois", "openssl"], 5, 5),
        ("google dorking for example.com", ["curl"], 1, 1),
        ("uncover search for example.com", ["uncover"], 1, 1),
        ("wayback machine urls for example.com", ["waybackurls"], 1, 1),
        ("gau url discovery for example.com", ["gau"], 1, 1),
        ("sherlock username search for johndoe", ["sherlock"], 1, 1),
        ("holehe email check for user@example.com", ["holehe"], 1, 1),
        ("maigret user search for johndoe", ["maigret"], 1, 1),
        ("whois domain registration lookup for example.com", ["whois"], 1, 1),
        ("reverse whois search for example.com", ["whois"], 1, 1),
        ("asn ownership recon on AS12345", ["whois"], 1, 1),
        ("email osint harvesting for example.com", ["theHarvester"], 1, 1),

        # ============ SECTION 7: ACTIVE DIRECTORY RECON (15) ============
        ("active directory assessment on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("ad recon on domain controller 10.0.0.5", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("ldap enum on 10.0.0.1", ["nmap"], 1, 1),
        ("kerberos user enum on 10.0.0.1", ["nmap"], 1, 1),
        ("smb share enum on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("smb enum on windows server 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("netbios scan on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("responder capture on eth0", ["responder"], 1, 1),
        ("impacket enumeration on dc.example.com", ["impacket"], 1, 1),
        ("enum4linux recon on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("ldap domain dump on dc.example.com", ["nmap"], 1, 1),
        ("samba recon on 10.0.0.1", ["nmap"], 1, 1),
        ("crackmapexec smb enum on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("netexec ad recon on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("adcs enumeration on dc.example.com", ["nmap"], 1, 1),

        # ============ SECTION 8: CLOUD RECON (15) ============
        ("cloud audit on https://example.com", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("aws metadata check on http://169.254.169.254", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("azure metadata check on 169.254.169.254", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("gcp metadata check on metadata.google.internal", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("cloudfront detection for example.com", ["curl"], 1, 1),
        ("s3 bucket enumeration for example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("cloud storage audit on example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("scoutsuite cloud audit for aws", ["scoutsuite"], 1, 1),
        ("prowler aws security audit", ["prowler"], 1, 1),
        ("cdn detection for cdn.example.com", ["curl"], 1, 1),
        ("azure blob check on https://test.blob.core.windows.net", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("gcp bucket scan on storage.googleapis.com", ["curl", "whatweb", "dig", "openssl"], 4, 4),
        ("docker discovery on 10.0.0.1:2375", ["nmap"], 1, 1),
        ("kubernetes discovery on k8s.example.com", ["nmap"], 1, 1),
        ("jenkins discovery on jenkins.example.com", ["nmap"], 1, 1),

        # ============ SECTION 9: ADVANCED WEB RECON (15) ============
        ("http probe with httpx on https://example.com", ["httpx"], 1, 1),
        ("web crawl with katana on https://example.com", ["katana"], 1, 1),
        ("spider with gospider on https://example.com", ["gospider"], 1, 1),
        ("subdomain takeover check on example.com", ["subjack"], 1, 1),
        ("arjun parameter discovery on https://example.com", ["arjun"], 1, 1),
        ("paramspider mining on example.com", ["paramspider"], 1, 1),
        ("directory busting on https://example.com", ["gobuster"], 1, 1),
        ("fuzz with ffuf on https://example.com/FUZZ", ["ffuf"], 1, 1),
        ("screenshot web on https://example.com", ["eyewitness"], 1, 1),
        ("trufflehog secret scan on repo", ["trufflehog"], 1, 1),
        ("gitleaks scan on repo", ["gitleaks"], 1, 1),
        ("web app scan on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 6, 6),
        ("cms detection on https://example.com", ["whatweb"], 1, 1),
        ("nikto vulnerability scan on https://example.com", ["nikto"], 1, 1),
        ("exposed panels scan on https://example.com", ["nuclei"], 1, 1),

        # ============ SECTION 10: DATABASE & MIDDLEWARE RECON (12) ============
        ("redis enumeration on 10.0.0.1:6379", ["nmap"], 1, 1),
        ("mongodb enum on 10.0.0.1:27017", ["nmap"], 1, 1),
        ("mysql scan on 10.0.0.1:3306", ["nmap"], 1, 1),
        ("mssql discovery on 10.0.0.1:1433", ["nmap"], 1, 1),
        ("elasticsearch discovery on 10.0.0.1:9200", ["curl"], 1, 1),
        ("memcached discovery on 10.0.0.1:11211", ["nmap"], 1, 1),
        ("kafka discovery on 10.0.0.1:9092", ["nmap"], 1, 1),
        ("activemq discovery on 10.0.0.1:61616", ["nmap"], 1, 1),
        ("cassandra scan on 10.0.0.1:9042", ["nmap"], 1, 1),
        ("postgresql enum on 10.0.0.1:5432", ["nmap"], 1, 1),
        ("rabbitmq discovery on 10.0.0.1:5672", ["nmap"], 1, 1),
        ("graphql endpoint check on https://example.com/graphql", ["curl"], 1, 1),

        # ============ SECTION 11: MULTI-STEP & COMPOUND RECON (15) ============
        # Multi-intent with "then" splits correctly
        ("enumerate subdomains then scan ports on example.com", ["subfinder", "nmap"], 2, 2),
        ("whois lookup then ssl check on example.com", ["whois", "openssl"], 2, 2),
        # Single intent with "and" picks best template
        ("find tech stack and check headers on https://example.com", ["whatweb"], 1, 1),
        ("dns recon and port scan on example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("subdomain enum and web screenshot on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),
        ("check ports and tech stack on example.com", ["whatweb"], 1, 1),
        ("full recon on example.com", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 8, 8),
        ("comprehensive recon on example.com", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 8, 8),
        ("thorough recon on example.com", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 8, 8),
        ("full recon and vuln scan on example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 4, 4),
        ("passive recon and dns enum on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 6, 6),
        ("network scan and service detection on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("web audit and directory enum on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 6, 6),
        ("smb enum and ldap check on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 4, 4),
        ("cloud audit and cdn check on https://example.com", ["curl", "whatweb", "dig", "openssl"], 4, 4),

        # ============ SECTION 12: SPECIALIZED / EDGE CASE RECON (12) ============
        ("quick check on https://example.com", ["curl"], 1, 1),
        ("stealth network scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("interactsh oob testing client", ["interactsh"], 1, 1),
        ("httpx probe on https://example.com", ["httpx"], 1, 1),
        ("dnsx query on example.com", ["dnsx"], 1, 1),
        ("waybackurls discovery on example.com", ["waybackurls"], 1, 1),
        ("gau wayback url discovery for example.com", ["gau"], 1, 1),
        ("broken access control scan on https://example.com", ["nuclei"], 1, 1),
        ("zone transfer test on example.com", ["dig"], 1, 1),
        ("oauth endpoint enum on https://example.com", ["nmap"], 1, 1),
        ("smtp user enum on mail.example.com", ["nmap"], 1, 1),
        ("snmpwalk on 10.0.0.1 community public", ["nmap"], 1, 1),

        # ============ SECTION 13: CVE & VULN-SPECIFIC RECON (12) ============
        ("log4j check on https://example.com", ["nuclei"], 1, 1),
        ("heartbleed test on https://example.com", ["nmap"], 1, 1),
        ("shellshock scan on https://example.com", ["nuclei"], 1, 1),
        ("spring4shell check on https://example.com", ["nuclei"], 1, 1),
        ("struts vulnerability scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 4, 4),
        ("searchsploit apache 2.4.49", ["searchsploit"], 1, 1),
        ("exploit search for wordpress 5.8", ["searchsploit"], 1, 1),
        ("cve scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 4, 4),
        ("vuln scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 4, 4),
        ("check cve-2021-44228 on https://example.com", ["nuclei"], 1, 1),
        ("check cve-2014-0160 on https://example.com", ["nmap"], 1, 1),
        ("check cve-2017-5638 on https://example.com", ["nuclei"], 1, 1),

        # ============ SECTION 14: PARAMETERIZED RECON (8) ============
        ("port scan on 10.0.0.1 ports 80,443,8080", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("dns enumeration on example.com with verbose output", ["dig", "subfinder", "amass", "whois"], 4, 4),
        ("whois lookup on example.com with json output", ["whois"], 1, 1),
        ("fast port scan on 10.0.0.1 with nmap", ["nmap"], 1, 1),
        ("stealth tcp scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),
        ("nmap aggressive scan on 10.0.0.1 all ports", ["nmap"], 1, 1),
        ("detailed ssl audit on https://example.com with cipher enum", ["openssl", "nmap", "nmap"], 3, 3),
        ("full port scan with service version on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 5, 5),

        # ============ SECTION 15: SEARCH ENGINE & CERTIFICATE RECON (6) ============
        ("searchsploit search for kernel exploits", ["searchsploit"], 1, 1),
        ("exploit search for remote code execution", ["searchsploit"], 1, 1),
        ("certificate transparency log inspection for example.com", ["curl"], 1, 1),
        ("crtsh domain search for example.com", ["curl"], 1, 1),
        ("ssl certificate info for https://example.com", ["openssl", "nmap", "nmap"], 3, 3),
        ("certificate chain validation for example.com", ["openssl"], 1, 1),
    ]

    total = len(tests)

    for i, (cmd, expected, min_steps, max_steps) in enumerate(tests, 1):
        try:
            result = check_plan(cmd, expected, min_steps, max_steps)
            if result:
                passed += 1
            else:
                failed += 1
                failures.append(cmd)
        except Exception as e:
            failed += 1
            failures.append(f"{cmd} (ERROR: {e})")

    print(f"\n{'='*60}")
    print(f"RECON EVALUATION RESULTS: {passed} passed, {failed} failed out of {total}")
    print(f"{'='*60}")

    if failures:
        print(f"\nFAILED COMMANDS ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")

        print("\nDebug: checking actual plans...")
        p = RegistryPlanner()
        p.build_index(AVAILABLE_TOOLS)
        for cmd in failures[:15]:
            try:
                plan = p.decompose_goal(cmd)
                tools = [s.tool for s in plan.steps]
                print(f"  {cmd:60s} -> steps={len(tools):2d}, tools={tools}")
            except Exception as e:
                print(f"  {cmd:60s} -> ERROR: {e}")

    return passed, failed, total


if __name__ == "__main__":
    import sys
    passed, failed, total = run_tests()
    sys.exit(0 if failed == 0 else 1)