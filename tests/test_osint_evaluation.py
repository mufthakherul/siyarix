#!/usr/bin/env python3
"""OSINT-focused NLP/planner evaluation — 160 commands, basic to advanced."""

import sys

sys.stdout.reconfigure(encoding="utf-8")

from siyarix import RegistryPlanner

AVAILABLE_TOOLS = [
    "nmap",
    "masscan",
    "rustscan",
    "naabu",
    "gobuster",
    "ffuf",
    "dirb",
    "dirsearch",
    "whatweb",
    "wappalyzer",
    "builtwith",
    "nuclei",
    "nikto",
    "wapiti",
    "skipfish",
    "hydra",
    "medusa",
    "ncrack",
    "patator",
    "subfinder",
    "amass",
    "sublist3r",
    "assetfinder",
    "curl",
    "wget",
    "httpie",
    "dig",
    "nslookup",
    "host",
    "aircrack-ng",
    "hashcat",
    "john",
    "sqlmap",
    "jSQL",
    "sqlninja",
    "whois",
    "openssl",
    "eyewitness",
    "tracert",
    "traceroute",
    "responder",
    "impacket",
    "impacket-secretsdump",
    "impacket-GetUserSPNs",
    "impacket-GetNPUsers",
    "bloodhound-python",
    "searchsploit",
    "shodan",
    "censys",
    "theHarvester",
    "gau",
    "waybackurls",
    "httpx",
    "katana",
    "gospider",
    "uncover",
    "subjack",
    "trufflehog",
    "gitleaks",
    "sherlock",
    "holehe",
    "maigret",
    "dnsx",
    "massdns",
    "puredns",
    "arjun",
    "paramspider",
    "cloud_enum",
    "scoutsuite",
    "prowler",
    "interactsh",
    "testssl.sh",
    "ssllabs-scan",
    "bluetoothctl",
    "crackmapexec",
    "netexec",
    "enum4linux",
    "wpscan",
]


def check_plan(planner, goal, expected_tools, min_steps=1, max_steps=None):
    """Check that the planner returns a valid plan for the given goal."""
    plan = planner.decompose_goal(goal)
    actual_tools = [s.tool for s in plan.steps]
    step_count = len(plan.steps)

    if step_count < min_steps:
        return False, f"step_count {step_count} < min_steps {min_steps}"
    if max_steps and step_count > max_steps:
        return False, f"step_count {step_count} > max_steps {max_steps}"
    for et in expected_tools:
        if et not in actual_tools:
            return False, f"expected tool {et!r} not in {actual_tools}"
    return True, f"OK steps={step_count} tools={actual_tools}"


# ==============================================================================
# OSINT COMMANDS — 160 total, organized by category
# ==============================================================================
OSINT_COMMANDS = [
    # ------------------------------------------------------------------
    # 1. WHOIS & Domain Registration (12)
    # ------------------------------------------------------------------
    ("whois lookup for example.com", ["whois"], 1, 1),
    ("domain whois on example.com", ["whois"], 1, 1),
    ("whois registration for example.com", ["whois"], 1, 1),
    ("reverse whois for example.com", ["whois"], 1, 1),
    ("asn lookup for 8.8.8.8", ["whois"], 1, 1),
    ("asn recon on AS15169", ["whois"], 1, 1),
    ("ip whois for 8.8.8.8", ["whois"], 1, 1),
    ("domain registration check example.com", ["whois"], 1, 1),
    ("whois domain ownership for example.com", ["whois"], 1, 1),
    ("rdap lookup for 8.8.8.8", ["whois"], 1, 1),
    ("registrar information for example.com", ["whois"], 1, 1),
    ("domain registration info for example.com", ["whois"], 1, 1),
    # ------------------------------------------------------------------
    # 2. DNS Reconnaissance (18)
    # ------------------------------------------------------------------
    ("dns enumeration on example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    ("dns record check for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    ("mx record lookup for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    ("dns resolution for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    ("nameserver lookup for example.com", ["dig", "subfinder", "amass", "whois"], 4, 4),
    ("dns zone transfer on example.com", ["dig"], 1, 1),
    ("axfr query for example.com", ["dig"], 1, 1),
    ("dns a record check for example.com", ["dig"], 1, 1),
    ("dns txt record enumeration for example.com", ["dig"], 1, 1),
    ("dns cname lookup for example.com", ["dig"], 1, 1),
    ("reverse dns lookup on 8.8.8.8", ["dig"], 1, 1),
    ("dns ptr record for 8.8.8.8", ["dig"], 1, 1),
    ("dns soa record for example.com", ["dig"], 1, 1),
    ("aaaa record check for example.com", ["dig"], 1, 1),
    ("dnssec check for example.com", ["dig"], 1, 1),
    ("spf record lookup for example.com", ["dig"], 1, 1),
    ("dmarc record check for example.com", ["dig"], 1, 1),
    ("dns cache snooping on 8.8.8.8", ["dig"], 1, 1),
    # ------------------------------------------------------------------
    # 3. Subdomain Enumeration (12)
    # ------------------------------------------------------------------
    (
        "subdomain enumeration on example.com",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "subdomain discovery for example.com",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    ("amass subdomain brute on example.com", ["amass"], 1, 1),
    ("amass intel on example.com", ["amass"], 1, 1),
    ("amass enum for example.com", ["amass"], 1, 1),
    ("subfinder passive enum on example.com", ["subfinder"], 1, 1),
    ("sublist3r subdomain search for example.com", ["sublist3r"], 1, 1),
    ("assetfinder subdomain discovery for example.com", ["assetfinder"], 1, 1),
    (
        "passive subdomain enum on example.com",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    (
        "dns brute force subdomain on example.com",
        ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"],
        6,
        6,
    ),
    ("subdomain takeover check on example.com", ["subjack"], 1, 1),
    ("check subdomain takeover on example.com", ["subjack"], 1, 1),
    # ------------------------------------------------------------------
    # 4. Certificate Transparency (8)
    # ------------------------------------------------------------------
    ("certificate transparency search for example.com", ["curl"], 1, 1),
    ("crtsh lookup for example.com", ["curl"], 1, 1),
    ("crt.sh search for example.com", ["curl"], 1, 1),
    ("certificate log inspection for example.com", ["openssl"], 1, 1),
    ("crtsh certificate search for example.com", ["curl"], 1, 1),
    ("certificate transparency logs for example.com", ["curl"], 1, 1),
    ("crt.sh domain search for example.com", ["curl"], 1, 1),
    ("ssl certificate transparency for example.com", ["openssl", "nmap", "nmap"], 3, 3),
    # ------------------------------------------------------------------
    # 5. Email OSINT (10)
    # ------------------------------------------------------------------
    ("theHarvester email osint on example.com", ["theHarvester"], 1, 1),
    ("the harvester harvest on example.com", ["theHarvester"], 1, 1),
    ("email osint harvesting for example.com", ["theHarvester"], 1, 1),
    ("email recon on example.com", ["theHarvester", "dig", "nmap", "dig"], 4, 4),
    ("email harvest on example.com", ["theHarvester", "dig", "nmap", "dig"], 4, 4),
    ("smtp enum on mail.example.com", ["theHarvester", "dig", "nmap", "dig"], 4, 4),
    ("mail server discovery for example.com", ["theHarvester", "dig", "nmap", "dig"], 4, 4),
    ("holehe email check for user@example.com", ["holehe"], 1, 1),
    ("holehe email check for user@example.com", ["holehe"], 1, 1),
    ("theHarvester email search on example.com", ["theHarvester"], 1, 1),
    # ------------------------------------------------------------------
    # 6. Username & Social Media OSINT (10)
    # ------------------------------------------------------------------
    ("sherlock username search for johndoe", ["sherlock"], 1, 1),
    ("maigret user search for johndoe", ["maigret"], 1, 1),
    ("social media lookup for johndoe", ["sherlock"], 1, 1),
    ("social media lookup for johndoe across platforms", ["sherlock"], 1, 1),
    ("social network search for johndoe on social media", ["sherlock"], 1, 1),
    ("find all accounts for johndoe across networks", ["sherlock"], 1, 1),
    (
        "digital footprint search for johndoe online",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    ("osint username reconnaissance for johndoe on social medias", ["sherlock"], 1, 1),
    ("identity osint on johndoe across all platforms", ["sherlock"], 1, 1),
    # ------------------------------------------------------------------
    # 7. URL Discovery & Wayback Machine (10)
    # ------------------------------------------------------------------
    ("wayback machine urls for example.com", ["waybackurls"], 1, 1),
    ("gau url discovery for example.com", ["gau"], 1, 1),
    ("get all urls for example.com", ["gau"], 1, 1),
    ("waybackurls discovery on example.com", ["waybackurls"], 1, 1),
    ("gau wayback url discovery for example.com", ["gau"], 1, 1),
    ("wayback machine endpoints for example.com", ["waybackurls"], 1, 1),
    ("historic urls for example.com from archive", ["gau"], 1, 1),
    ("url enumeration on example.com from wayback", ["waybackurls"], 1, 1),
    ("fetch all wayback urls for example.com", ["waybackurls"], 1, 1),
    ("waybackurls discovery on example.com", ["waybackurls"], 1, 1),
    # ------------------------------------------------------------------
    # 8. Web Probing & Crawling (12)
    # ------------------------------------------------------------------
    ("httpx probe on https://example.com", ["httpx"], 1, 1),
    ("http probe on example.com", ["httpx"], 1, 1),
    ("web crawl with katana on https://example.com", ["katana"], 1, 1),
    ("spider with gospider on https://example.com", ["gospider"], 1, 1),
    ("httpx live host probing for example.com", ["httpx"], 1, 1),
    ("katana crawl example.com for endpoints", ["katana"], 1, 1),
    ("gospider web spider on https://example.com", ["gospider"], 1, 1),
    ("probe all subdomains for example.com with httpx", ["httpx"], 1, 1),
    ("crawl and spider example.com", ["katana"], 1, 1),
    ("httpx tech detection on https://example.com", ["httpx"], 1, 1),
    ("katana url discovery on example.com", ["katana"], 1, 1),
    ("gospider content discovery on https://example.com", ["gospider"], 1, 1),
    # ------------------------------------------------------------------
    # 9. Parameter Discovery (8)
    # ------------------------------------------------------------------
    ("arjun parameter discovery on https://example.com", ["arjun"], 1, 1),
    ("paramspider mining on example.com", ["paramspider"], 1, 1),
    ("discover http parameter on https://example.com", ["arjun"], 1, 1),
    ("param mining on example.com", ["arjun"], 1, 1),
    ("arjun find hidden params on https://example.com", ["arjun"], 1, 1),
    ("parameter discovery scan on example.com", ["arjun"], 1, 1),
    ("url parameter enumeration on https://example.com", ["arjun"], 1, 1),
    ("get params from url on https://example.com", ["arjun"], 1, 1),
    # ------------------------------------------------------------------
    # 10. Cloud & Infrastructure OSINT (10)
    # ------------------------------------------------------------------
    ("cloud_enum storage scan for example", ["cloud_enum"], 1, 1),
    ("scoutsuite cloud audit for aws", ["scoutsuite"], 1, 1),
    ("prowler aws security audit", ["prowler"], 1, 1),
    ("cloud_enum storage scan for example", ["cloud_enum"], 1, 1),
    ("aws bucket discovery on example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
    ("azure cloud storage check for example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
    ("gcp bucket enumeration on example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
    ("cloud_enum multi cloud scan for example", ["cloud_enum"], 1, 1),
    ("s3 bucket osint for example", ["curl", "whatweb", "dig", "openssl"], 4, 4),
    ("cloud_enum discovery on example", ["cloud_enum"], 1, 1),
    # ------------------------------------------------------------------
    # 11. Shodan / Censys / Uncover (10)
    # ------------------------------------------------------------------
    ("shodan search for example.com on internet", ["shodan"], 1, 1),
    ("shodan internet device search for example.com", ["shodan"], 1, 1),
    ("censys search for example.com certificates", ["censys"], 1, 1),
    ("censys ip lookup for 8.8.8.8", ["censys"], 1, 1),
    ("shodan port scan history for 8.8.8.8", ["shodan"], 1, 1),
    ("shodan honeypot check for 8.8.8.8", ["shodan"], 1, 1),
    ("uncover search for example.com", ["uncover"], 1, 1),
    ("shodan and censys search on example.com", ["shodan"], 1, 1),
    ("shodan internet search for example.com", ["shodan"], 1, 1),
    ("attack surface discovery with shodan for example.com", ["shodan"], 1, 1),
    # ------------------------------------------------------------------
    # 12. Secret Scanning (8)
    # ------------------------------------------------------------------
    ("trufflehog secret scan on git repo", ["trufflehog"], 1, 1),
    ("gitleaks scan on repository", ["gitleaks"], 1, 1),
    ("git secret scanning on repo", ["trufflehog"], 1, 1),
    ("find leaked secrets in repo", ["trufflehog"], 1, 1),
    ("trufflehog git history scan for credentials", ["trufflehog"], 1, 1),
    ("gitleaks git secrets detection", ["gitleaks"], 1, 1),
    ("scan for api keys in repository", ["trufflehog"], 1, 1),
    ("credential leak detection in git repo", ["trufflehog"], 1, 1),
    # ------------------------------------------------------------------
    # 13. DNS Toolkit (8)
    # ------------------------------------------------------------------
    ("dnsx query on example.com", ["dnsx"], 1, 1),
    ("massdns on example.com with resolvers", ["massdns"], 1, 1),
    ("puredns resolve for example.com", ["puredns"], 1, 1),
    ("dns probe with dnsx on example.com", ["dnsx"], 1, 1),
    ("massdns brute force subdomains on example.com", ["massdns"], 1, 1),
    ("puredns wildcard filter for example.com", ["puredns"], 1, 1),
    ("dnsx a record query for example.com", ["dnsx"], 1, 1),
    ("bulk dns resolution with dnsx for example.com", ["dnsx"], 1, 1),
    # ------------------------------------------------------------------
    # 14. SSL/TLS OSINT (8)
    # ------------------------------------------------------------------
    ("ssl labs scan for example.com", ["ssllabs-scan"], 1, 1),
    ("testssl full check on example.com", ["testssl.sh"], 1, 1),
    ("ssl certificate info for https://example.com", ["openssl", "nmap", "nmap"], 3, 3),
    ("ssl certificate chain validation for example.com", ["openssl", "nmap", "nmap"], 3, 3),
    ("tls cipher suite check on example.com", ["openssl", "nmap", "nmap"], 3, 3),
    ("ssl tls security assessment on example.com", ["openssl", "nmap", "nmap"], 3, 3),
    ("testssl audit on example.com", ["testssl.sh"], 1, 1),
    ("ssllabs certificate analysis for example.com", ["ssllabs-scan"], 1, 1),
    # ------------------------------------------------------------------
    # 15. Passive Recon (8)
    # ------------------------------------------------------------------
    ("passive recon on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 5, 5),
    (
        "passive reconnaissance on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    ("passive scan on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 5, 5),
    (
        "passive intel gathering on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    ("stealth osint on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 5, 5),
    (
        "quiet passive recon on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "passive information gathering on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "non intrusive recon on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    # ------------------------------------------------------------------
    # 16. Full OSINT Recon (8)
    # ------------------------------------------------------------------
    (
        "osint recon on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "full osint recon on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "open source intelligence on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "osint intelligence gathering on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "complete osint assessment on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "deep osint reconnaissance on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "thorough osint investigation on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "recon-ng style osint on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    # ------------------------------------------------------------------
    # 17. External Attack Surface (6)
    # ------------------------------------------------------------------
    (
        "external recon on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "external attack surface on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "external attack surface recon on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "internet scan for example.com assets",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "external perimeter recon on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "edge discovery for example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    # ------------------------------------------------------------------
    # 18. Multi-Tool / Compound OSINT (14)
    # ------------------------------------------------------------------
    ("gau then httpx on example.com", ["gau", "httpx"], 2, 2),
    ("subfinder then httpx on example.com", ["subfinder", "httpx"], 2, 2),
    ("waybackurls then httpx on example.com", ["waybackurls", "httpx"], 2, 2),
    ("theHarvester and then holehe on example.com", ["theHarvester", "holehe"], 2, 2),
    ("amass subdomains and then httpx probe on example.com", ["amass", "httpx"], 2, 2),
    ("gau and then katana on example.com", ["gau", "katana"], 2, 2),
    ("subfinder and then gospider on example.com", ["subfinder", "gospider"], 2, 2),
    ("dnsx then httpx on example.com", ["dnsx", "httpx"], 2, 2),
    ("massdns then puredns on example.com", ["massdns", "puredns"], 2, 2),
    ("arjun then paramspider on https://example.com", ["arjun", "paramspider"], 2, 2),
    ("uncover then httpx on example.com", ["uncover", "httpx"], 2, 2),
    ("theHarvester then sherlock for johndoe", ["theHarvester", "sherlock"], 2, 2),
    ("gau and then waybackurls on example.com", ["gau", "waybackurls"], 2, 2),
    ("crtsh and then httpx on example.com", ["curl", "httpx"], 2, 2),
    # ------------------------------------------------------------------
    # 19. Advanced / Specialized OSINT (10)
    # ------------------------------------------------------------------
    ("interactsh oob testing client", ["interactsh"], 1, 1),
    ("oob collaboration test with interactsh", ["interactsh"], 1, 1),
    ("certificate transparency log monitoring for example.com", ["curl"], 1, 1),
    ("google dorking for example.com", ["curl"], 1, 1),
    ("dork search for exposed configs on example.com", ["curl"], 1, 1),
    ("ssllabs api scan for example.com", ["ssllabs-scan"], 1, 1),
    ("ssllabs api scan on example.com", ["ssllabs-scan"], 1, 1),
    ("web technology fingerprint on example.com", ["whatweb"], 1, 1),
    ("tech stack detection on example.com", ["whatweb"], 1, 1),
    ("cdn detection for cdn.example.com", ["curl"], 1, 1),
    # ------------------------------------------------------------------
    # 20. Complex / Professional OSINT Workflows (12)
    # ------------------------------------------------------------------
    (
        "full external osint assessment on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "comprehensive passive recon on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "multi vector external recon on example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "initial access osint on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "pre engagement osint on example.com",
        ["whatweb", "subfinder", "dig", "whois", "openssl"],
        5,
        5,
    ),
    (
        "attack surface mapping for example.com",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        6,
        6,
    ),
    (
        "osint profiling on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "adversary recon on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "full scope osint engagement on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "reconnaissance lifecycle on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "tier 1 osint collection on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
    (
        "zero touch osint automation on example.com",
        ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"],
        7,
        7,
    ),
]


def main():
    planner = RegistryPlanner()
    planner.build_index(AVAILABLE_TOOLS)

    passed = 0
    failed = 0
    failures = []

    print(f"\n{'='*60}")
    print(f"  OSINT EVALUATION: {len(OSINT_COMMANDS)} Commands")
    print(f"{'='*60}\n")

    for idx, (cmd, expected_tools, min_steps, max_steps) in enumerate(OSINT_COMMANDS):
        ok, msg = check_plan(planner, cmd, expected_tools, min_steps, max_steps)
        if ok:
            passed += 1
        else:
            failed += 1
            failures.append((cmd, msg))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status:4s}] ({idx+1:3d}) {cmd:55s} → {msg}")

    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {len(OSINT_COMMANDS)}")
    print(f"  SCORE: {passed/len(OSINT_COMMANDS)*100:.1f}%")
    print(f"{'='*60}\n")

    if failures:
        print("FAILED COMMANDS:")
        for cmd, msg in failures:
            print(f"  - {cmd}")
            print(f"    Reason: {msg}")
        print()

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
