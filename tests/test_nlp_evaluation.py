"""NLP Evaluation: 50+ commands to test RegistryPlanner execution plans."""

from __future__ import annotations

from siyarix.planner_registry import RegistryPlanner

planner = RegistryPlanner()

HIGH = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def evaluate(goal: str, expected_tools: list[str] | None = None, min_steps: int = 1):
    plan = planner.decompose_goal(goal)
    tools = [s.tool for s in plan.steps]
    descs = [s.description for s in plan.steps]

    print(f"\n{BOLD}CMD: {goal}{RESET}")
    print(f"  PlanType: {plan.plan_type.value} | Steps: {len(plan.steps)}")

    if plan.steps:
        for s in plan.steps:
            flags = s.args.get("flags", "")
            target = s.args.get("target", "")
            print(f"  [{s.tool}] {s.description}  target={target}  flags={flags}")
    else:
        print(f"  {YELLOW}NO STEPS GENERATED{YELLOW}")

    issues = []

    if min_steps > 0 and len(plan.steps) == 0:
        issues.append(f"Expected at least {min_steps} step(s), got 0")

    if min_steps > 0 and len(plan.steps) < min_steps:
        issues.append(f"Expected at least {min_steps} steps, got {len(plan.steps)}")

    if expected_tools:
        for et in expected_tools:
            if et not in tools:
                issues.append(f"Expected tool '{et}' not found in plan. Tools: {tools}")

    if issues:
        for issue in issues:
            print(f"  {HIGH}ISSUE: {issue}{RESET}")
        print(f"  {HIGH}STATUS: FAIL{RESET}")
        return False
    else:
        print(f"  {GREEN}STATUS: PASS{RESET}")
        return True


def main():
    passed = 0
    failed = 0

    tests = [
        # ── Port Scanning & Reconnaissance ──
        ("scan example.com", ["nmap"], 1),
        ("quick port scan on 192.168.1.1", ["nmap"], 1),
        ("full port scan of 10.0.0.1 with all ports", ["nmap"], 1),
        ("stealth scan on 10.0.0.0/24", ["nmap"], 1),
        ("fast network scan of 192.168.1.0/24", ["nmap"], 1),
        ("reconnaissance on target.com", ["nmap"], 1),
        ("enumerate open ports on 10.10.10.10", ["nmap"], 1),
        ("mass port scan of 10.0.0.0/8", ["masscan"], 1),
        # ── Web Application Testing ──
        ("check http headers on https://example.com", ["curl"], 1),
        ("web audit for https://testsite.com", ["curl", "whatweb"], 2),
        ("test for sql injection on https://example.com", ["sqlmap"], 1),
        ("check xss vulnerabilities on https://target.com", ["nuclei"], 1),
        ("scan wordpress site at https://blog.example.com", ["wpscan"], 1),
        ("cors misconfiguration check on https://api.example.com", ["curl"], 1),
        ("ssl tls audit for https://secure.example.com", ["openssl", "nmap"], 2),
        ("directory busting on https://example.com", ["gobuster"], 1),
        ("fuzz endpoints on https://api.example.com", ["ffuf"], 1),
        ("web vulnerability scan of https://example.com using nuclei", ["nuclei"], 1),
        ("cms fingerprinting on https://example.com", ["whatweb"], 1),
        ("check for exposed .git repositories on https://example.com", None, 1),
        ("api endpoint discovery on https://api.example.com", ["curl"], 1),
        # ── DNS & Subdomain Enumeration ──
        ("dns enumeration for example.com", ["dig"], 1),
        ("subdomain discovery for example.com", ["subfinder"], 1),
        ("brute force subdomains on target.com", ["amass"], 1),
        ("dns record lookup including mx and txt on example.com", ["dig"], 1),
        ("full dns recon on example.com", ["dig", "subfinder"], 2),
        ("find all subdomains of example.com using amass", ["amass"], 1),
        # ── Vulnerability Scanning ──
        ("critical vulnerability scan on https://example.com", ["nuclei"], 1),
        ("cve scanning for known vulnerabilities on example.com", ["nuclei"], 1),
        ("check for CVE-2024-1234 on https://example.com", None, 1),
        ("vulnerability assessment for example.com", ["nuclei"], 1),
        ("pentest example.com for common web vulnerabilities", ["whatweb", "nmap"], 2),
        # ── Cloud Security ──
        ("cloud audit for https://myapp.azurewebsites.net", ["curl", "whatweb"], 2),
        ("check aws s3 bucket permissions for https://bucket.s3.amazonaws.com", ["curl"], 1),
        ("gcp cloud storage audit on https://bucket.storage.googleapis.com", ["curl"], 1),
        # ── Active Directory & Windows ──
        ("active directory assessment on dc.example.com", ["nmap"], 4),
        ("smb enumeration on 192.168.1.100", ["nmap"], 4),
        ("kerberos enumeration against domain controller", ["nmap"], 1),
        ("ldap anonymous bind check on 192.168.1.100", ["nmap"], 1),
        ("enumerate windows shares on 10.10.10.50", ["nmap"], 1),
        # ── Brute Force & Credential Testing ──
        ("brute force ssh on 192.168.1.100", ["nmap", "hydra"], 2),
        ("password cracking of captured hashes", ["hashcat"], 1),
        ("credential brute force on web login at https://example.com", None, 1),
        # ── Network Infrastructure ──
        ("whois lookup for example.com", ["whois"], 1),
        ("check if host is up on 8.8.8.8", ["nmap"], 1),
        ("traceroute to example.com", None, 1),
        ("check open ports on 10.0.0.1 using nmap", ["nmap"], 1),
        ("discover live hosts on 192.168.1.0/24", ["nmap"], 1),
        # ── Advanced Security Scenarios ──
        ("linux privilege escalation check on target", ["uname", "find"], 2),
        ("check for shell shock vulnerability on https://example.com/cgi-bin", ["nuclei"], 1),
        ("waf detection on https://example.com", ["nmap"], 1),
        ("cors and preflight check on https://api.example.com", ["curl"], 2),
        ("check http security headers and ssl cert on https://example.com", None, 2),
        ("full audit of security posture for example.com", ["nmap", "curl"], 2),
        # ── Docker & Container Security ──
        ("discover docker containers on 10.0.0.1", ["nmap"], 1),
        ("kubernetes api discovery on k8s.example.com", ["nmap"], 1),
        # ── Wireless Security ──
        ("capture wpa handshake on wlan0", ["aircrack-ng"], 1),
        ("crack wifi password from handshake capture", ["aircrack-ng"], 1),
        # ── Multi-Step Operations ──
        ("scan example.com and then enumerate subdomains", ["nmap", "subfinder"], 2),
        ("check headers and test for cors on https://example.com", ["curl"], 2),
        ("find tech stack then scan for vulnerabilities on https://example.com", None, 2),
        # ── Edge Cases & Complex Queries ──
        ("scan port 80,443 on 10.0.0.1 very fast with timeout 5m", ["nmap"], 1),
        ("detailed scan of all ports udp on 10.0.0.1", ["nmap"], 1),
        ("stealth recon of internal network 192.168.1.0/24 avoiding detection", ["nmap"], 1),
        ("skip low severity, find critical and high vulns on example.com", ["nuclei"], 1),
        # ── Additional Professional Commands ──
        ("check for open s3 buckets belonging to example.com", ["curl"], 1),
        ("enumerate email servers for example.com using dns", ["dig"], 1),
        ("check certificate transparency logs for example.com", None, 1),
        ("scan for open memcached instances on 10.0.0.0/24", ["nmap"], 1),
        ("check for spring4shell vulnerability on https://example.com", ["nuclei"], 1),
        ("log4j scan on https://example.com", ["nuclei"], 1),
        ("heartbleed check on https://example.com", ["nmap"], 1),
        ("find exposed jenkins instances on 10.0.0.0/24", ["nmap"], 1),
        ("check for open elasticsearch databases on 10.0.0.0/24", ["curl"], 1),
        ("dnsscan and zone transfer attempt on example.com", ["dig"], 1),
        (
            "full passive recon on example.com",
            ["whatweb", "subfinder", "dig", "whois", "openssl"],
            5,
        ),
    ]

    results = []
    for args in tests:
        if len(args) == 3:
            goal, expected_tools, min_steps = args
        else:
            goal, expected_tools = args
            min_steps = 1
        result = evaluate(goal, expected_tools, min_steps)
        results.append((goal, result))
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"{BOLD}RESULTS: {passed} passed, {failed} failed out of {len(tests)}{RESET}")
    print(f"{'=' * 60}")

    if failed > 0:
        print(f"\n{YELLOW}FAILED COMMANDS:{RESET}")
        for goal, result in results:
            if not result:
                print(f"  - {goal}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
