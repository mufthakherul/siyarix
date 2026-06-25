"""NLP Advanced Evaluation: 60+ deep, advanced, complex commands."""

from __future__ import annotations

from siyarix.planner_registry import RegistryPlanner

planner = RegistryPlanner()

HIGH = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def evaluate(
    goal: str,
    expected_tools: list[str] | None = None,
    min_steps: int = 1,
    max_steps: int | None = None,
    must_not_have_tools: list[str] | None = None,
    target_check: str | None = None,
):
    plan = planner.decompose_goal(goal)
    tools = [s.tool for s in plan.steps]
    targets = [s.args.get("target", "") for s in plan.steps]

    print(f"\n{BOLD}CMD: {goal}{RESET}")
    print(f"  PlanType: {plan.plan_type.value} | Steps: {len(plan.steps)}")

    if plan.steps:
        for s in plan.steps:
            flags = s.args.get("flags", "")
            target = s.args.get("target", "")
            print(f"  [{s.tool}] {s.description}  target={target}  flags={flags}")
    else:
        print(f"  {YELLOW}NO STEPS GENERATED{RESET}")

    issues = []

    if min_steps > 0 and len(plan.steps) < min_steps:
        issues.append(f"Expected at least {min_steps} steps, got {len(plan.steps)}")
    if max_steps is not None and len(plan.steps) > max_steps:
        issues.append(f"Expected at most {max_steps} steps, got {len(plan.steps)}")
    if expected_tools:
        for et in expected_tools:
            if et not in tools:
                issues.append(f"Expected tool '{et}' not in plan. Tools: {tools}")
    if must_not_have_tools:
        for mt in must_not_have_tools:
            if mt in tools:
                issues.append(f"Tool '{mt}' should NOT be in plan but was found")
    if target_check:
        if not targets or target_check not in targets:
            issues.append(f"Expected target containing '{target_check}' but got: {targets}")

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

    # Test format: (goal, expected_tools, min_steps, max_steps, must_not_have_tools, target_check)
    # Each element can be None to skip check
    tests = [
        # ═══════════════════════════════════════════════════════════════
        # SECTION 1: ADVANCED MULTI-STEP CHAINS (DEEPER "then" USAGE)
        # ═══════════════════════════════════════════════════════════════
        (
            "find tech stack then scan for vulnerabilities on https://example.com",
            None,
            2,
            None,
            None,
            None,
        ),
        ("enumerate subdomains then scan for open ports on example.com", None, 2, None, None, None),
        (
            "check headers then test cors then audit ssl on https://example.com",
            None,
            3,
            None,
            None,
            None,
        ),
        ("scan for sql injection then check xss on https://example.com", None, 2, None, None, None),
        ("dns recon followed by whois lookup for example.com", None, 2, None, None, None),
        (
            "run wpscan && then brute force admin login on https://wordpress-site.com",
            None,
            2,
            None,
            None,
            None,
        ),
        (
            "check for exposed git and then enumerate api endpoints on https://example.com",
            None,
            2,
            None,
            None,
            None,
        ),
        (
            "find all subdomains && scan for heartbleed && check cve-2024-1234 on example.com",
            None,
            3,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 2: COMPOUND / AMBIGUOUS QUERIES
        # ═══════════════════════════════════════════════════════════════
        ("scan ports 80 and 443 on 10.0.0.1", ["nmap"], 1, None, None, None),
        ("check both http and https on example.com", ["curl"], 1, None, None, None),
        ("scan for open tcp and udp ports on 10.0.0.1", ["nmap"], 1, None, None, None),
        ("enum dns records mx txt a aaaa on example.com", ["dig"], 1, None, None, None),
        (
            "check for log4j heartbleed and shellshock on https://example.com",
            ["nuclei", "nikto"],
            2,
            None,
            None,
            None,
        ),
        (
            "list s3 buckets and check iam roles on https://aws.example.com",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        (
            "find exposed panels and check for default creds on https://example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 3: NEGATION / EXCLUSION QUERIES
        # ═══════════════════════════════════════════════════════════════
        ("scan example.com without port scan", None, 1, None, None, None),
        ("recon on example.com avoid aggressive scanning", None, 1, None, None, None),
        (
            "check vulnerabilities but skip low severity on https://example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        (
            "audit web app without directory bruteforce on https://example.com",
            None,
            1,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 4: TOOL-SPECIFIC MENTIONS
        # ═══════════════════════════════════════════════════════════════
        ("scan 10.0.0.1 using masscan", ["masscan"], 1, None, None, None),
        ("enumerate dns using dig on example.com", ["dig"], 1, None, None, None),
        ("crack hashes with hashcat from dump.txt", ["hashcat"], 1, None, None, None),
        (
            "brute force login page with hydra on https://example.com/login",
            ["hydra", "nmap"],
            2,
            None,
            None,
            None,
        ),
        ("scan 10.0.0.0/24 using rustscan", None, 1, None, None, None),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 5: ADVANCED WEB VULNERABILITY DETECTION
        # ═══════════════════════════════════════════════════════════════
        (
            "check for ssrf vulnerability on https://api.example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        (
            "test for idor and broken access control on https://example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        (
            "check for lfi rfi vulnerabilities on https://example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        (
            "scan for open redirect and clickjacking on https://example.com",
            ["curl", "nuclei"],
            2,
            None,
            None,
            None,
        ),
        (
            "check for insecure deserialization on https://example.com",
            ["nuclei"],
            1,
            None,
            None,
            None,
        ),
        ("test websocket security on wss://example.com/socket", ["curl"], 1, None, None, None),
        (
            "graphql introspection query on https://api.example.com/graphql",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        (
            "check swagger api documentation exposure on https://api.example.com",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 6: DATABASE & MIDDLEWARE ENUMERATION
        # ═══════════════════════════════════════════════════════════════
        ("enum redis databases on 10.0.0.50", ["nmap"], 1, None, None, None),
        ("check for open mongodb instances on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        ("scan for mysql databases on 192.168.1.0/24", ["nmap"], 1, None, None, None),
        ("enumerate mssql servers on 10.10.10.0/24", ["nmap"], 1, None, None, None),
        ("check for open elasticsearch clusters on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        ("enumerate kafka brokers on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        ("check for rabbitmq management interface on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        ("scan for cassandra databases on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        ("test activemq vulnerability on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 7: ADVANCED ACTIVE DIRECTORY ATTACKS
        # ═══════════════════════════════════════════════════════════════
        ("perform dcsync attack on dc.example.com", ["impacket-secretsdump"], 1, None, None, None),
        (
            "kerberoast all users on domain controller",
            ["impacket-GetUserSPNs"],
            1,
            None,
            None,
            None,
        ),
        (
            "asrep roast domain users on dc.example.com",
            ["impacket-GetNPUsers"],
            1,
            None,
            None,
            None,
        ),
        ("check for zerologon vulnerability on dc.example.com", ["nmap"], 1, None, None, None),
        ("check for petitpotam vulnerability on dc.example.com", ["nmap"], 1, None, None, None),
        ("run bloodhound collector on internal domain", ["bloodhound-python"], 1, None, None, None),
        ("smb signing check and relay attack prep on 192.168.1.100", ["nmap"], 1, None, None, None),
        ("ntlm relay attack prep on 192.168.1.0/24", ["nmap"], 1, None, None, None),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 8: CLOUD INFRASTRUCTURE (DEEP)
        # ═══════════════════════════════════════════════════════════════
        ("enumerate aws ec2 instances metadata on 169.254.169.254", ["curl"], 1, None, None, None),
        ("check for open aws s3 buckets via dns on example.com", ["dig"], 1, None, None, None),
        (
            "audit azure blob storage containers on https://storage.blob.core.windows.net",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        (
            "enumerate gcp cloud storage buckets on https://storage.googleapis.com",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        (
            "check for cloudfront misconfiguration on https://d1.example.cloudfront.net",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 9: WIRELESS & BLUETOOTH
        # ═══════════════════════════════════════════════════════════════
        ("scan for wifi access points on wlan0mon", None, 1, None, None, None),
        ("deauth attack on target bssid on wlan0", None, 1, None, None, None),
        ("wpa enterprise authentication testing on wlan0", None, 1, None, None, None),
        ("bluetooth device discovery on hci0", None, 1, None, None, None),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 10: CONTAINER & ORCHESTRATION
        # ═══════════════════════════════════════════════════════════════
        ("check for docker daemon exposed on tcp://10.0.0.1:2375", ["nmap"], 1, None, None, None),
        ("k8s rbac check on k8s.example.com", ["nmap"], 1, None, None, None),
        ("scan kubernetes pods for vulnerabilities on 10.0.0.0/24", ["nmap"], 1, None, None, None),
        (
            "check container registry for exposed images on 10.0.0.1:5000",
            ["curl"],
            1,
            None,
            None,
            None,
        ),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 11: PERFORMANCE / PARAMETER TUNING
        # ═══════════════════════════════════════════════════════════════
        ("fast udp scan on 10.0.0.1 with rate 10000", ["nmap"], 1, None, None, None),
        ("stealth syn scan on 10.0.0.1 with 100 threads", ["nmap"], 1, None, None, None),
        ("verbose json output vulnerability scan on example.com", ["nuclei"], 1, None, None, None),
        ("comprehensive scan with xml output on 10.0.0.1", ["nmap"], 1, None, None, None),
        # ═══════════════════════════════════════════════════════════════
        # SECTION 12: EDGE CASES & UNUSUAL COMMANDS
        # ═══════════════════════════════════════════════════════════════
        ("", None, 0, 0, None, None),  # Empty goal
        ("   ", None, 0, 0, None, None),  # Whitespace only
        ("just browsing", None, 0, 0, None, None),  # Non-security
        ("scan scan scan scan 10.0.0.1", ["nmap"], 1, None, None, None),  # Repeated noise
        ("TEST UPPERCASE RECON ON EXAMPLE.COM", ["nmap"], 1, None, None, None),  # Case handling
        (
            "scan example.com and scan example.org and scan example.net",
            ["nmap"],
            1,
            None,
            None,
            None,
        ),  # Multi-target
        ("check http://example.com and https://example.org", ["curl"], 1, None, None, None),  # URLs
        (
            "perform a thorough deep dive security assessment of the external attack surface for example.com",
            None,
            1,
            None,
            None,
            None,
        ),
    ]

    results = []
    for args in tests:
        goal, expected_tools, min_steps, max_steps, must_not_have, target_check = args
        result = evaluate(
            goal,
            expected_tools=expected_tools,
            min_steps=min_steps,
            max_steps=max_steps,
            must_not_have_tools=must_not_have,
            target_check=target_check,
        )
        results.append((goal, result))
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n{'='*60}")
    print(f"{BOLD}RESULTS: {passed} passed, {failed} failed out of {len(tests)}{RESET}")
    print(f"{'='*60}")

    if failed > 0:
        print(f"\n{YELLOW}FAILED COMMANDS:{RESET}")
        for goal, result in results:
            if not result:
                print(f"  - {goal}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
