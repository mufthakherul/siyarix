"""Diagnose 12 failures showing actual vs expected."""

import sys

sys.path.insert(0, "src")
from siyarix import RegistryPlanner

planner = RegistryPlanner()

failures = [
    ("Look up the AS15169 ownership and find out what organization it belongs to", ["whois"], 1, 3),
    (
        "Enumerate subdomains for example.com then check which are alive",
        ["subfinder", "httpx"],
        2,
        4,
    ),
    ("Scan https://example.com for exposed admin panels and login pages", ["nuclei"], 1, 2),
    (
        "Run a directory brute force and then check found paths for vulnerabilities",
        ["gobuster", "nuclei"],
        2,
        5,
    ),
    ("Query CT logs for example.com to discover subdomains and expired certs", ["curl"], 1, 2),
    ("Discover URL parameters for https://example.com to find hidden functionality", ["gau"], 1, 2),
    ("Run uncover to discover assets for example.com from Shodan and Censys", ["uncover"], 1, 2),
    (
        "Map the entire external attack surface for example.com including Shodan and certificates",
        ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"],
        4,
        7,
    ),
    ("subdomain enumeration then port scan on example.com", ["subfinder", "nmap"], 2, 4),
    ("enumerate subdomains then probe with httpx on example.com", ["subfinder", "httpx"], 2, 4),
    ("find emails then check subdomains on example.com", ["theHarvester", "subfinder"], 2, 4),
    ("Check if example.com has any cloud storage buckets open to the public", ["curl"], 1, 2),
]

for goal, expected_tools, min_steps, max_steps in failures:
    plan = planner.decompose_goal(goal)
    actual_tools = [s.tool for s in plan.steps]
    step_count = len(plan.steps)

    issues = []
    if step_count < min_steps:
        issues.append(f"step_count {step_count} < min_steps {min_steps}")
    if step_count > max_steps:
        issues.append(f"step_count {step_count} > max_steps {max_steps}")
    for et in expected_tools:
        if et not in actual_tools:
            issues.append(f"expected {et!r} not in {actual_tools}")

    status = "FAIL" if issues else "PASS"
    print(f"[{status}] GOAL: {goal}")
    print(f"  Steps({step_count}): {actual_tools}")
    print(f"  Expected: {expected_tools} [{min_steps}-{max_steps} steps]")
    for s in plan.steps:
        print(f"    {s.tool}: {s.description}")
    if issues:
        for i in issues:
            print(f"  ISSUE: {i}")
    print()
