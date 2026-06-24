"""Find expected values for all 12 failing commands."""
import re

fail_goals = [
    'Look up the AS15169 ownership and find out what organization it belongs to',
    'Enumerate subdomains for example.com then check which are alive',
    'Scan https://example.com for exposed admin panels and login pages',
    'Run a directory brute force and then check found paths for vulnerabilities',
    'Query CT logs for example.com to discover subdomains and expired certs',
    'Discover URL parameters for https://example.com to find hidden functionality',
    'Run uncover to discover assets for example.com from Shodan and Censys',
    'Map the entire external attack surface for example.com including Shodan and certificates',
    'subdomain enumeration then port scan on example.com',
    'enumerate subdomains then probe with httpx on example.com',
    'find emails then check subdomains on example.com',
    'Check if example.com has any cloud storage buckets open to the public',
]

with open('tests/test_recon_nlp.py', 'r', encoding='utf-8') as f:
    content = f.read()

for g in fail_goals:
    escaped = re.escape(g)
    match = re.search(r'\("' + escaped + r'"\s*,\s*(\[.*?\])\s*,\s*(\d+)\s*,\s*(\d+)\)', content)
    if match:
        expected_tools = match.group(1)
        min_steps = match.group(2)
        max_steps = match.group(3)
        print(f'GOAL: {g}')
        print(f'  EXPECTED: tools={expected_tools}, min={min_steps}, max={max_steps}')
    else:
        print(f'GOAL: {g}')
        print(f'  NOT FOUND')
    print()
