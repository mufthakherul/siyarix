#!/usr/bin/env python3
"""Comprehensive Recon NLP evaluation — 440 commands, direct + natlang, basic->advanced->complex."""

import sys
sys.stdout.reconfigure(encoding='utf-8')

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
    "wpscan",
]

def check_plan(planner, goal, expected_tools, min_steps=1, max_steps=None):
    plan = planner.decompose_goal(goal)
    actual_tools = [s.tool for s in plan.steps]
    step_count = len(plan.steps)
    if step_count < min_steps:
        return False, f"step_count {step_count} < min_steps {min_steps}, tools={actual_tools}"
    if max_steps and step_count > max_steps:
        return False, f"step_count {step_count} > max_steps {max_steps}, tools={actual_tools}"
    for et in expected_tools:
        if et not in actual_tools:
            return False, f"expected {et!r} not in {actual_tools}"
    return True, f"OK steps={step_count} tools={actual_tools}"


RECON_COMMANDS = [
    # ===== SECTION 1: BASIC NETWORK RECON (22) =====
    ("nmap scan on 10.0.0.1", ["nmap"], 1, 2),
    ("port scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("full port scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("quick scan on 10.0.0.1", ["nmap"], 1, 2),
    ("tcp scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("udp scan on 10.0.0.1", ["nmap"], 1, 2),
    ("stealth scan on 10.0.0.1", ["nmap"], 1, 2),
    ("ping sweep on 10.0.0.0/24", ["nmap"], 1, 2),
    ("host discovery on 192.168.1.0/24", ["nmap"], 1, 2),
    ("live hosts scan on 172.16.0.0/24", ["nmap"], 1, 2),
    ("find up hosts on 10.0.0.0/24", ["nmap"], 1, 2),
    ("Check what ports are open on 10.0.0.1", ["nmap"], 1, 2),
    ("service version scan on 10.0.0.1", ["nmap"], 1, 2),
    ("aggressive scan on 10.0.0.1 all ports", ["nmap"], 1, 2),
    ("fast port scan on 10.0.0.1 top 1000", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("masscan full sweep on 10.0.0.0/16", ["masscan"], 1, 2),
    ("rustscan on 10.0.0.1", ["rustscan"], 1, 2),
    ("naabu fast scan on 10.0.0.1", ["naabu"], 1, 2),
    ("traceroute to example.com", ["tracert"], 1, 2),
    ("tracert to 8.8.8.8", ["tracert"], 1, 2),
    ("Can you run a network scan on 10.0.0.1 and tell me what services are running?", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("I need to discover all live hosts on the 10.0.0.0/24 subnet", ["nmap"], 1, 2),

    # ===== SECTION 2: ADVANCED NETWORK RECON (16) =====
    ("full tcp scan on 10.0.0.1 all ports", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("infrastructure scan on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("open ports check on 10.0.0.1", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("nmap os detection on 10.0.0.1", ["nmap"], 1, 2),
    ("ipmi recon on 10.0.0.1", ["nmap"], 1, 2),
    ("snmp enumeration on 10.0.0.1", ["nmap"], 1, 2),
    ("smtp server enum on mail.example.com", ["nmap"], 1, 2),
    ("imap enumeration on 10.0.0.1", ["nmap"], 1, 2),
    ("tcp port sweep 10.0.0.0/24", ["nmap"], 1, 2),
    ("network mapping on 10.0.0.0/24", ["curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois", "nmap", "masscan"], 8, 10),
    ("scan for up hosts and open services on 10.0.0.0/24", ["nmap"], 1, 2),
    ("Perform a full infrastructure scan of 10.0.0.1 including OS detection", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),
    ("I need to do SNMP recon on the target 10.0.0.1 to enumerate network devices", ["nmap"], 1, 2),
    ("Run IPMI reconnaissance on 10.0.0.1 to check for BMC vulnerabilities", ["nmap"], 1, 2),
    ("Do a masscan of the entire 10.0.0.0/16 range to find all responsive hosts", ["masscan"], 1, 2),
    ("Network scan for SMTP, IMAP, and POP3 services on mail.example.com", ["nmap", "nmap", "dig", "whois", "masscan"], 4, 6),

    # ===== SECTION 3: DNS RECON (28) =====
    ("dns enumeration on example.com", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("dns record check for example.com", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("mx record lookup for example.com", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("dns resolution for example.com", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("nameserver lookup for example.com", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("dns zone transfer on example.com", ["dig"], 1, 2),
    ("axfr query for example.com", ["dig"], 1, 2),
    ("dns a record check for example.com", ["dig"], 1, 2),
    ("dns txt record enumeration for example.com", ["dig"], 1, 2),
    ("dns cname lookup for example.com", ["dig"], 1, 2),
    ("reverse dns lookup on 8.8.8.8", ["dig"], 1, 2),
    ("dns ptr record for 8.8.8.8", ["dig"], 1, 2),
    ("dns soa record for example.com", ["dig"], 1, 2),
    ("aaaa record check for example.com", ["dig"], 1, 2),
    ("dnssec check for example.com", ["dig"], 1, 2),
    ("spf record lookup for example.com", ["dig"], 1, 2),
    ("dmarc record check for example.com", ["dig"], 1, 2),
    ("dns cache snooping on 8.8.8.8", ["dig"], 1, 2),
    ("dnsx query on example.com", ["dnsx"], 1, 2),
    ("massdns on example.com with resolvers", ["massdns"], 1, 2),
    ("puredns resolve for example.com", ["puredns"], 1, 2),
    ("dns probe with dnsx on example.com", ["dnsx"], 1, 2),
    ("massdns brute force subdomains on example.com", ["massdns"], 1, 2),
    ("puredns wildcard filter for example.com", ["puredns"], 1, 2),
    ("dnsx a record query for example.com", ["dnsx"], 1, 2),
    ("bulk dns resolution with dnsx for example.com", ["dnsx"], 1, 2),
    ("Look up the MX, SPF, and DMARC records for example.com to understand email security", ["dig"], 1, 2),
    ("Do a full DNS reconnaissance on example.com including all record types and zone transfer attempt", ["dig", "subfinder", "amass", "whois"], 3, 5),

    # ===== SECTION 4: WHOIS & DOMAIN OSINT (20) =====
    ("whois lookup for example.com", ["whois"], 1, 2),
    ("domain whois on example.com", ["whois"], 1, 2),
    ("whois registration for example.com", ["whois"], 1, 2),
    ("reverse whois for example.com", ["whois"], 1, 2),
    ("asn lookup for 8.8.8.8", ["whois"], 1, 2),
    ("asn recon on AS15169", ["whois"], 1, 2),
    ("ip whois for 8.8.8.8", ["whois"], 1, 2),
    ("domain registration check example.com", ["whois"], 1, 2),
    ("whois domain ownership for example.com", ["whois"], 1, 2),
    ("rdap lookup for 8.8.8.8", ["whois"], 1, 2),
    ("registrar information for example.com", ["whois"], 1, 2),
    ("domain registration info for example.com", ["whois"], 1, 2),
    ("whois ip block ownership for 8.8.8.0/24", ["whois"], 1, 2),
    ("Find out who owns the domain example.com and get registrar details", ["whois"], 1, 2),
    ("I need to know what ASN owns the IP 8.8.8.8 and who its ISP is", ["whois"], 1, 2),
    ("Do a reverse WHOIS lookup on example.com to find other domains owned by the same person", ["whois"], 1, 2),
    ("Check domain registration expiry for example.com and look up registrar info", ["whois"], 1, 2),
    ("RDAP lookup on 8.8.8.8 to get the latest RIR data", ["whois"], 1, 2),
    ("Who owns this IP? Do a full whois investigation on 8.8.8.8", ["whois"], 1, 2),
    ("Look up the AS15169 ownership and find out what organization it belongs to", ["whois"], 1, 3),

    # ===== SECTION 5: SUBDOMAIN ENUMERATION (22) =====
    ("subdomain enumeration on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("subdomain discovery for example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("amass subdomain brute on example.com", ["amass"], 1, 2),
    ("amass intel on example.com", ["amass"], 1, 2),
    ("amass enum for example.com", ["amass"], 1, 2),
    ("subfinder passive enum on example.com", ["subfinder"], 1, 2),
    ("sublist3r subdomain search for example.com", ["sublist3r"], 1, 2),
    ("assetfinder subdomain discovery for example.com", ["assetfinder"], 1, 2),
    ("passive subdomain enum on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("dns brute force subdomain on example.com", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("subdomain takeover check on example.com", ["subjack"], 1, 2),
    ("check subdomain takeover on example.com", ["subjack"], 1, 2),
    ("Find all subdomains of example.com using passive sources and brute force", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("Use subfinder and amass to enumerate subdomains for example.com", ["amass"], 1, 2),
    ("I need a comprehensive subdomain discovery on example.com including passive and active techniques", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("Check if any subdomains of example.com are vulnerable to takeover", ["subjack"], 1, 2),
    ("Run sublist3r to find subdomains for example.com", ["sublist3r"], 1, 2),
    ("Enumerate all subdomains passively using subfinder on example.com", ["subfinder"], 1, 2),
    ("Do an aggressive subdomain brute force with amass on example.com", ["amass"], 1, 2),
    ("Use assetfinder to find related domains and subdomains for example.com", ["assetfinder"], 1, 2),
    ("Enumerate subdomains for example.com then check which are alive", ["subfinder", "httpx"], 2, 4),
    ("subdomain brute force on example.com with amass and then httpx", ["amass", "httpx"], 2, 4),

    # ===== SECTION 6: WEB RECON - HEADERS & TECH (22) =====
    ("check headers of https://example.com", ["curl"], 1, 2),
    ("find tech stack on example.com", ["whatweb"], 1, 2),
    ("web technology fingerprint on example.com", ["whatweb"], 1, 2),
    ("tech stack detection on example.com", ["whatweb"], 1, 2),
    ("cms detection on https://example.com", ["whatweb"], 1, 2),
    ("wordpress scan on https://example.com", ["wpscan"], 1, 2),
    ("check http headers on https://example.com", ["curl"], 1, 2),
    ("cors check on https://example.com", ["curl"], 1, 3),
    ("cookie analysis on https://example.com", ["curl"], 1, 2),
    ("redirect chain for https://example.com", ["curl"], 1, 2),
    ("clickjacking test on https://example.com", ["curl"], 1, 2),
    ("api endpoint check on https://example.com", ["curl"], 1, 2),
    ("check for exposed .git on https://example.com", ["curl"], 1, 2),
    ("joomla detection on https://example.com", ["whatweb"], 1, 2),
    ("drupal scan on https://example.com", ["whatweb"], 1, 2),
    ("nginx info on https://example.com", ["whatweb"], 1, 2),
    ("apache version check on https://example.com", ["whatweb"], 1, 2),
    ("iis fingerprint on https://example.com", ["whatweb"], 1, 2),
    ("tomcat manager check on https://example.com", ["whatweb"], 1, 2),
    ("What web server and technologies is example.com running? Check headers and tech stack", ["whatweb"], 1, 2),
    ("Check if example.com is running WordPress and what version", ["wpscan"], 1, 2),
    ("Inspect the HTTP security headers on https://example.com for missing protections", ["curl"], 1, 2),

    # ===== SECTION 7: WEB RECON - DIRECTORY & FUZZING (16) =====
    ("enumerate directories on https://example.com", ["gobuster"], 1, 2),
    ("fuzz endpoints on https://example.com", ["ffuf"], 1, 2),
    ("directory busting on https://example.com", ["gobuster"], 1, 2),
    ("fuzz with ffuf on https://example.com/FUZZ", ["ffuf"], 1, 2),
    ("dirb scan on https://example.com", ["dirb"], 1, 2),
    ("dirsearch on https://example.com", ["dirsearch"], 1, 2),
    ("exposed panel scan on https://example.com", ["nuclei"], 1, 2),
    ("Find hidden directories and files on https://example.com using gobuster", ["gobuster"], 1, 2),
    ("Fuzz the https://example.com web app for hidden endpoints with ffuf", ["ffuf"], 1, 2),
    ("I want to brute force directories on https://example.com with a wordlist", ["nmap", "hydra", "hashcat"], 2, 4),
    ("Use dirsearch to find hidden paths on https://example.com", ["dirsearch"], 1, 2),
    ("Scan https://example.com for exposed admin panels and login pages", ["nuclei"], 1, 2),
    ("Run dirb on https://example.com to find common web directories", ["dirb"], 1, 2),
    ("Content discovery on https://example.com - find all accessible paths", ["gobuster"], 1, 2),
    ("Discover all endpoints and hidden files on https://example.com", ["gobuster"], 1, 2),
    ("Run a directory brute force and then check found paths for vulnerabilities", ["gobuster", "nuclei"], 2, 5),

    # ===== SECTION 8: SSL/TLS RECON (20) =====
    ("ssl check on https://example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("tls cipher scan on example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("certificate info for https://example.com", ["openssl"], 1, 2),
    ("full ssl audit on https://example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("tls cipher suite check on example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("heartbleed check on https://example.com", ["nmap"], 1, 2),
    ("ssl certificate chain validation for example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("ssl labs scan for example.com", ["ssllabs-scan"], 1, 2),
    ("testssl full check on example.com", ["testssl.sh"], 1, 2),
    ("ssl cipher enum on example.com:443", ["openssl", "nmap", "nmap"], 2, 4),
    ("ssllabs api scan for example.com", ["ssllabs-scan"], 1, 2),
    ("testssl audit on example.com", ["testssl.sh"], 1, 2),
    ("ssl tls security assessment on example.com", ["openssl", "nmap", "nmap"], 2, 4),
    ("Run a comprehensive SSL/TLS audit on example.com with cipher enumeration", ["openssl", "nmap", "nmap"], 2, 4),
    ("Check if example.com is vulnerable to Heartbleed", ["nmap"], 1, 2),
    ("Use SSLLabs to analyze example.com certificate and SSL configuration", ["ssllabs-scan"], 1, 2),
    ("Do a full testssl.sh assessment on example.com for TLS vulnerabilities", ["testssl.sh"], 1, 2),
    ("Validate the SSL certificate chain for https://example.com and check ciphers", ["openssl", "nmap", "nmap"], 2, 4),
    ("I need a detailed SSL report for example.com including weak cipher detection", ["openssl", "nmap", "nmap"], 2, 4),
    ("Check TLS 1.3 support on example.com and list all available cipher suites", ["openssl", "nmap", "nmap"], 2, 4),

    # ===== SECTION 9: CERTIFICATE TRANSPARENCY (12) =====
    ("certificate transparency search for example.com", ["curl"], 1, 2),
    ("crtsh lookup for example.com", ["curl"], 1, 2),
    ("crt.sh search for example.com", ["curl"], 1, 2),
    ("certificate log inspection for example.com", ["openssl"], 1, 2),
    ("crtsh certificate search for example.com", ["curl"], 1, 2),
    ("certificate transparency logs for example.com", ["curl"], 1, 2),
    ("crt.sh domain search for example.com", ["curl"], 1, 2),
    ("ssl certificate transparency for example.com", ["openssl", "nmap"], 2, 4),
    ("Search certificate transparency logs on crt.sh for example.com subdomains", ["curl"], 1, 2),
    ("Use crt.sh to find all SSL certificates issued for example.com", ["curl"], 1, 2),
    ("Query CT logs for example.com to discover subdomains and expired certs", ["curl"], 1, 2),
    ("Monitor certificate transparency logs for new certificates issued to example.com", ["curl"], 1, 2),

    # ===== SECTION 10: URL DISCOVERY & WAYBACK (18) =====
    ("wayback machine urls for example.com", ["waybackurls"], 1, 2),
    ("gau url discovery for example.com", ["gau"], 1, 2),
    ("get all urls for example.com", ["gau"], 1, 2),
    ("waybackurls discovery on example.com", ["waybackurls"], 1, 2),
    ("gau wayback url discovery for example.com", ["gau"], 1, 2),
    ("wayback machine endpoints for example.com", ["waybackurls"], 1, 2),
    ("historic urls for example.com from archive", ["gau"], 1, 2),
    ("url enumeration on example.com from wayback", ["waybackurls"], 1, 2),
    ("gau wayback url discovery for example.com", ["gau"], 1, 2),
    ("Fetch all historical URLs for example.com from Wayback Machine", ["waybackurls"], 1, 2),
    ("Use gau to get every URL ever seen for example.com", ["gau"], 1, 2),
    ("I need to find old endpoints and archived pages for example.com", ["gobuster"], 1, 2),
    ("Discover all URLs for example.com from the Wayback Machine archive", ["waybackurls"], 1, 2),
    ("Extract all JavaScript URLs and API endpoints from wayback data for example.com", ["waybackurls"], 1, 2),
    ("Get the complete URL history for example.com including hidden paths", ["gau"], 1, 2),
    ("Wayback Machine URL discovery for example.com to find forgotten endpoints", ["waybackurls"], 1, 2),
    ("Use gau to collect all URLs for example.com and then filter for interesting parameters", ["gau", "arjun"], 2, 3),
    ("Pull wayback URLs then probe with httpx for live endpoints", ["waybackurls", "httpx"], 2, 3),

    # ===== SECTION 11: HTTP PROBING & CRAWLING (16) =====
    ("httpx probe on https://example.com", ["httpx"], 1, 2),
    ("http probe on example.com", ["httpx"], 1, 2),
    ("web crawl with katana on https://example.com", ["katana"], 1, 2),
    ("spider with gospider on https://example.com", ["gospider"], 1, 2),
    ("httpx live host probing for example.com", ["httpx"], 1, 2),
    ("katana crawl example.com for endpoints", ["katana"], 1, 2),
    ("gospider web spider on https://example.com", ["gospider"], 1, 2),
    ("probe all subdomains for example.com with httpx", ["httpx"], 1, 2),
    ("crawl and spider example.com", ["katana"], 1, 2),
    ("httpx tech detection on https://example.com", ["httpx"], 1, 2),
    ("katana url discovery on example.com", ["katana"], 1, 2),
    ("gospider content discovery on https://example.com", ["gospider"], 1, 2),
    ("Probe https://example.com with httpx to get status codes and tech detection", ["httpx"], 1, 2),
    ("Crawl example.com with katana to discover all accessible endpoints", ["katana"], 1, 2),
    ("Spider the entire https://example.com site with gospider for content discovery", ["gospider"], 1, 2),
    ("JavaScript endpoint discovery on https://example.com - find JS files and endpoints", ["gospider"], 1, 2),

    # ===== SECTION 12: PARAMETER DISCOVERY (12) =====
    ("arjun parameter discovery on https://example.com", ["arjun"], 1, 2),
    ("paramspider mining on example.com", ["paramspider"], 1, 2),
    ("discover http parameter on https://example.com", ["arjun"], 1, 2),
    ("param mining on example.com", ["arjun"], 1, 2),
    ("arjun find hidden params on https://example.com", ["arjun"], 1, 2),
    ("parameter discovery scan on example.com", ["arjun"], 1, 2),
    ("url parameter enumeration on https://example.com", ["arjun"], 1, 2),
    ("get params from url on https://example.com", ["arjun"], 1, 2),
    ("Find hidden GET and POST parameters on https://example.com with arjun", ["arjun"], 1, 2),
    ("Use paramspider to mine URLs for common parameters on example.com", ["paramspider"], 1, 2),
    ("Discover URL parameters for https://example.com to find hidden functionality", ["arjun"], 1, 2),
    ("Parameter fuzzing on https://example.com to discover undocumented parameters", ["arjun"], 1, 2),

    # ===== SECTION 13: CLOUD RECON (16) =====
    ("cloud audit on https://example.com", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("aws metadata check on http://169.254.169.254", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("azure metadata check on 169.254.169.254", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("gcp metadata check on metadata.google.internal", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("cloudfront detection for example.com", ["curl"], 1, 2),
    ("s3 bucket enumeration for example", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("cloud storage audit on example", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("cloud_enum storage scan for example", ["cloud_enum"], 1, 2),
    ("scoutsuite cloud audit for aws", ["scoutsuite"], 1, 2),
    ("prowler aws security audit", ["prowler"], 1, 2),
    ("cdn detection for cdn.example.com", ["curl"], 1, 2),
    ("azure blob check on https://test.blob.core.windows.net", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("gcp bucket scan on storage.googleapis.com", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("Check if example.com uses any cloud services like AWS CloudFront or Azure", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("Enumerate S3 buckets for example to find open storage", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("I need to audit the cloud infrastructure of example.com including CDN and storage", ["curl", "whatweb", "dig", "openssl"], 3, 5),

    # ===== SECTION 14: SHODAN / CENSYS / UNCOVER (12) =====
    ("shodan search for example.com on internet", ["shodan"], 1, 2),
    ("shodan internet device search for example.com", ["shodan"], 1, 2),
    ("censys search for example.com certificates", ["censys"], 1, 2),
    ("censys ip lookup for 8.8.8.8", ["censys"], 1, 2),
    ("shodan port scan history for 8.8.8.8", ["shodan"], 1, 2),
    ("shodan honeypot check for 8.8.8.8", ["shodan"], 1, 2),
    ("uncover search for example.com", ["uncover"], 1, 2),
    ("shodan and censys search on example.com", ["shodan"], 1, 2),
    ("Search Shodan for all exposed services on example.com's IP range", ["shodan"], 1, 2),
    ("Use Censys to find all certificates and services for example.com", ["censys"], 1, 2),
    ("Run uncover to discover assets for example.com from Shodan and Censys", ["uncover"], 1, 2),
    ("I need to find all internet-facing infrastructure for example.com using Shodan", ["shodan"], 1, 2),

    # ===== SECTION 15: EMAIL OSINT (14) =====
    ("theHarvester email osint on example.com", ["theHarvester"], 1, 2),
    ("the harvester harvest on example.com", ["theHarvester"], 1, 2),
    ("email osint harvesting for example.com", ["theHarvester"], 1, 2),
    ("email recon on example.com", ["theHarvester", "dig", "nmap", "dig"], 3, 5),
    ("email harvest on example.com", ["theHarvester", "dig", "nmap", "dig"], 3, 5),
    ("smtp enum on mail.example.com", ["theHarvester", "dig", "nmap", "dig"], 3, 5),
    ("mail server discovery for example.com", ["theHarvester", "dig", "nmap", "dig"], 3, 5),
    ("holehe email check for user@example.com", ["holehe"], 1, 2),
    ("theHarvester email search on example.com", ["theHarvester"], 1, 2),
    ("enumerate emails on example.com", ["theHarvester"], 1, 2),
    ("find email addresses on example.com", ["theHarvester"], 1, 2),
    ("Gather all email addresses associated with example.com using theHarvester", ["theHarvester"], 1, 2),
    ("Check if user@example.com is registered on popular websites using holehe", ["holehe"], 1, 2),
    ("I need to find employees email addresses for example.com for the phishing assessment", ["theHarvester"], 1, 2),

    # ===== SECTION 16: USERNAME / SOCIAL OSINT (12) =====
    ("sherlock username search for johndoe", ["sherlock"], 1, 2),
    ("maigret user search for johndoe", ["maigret"], 1, 2),
    ("social media lookup for johndoe", ["sherlock"], 1, 2),
    ("social media lookup for johndoe across platforms", ["sherlock"], 1, 2),
    ("social network search for johndoe on social media", ["sherlock"], 1, 2),
    ("find all accounts for johndoe across networks", ["sherlock"], 1, 2),
    ("digital footprint search for johndoe online", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("osint username reconnaissance for johndoe on social medias", ["sherlock"], 1, 2),
    ("Find all social media profiles for username johndoe across 400+ platforms", ["sherlock"], 1, 2),
    ("Use maigret to perform a comprehensive username search for johndoe", ["maigret"], 1, 2),
    ("Search for johndoe across social networks and online platforms", ["sherlock"], 1, 2),
    ("I need to build a digital footprint profile for johndoe using OSINT techniques", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),

    # ===== SECTION 17: SECRET SCANNING (12) =====
    ("trufflehog secret scan on git repo", ["trufflehog"], 1, 2),
    ("gitleaks scan on repository", ["gitleaks"], 1, 2),
    ("git secret scanning on repo", ["trufflehog"], 1, 2),
    ("find leaked secrets in repo", ["trufflehog"], 1, 2),
    ("trufflehog git history scan for credentials", ["trufflehog"], 1, 2),
    ("gitleaks git secrets detection", ["gitleaks"], 1, 2),
    ("scan for api keys in repository", ["trufflehog"], 1, 2),
    ("credential leak detection in git repo", ["trufflehog"], 1, 2),
    ("Scan the repository for leaked API keys and secrets using trufflehog", ["trufflehog"], 1, 2),
    ("Run gitleaks on the repo to detect hardcoded passwords and tokens", ["gitleaks"], 1, 2),
    ("Find leaked credentials in our github repository before the security audit", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("We need to scan git history for any accidentally committed secrets", ["trufflehog"], 1, 2),

    # ===== SECTION 18: ACTIVE DIRECTORY RECON (16) =====
    ("active directory assessment on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("ad recon on domain controller 10.0.0.5", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("ldap enum on 10.0.0.1", ["nmap"], 1, 2),
    ("kerberos user enum on 10.0.0.1", ["nmap"], 1, 2),
    ("smb share enum on 10.0.0.1", ["nmap"], 1, 5),
    ("smb enum on windows server 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("netbios scan on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("responder capture on eth0", ["responder"], 1, 2),
    ("impacket enumeration on dc.example.com", ["impacket"], 1, 2),
    ("enum4linux recon on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("ldap domain dump on dc.example.com", ["nmap"], 1, 2),
    ("crackmapexec smb enum on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("netexec ad recon on 10.0.0.1", ["nmap", "nmap", "nmap", "nmap"], 3, 5),
    ("Enumerate SMB shares and users on 10.0.0.1 for privilege escalation", ["nmap"], 1, 5),
    ("Perform LDAP anonymous bind check on dc.example.com to enumerate users", ["nmap"], 1, 2),
    ("Run responder to capture LLMNR/NBT-NS traffic on the network", ["responder"], 1, 2),

    # ===== SECTION 19: VULNERABILITY RECON (16) =====
    ("vuln scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 3, 5),
    ("cve scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 3, 5),
    ("log4j check on https://example.com", ["nuclei"], 1, 2),
    ("heartbleed test on https://example.com", ["nmap"], 1, 2),
    ("shellshock scan on https://example.com", ["nuclei"], 1, 2),
    ("spring4shell check on https://example.com", ["nuclei"], 1, 2),
    ("struts vulnerability scan on https://example.com", ["nuclei", "nikto", "wpscan", "sqlmap"], 3, 5),
    ("searchsploit apache 2.4.49", ["searchsploit"], 1, 2),
    ("exploit search for wordpress 5.8", ["searchsploit"], 1, 2),
    ("ssrf check on https://example.com", ["nuclei"], 1, 2),
    ("idor scan on https://example.com/api", ["nuclei"], 1, 2),
    ("lfi scan on https://example.com/page", ["nuclei"], 1, 2),
    ("rfi scan on https://example.com/page", ["nuclei"], 1, 2),
    ("open redirect scan on https://example.com", ["nuclei"], 1, 2),
    ("deserialization check on https://example.com", ["nuclei"], 1, 2),
    ("broken access control check on https://example.com", ["nuclei"], 1, 2),

    # ===== SECTION 20: WEB APP VULN SCANNING (10) =====
    ("web audit on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("web scan on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("full web audit on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("nikto vulnerability scan on https://example.com", ["nikto"], 1, 2),
    ("nuclei scan on https://example.com", ["nuclei"], 1, 2),
    ("Run a comprehensive web application scan on https://example.com", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("I need a full web audit of example.com including headers, vulns, and directories", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("Do a vulnerability assessment on https://example.com with nuclei templates", ["nuclei"], 1, 2),
    ("Web application security scan for example.com - find all OWASP Top 10 issues", ["curl", "whatweb", "nuclei", "ffuf", "wpscan", "nikto"], 5, 7),
    ("Run nikto for a full web server vulnerability scan on https://example.com", ["nikto"], 1, 2),

    # ===== SECTION 21: EXTERNAL / PASSIVE / FULL RECON (18) =====
    ("external recon on example.com", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("external attack surface on example.com", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("passive recon on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("passive reconnaissance on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("osint recon on example.com", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("full osint recon on example.com", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("external attack surface recon on example.com", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("passive scan on example.com", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("full recon on example.com", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("comprehensive recon on example.com", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("Map the entire external attack surface for example.com including Shodan and certificates", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("Do passive intelligence gathering on example.com without any active scanning", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("Full open source intelligence gathering for example.com", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Initial access OSINT on example.com for the red team engagement", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("Pre engagement reconnaissance on example.com to gather threat intel", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("Attack surface mapping for example.com across all external assets", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("Stealth passive recon on example.com using only non-intrusive techniques", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("Red team external recon on example.com to discover perimeter weaknesses", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),

    # ===== SECTION 22: COMPOUND MULTI-TOOL (20) =====
    ("subfinder then httpx on example.com", ["subfinder", "httpx"], 2, 3),
    ("gau then httpx on example.com", ["gau", "httpx"], 2, 3),
    ("waybackurls then httpx on example.com", ["waybackurls", "httpx"], 2, 3),
    ("theHarvester and then holehe on example.com", ["theHarvester", "holehe"], 2, 3),
    ("amass subdomains and then httpx probe on example.com", ["amass", "httpx"], 2, 3),
    ("gau and then katana on example.com", ["gau", "katana"], 2, 3),
    ("subfinder and then gospider on example.com", ["subfinder", "gospider"], 2, 3),
    ("dnsx then httpx on example.com", ["dnsx", "httpx"], 2, 3),
    ("massdns then puredns on example.com", ["massdns", "puredns"], 2, 3),
    ("uncover then httpx on example.com", ["uncover", "httpx"], 2, 3),
    ("theHarvester then sherlock for johndoe", ["theHarvester", "sherlock"], 2, 3),
    ("crtsh and then httpx on example.com", ["curl", "httpx"], 2, 3),
    ("subdomain enumeration then port scan on example.com", ["subfinder", "nmap"], 2, 4),
    ("whois lookup then ssl check on example.com", ["whois", "openssl"], 2, 4),
    ("discover urls then find parameters on https://example.com", ["gau", "arjun"], 2, 3),
    ("enumerate subdomains then probe with httpx on example.com", ["subfinder", "httpx"], 2, 4),
    ("subdomain brute force with amass then httpx probe on example.com", ["amass", "httpx"], 2, 3),
    ("find emails then check subdomains on example.com", ["theHarvester", "subfinder"], 2, 4),
    ("gau then waybackurls on example.com", ["gau", "waybackurls"], 2, 3),
    ("crtsh certificate search then httpx probe on example.com", ["curl", "httpx"], 2, 3),

    # ===== SECTION 23: ADVANCED PROFESSIONAL WORKFLOWS (18) =====
    ("We are doing a red team engagement on example.com, start with external recon", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("I need to understand the security posture of example.com, do a comprehensive assessment", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("I am starting a penetration test on example.com, map out the attack surface first", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("Before the pentest, do pre-engagement OSINT on example.com to gather intel silently", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("Automated recon pipeline for example.com: subdomains, httpx probe, nuclei scan, screenshots", ["httpx"], 1, 3),
    ("Full scope external recon for example.com - find all assets, subdomains, and exposed services", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("Comprehensive passive recon on example.com without touching the target infrastructure", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("Multi-vector external recon on example.com using Shodan, CT logs, and passive DNS", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("OSINT profiling for example.com: gather domains, emails, tech stack, and SSL certs", ["openssl", "nmap", "nmap"], 2, 4),
    ("Adversary reconnaissance on example.com to understand the target from an attacker perspective", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("I need to map example.com's cloud infrastructure - check AWS, Azure, GCP services", ["curl", "whatweb", "dig", "openssl"], 3, 5),
    ("Bug bounty recon on example.com: subdomains, wayback urls, parameter discovery", ["waybackurls"], 1, 3),
    ("Zero-touch OSINT automation for example.com - all passive intelligence gathering", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Complete digital footprint analysis of example.com across the entire internet", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Continuous recon monitoring for example.com - track changes in external assets", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Tier 1 OSINT collection for example.com: gather all publicly available information", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Reconnaissance lifecycle for example.com - full intelligence gathering lifecycle", ["whois", "dig", "dig", "curl", "subfinder", "amass", "whatweb"], 5, 8),
    ("Attack surface discovery for example.com - perimeter mapping and external assessment", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),

    # ===== SECTION 24: NATURAL LANGUAGE TASKS (28) =====
    ("Check what services are running on 10.0.0.1 and identify the operating system", ["nmap"], 1, 2),
    ("Find all DNS records for example.com including MX, TXT, NS, and CNAME", ["dig", "subfinder", "amass", "whois"], 3, 5),
    ("I need to find all subdomains for example.com and check which ones return HTTP 200", ["nmap", "whatweb", "gobuster", "subfinder", "amass", "nuclei"], 4, 7),
    ("Can you scan example.com for open ports and then check what web technologies they use?", ["nmap", "whatweb", "nmap"], 3, 5),
    ("Do a complete security analysis of example.com including headers, SSL, and vulnerabilities", ["openssl", "nmap", "nmap"], 2, 4),
    ("Find all JavaScript files on https://example.com and extract API endpoints from them", ["gospider"], 1, 2),
    ("I need to enumerate SMB shares on 10.0.0.1 and check for null session access", ["nmap"], 1, 5),
    ("Check if example.com has any exposed .git directories or backup files", ["curl"], 1, 2),
    ("Run a vulnerability scan on https://example.com for critical and high severity issues only", ["nuclei", "nikto", "wpscan", "sqlmap"], 3, 5),
    ("Discover all API endpoints on https://example.com including REST and GraphQL", ["curl"], 1, 2),
    ("I need to test whether example.com is vulnerable to subdomain takeover", ["subjack"], 1, 2),
    ("Find all email addresses associated with example.com and verify if they are valid", ["theHarvester"], 1, 2),
    ("Do a full reconnaissance on example.com and provide a comprehensive report", ["nmap", "curl", "whatweb", "nuclei", "gobuster", "dig", "subfinder", "whois"], 5, 9),
    ("Check if example.com has any cloud storage buckets open to the public", ["curl", "whatweb", "dig", "openssl"], 4, 5),
    ("I need to find the technology stack behind example.com including web server and frameworks", ["whatweb"], 1, 2),
    ("Test all cipher suites supported by example.com and check for weak TLS configurations", ["openssl", "nmap", "nmap"], 2, 4),
    ("Find historical URLs for example.com from the Wayback Machine that might contain sensitive data", ["waybackurls"], 1, 2),
    ("I need to map the external attack surface of example.com using Shodan and certificate logs", ["shodan"], 1, 2),
    ("Check if the target 10.0.0.1 is vulnerable to EternalBlue or other SMB exploits", ["nmap"], 1, 5),
    ("Do passive OSINT on example.com without generating any traffic to their servers", ["whatweb", "subfinder", "dig", "whois", "openssl"], 4, 6),
    ("Enumerate all LDAP information from dc.example.com including users and groups", ["nmap"], 1, 2),
    ("I need to find API keys and tokens that were accidentally committed to the git repository", ["trufflehog"], 1, 2),
    ("Check example.com's SSL certificate chain and validate it against trusted root CAs", ["openssl", "nmap", "nmap"], 2, 4),
    ("Find all parameters accepted by https://example.com/endpoint using param mining", ["gobuster"], 1, 2),
    ("I'm doing a bug bounty assessment on example.com, start with subdomain enumeration and httpx probing", ["httpx"], 1, 2),
    ("Check if the docker daemon is exposed on 10.0.0.1 and enumerate containers", ["nmap"], 1, 2),
    ("Perform a complete passive reconnaissance on example.com for red team preparation", ["shodan", "curl", "whatweb", "subfinder", "whois", "dig"], 4, 7),
    ("I need to discover all cloud assets of example.com including S3, Azure Blob, and GCP buckets", ["curl", "whatweb", "dig", "openssl"], 3, 5),

    # ===== SECTION 25: SPECIALIZED / EDGE CASE (24) =====
    ("quick check on https://example.com", ["curl"], 1, 2),
    ("interactsh oob testing client", ["interactsh"], 1, 2),
    ("exposed panels scan on https://example.com", ["nuclei"], 1, 2),
    ("broken access control scan on https://example.com", ["nuclei"], 1, 2),
    ("oauth endpoint enum on https://example.com", ["nmap"], 1, 2),
    ("smtp user enum on mail.example.com", ["nmap"], 1, 2),
    ("waf detection on https://example.com", ["nmap"], 1, 2),
    ("cdn detection for https://example.com", ["curl"], 1, 2),
    ("docker discovery on 10.0.0.1:2375", ["nmap"], 1, 2),
    ("jenkins discovery on jenkins.example.com", ["nmap"], 1, 2),
    ("redis enumeration on 10.0.0.1:6379", ["nmap"], 1, 2),
    ("mongodb enum on 10.0.0.1:27017", ["nmap"], 1, 2),
    ("mysql scan on 10.0.0.1:3306", ["nmap"], 1, 2),
    ("mssql discovery on 10.0.0.1:1433", ["nmap"], 1, 2),
    ("elasticsearch discovery on 10.0.0.1:9200", ["nmap"], 1, 2),
    ("postgresql enum on 10.0.0.1:5432", ["nmap"], 1, 2),
    ("kafka discovery on 10.0.0.1:9092", ["nmap"], 1, 2),
    ("rabbitmq discovery on 10.0.0.1:5672", ["nmap"], 1, 2),
    ("cassandra scan on 10.0.0.1:9042", ["nmap"], 1, 2),
    ("graphql introspection on https://example.com", ["curl"], 1, 2),
    ("swagger discovery on https://example.com", ["curl"], 1, 2),
    ("websocket upgrade check on https://example.com", ["curl"], 1, 2),
    ("server header check on https://example.com", ["whatweb"], 1, 2),
    ("container discovery on 10.0.0.1", ["nmap"], 1, 2),
]


def main():
    planner = RegistryPlanner()
    planner.build_index(AVAILABLE_TOOLS)

    passed = 0
    failed = 0
    failures = []

    total = len(RECON_COMMANDS)
    print(f"\n{'='*60}")
    print(f"  RECON NLP EVALUATION: {total} Commands")
    print(f"{'='*60}\n")

    for idx, (cmd, expected_tools, min_steps, max_steps) in enumerate(RECON_COMMANDS):
        ok, msg = check_plan(planner, cmd, expected_tools, min_steps, max_steps)
        if ok:
            passed += 1
        else:
            failed += 1
            failures.append((cmd, msg))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status:4s}] ({idx+1:3d}) {cmd:75s} \u2192 {msg}")

    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {total}")
    print(f"  SCORE: {passed/total*100:.1f}%")
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
