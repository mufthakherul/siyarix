"""Debug trace for decompose_goal on specific commands."""

from siyarix import RegistryPlanner
from siyarix.nlp_engine import NaturalLanguageParser
from siyarix.models import PlanType
import re, os

_IS_WIN = os.name == "nt"

p = RegistryPlanner()
tools = [
    "nmap","masscan","subfinder","amass","curl","whatweb","dig","whois",
    "nuclei","ffuf","gobuster","nikto","wpscan","sqlmap","openssl",
    "shodan","censys","theHarvester","sherlock","holehe","maigret",
    "dnsx","massdns","puredns","httpx","katana","gospider",
    "arjun","paramspider","uncover","subjack","trufflehog","gitleaks",
    "cloud_enum","scoutsuite","prowler","waybackurls","gau","interactsh",
    "testssl.sh","ssllabs-scan","eyewitness","responder","impacket",
    "impacket-secretsdump","impacket-GetUserSPNs","impacket-GetNPUsers",
    "bloodhound-python","searchsploit","tracert","crackmapexec","netexec","enum4linux",
]
p.build_index(tools)

goal = "nmap os detection on 10.0.0.1"
goal_lower = goal.lower()
avail_set = set(tools)

# Step 0
intent = p._nlp.parse(goal)
print(f"[0] intent.confidence={intent.confidence:.2f}, tool_name={intent.tool_name}, tpl={intent.template_name}")

# Step 0.5
direct_tool_keywords = {
    "dcsync": ("impacket-secretsdump", "DCSync attack", "-just-dc"),
    "kerberoast": ("impacket-GetUserSPNs", "Kerberoasting", "-dc-ip"),
    "asrep": ("impacket-GetNPUsers", "AS-REP roasting", "-dc-ip -request"),
    "bloodhound": ("bloodhound-python", "BloodHound AD collector", ""),
    "zerologon": ("nmap", "Zerologon check", "--script smb-vuln-zerologon -p 445"),
    "petitpotam": ("nmap", "PetitPotam check", "--script smb-vuln-petitpotam -p 445"),
    "shodan": ("shodan", "Shodan internet device search", "search"),
    "censys": ("censys", "Censys certificate/device search", ""),
    "uncover": ("uncover", "Shodan/Censys search via CLI", ""),
    "subjack": ("subjack", "Subdomain takeover detection", ""),
    "interactsh": ("interactsh", "OOB interaction testing client", "-c"),
    "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", ""),
    "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
    "dnsx": ("dnsx", "DNS toolkit and probing", ""),
    "massdns": ("massdns", "High-speed DNS brute-force resolver", ""),
    "puredns": ("puredns", "DNS brute-force with wildcard filtering", ""),
    "cloud_enum": ("cloud_enum", "Cloud storage enumeration", ""),
    "scoutsuite": ("scoutsuite", "Multi-cloud security auditing", ""),
    "prowler": ("prowler", "AWS security auditing", ""),
    "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
    "gitleaks": ("gitleaks", "Git repository secret scanning", ""),
    "trufflehog": ("trufflehog", "Git secret scanning", ""),
    "sherlock": ("sherlock", "Username search across social networks", ""),
    "holehe": ("holehe", "Email-to-account mapping", ""),
    "maigret": ("maigret", "Username search engine", ""),
    "arjun": ("arjun", "HTTP parameter discovery", ""),
    "paramspider": ("paramspider", "Parameter mining from URLs", ""),
    "gospider": ("gospider", "Web spider and content discovery", ""),
    "katana": ("katana", "Web crawler and URL discovery", ""),
    "theharvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
    "the harvester": ("theHarvester", "Email/subdomain OSINT harvesting", ""),
    "httpx": ("httpx", "HTTP endpoint probing", ""),
    "gau": ("gau", "GetAllUrls from Wayback Machine", ""),
    "testssl": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
    "testssl.sh": ("testssl.sh", "SSL/TLS comprehensive testing", "--full"),
    "ssllabs": ("ssllabs-scan", "SSL Labs API scanner", ""),
    "responder": ("responder", "LLMNR/NBT-NS responder", "-I eth0"),
    "impacket": ("impacket", "Impacket toolkit", ""),
    "searchsploit": ("searchsploit", "Exploit search", ""),
    "waybackurls": ("waybackurls", "Wayback Machine URL discovery", ""),
    "takeover": ("subjack", "Subdomain takeover detection", ""),
    "nikto": ("nikto", "Web server vulnerability scan", ""),
    "exposed panel": ("nuclei", "Exposed panel scan", "-t http/exposed-panels"),
    "ssl labs": ("ssllabs-scan", "SSL Labs API scanner", ""),
    "labs": ("ssllabs-scan", "SSL Labs API scanner", ""),
    "secret": ("trufflehog", "Git secret scanning", ""),
    "amass": ("amass", "Aggressive subdomain discovery", ""),
    "subfinder": ("subfinder", "Passive subdomain enumeration", ""),
    "sublist3r": ("sublist3r", "Subdomain search via Sublist3r", ""),
    "assetfinder": ("assetfinder", "Asset discovery via public sources", ""),
    "crtsh": ("curl", "Certificate transparency via crt.sh", "-s https://crt.sh/?q=%25.{target}&output=json"),
    "wayback": ("waybackurls", "Wayback Machine URL discovery", ""),
}
for kw, (tool, desc, flags) in direct_tool_keywords.items():
    if kw in goal_lower.split():
        print(f"[0.5] DIRECT MATCH: kw={kw!r}, tool={tool}")
        break
else:
    print("[0.5] no direct match")

# Step 1 kw_map
kw_map = [
    (("ssl","tls","cipher suite"),"ssl_audit"),
    (("http header","response header","security header"),"headers_check"),
    (("cors","cross-origin","cross origin","preflight"),"cors_check"),
    (("dns recon","dns enumeration","dns record","nameserver","mx record","dns resolution"),"dns_recon"),
    (("subdomain","subdomain enum","subdomain discover","dns enum","dnsrecon","subdomain brute"),"recon_full"),
    (("network scan","infrastructure scan","port scan","full port scan","open ports","tcp scan"),"network_scan"),
    (("brute force","crack password","password crack","credential brute"),"brute_force"),
    (("dcsync","dc sync","domain replication"),"ad_assessment"),
    (("kerberoast","kerberoasting"),"ad_assessment"),
    (("asrep","as-rep","asrep roast"),"ad_assessment"),
    (("bloodhound","bloodhound collector","bloodhound-python"),"ad_assessment"),
    (("zerologon","zerologon check"),"ad_assessment"),
    (("petitpotam","petitpotam check"),"ad_assessment"),
    (("deauth","deauthentication","beacon flood","aireplay"),"wifi_audit"),
    (("bluetooth","bt scan","hci0","bluez"),"wifi_audit"),
    (("wifi","wireless","wpa","wpa2","wep","handshake"),"wifi_audit"),
    (("ad ","active directory","domain controller"),"ad_assessment"),
    (("external recon","external attack surface","internet scan","external perimeter","full external","edge discovery","attack surface","attack surface mapping","red team","bug bounty"),"external_recon"),
    (("osint recon","open source","recon-ng","osint gather","osint intelligence","osint assessment","osint investigation","osint collection","osint automation","deep osint","full osint","complete osint","thorough osint","target profile","target profiling","adversary recon","reconnaissance lifecycle","full scope","tier 1 osint","osint profiling","automated recon","recon pipeline","continuous recon","recon automation"),"osint_recon"),
    (("email recon","email enum","email harvest","smtp enum","mail server"),"email_recon"),
    (("cloud audit","aws","s3 ","azure","gcp"),"cloud_audit"),
    (("privesc","privilege escalation","linux audit","suid"),"linux_privesc"),
    (("web audit","web scan","website","webapp","web app"),"web_audit"),
    (("vuln scan","cve scan","vulnerability scan"),"vuln_scan"),
    (("smb enum","windows share","cifs","netbios","crackmapexec","netexec","enum4linux"),"smb_enum"),
    (("passive recon","passive scan","passive reconnaissance","passive intel","passive intelligence","passive information","stealth recon","stealth osint","non intrusive","initial access","pre engagement","quiet recon"),"passive_recon"),
    (("full audit","full scan","comprehensive scan","comprehensive recon","thorough check","thorough recon","full recon","security posture","pentest","penetration test","security assessment","security audit"),"full_audit"),
]
for keywords, template_name in kw_map:
    if any(kw in goal_lower for kw in keywords):
        print(f"[1] TEMPLATE MATCH: {template_name} via {[kw for kw in keywords if kw in goal_lower]}")
        break
else:
    print("[1] no kw_map match")

# Step 2 target
url_match = re.search(r"(?:https?|tcp|udp|ws|wss)://[^\s]+", goal)
host_match = re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", goal_lower)
ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", goal)
target = ""
if url_match:
    target = url_match.group(0)
elif host_match:
    target = host_match.group(0)
elif ip_match:
    target = ip_match.group(0)
print(f"[2] target={target!r}")

# Step 3
tool_match = None
candidates = p._search_index(goal)
print(f"[3] candidates={candidates[:5]}")
for c in candidates:
    if c in avail_set:
        pattern = r"(?<!\w)" + re.escape(c.lower()) + r"(?!\w)"
        if re.search(pattern, goal_lower):
            tool_match = c
            print(f"[3] MATCHED {c}")
            break

# Step 4 intent_map with target
if target:
    intent_map = {"port": ("nmap", "Port scan", "-sT -T4 --top-ports 100")}
    # Check just the REAL intent_map scanning
    GENERIC = frozenset({"scan", "run", "do", "get", "find", "check", "test", "list", "show", "explore", "discover", "probe"})
    print(f"[4] Searching intent_map...")
    # Only show what matches
    for kw in goal_lower.split():
        print(f"    word={kw!r}")

# Probe fallback
print(f"[5] After Step 3: tool_match={tool_match!r}")
if tool_match:
    print("Would return 1-step nmap plan")
else:
    print("Would fall through to probe fallback (9 steps)")
