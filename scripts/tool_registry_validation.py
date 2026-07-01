import json

import os

json_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src",
    "siyarix",
    "data",
    "cyber_tools.json",
)
with open(json_path, encoding="utf-8") as f:
    t = json.load(f)

print(f"Total tools: {len(t)}")
print()

# Check category fixes
for name in ["bloodhound", "linpeas", "winpeas", "pspy", "smbclient", "crackmapexec", "certipy-ad"]:
    if name in t:
        print(f"  {name}: category={t[name]['category']}, risk_level={t[name]['risk_level']}")
    else:
        print(f"  {name}: MISSING")

# Check additions
print()
for name in [
    "trufflehog",
    "sliver",
    "velociraptor",
    "crunch",
    "arjun",
    "zmap",
    "ysoserial",
    "checkov",
]:
    print(f"  + {name}: {'present' if name in t else 'MISSING'}")

# Check removals
print()
for name in ["bash", "cat", "grep", "kill", "rm", "chmod", "python", "powershell", "nano", "vim"]:
    print(f"  - {name}: {'present (SHOULD BE REMOVED!)' if name in t else 'removed'}")

# Check duplicates removed
print()
for name in ["hashid", "searchsploit", "proxychains4", "reaver-wps", "az-cli", "gcloud-cli"]:
    print(f"  dup {name}: {'present (SHOULD BE REMOVED!)' if name in t else 'removed'}")
