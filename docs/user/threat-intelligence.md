!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 🌐 Threat Intelligence

A security tool is only as good as the data it uses. Siyarix integrates directly with real-world threat intelligence feeds, allowing you to instantly perform IP reputation lookups and enrich your CVE data.

!!! note
    Currently, Siyarix supports AlienVault OTX and the National Vulnerability Database (NVD). We are actively building out our MITRE ATT&CK integration!

---

## 🔌 Active Integrations

### 👽 AlienVault OTX
Check the reputation of any IP address instantly using the AlienVault Open Threat Exchange API.

```python
from siyarix.threat_intel import AlienVaultOTX

otx = AlienVaultOTX()

# Instantly check if this IP is known to be malicious
result = await otx.lookup_ip("8.8.8.8")
# Returns: pulse_count, reputation, source
```

!!! info
    To use this integration, you must set your `ALIENVAULT_API_KEY` environment variable!

### 🏛️ National Vulnerability Database (NVD)
Get the latest, most accurate details on any vulnerability directly from the NVD API 2.0.

```python
from siyarix.threat_intel import NVDDatabase

nvd = NVDDatabase()

# Fetch the CVSS score and description for a CVE
result = await nvd.lookup_cve("CVE-2024-0001")
# Returns: description, base_score (CVSS v3.1), source
```

### 🧠 The ThreatIntelManager
Don't want to manage multiple APIs? Use the `ThreatIntelManager` as a unified facade! Siyarix will automatically route your request to the right provider.

```python
from siyarix.threat_intel import ThreatIntelManager

manager = ThreatIntelManager()

result = await manager.analyze_target("8.8.8.8")        # Routes to OTX
result = await manager.analyze_target("CVE-2024-0001")  # Routes to NVD
```

---

## 🗺️ MITRE ATT&CK Integration (Coming Soon)

We are building a large `MITREAttackDB` layer! Soon, Siyarix will automatically map findings to specific threat actor tactics and techniques.

```bash
# 📊 View your current MITRE ATT&CK coverage right now!
siyarix security mitre-coverage

# (Detailed technique analysis and automatic mapping coming soon!)
```

**What to expect:**
- A complete, offline database of MITRE tactics and techniques.
- Automatic CVE-to-technique correlation.
- Finding enrichment (Siyarix will tell you *how* an attacker might use a vulnerability).
- Deep coverage analysis to spot gaps in your defenses.

---

## 🚀 Planned Enhancements

We are never done building. Here is what is on the threat intel roadmap:

- **MISP Feed Ingestion**: Consume MISP JSON events as structured threat intelligence.
- **STIX 2.x & OpenIOC**: Import standard indicators of compromise (IoCs).
- **Knowledge Graph Integration**: Visually link threat indicators to your scan findings.
- **Unified Threat Model**: A standardized data format for representing threats across all providers.

---

## 🎯 Key Use Cases

### What You Can Do Right Now:
- **IP Reputation Checking**: Instantly vet IPs against AlienVault during your reconnaissance phases.
- **CVE Enrichment**: Automatically pull CVSS scores and detailed descriptions when assessing vulnerabilities.
- **Smarter Threat Hunting**: Combine live reputation data with your offline scan findings.

### What You Will Be Able To Do Soon:
- **Advanced Threat Hunting**: Automatically match your scan findings against known attacker TTPs (Tactics, Techniques, and Procedures).
- **Dynamic Risk Scoring**: Automatically raise the severity of a finding if it matches an active, real-world threat campaign.
- **Compliance Reporting**: Automatically include MITRE ATT&CK mapping in your final executive reports.
