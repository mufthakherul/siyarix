# Threat Intelligence

Siyarix integrates threat intelligence feeds and MITRE ATT&CK mapping to enrich scan findings with real-world threat context.

## MITRE ATT&CK integration

The built-in `MITREAttackDB` maintains 13 tactics (TA0001–TA0043) and 24 techniques with CVE-to-technique mappings.

### Tactics covered

| Tactic ID | Tactic | Example techniques |
|-----------|--------|-------------------|
| TA0001 | Initial Access | T1078 (Valid Accounts), T1190 (Exploit Public-Facing App) |
| TA0002 | Execution | T1059 (Command and Scripting Interpreter) |
| TA0003 | Persistence | T1098 (Account Manipulation) |
| TA0004 | Privilege Escalation | T1068 (Exploitation for Privilege Escalation) |
| TA0005 | Defense Evasion | T1027 (Obfuscated Files or Information) |
| TA0006 | Credential Access | T1110 (Brute Force), T1555 (Credentials from Password Stores) |
| TA0007 | Discovery | T1046 (Network Service Scanning) |
| TA0008 | Lateral Movement | T1021 (Remote Services) |
| TA0009 | Collection | T1005 (Data from Local System) |
| TA0011 | Command and Control | T1071 (Application Layer Protocol) |
| TA0010 | Exfiltration | T1048 (Exfiltration Over Alternative Protocol) |
| TA0040 | Impact | T1485 (Data Destruction), T1490 (Inhibit System Recovery) |
| TA0043 | Reconnaissance | T1595 (Active Scanning) |

### Finding enrichment

Scan findings are automatically enriched with MITRE ATT&CK context:

```python
threat_intel.enrich_finding(finding)
# Adds: mitre_attack_id, mitre_tactic, mitre_technique, related_threat_actors
```

### Viewing MITRE coverage

```bash
siyarix security mitre --technique T1078
# Shows: Valid Accounts - tools and commands that map to this technique
```

## Threat feed ingestion

### MISP feeds

Import MISP JSON events:

```bash
siyarix run "import threat intel from misp_feed.json"
```

The importer processes MISP attributes (IPs, domains, hashes, URLs) and converts them to `ThreatIntel` objects.

### STIX 2.x feeds

Import STIX indicators:

```bash
siyarix run "import STIX indicators from stix_feed.json"
```

Supports STIX 2.x Indicator and Observed Data objects.

### Data model

```python
@dataclass
class ThreatIntel:
    id: str
    source: str           # misp, stix, mitre, custom
    indicator: str        # IP, domain, hash, URL
    indicator_type: str   # ipv4, domain, md5, url, etc.
    severity: str         # info, low, medium, high, critical
    confidence: str       # low, medium, high
    mitre_attack_id: str
    mitre_tactic: str
    mitre_technique: str
    tags: list[str]
```

## Knowledge graph integration

Threat intelligence is linked into the knowledge graph:

- Threat indicators are added as nodes
- Relationships are created between indicators and matched findings
- BFS traversal can find attack paths based on threat intel

## Built-in CVE mappings

The `MITREAttackDB` includes CVE-to-technique mappings:

```python
mitre = MITREAttackDB()
technique = mitre.map_cve("CVE-2023-44487")
# Returns: T1498 (Network Denial of Service)
```

## Use cases

- **Threat hunting**: Match scan findings against known attacker TTPs
- **Risk scoring**: Elevate severity when findings match active threat campaigns
- **Reporting**: Include MITRE ATT&CK mapping in assessment reports
- **Coverage analysis**: Identify gaps in detection coverage
