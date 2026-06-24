# Intent Routing

The intent routing subsystem classifies user input, determines risk level, and selects the appropriate execution path. It works in conjunction with the **NLP Engine** for zero-dependency semantic parsing and the **Planner Router** for intent-to-plan mapping.

---

## Architecture

```
User Input
    │
    ▼
┌────────────────────────────────────────────┐
│              IntentRouter                   │
│                                            │
│  Keyword-based routing via compat.py:      │
│  • scan / nmap / port scan → "scan"         │
│  • recon / enumerate / discover → "recon"   │
│  • web / http / nikto / nuclei → "web"     │
│  • brute / crack / password → "brute"      │
│  • exploit / metasploit / attack → "exploit"│
│  • default → "general"                     │
│             │                              │
│             ▼                              │
│       IntentRoute                          │
│  (mode, risk_tier,                         │
│   requires_confirmation)                   │
└────────────────────────────────────────────┘
    │
    ├──→ Planner Router (selects REGISTRY / AUTONOMOUS / HYBRID)
    ├──→ NLP Engine (semantic parsing, entity extraction)
    └──→ RegistryPlanner (intent → plan template)
```

---

## IntentRouter (compat.py)

The simplified `IntentRouter` in `siyarix/compat.py` provides keyword-based routing:

```python
router = IntentRouter()
route = router.route("scan 10.0.0.1 for open ports")
# IntentRoute(mode="scan", risk_tier=RiskTier("medium"), requires_confirmation=False)
```

### Routing Rules

| Keywords | Mode | Risk Tier | Requires Confirmation |
|----------|------|-----------|----------------------|
| scan, nmap, port scan | scan | medium | No |
| recon, enumerate, discover | recon | low | No |
| web, http, nikto, nuclei | web | medium | No |
| brute, crack, password | brute | high | Yes |
| exploit, metasploit, attack | exploit | high | Yes |
| (default) | general | low | No |

### RouteResult

```python
@dataclass
class IntentRoute:
    mode: str                         # scan | recon | web | brute | exploit | general
    risk_tier: RiskTier               # low | medium | high
    requires_confirmation: bool
```

---

## NLP Engine

The `NaturalLanguageParser` in `siyarix/nlp_engine.py` provides zero-dependency semantic parsing:

```python
nlp = NaturalLanguageParser()
parsed = nlp.parse("scan 10.0.0.1 for open ports and run vulnerability scan")
# ParsedIntent(
#     target="10.0.0.1",
#     target_type="ipv4",
#     tool_name=None,
#     template_name=None,
#     parameters={"ports": "open", "severity": "high,critical"},
#     confidence=score,
#     tokens=[...],
#     raw_text="..."
# )
```

### Features

- **Zero-dependency**: Pure stdlib — no ML libraries required
- **Entity extraction**: IP addresses, domains, URLs, CIDR ranges, ports, emails, MACs, hashes, ASNs, Windows/Linux paths
- **Parameter extraction**: Port numbers, speed (fast/stealth/aggressive), severities, timeouts, formats, protocols, wordlists, threads, credentials
- **BM25 scoring**: Okapi BM25 similarity for intent matching against tool and template corpora
- **Fuzzy matching**: Jaccard N-gram similarity with phonetic normalization for typos
- **Synonym mapping**: 380+ cybersecurity-specific synonym/canonical mappings (CVE, subdomain, exploit, AD, cloud, etc.)
- **Multi-intent parsing**: Splits conjunctions ("then", "and then", "followed by") into multiple intents

### Entity Extraction Patterns

| Type | Example | Pattern |
|------|---------|---------|
| CVE | `CVE-2024-1234` | Regex |
| IPv4 | `10.0.0.1` | Full octet validation |
| IPv6 | `fe80::1` | Full hex validation |
| CIDR | `10.0.0.0/24` | IPv4/IPv6 with prefix |
| Domain | `example.com` | Multi-label hostname |
| URL | `https://example.com` | HTTP/HTTPS |
| Email | `user@example.com` | RFC 5321 simplified |
| MAC | `00:1A:2B:3C:4D:5E` | Hex with colon/hyphen |
| SHA256 | 64 hex chars | Hash pattern |
| ASN | `AS12345` | ASN notation |

### Corpus Training

The parser can be trained with tool descriptions and template names to improve scoring:

```python
nlp.train_tools(tool_metadata)       # Feed tool names + descriptions
nlp.train_templates(template_data)   # Feed template names + descriptions
```

---

## Planner Router

The `Planner` class in `siyarix/planner.py` dispatches to the appropriate planner:

| Mode | Planner | Behavior |
|------|---------|----------|
| `registry` / `offline` | RegistryPlanner | Heuristic-only, no AI |
| `autonomous` | AutonomousPlanner | LLM-only, no fallback |
| `integrated` (default) | Tries Autonomous → falls back to Registry | AI-first with heuristic fallback |

```python
planner = Planner()
plan = await planner.plan(
    goal="scan 10.0.0.1 for open ports",
    mode="integrated",           # autonomous | registry | offline | integrated
    provider="openai",           # Provider name (or "registry" to skip LLM)
    available_tools=["nmap", "nuclei", ...],
    llm_call=async_llm_function,
    tool_schemas=tool_schemas,
)
```

---

## RegistryPlanner

The `RegistryPlanner` in `siyarix/planner_registry.py` provides heuristic planning without any AI dependency:

### Tool Alternatives

```python
TOOL_ALTERNATIVES = {
    "nmap": ["masscan", "rustscan", "naabu"],
    "gobuster": ["ffuf", "dirb", "dirsearch"],
    "nuclei": ["nikto", "wapiti", "skipfish"],
    "hydra": ["medusa", "ncrack", "patator"],
    "subfinder": ["amass", "sublist3r", "assetfinder"],
    # ... 15+ alternative chains
}
```

### Multi-Word Intent Matching

500+ multi-word patterns map natural language to specific tools and commands, covering:

- **Reconnaissance**: subdomain enumeration, port scanning, technology fingerprinting
- **Vulnerability scanning**: nuclei, nikto, sqlmap
- **Web auditing**: CORS check, headers, SSL/TLS
- **Active Directory**: kerberoasting, AS-REP roasting, LDAP enumeration, SMB analysis
- **Exploitation**: metasploit, hydra, reverse shells
- **Blue Team / Defensive**: event log analysis, forensic triage, endpoint detection, SIEM queries
- **Memory forensics**: volatility-based patterns for process hollowing, Cobalt Strike, ransomware
- **Network forensics**: PCAP analysis, DNS tunneling, traffic analysis
- **Compliance scanning**: CIS benchmarks, SOC 2, PCI DSS, HIPAA, NIST 800-53
- **Cloud security**: AWS/Prowler audits, container security
- **System utilities**: disk usage, memory, processes, uptime

### Template-Based Workflow Generation

Pre-built templates for common security operations:

| Template | Tool Chain | Steps |
|----------|-----------|-------|
| `recon_full` | nmap → whatweb → gobuster → subfinder → amass → nuclei | 6 |
| `web_audit` | curl → whatweb → nuclei → ffuf → wpscan → nikto | 6 |
| `network_scan` | nmap → dig → whois → masscan | 4 |
| `vuln_scan` | nuclei → nikto → wpscan → sqlmap | 4 |
| `dns_recon` | dig → subfinder → amass → whois | 4 |
| `cloud_audit` | curl → whatweb → dig → openssl | 4 |
| `ad_assessment` | nmap × 4 (ports, SMB, LDAP, Kerberos) | 4 |
| `brute_force` | nmap → hydra → hashcat | 3 |
| `linux_privesc` | uname → find (SUID) → find (writable) → cat (crontab) | 4 |
| `ssl_audit` | openssl → nmap (ssl-enum-ciphers) → nmap (ssl-cert) | 3 |

---

## Integration Points

| Component | Role |
|-----------|------|
| **AgentCore** | Receives IntentRoute, dispatches to correct mode |
| **NLP Engine** | Provides semantic parsing for intent matching |
| **RegistryPlanner** | Maps intent to plan template for REGISTRY/OFFLINE mode |
| **Planner Router** | Selects between heuristic and LLM-based planning |
| **Context Manager** | Receives route metadata for context building |
| **PermissionGate** | Evaluates route risk tier for gating decisions |
| **EventBus** | Emits `intent.routed` event with route information |
