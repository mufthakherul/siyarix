# 🚦 Intent Routing

Welcome to the **Intent Routing** subsystem! Think of this as the intelligent traffic cop of the application. It listens to what the user wants to do (their input), figures out how risky that action is, and directs it down the safest and most efficient execution path. 

This system teams up with two other key components:
- **NLP Engine**: For super-smart, zero-dependency semantic parsing.
- **Planner Router**: For translating the user's intent into an actionable step-by-step plan.

---

## 🏗️ Architecture

At a high level, here is how user input flows through the system:

```text
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

> [!NOTE]
> The diagram above illustrates how raw input is categorized into a standard `IntentRoute` before being passed along to the planners and parsers.

---

## 🔀 IntentRouter (`compat.py`)

The `IntentRouter` (found in `siyarix/compat.py`) is designed to be simple yet effective. It uses keyword-based routing to quickly categorize inputs.

Here's a quick look at how you might use it in code:

```python
router = IntentRouter()
route = router.route("scan 10.0.0.1 for open ports")
# Returns: IntentRoute(mode="scan", risk_tier=RiskTier("medium"), requires_confirmation=False)
```

### 📏 Routing Rules

The router relies on a straightforward set of rules to determine the mode, the risk level, and whether we need the user to confirm the action before proceeding.

| Keywords | Mode | Risk Tier | Requires Confirmation? |
|----------|------|-----------|------------------------|
| `scan`, `nmap`, `port scan` | `scan` | Medium | No |
| `recon`, `enumerate`, `discover` | `recon` | Low | No |
| `web`, `http`, `nikto`, `nuclei` | `web` | Medium | No |
| `brute`, `crack`, `password` | `brute` | High | Yes 🛑 |
| `exploit`, `metasploit`, `attack`| `exploit` | High | Yes 🛑 |
| *(Any other input)* | `general` | Low | No |

> [!WARNING]
> Notice that `brute` and `exploit` modes are classified as **High Risk** and explicitly require user confirmation. This safety mechanism prevents accidental execution of intrusive operations.

### 📦 The `IntentRoute` Object

When the router successfully classifies an input, it spits out an `IntentRoute` data class:

```python
@dataclass
class IntentRoute:
    mode: str                         # scan | recon | web | brute | exploit | general
    risk_tier: RiskTier               # low | medium | high
    requires_confirmation: bool       # True if human approval is needed
```

---

## 🧠 NLP Engine

The `NaturalLanguageParser` (located in `siyarix/nlp_engine.py`) is where the magic happens. It provides robust semantic parsing without relying on heavy third-party machine learning libraries!

```python
nlp = NaturalLanguageParser()
parsed = nlp.parse("scan 10.0.0.1 for open ports and run vulnerability scan")

# The result is a richly detailed ParsedIntent object:
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

### ✨ Key Features

- **Zero-dependency**: Built entirely with Python's standard library. No bulky ML frameworks to install!
- **Entity Extraction**: Easily pulls out IP addresses, domains, URLs, CIDR ranges, ports, emails, MAC addresses, hashes, ASNs, and even Windows/Linux file paths.
- **Parameter Extraction**: Smartly identifies port numbers, execution speeds (like fast, stealth, or aggressive), severities, timeouts, formats, protocols, threads, credentials, and wordlists.
- **BM25 Scoring**: Uses Okapi BM25 similarity to match what the user typed against our known tools and templates.
- **Fuzzy Matching**: Implements Jaccard N-gram similarity (with phonetic normalization) to gracefully handle typos.
- **Synonym Mapping**: Comes packed with over 380 cybersecurity-specific synonyms (e.g., mapping "AD" to "Active Directory", understanding "CVE", "subdomain", etc.).
- **Multi-intent Parsing**: Can split complex sentences using conjunctions (like "then", "and then") into multiple distinct intents.

> [!TIP]
> Because it's purely stdlib, the NLP Engine is incredibly lightweight and blazing fast.

### 🔍 Entity Extraction Patterns

Here is a quick overview of how the engine identifies different types of entities:

| Entity Type | Example | How It Works |
|-------------|---------|--------------|
| **CVE** | `CVE-2024-1234` | Matched via Regex |
| **IPv4** | `10.0.0.1` | Full octet validation |
| **IPv6** | `fe80::1` | Full hex validation |
| **CIDR** | `10.0.0.0/24` | IPv4/IPv6 with prefix validation |
| **Domain** | `example.com` | Multi-label hostname parsing |
| **URL** | `https://example.com` | HTTP/HTTPS detection |
| **Email** | `user@example.com` | Simplified RFC 5321 check |
| **MAC Address** | `00:1A:2B:3C:4D:5E` | Hex pattern with colons or hyphens |
| **SHA256 Hash**| `e3b0c442...` (64 chars) | Fixed-length hex pattern |
| **ASN** | `AS12345` | Standard ASN notation |

### 🎓 Training the Corpus

You can actually "teach" the parser about new tools and templates to make it even smarter. By feeding it descriptions, it improves its BM25 scoring accuracy:

```python
nlp.train_tools(tool_metadata)       # Feed it tool names and descriptions
nlp.train_templates(template_data)   # Feed it template names and descriptions
```

---

## 🗺️ Planner Router

Once we understand what the user wants to do, the `Planner` class (in `siyarix/planner.py`) decides *who* should create the execution plan. It acts as a dispatcher:

| Planning Mode | Which Planner is Used? | Behavior Details |
|---------------|------------------------|------------------|
| `registry` / `offline` | `RegistryPlanner` | Uses strict heuristics. Completely AI-free! |
| `autonomous` | `AutonomousPlanner` | Relies entirely on an LLM. No fallback if the LLM fails. |
| `integrated` (Default) | Tries `Autonomous`, then `Registry` | The best of both worlds. AI-first, with a rock-solid heuristic fallback. |

Here's an example of how a plan is requested:

```python
planner = Planner()
plan = await planner.plan(
    goal="scan 10.0.0.1 for open ports",
    mode="integrated",           # Options: autonomous, registry, offline, integrated
    provider="openai",           # The AI provider (or "registry" to skip the LLM)
    available_tools=["nmap", "nuclei", "gobuster"],
    llm_call=async_llm_function,
    tool_schemas=tool_schemas,
)
```

> [!IMPORTANT]
> The `integrated` mode is highly recommended. It attempts to generate a creative, optimized plan using AI but gracefully falls back to reliable, pre-defined templates if the AI is unavailable or produces an invalid result.

---

## 📋 RegistryPlanner

The `RegistryPlanner` (found in `siyarix/planner_registry.py`) is our fallback hero. It provides intelligent, heuristic-based planning without ever needing an API key or internet connection to an AI provider.

### 🔄 Tool Alternatives

If a preferred tool isn't installed or available, the `RegistryPlanner` automatically substitutes it with a capable alternative!

```python
TOOL_ALTERNATIVES = {
    "nmap": ["masscan", "rustscan", "naabu"],
    "gobuster": ["ffuf", "dirb", "dirsearch"],
    "nuclei": ["nikto", "wapiti", "skipfish"],
    "hydra": ["medusa", "ncrack", "patator"],
    "subfinder": ["amass", "sublist3r", "assetfinder"],
    # ... and over 15+ more alternative tool chains!
}
```

### 🧩 Multi-Word Intent Matching

We've baked in over 500 multi-word patterns that translate natural language into specific tool commands. This covers a massive range of cybersecurity operations:

- 🕵️ **Reconnaissance**: Subdomain enumeration, port scanning, tech fingerprinting.
- 🎯 **Vulnerability Scanning**: Seamlessly kicking off Nuclei, Nikto, or SQLMap.
- 🌐 **Web Auditing**: Checking CORS, headers, and SSL/TLS setups.
- 🏢 **Active Directory**: Everything from Kerberoasting and AS-REP roasting to LDAP enum and SMB analysis.
- 💥 **Exploitation**: Firing up Metasploit, Hydra, or dropping reverse shells.
- 🛡️ **Blue Team / Defensive**: Parsing event logs, performing forensic triage, endpoint detection, and SIEM queries.
- 🧠 **Memory Forensics**: Volatility-based checks for process hollowing, Cobalt Strike, and ransomware.
- 📡 **Network Forensics**: PCAP analysis, sniffing out DNS tunneling, and traffic analysis.
- 📝 **Compliance Scanning**: Auditing against CIS benchmarks, SOC 2, PCI DSS, HIPAA, and NIST 800-53.
- ☁️ **Cloud Security**: AWS and Prowler audits, plus container security checks.
- 💻 **System Utilities**: Checking disk usage, memory, running processes, and system uptime.

### 🏗️ Template-Based Workflow Generation

For common scenarios, the `RegistryPlanner` uses battle-tested templates. These templates define the exact sequence of tools needed to get the job done.

| Template Name | Tool Chain Execution Flow | Total Steps |
|---------------|---------------------------|-------------|
| `recon_full` | nmap → whatweb → gobuster → subfinder → amass → nuclei | 6 |
| `web_audit` | curl → whatweb → nuclei → ffuf → wpscan → nikto | 6 |
| `network_scan` | nmap → dig → whois → masscan | 4 |
| `vuln_scan` | nuclei → nikto → wpscan → sqlmap | 4 |
| `dns_recon` | dig → subfinder → amass → whois | 4 |
| `cloud_audit` | curl → whatweb → dig → openssl | 4 |
| `ad_assessment`| nmap × 4 (specifically for ports, SMB, LDAP, Kerberos) | 4 |
| `brute_force` | nmap → hydra → hashcat | 3 |
| `linux_privesc`| uname → find (SUID) → find (writable) → cat (crontab) | 4 |
| `ssl_audit` | openssl → nmap (`ssl-enum-ciphers`) → nmap (`ssl-cert`) | 3 |

> [!TIP]
> These templates ensure that even when running completely offline, the system still executes complex, multi-stage workflows logically and securely.

---

## 🤝 Integration Points

Wondering how all these pieces fit into the broader ecosystem? Here is a breakdown of the key integration points:

| Component | Its Role in the Ecosystem |
|-----------|---------------------------|
| **AgentCore** | The central brain. It receives the `IntentRoute` and dispatches the task to the correct mode. |
| **NLP Engine** | Provides the deep semantic parsing required for accurate intent matching. |
| **RegistryPlanner** | Maps the parsed intent directly to a plan template (used in REGISTRY or OFFLINE modes). |
| **Planner Router** | Acts as the switchboard, deciding whether to use heuristic templates or an LLM for planning. |
| **Context Manager** | Grabs the route metadata to build out execution context. |
| **PermissionGate** | Looks at the route's risk tier and decides if we need to pause and ask the human for permission. |
| **EventBus** | Broadcasts an `intent.routed` event so the rest of the application knows what's happening! |
