# Siyarix v1.0.0 — The Dawn of Autonomous Cybersecurity Orchestration

**Release Date:** June 17, 2026  
**Version:** 1.0.0  
**License:** AGPL-3.0-or-later  
**Author:** MD MUFTHAKHERUL ISLAM MIRAZ

---

## Foreword

There comes a moment in every project's life when it steps out of the shadows of "work in progress" and declares itself ready. Today is that moment for Siyarix.

What began as an ambitious idea — *"what if you could tell your security tools what to do in plain English?"* — has matured into a production-grade, AI-native cybersecurity orchestration platform. v1.0.0 is not just another release; it is a statement of intent. It represents thousands of hours of development, hundreds of resolved issues, 1,600+ commits, and an unwavering belief that security operations should be driven by human intent, not cryptic command-line flags.

Siyarix is no longer a prototype. It is a foundation.

---

## The Vision: Why Siyarix Exists

Security professionals today face an impossible paradox: the attack surface expands daily, yet the tooling ecosystem remains fragmented across dozens of CLI tools, each with its own syntax, output format, and workflow. The mental overhead of remembering flags, piping outputs, and correlating results is exhausting.

Siyarix bridges the gap. It is your intelligent co-pilot that:

- **Understands natural language** — "scan this subnet," "enumerate services," "find vulnerabilities"
- **Plans multi-tool workflows** — decomposes high-level goals into precise execution steps
- **Executes safely** — with a two-stage permission gate, danger analysis, and encrypted audit trails
- **Learns continuously** — builds a knowledge graph of your infrastructure across sessions
- **Adapts to you** — four operating modes from fully manual to fully autonomous

It is designed for red teams, blue teams, DFIR analysts, cloud security engineers, and anyone who needs to move fast without breaking things.

---

## What v1.0.0 Brings

### AI Ecosystem: 24+ Providers, One Unified Interface

Siyarix v1.0 ships with the most comprehensive AI provider abstraction layer in any open-source security tool. We integrated with every major LLM provider so *you* can choose what works best for your workflow, budget, and compliance requirements.

**Supported providers:** OpenAI, Google Gemini, Anthropic Claude, Groq, Together AI, OpenRouter, DeepSeek, xAI (Grok), Mistral AI, Perplexity, Cerebras, Fireworks AI, Z.AI, MiniMax, Moonshot (Kimi), NVIDIA Nemotron, Hugging Face Inference, Azure OpenAI, OpenCode Zen, Ollama, LM Studio, llama.cpp, vLLM, LocalAI

Each provider profile handles authentication, rate limiting, error handling, and token management. The `ProviderManager` singleton orchestrates everything — including automatic failover with circuit-breaker pattern across providers, so your operations never stall.

### 80+ Security Tool Parsers

Running a tool is one thing. *Understanding* its output is another. Siyarix v1.0 includes 80+ native output parsers spanning the full security tool ecosystem:

| Domain | Tools |
|--------|-------|
| **Reconnaissance** | nmap, masscan, rustscan, naabu, zmap, zgrab, dnsrecon, dnsenum, massdns, shuffledns, dnsx, httpx, katana, hakrawler, gospider, waybackurls, gau, subfinder, sublister, assetfinder, findomain, amass, recon-ng, theHarvester, dig, whois, shodan, dmitry, finger, ike_scan |
| **Web Application** | gobuster, ffuf, wfuzz, dirb, dirsearch, feroxbuster, kiterunner, arjun, paramspider, corsy, dalfox, kxss, xsstrike, commix, nikto, wpscan, whatweb, aquatone, gowitness, wafw00f, jwt_tool, interactsh |
| **Vulnerability** | nuclei, sqlmap, searchsploit, lynis, scoutsuite, prowler, checkov |
| **Exploitation** | metasploit (msfconsole/msfvenom), burpsuite, zaproxy, bettercap, impacket, crackmapexec, responder, mimikatz, pypykatz, bloodhound, sharphound, certipy, kerbrute, evil-winrm, hashcat, hash_identifier, john |
| **Network & Cloud** | tcpdump, netcat, smtp_user_enum, smbclient, smbmap, ldapsearch, enum4linux, s3scanner, kubectl, aws, terraform |
| **Container & Code** | trivy, grype, semgrep, gitleaks, trufflehog, yara, exiftool |
| **Forensics** | volatility |
| **Wireless** | aircrack-ng, ettercap |
| **TLS/SSL** | ssh_audit, sslscan, sslyze, testssl |

Each parser converts raw tool output into structured, typed data that the AI can reason about, correlate, and act upon.

### Four Agent Modes for Every Workflow

Siyarix v1.0 introduces four distinct operating modes because one size does not fit all:

| Mode | Philosophy |
|------|-----------|
| **REGISTRY** | You drive, AI assists. Run commands directly while the AI offers syntax help and planning advice. |
| **AUTONOMOUS** | Set a goal and let the agent run. Uses an Observe-Reason-Act loop to independently plan, execute, and adapt. |
| **HYBRID** | The AI proposes a plan, then pauses for your approval before executing sensitive steps. Best of both worlds. |
| **INTERACTIVE** | Every action is reviewed step-by-step. Ideal for sensitive environments or learning new workflows. |

### Security & Safety Architecture

We built Siyarix with the understanding that combining AI with security tools carries inherent risk. Our safety architecture is multi-layered:

- **Permission Gate:** Two-stage AI-driven danger analysis with configurable risk thresholds. High-risk commands are flagged before execution.
- **Credential Vault:** AES-256-GCM encrypted vault (Fernet + PBKDF2) for API keys and secrets, with optional OS keyring integration.
- **Stealth Engine:** TOR routing, request jitter, User-Agent rotation, proxy chaining, decoy traffic, and 9 honeypot detection signatures.
- **OPSEC Manager:** Target isolation, burn-after-reading, DNS over HTTPS, and operational countermeasures.
- **Tamper-Evident Audit Log:** SHA-256 chained cryptographic audit trail with built-in `verify` command for chain integrity validation.
- **DLP Engine:** Pattern-based sensitive data detection and redaction to prevent accidental data leaks.
- **Canary Tokens:** 7 types of configurable canary tokens for intrusion detection.
- **Health Checker:** Comprehensive `siyarix health` diagnostics covering tool dependencies, provider connectivity, and system integrity.

### CLI & User Experience

- **50+ CLI commands** across 12 command groups for every security domain
- **Interactive REPL** with 40+ slash commands, session persistence (SQLite), session branching for concurrent workflow exploration, and command palette
- **12 stunning color themes:** CYBER_NOIR, MATRIX, BLOODMOON, ARCTIC, GOLDENROD, ECLIPSE, SYNTHWAVE, DARK, LIGHT, NEON, MINIMAL, DEFAULT — each with curated severity color palettes
- **8 output formats:** TABLE, JSON, YAML, CSV, HTML, XML, RAW, QUIET
- **4 report formats:** MARKDOWN, HTML, JSON, SARIF
- **Shell completions** for bash, zsh, fish, and PowerShell
- **FastAPI REST API** with JWT authentication, WebSocket streaming, and OpenAI-compatible endpoint

### Expert Persona System

10 specialized security mindsets that the AI can adopt, each with tailored system prompts, example workflows, and operational heuristics:

- Red Team, Blue Team, DFIR, Cloud Security, Application Security
- Malware Analysis, Threat Intelligence, Compliance & Audit
- Network Security, Social Engineering

Switch between them at runtime with `/persona` in the REPL.

### Multi-Wave Execution & Self-Correction

Unlike simpler orchestrators that run a plan once and report results, Siyarix implements an iterative multi-wave execution loop (up to 25 waves). After each wave, the AI analyzes results, learns from failures, and adapts its approach — just like a human operator would.

### Compliance & Threat Intelligence

- **Compliance Engine:** Framework-based compliance checking against PCI-DSS, HIPAA, ISO 27001, and SOC 2
- **Threat Intel:** STIX-based structured threat intelligence consumption and correlation
- **Knowledge Graph:** In-memory infrastructure relationship modeling with persistent JSON storage

### Infrastructure & Platform Support

- **Python 3.11, 3.12, and 3.13** support across Windows, macOS, Linux, and Android (Termux)
- **Docker** with multi-stage builds (Python-slim, Kali, Parrot) and Docker Compose orchestration
- **Distribution formats:** pip, Docker, Debian (.deb), Homebrew, Winget, Chocolatey, HarmonyOS
- **OpenTelemetry integration** for distributed tracing and observability
- **Redis caching layer** with configurable TTL

---

## Behind the Numbers

| Metric | Value |
|--------|-------|
| Source modules | 80+ |
| AI providers | 24+ |
| Tool parsers | 80+ |
| CLI commands | 50+ |
| REPL slash commands | 40+ |
| Test files | 112 |
| Total tests | 900+ passing |
| Code coverage | 70%+ |
| CI/CD workflows | 57 |
| Documentation pages | 70+ (docs) + 40+ (wiki) |
| Package formats | 6+ |
| Git commits | 1,600+ |

---

## Migration & What's Next

Siyarix is migrating from `mufthakherul/siyarix` to its own GitHub organization at `siyarix/siyarix` to better support its growing community. All existing links will redirect seamlessly.

For v1.1 and beyond, the roadmap includes:
- Enhanced multi-agent swarm coordination
- Deeper SIEM integration
- Expanded playbook engine with community playbook marketplace
- Real-time collaborative sessions
- Mobile companion app for alerts and approvals

---

## Acknowledgments

Siyarix v1.0.0 is the work of **MD MUFTHAKHERUL ISLAM MIRAZ** and a growing community of contributors who believed in the vision. Thank you to everyone who filed issues, submitted PRs, tested edge cases, and provided feedback during the alpha and beta phases.

Special thanks to the open-source security and AI communities whose tools and models make Siyarix possible: the maintainers of nmap, nuclei, Metasploit, OWASP ZAP, Impacket, BloodHound, and every tool whose parser ships with this release.

---

## Get Started Today

```bash
pip install siyarix
siyarix           # Launch the interactive onboarding wizard
siyarix --help    # Explore all commands
```

Or visit the documentation: [Siyarix Docs](https://mufthakherul.github.io/siyarix/)

---

*"Security operations should be driven by intent, not syntax. Siyarix is our answer to that vision."*
