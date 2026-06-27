# 🛡️ Security Workflows

Siyarix is designed to handle the heavy lifting of your day-to-day security operations. From initial reconnaissance to incident response and compliance, here are the core workflows you can run right out of the box.

---

## 🔭 Network Reconnaissance

Before you can secure a network, you have to understand it. Siyarix offers multiple ways to map your environment.

```bash
# ⚡ Quick Scan: Find live hosts and check the top 100 ports
siyarix scan-quick 10.0.0.0/24

# 🔍 Full Scan: Scan all 65,535 ports and detect service versions
siyarix scan-full target.example.com

# 🕵️ Deep Scan: A 4-pass scan (discovery → fingerprint → vuln → enumeration)
siyarix scan-deep target.example.com

# 🗺️ Discovery: Basic asset and service mapping
siyarix discover example.com

# 🧠 AI-Powered Recon: Just ask!
siyarix run "enumerate all subdomains and live hosts for example.com"

# 📴 Offline Recon: Scan without relying on an AI provider
siyarix scan 10.0.0.0/24 --mode offline
```

---

## 🎯 Vulnerability Assessment

Once you know what's out there, find out where it's weak.

```bash
# 🗣️ Natural Language Scan
siyarix run "scan target.example.com for common vulnerabilities"

# 🌐 Web App Scan: Specialized multi-tool preset for web targets
siyarix scan-web https://target.com

# 🤖 Agent-Driven Assessment: Let the AI handle the complex logic
siyarix agent "find all vulnerabilities on the web server and categorize by severity"

# 💾 Deep Scan & Save: Run a deep scan and persist results
siyarix scan-deep 10.0.0.1 --save
```

---

## 🕸️ Web Application Testing

Web apps are often the weakest link. Siyarix chains together standard tools (like Nikto, Nuclei, WPScan, and WhatWeb) dynamically based on what it fingerprints.

```bash
# 🚨 OWASP Top 10 automated scan
siyarix run "scan web application at https://target.com for OWASP Top 10"

# 🛠️ Standard Web Preset
siyarix scan-web https://target.com
```

---

## 🚨 Incident Response

When things go wrong, Siyarix helps you manage the chaos.

```bash
# 📊 View the high-level security dashboard
siyarix security dashboard

# 📋 List all currently active incidents
siyarix security incidents

# 🔎 Drill down into a specific incident
siyarix security incident INC-001

# 📝 Manually create a new incident ticket
siyarix security incident-create --title "SQLi on login" --description "Blind SQL injection detected" --category intrusion --severity high

# 📓 List your pre-defined incident response playbooks
siyarix security playbooks

# 🚀 Execute a playbook to contain a threat
siyarix playbook run response-playbook.yml
```

---

## 🥷 Exploitation and Red Team Campaigns

*(For authorized engagements only!)* Siyarix can help manage multi-phase red team operations.

```bash
# 🗺️ Plan a complex campaign using natural language
siyarix run "plan campaign: recon -> scan -> enumerate -> exploit"

# Track your campaign's progress interactively via the /campaign command in the REPL!
```

---

## 🕵️ Threat Hunting and Intelligence

Proactively hunt for bad actors in your environment.

```bash
# 🎯 Execute a predefined hunt query
siyarix security hunt q_ps_exec

# 📜 View all available threat hunt queries
siyarix security queries

# 🔍 Filter queries by specific MITRE tactics
siyarix security queries --mitre-tactic execution

# 📊 See your overall MITRE ATT&CK coverage
siyarix security mitre-coverage
```

---

## 📋 Compliance and Governance

Prepare for your audits automatically.

```bash
# 🏛️ Run SOC 2 compliance checks against a specific target
siyarix compliance run SOC2 10.0.0.1

# 📄 Generate a beautiful, HTML compliance report
siyarix report generate --format html --output compliance-report.html
```

!!! note
    Siyarix is building support for major frameworks including: **SOC 2, ISO 27001, NIST 800-53, GDPR, HIPAA, and PCI-DSS**.

---

## 🤖 Autonomous Agent Workflows

Let the AI take the wheel. The agent decomposes objectives, assigns sub-tasks, executes them, and aggregates the final results.

```bash
# 🧠 Full autonomous multi-step objective
siyarix agent "enumerate all services, find vulnerabilities, generate a report"

# ⚠️ Force autonomous mode (No confirmation prompts!)
siyarix agent "scan network" --mode autonomous
```

---

## 🔒 Audit Trail Verification

Every single command run by Siyarix is logged using a cryptographic SHA-256 hash chain. This provides tamper-evident proof of your actions for compliance and review.

```bash
# 📜 View the audit logs
siyarix audit logs

# ✅ Cryptographically verify the integrity of the audit chain
siyarix audit verify

# 📄 Generate a compliance-specific audit report
siyarix audit report soc2 -o audit-report.md
```
