# How to Use Siyarix

Siyarix supports multiple interaction modes: interactive chat, direct CLI, autonomous agent, workflow automation, and web dashboard.

---

## 💬 Interactive Chat (Recommended)

```bash
siyarix
```

Launches the REPL with slash commands:

```text
/key set gemini <your-api-key>     # Configure AI provider
/model gemini                       # Set active model
/work-mode bug_hunter              # Switch persona
/theme mode dark                   # Change UI theme
/target example.com                # Set persistent target
/tools                             # List discovered tools
/help                              # Show all commands
/bye                               # Save and exit
```

### Example Conversations
- *"Scan 192.168.1.1 for open ports and explain what they do"*
- *"Find subdomains for example.com and check for vulnerabilities"*
- *"What security tools are installed on my system?"*
- *"Run a compliance check against PCI-DSS standards"*

---

## ⚡ Direct CLI

```bash
# Quick scan
siyarix scan 192.168.1.1

# Natural language task
siyarix run "find open ports on scanme.nmap.org"

# List tool registry
siyarix tool-registry list

# Health check
siyarix health

# Shell diagnostics
siyarix shell doctor
```

---

## 📋 Playbook System

Save and replay multi-step workflows:

```bash
# Create and save a playbook
siyarix playbook save my-recon \
  --steps "subfinder -d {target}" \
  --steps "nuclei -u {target}"

# Run a saved playbook
siyarix playbook run bugbounty-recon --target example.com

# List all playbooks
siyarix playbook list

# Install built-in playbooks
siyarix playbook install-builtins
```

Built-in playbooks: `bugbounty-recon`, `incident-response`

---

## 📊 Report Generation

```bash
# Generate report from findings
siyarix report generate \
  --findings results.json \
  --target example.com \
  --format markdown \
  --output report.md

# HTML format for client deliverables
siyarix report generate \
  --findings results.json \
  --format html \
  --output report.html

# SARIF format for CI/CD integration
siyarix report generate \
  --findings results.json \
  --format sarif \
  --output results.sarif
```

---

## 🔐 Stealth & Evasion

```bash
# Enable stealth mode
siyarix stealth enable --level medium

# Check stealth configuration
siyarix stealth status

# Disable stealth mode
siyarix stealth disable

# Enable canary tokens on target
siyarix canary deploy --target example.com

# List canary tokens
siyarix canary list

# View triggered tokens
siyarix canary triggered
```

---

## ☁️ Cloud Security Scanning

```bash
# Scan AWS account
siyarix cloud scan --provider aws --account 123456789012

# Scan Kubernetes cluster
siyarix cloud scan --provider kubernetes --namespace default

# Scan Docker image
siyarix cloud scan --provider docker --image nginx:latest
```

---

## 📋 Compliance Assessment

```bash
# Run compliance check against a framework
siyarix compliance run --framework pci-dss --target example.com

# Run all frameworks
siyarix compliance run --all --target example.com

# View compliance summary
siyarix compliance summary

# Available frameworks:
#   - pci-dss    (Payment Card Industry)
#   - iso-27001  (Information Security)
#   - nist-800-53 (US Federal)
#   - soc-2      (Service Organizations)
#   - gdpr       (EU Data Protection)
#   - hipaa      (Healthcare)
```

---

## 🔍 Threat Intelligence

```bash
# Ingest STIX feed
siyarix intel ingest --stix feed.json

# Query MITRE ATT&CK
siyarix intel mitre --technique T1110

# Enrich findings with threat intel
siyarix intel enrich --findings results.json
```

---

## 🧠 Multi-Model Ensemble

```bash
# Run ensemble across multiple providers
siyarix ensemble plan "scan example.com" \
  --providers openai gemini \
  --strategy weighted

# Check ensemble statistics
siyarix ensemble summary
```

---

## 🗓️ Scheduled Scans

```bash
# Create a recurring scan
siyarix schedule create daily-scan \
  --target example.com \
  --frequency daily \
  --time "02:00" \
  --persona defensive

# List schedules
siyarix schedule list

# Delete a schedule
siyarix schedule delete daily-scan
```

---

## 🖥️ Cross-Platform Shell Translation

```bash
# Translate intent to native command
siyarix shell translate ping
# Linux:   ping -c 4 {target}
# Windows: ping -n 4 {target}

# List all available translations
siyarix shell list-intents

# Full platform diagnostics
siyarix shell platform
```

---

## 🤝 Collaborative Sessions

```bash

# Share tool registry and context
# Both participants see the same output
# Joint approval required for PERMISSION-level commands
```

---

## 🔧 Advanced Configuration

```bash
# Configure environment
export SIYARIX_LOG_LEVEL=DEBUG
export SIYARIX_PERSONA=bug_hunter
export SIYARIX_PROVIDER=gemini
export SIYARIX_TIMEOUT=300
export SIYARIX_SAFE_MODE=1
export SIYARIX_NO_TELEMETRY=1

# All options documented in .env.example
```

---

## 🐳 Docker Deployment

```bash
# Start all services
docker compose up -d

# Scale workers
docker compose up -d --scale siyarix-worker=5

# View logs
docker compose logs -f

# Stop services
docker compose down
```

Services: `siyarix`, `siyarix-worker`, `siyarix-dashboard`, `redis`, `otel-collector`
