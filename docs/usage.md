# How to Use Phalanx

Phalanx supports multiple interaction modes: interactive chat, direct CLI, autonomous agent, workflow automation, and web dashboard.

---

## 💬 Interactive Chat (Recommended)

```bash
phalanx
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
phalanx scan 192.168.1.1

# Natural language task
phalanx run "find open ports on scanme.nmap.org"

# List tool registry
phalanx tool-registry list

# Health check
phalanx health

# Shell diagnostics
phalanx shell doctor
```

---

## 📋 Playbook System

Save and replay multi-step workflows:

```bash
# Create and save a playbook
phalanx playbook save my-recon \
  --steps "subfinder -d {target}" \
  --steps "nuclei -u {target}"

# Run a saved playbook
phalanx playbook run bugbounty-recon --target example.com

# List all playbooks
phalanx playbook list

# Install built-in playbooks
phalanx playbook install-builtins
```

Built-in playbooks: `bugbounty-recon`, `incident-response`

---

## 📊 Report Generation

```bash
# Generate report from findings
phalanx report generate \
  --findings results.json \
  --target example.com \
  --format markdown \
  --output report.md

# HTML format for client deliverables
phalanx report generate \
  --findings results.json \
  --format html \
  --output report.html

# SARIF format for CI/CD integration
phalanx report generate \
  --findings results.json \
  --format sarif \
  --output results.sarif
```

---

## 🔐 Stealth & Evasion

```bash
# Enable stealth mode
phalanx stealth enable --level medium

# Check stealth configuration
phalanx stealth status

# Disable stealth mode
phalanx stealth disable

# Enable canary tokens on target
phalanx canary deploy --target example.com

# List canary tokens
phalanx canary list

# View triggered tokens
phalanx canary triggered
```

---

## ☁️ Cloud Security Scanning

```bash
# Scan AWS account
phalanx cloud scan --provider aws --account 123456789012

# Scan Kubernetes cluster
phalanx cloud scan --provider kubernetes --namespace default

# Scan Docker image
phalanx cloud scan --provider docker --image nginx:latest
```

---

## 📋 Compliance Assessment

```bash
# Run compliance check against a framework
phalanx compliance run --framework pci-dss --target example.com

# Run all frameworks
phalanx compliance run --all --target example.com

# View compliance summary
phalanx compliance summary

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
phalanx intel ingest --stix feed.json

# Query MITRE ATT&CK
phalanx intel mitre --technique T1110

# Enrich findings with threat intel
phalanx intel enrich --findings results.json
```

---

## 🧠 Multi-Model Ensemble

```bash
# Run ensemble across multiple providers
phalanx ensemble plan "scan example.com" \
  --providers openai gemini \
  --strategy weighted

# Check ensemble statistics
phalanx ensemble summary
```

---

## 📈 Web Dashboard

```bash
# Start the web dashboard
phalanx dashboard --port 8090

# Access at http://localhost:8090
# WebSocket live updates at ws://localhost:8090/ws
```

REST API endpoints:
- `GET /api/health` — System health
- `GET /api/metrics` — Platform metrics
- `GET /api/findings` — Recent findings
- `GET /api/agents` — Agent status
- `GET /api/snapshot` — Full dashboard snapshot

---

## 🗓️ Scheduled Scans

```bash
# Create a recurring scan
phalanx schedule create daily-scan \
  --target example.com \
  --frequency daily \
  --time "02:00" \
  --persona defensive

# List schedules
phalanx schedule list

# Delete a schedule
phalanx schedule delete daily-scan
```

---

## 🖥️ Cross-Platform Shell Translation

```bash
# Translate intent to native command
phalanx shell translate ping
# Linux:   ping -c 4 {target}
# Windows: ping -n 4 {target}

# List all available translations
phalanx shell list-intents

# Full platform diagnostics
phalanx shell platform
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
export PHALANX_LOG_LEVEL=DEBUG
export PHALANX_PERSONA=bug_hunter
export PHALANX_PROVIDER=gemini
export PHALANX_TIMEOUT=300
export PHALANX_SAFE_MODE=1
export PHALANX_NO_TELEMETRY=1

# All options documented in .env.example
```

---

## 🐳 Docker Deployment

```bash
# Start all services
docker compose up -d

# Scale workers
docker compose up -d --scale phalanx-worker=5

# View logs
docker compose logs -f

# Stop services
docker compose down
```

Services: `phalanx`, `phalanx-worker`, `phalanx-dashboard`, `redis`, `otel-collector`
