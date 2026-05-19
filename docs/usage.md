# Usage — Quick Start & Examples

## Interactive AI Assistant (Chat Mode)

The most powerful way to use NexSec is the interactive chat mode. It provides a conversational interface with session persistence and slash commands.

```bash
# Launch chat
nexsec chat

# Launch with an initial target
nexsec chat --target example.com

# Resume the most recent session
nexsec chat --resume
```

**Common Chat Commands:**
- `/help`: Show all slash commands.
- `/mode autonomous`: Switch to AI-driven planning.
- `/target 10.0.0.1`: Set the current session target.
- `/tools`: List security tools found on your system.

---

## Security Operations (SecOps)

Manage incidents, vulnerabilities, and threat hunts from the unified security console.

```bash
# List open incidents
nexsec security incidents --status open

# Create a new incident report
nexsec security incident-create --title "Suspicious C2 activity" --category intrusion --severity critical

# View remediation priorities
nexsec security remediation-plan

# Run a MITRE-mapped threat hunt
nexsec security hunt q_ps_exec --target win-srv-01
```

---

## Bulk Operations & Monitoring

```bash
# Scan multiple targets from a file
nexsec bulk scan targets.txt --tool nmap

# Start live monitoring for new findings
nexsec watch start "severity:critical"
```

---

## Automation & CI/CD

NexSec is designed for seamless integration into DevOps pipelines.

```bash
# Run a scan and exit with non-zero if critical vulns are found
nexsec scan my-app.com --save
nexsec ci gate

# Generate a compliance report
nexsec audit report soc2 --output audit_results.md
```

---

## Cross-Platform Shell Translation

Translate high-level intents to platform-native commands (Linux, Mac, Windows).

```bash
# List all intents
nexsec shell list-intents

# Translate "network_connections" to current shell
nexsec shell translate network_connections

# Get a security readiness report for your terminal
nexsec shell doctor
```
