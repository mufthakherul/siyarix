# Usage — Quick Start & Examples

## Interactive AI Assistant (Chat Mode)

The most powerful way to use NexSec is the interactive chat mode. It provides a conversational interface with session persistence, slash commands, model selection, and a polished landing screen when launched via `nexsec`.

```bash
# Launch chat
nexsec chat

# Launch with an initial target
nexsec chat --target example.com

# Resume the most recent session
nexsec chat --resume

# Launch the default assistant-style shell
nexsec
```

**Common Chat Commands:**
- `/help`: Show all slash commands.
- `/mode autonomous`: Switch to AI-driven planning.
- `/target 10.0.0.1`: Set the current session target.
- `/tools`: List security tools found on your system.
- `/key set gemini <api-key>`: Store a Gemini key in the vault and `.env`.
- `/key list`: Show configured providers and status.
- `/theme mode dark`: Switch the interface theme.
- `/theme appearance`: Preview the current UI appearance.
- `/model gemini`: Prefer Gemini for planning.

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

## Command-Center Launch Flow

When you run `nexsec` with no subcommand, the app opens directly into the interactive assistant shell and shows:

- current platform and shell
- active mode and session ID
- current theme and model provider
- quick actions for keys, themes, models, and command search

This is the recommended entry point if you want a CLI assistant experience similar to other modern agent shells.
