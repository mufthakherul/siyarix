# CLI Reference

NexSec CLI Version: **1.2.0**

This document provides a comprehensive reference for the NexSec command hierarchy. The CLI is built with Typer; use `nexsec --help` or `nexsec <subcommand> --help` for real-time usage and flag details.

> Launching `nexsec` with no subcommand opens the interactive assistant shell. The landing screen shows your platform, current mode, theme, model provider, session ID, and quick actions for the most common tasks.

## Global Options

- `--mode <registry|autonomous|integrated>`: Set the execution engine strategy (Default: `integrated`).
- `--no-banner`: Suppress the ASCII startup banner.
- `--help`: Show help for any command or sub-command.

---

## Core Commands

### `chat`
Start an interactive AI cybersecurity REPL.
- **Flags**:
  - `--mode, -m`: Execution mode.
  - `--target, -t`: Set initial session target.
  - `--session, -s`: Resume a specific session by ID.
  - `--resume, -r`: Resume the most recent session.

### Chat Slash Commands

The chat shell supports the following high-value slash commands:

- `/help`: Show all commands.
- `/tools`: Discover installed security tools.
- `/palette`: Search and run saved commands or intents.
- `/key set <provider> <api_key>`: Store keys in the vault and `.env`.
- `/key list`: Show configured providers.
- `/theme mode <system|dark|light|minimal|neon>`: Change the UI theme.
- `/theme appearance`: Preview the interface styling.
- `/model <auto|openai|gemini|ollama|cloud>`: Set the preferred planner provider.
- `/model gemini <model-name>`: Set a Gemini model name.

### `scan`
Run security scans against targets using the execution engine.
- **Arguments**: `targets` (IP, CIDR, URL, or hostname)
- **Flags**:
  - `--tool, -t`: Specify a tool.
  - `--output, -o`: format (table|json|yaml|csv).
  - `--parallel, -p`: Number of concurrent workers.
  - `--save, -s`: Persist results to the offline store.
  - `--dry-run`: Plan only, do not execute.

### `discover`
Discover assets, services, and vulnerabilities on a target.
- **Flags**:
  - `--deep, -d`: Enable deep OS and service detection.
  - `--export, -e`: Export results to a file.

### `run`
Execute a natural language instruction through the autonomous engine.
- **Example**: `nexsec run "find open ports on 10.0.0.1"`

### `health`
Run system health checks for all components.

### `metrics`
Show execution and performance metrics for the current session.

### `dashboard`
Display the live security operations dashboard.

---

## Sub-App Groups

### `security` (🔐 SecOps Console)
- `incidents`: List and filter security incidents.
- `incident <id>`: Show details for a specific incident.
- `incident-create`: Manually report a new incident.
- `vulnerabilities`: View tracked CVEs and status.
- `remediation-plan`: Generate a prioritized fix list.
- `hunt`: Execute threat hunting queries.
- `queries`: List available MITRE-mapped hunt queries.
- `mitre-coverage`: Show technique coverage map.
- `playbooks`: List incident response playbooks.
- `dashboard`: Show specialized SecOps metrics.

### `shell` (🖥 Cross-platform Helper)
- `platform`: Detailed terminal and OS diagnostics.
- `doctor`: Readiness report for security tools.
- `translate <intent>`: Convert goals (e.g., `ping`) to platform-specific commands.
- `list-intents`: Show all supported command intents.
- `list-shells`: Show supported shells (Bash, PowerShell, Zsh, etc.).
- `security-cmds`: Show platform-native security commands.

### `workflow` (⚙️ Orchestration)
- `list`: List persisted execution plans.
- `show <id>`: Inspect plan steps and status.
- `resume <id>`: Continue a paused or failed plan.
- `run <file>`: Execute a YAML/JSON workflow pipeline.
- `catalog`: List available workflow templates.

### `auth` (🔑 Secrets Management)
- `set-key <provider>`: Securely store API keys (OpenAI, Gemini, Anthropic, etc.). Keys are saved to the credential vault and synced to `.env`.
- `show`: Check configuration status of API keys.

### `audit` (📋 Compliance & Logs)
- `logs`: View the enterprise audit trail.
- `verify`: Check audit log chain integrity.
- `report <framework>`: Generate SOC2/ISO/NIST compliance reports.

### `bulk` (📦 Batch Operations)
- `scan <file>`: Run scans against a list of targets from a file.
- `update`: Bulk update incident or vulnerability statuses.

### `findings` (🔍 Data Management)
- `list`: Search and filter findings in the offline store.
- `export`: Export findings to JSON or CSV.

### `config` (⚙️ Settings)
- `list`: Show all current settings and defaults.
- `set <key> <val>`: Update a configuration value.
- `reset`: Restore settings to default.

### `tool-registry` (🛠 Discovery)
- `list`: Show discovered security tools on the current system.
- `show <name>`: Show detailed metadata for a tool.

### `ci` (🚀 CI/CD Gates)
- `gate`: Exit with failure if critical findings or unhealthy states are detected.

### `profile` (👤 Workspaces)
- `save-cmd`: Save a reusable command profile.
- `list-cmds`: List saved command templates.

### `theme` (🎨 Customization)
- `list`: Show available UI color themes.
- `set <name>`: Set the global UI theme.
- `preview` / `appearance`: Preview the interface with shell, text, and command samples.
