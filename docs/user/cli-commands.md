# CLI Commands Reference

Siyarix is a CLI-first platform built with **Typer**. This reference covers all available commands and sub-command groups in v3.0.0.

---

## Global Options

```bash
siyarix [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--config`, `-c` | Path to custom config file |
| `--batch`, `-b` | Path to batch script file to execute |
| `--mode`, `-m` | Execution mode: `autonomous`, `integrated`, `registry` |
| `--target`, `-t` | Set initial target for the session |
| `--session` | Resume a previous session by ID |
| `--resume` | Resume the last existing session |
| `--version` | Show version information |
| `--help` | Show help message |

---

## Usage Modes

1. **Interactive Chat**: `siyarix` (no subcommand) — launches the context-aware chat REPL
2. **Direct Command**: `siyarix scan 10.0.0.1` — executes and exits
3. **Pipe Mode**: `echo "scan 10.0.0.1" | siyarix` — batch commands via stdin
4. **Batch File**: `siyarix --batch script.txt` — execute a script file
5. **Goal-Driven Agent**: `siyarix agent "find vulnerabilities"` — autonomous Observe-Reason-Act loop

---

## Core Commands

### Scan

Run security scans against one or more targets using discovered tools on your `PATH`.

```bash
siyarix scan <targets...> [OPTIONS]
```

Supports `@targets.txt` multi-target mode — prefix a file path with `@` to load targets line by line.

| Option | Description |
|--------|-------------|
| `--tool`, `-t` | Specific tool to use |
| `--mode`, `-m` | Execution mode (`autonomous`, `integrated`, `registry`) |
| `--output`, `-o` | Output format: `table`, `json`, `yaml`, `csv` |
| `--parallel`, `-p` | Number of parallel workers |
| `--timeout` | Timeout per tool in seconds |
| `--save`, `-s` | Save results to database |
| `--dry-run` | Plan only, do not execute |
| `--profile` | Use specific command profile |
| `--cloud` | Run cloud provider scan (`aws`, `azure`, `gcp`, `kubernetes`, `docker`, `all`) |

### Run

Convert natural language into structured execution plans:

```bash
siyarix run "scan my network for open ports"
siyarix run "enumerate services on 10.0.0.1"
siyarix run "check SOC 2 compliance on the infrastructure"
```

### Agent

Goal-driven autonomous agent with Observe-Reason-Act loop:

```bash
siyarix agent "find all vulnerabilities on our web server"
siyarix agent "enumerate subdomains, find live hosts, scan for vulns, and report"
```

### Discover

Asset and service discovery for specified targets:

```bash
siyarix discover <target>
```

### Init

Interactive setup wizard — runs the ethics pledge, requirements check, provider setup, and persona configuration:

```bash
siyarix init [--force] [--skip-requirements]
```

### Palette & Render

| Command | Description |
|---------|-------------|
| `siyarix palette` | Open interactive command palette (requires `prompt_toolkit`) |
| `siyarix render-cmd <name> [kv...]` | Render a saved command profile using key=value pairs |

---

## Sub-Command Groups

### Profile

Command profile management:

| Command | Description |
|---------|-------------|
| `siyarix profile list-cmds` | List saved command profiles |
| `siyarix profile save-cmd <name> <command>` | Save a reusable command profile |
| `siyarix profile rm-cmd <name>` | Remove a saved command profile |

### Config

CLI configuration and settings management:

| Command | Description |
|---------|-------------|
| `siyarix config list` | Show all settings |
| `siyarix config get <key>` | Get a single setting |
| `siyarix config set <key> <value>` | Set a setting |
| `siyarix config reset` | Reset to defaults |
| `siyarix config edit` | Open config in default editor |
| `siyarix config backup` | Backup current configuration |
| `siyarix config restore` | Restore configuration from backup |

### Auth

API key management for AI providers:

```bash
siyarix auth set-key <provider>
siyarix auth list-keys
siyarix auth remove-key <provider>
```

Configure AI provider API keys interactively. Supported providers: openai, gemini, anthropic, groq, together, openrouter, deepseek, xai, mistral, perplexity, cerebras, fireworks, zai, minimax, moonshot, nvidia, huggingface, azure.

### Cache

Manage the LRU cache:

| Command | Description |
|---------|-------------|
| `siyarix cache status` | Show cache statistics |
| `siyarix cache clear` | Clear all cached data |

### Security

Security operations management:

| Command | Description |
|---------|-------------|
| `siyarix security incidents` | View and manage security incidents |
| `siyarix security vulns` | Vulnerability management |
| `siyarix security hunt <query>` | Threat hunting operations |
| `siyarix security mitre [--technique]` | MITRE ATT&CK coverage mapping |
| `siyarix security playbooks [run/list]` | Incident response playbooks |
| `siyarix security dashboard` | View TUI security dashboard |
| `siyarix security compliance --framework <name>` | Run compliance assessment |

### Theme

Customize terminal color themes:

| Command | Description |
|---------|-------------|
| `siyarix theme list` | List available color themes |
| `siyarix theme set <name>` | Set default color theme |
| `siyarix theme preview [name]` | Preview a theme's appearance |

### Tool Registry

Manage and view discovered tools and providers:

| Command | Description |
|---------|-------------|
| `siyarix tool-registry list` | List all discovered tools on PATH |
| `siyarix tool-registry providers` | List configured model providers with preference order |
| `siyarix tool-registry update-metadata` | Refresh tool metadata cache |

### Workflow

Execute DAG workflow files:

```bash
siyarix workflow run assessment.yaml
siyarix workflow run assessment.yaml --dry-run
```

### System & Ops

| Command | Description |
|---------|-------------|
| `siyarix health` | System health checks (components, latency, state) |
| `siyarix metrics` | Session performance metrics |
| `siyarix audit report` | View audit trail report |
| `siyarix audit logs` | View detailed audit logs |
| `siyarix audit verify` | Verify audit chain integrity |
| `siyarix report generate [--format]` | Generate assessment report |
| `siyarix completions [shell]` | Generate and install shell completions |
| `siyarix ci-gate` | CI/CD pipeline compliance gate |
| `siyarix session-log` | View structured session log |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / unknown command / target missing |
| 2 | Validation error |
| 3 | Permission denied / file missing |
| 4 | Timeout |
| 5 | Safety gate denied |
