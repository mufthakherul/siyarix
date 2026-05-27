# CLI Commands Reference

Siyarix is a CLI-first tool built with Typer. This reference covers all command groups.

## Global options

```bash
siyarix [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--config`, `-c` | Path to custom config file |
| `--batch`, `-b` | Path to batch script file |
| `--mode`, `-m` | Execution mode: `registry`, `autonomous`, `integrated` |
| `--target`, `-t` | Set initial target for the session |
| `--help` | Show help message |
| `--version` | Show version |

## Usage modes

1. **Interactive shell**: `siyarix` (no subcommand) — launches the chat REPL
2. **Direct command**: `siyarix scan 10.0.0.1` — executes and exits
3. **Pipe mode**: `echo "scan 10.0.0.1" | siyarix` — batch commands via stdin
4. **Batch file**: `siyarix --batch script.txt` — execute a script file

## Command groups

### Scan

```
siyarix scan <target>
```

Network scanning, service discovery, and port enumeration. Uses discovered tools on your PATH.

| Subcommand | Description |
|------------|-------------|
| `siyarix scan quick <target>` | Quick port scan |
| `siyarix scan full <target>` | Comprehensive scan |
| `siyarix scan --list-tools` | List all discovered security tools |
| `siyarix scan --all` | Run all available scanning tools |

### Recon

```
siyarix recon <target>
```

Reconnaissance and asset discovery.

### Run (natural language)

```
siyarix run "scan my network for open ports"
```

Converts natural language into structured commands via AI planning.

### Agent

```
siyarix agent "find all vulnerabilities on our web server"
```

Goal-driven autonomous agent that decomposes objectives into sub-tasks.

### Shell

```
siyarix shell <command>
```

Cross-platform shell helper. Provides platform-aware command execution.

### Workflow

```
siyarix workflow run <file>
```

Load and execute YAML/JSON workflow definitions.

### Chat

```
siyarix chat
```

Start interactive AI-powered session with slash commands, auto-complete, history.

### Auth

```
siyarix auth set-key <provider>
```

Configure AI provider API keys interactively.

### Config

| Command | Description |
|---------|-------------|
| `siyarix config list` | Show all settings |
| `siyarix config get <key>` | Get a single setting |
| `siyarix config set <key> <value>` | Set a setting |
| `siyarix config reset` | Reset to defaults |
| `siyarix config edit` | Open config in editor |

### Creds

| Command | Description |
|---------|-------------|
| `siyarix creds list` | List stored credentials |
| `siyarix creds set <provider> <key>` | Store a credential |
| `siyarix creds get <provider> <key>` | Retrieve a credential |
| `siyarix creds delete <provider> <key>` | Delete a credential |
| `siyarix creds rotate` | Rotate encryption key |

### Security

```
siyarix security <subcommand>
```

Security operations management:

| Subcommand | Description |
|------------|-------------|
| `incidents` | View and manage security incidents |
| `vulns` | Vulnerability management |
| `hunt` | Threat hunting operations |
| `mitre` | MITRE ATT&CK coverage mapping |
| `playbooks` | Incident response playbooks |
| `dashboard` | Security dashboard |

### Health

```
siyarix health
```

System health check — components, latency, state.

### Metrics

```
siyarix metrics
```

Performance metrics — scan counts, durations, planner stats.

### Themes

```
siyarix themes
```

Preview available terminal color themes.

### Palette

```
siyarix palette
```

Open interactive command palette for browsing available commands.

### Discover

```
siyarix discover <target>
```

Asset and service discovery.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / unknown command |
| 2 | Validation error |
| 3 | Permission denied |
| 4 | Timeout |
