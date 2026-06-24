# First Run

Your first Siyarix session walks through onboarding, health verification, and executing a live command. We will guide you step by step.

## Step 1: Launch and Onboard

```bash
siyarix
```

If Siyarix has not been initialized, the interactive 11-step onboarding wizard launches automatically. The `BootstrapEngine` detects your platform, checks dependencies, and sets up the workspace directory structure. Follow the prompts to configure your AI provider, credentials, and preferences.

See the [Onboarding Wizard](onboarding.md) for a detailed walkthrough of each step.

## Step 2: Verify Health

Ensure everything is operational:

```bash
siyarix health
```

The `HealthChecker` performs a comprehensive assessment:

- **Python version** and system requirements
- **Installed tools** in PATH (critical runtime tools like bash, python, curl, and security tools)
- **Credential store** status (encrypted vault ready)
- **Provider connectivity** — checks all configured AI providers (cloud API key presence, local provider responsiveness via health endpoints)
- **System resources** — memory, disk, CPU usage (via psutil)
- **Overall state** — reports healthy, degraded, or unhealthy with per-component details

## Step 3: Run a Scan

Execute a quick port scan against a domain:

```bash
siyarix scan quick example.com
```

Siyarix will plan the operation, route it through the permission gate, execute the tools, parse the output, and display structured results.

### Deep Scan

For more comprehensive reconnaissance:

```bash
siyarix scan deep example.com
```

The `DeepScanEngine` performs multi-layered analysis with OS fingerprinting, vulnerability detection, and comprehensive reporting.

## Step 4: Enter the REPL

Launch the interactive REPL for multi-turn conversations:

```bash
siyarix
```

From the REPL you can run slash commands (`/scan`, `/run`, `/persona`), switch providers mid-session, and chain multiple operations. The `SmartAutocomplete` provides context-aware tab completion for commands, tools, models, providers, and file paths.

## Step 5: Natural Language Execution

```bash
siyarix run "enumerate services on 10.0.0.1"
```

Siyarix interprets the request, selects appropriate tools, builds an execution plan, and presents the results.

### Offline Mode

For environments without AI provider access:

```bash
siyarix --mode offline run "scan example.com"
```

In offline mode, the `OfflineRegistry` planner uses heuristic planning without any AI dependency — always available, no API keys required.

## Getting Help

```bash
siyarix --help              # Top-level help
siyarix scan --help         # Subcommand help
siyarix                     # /help lists all slash commands in REPL
```

## What's Next

- [Interactive Chat](../user/interactive-chat.md) — Master the REPL
- [Security Workflows](../user/security-workflows.md) — Real-world scenarios
- [CLI Commands](../user/cli-commands.md) — Full command reference
