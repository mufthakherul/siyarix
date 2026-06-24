# ⌨️ CLI Commands Reference

Siyarix is a CLI-first platform built on the blazing fast **Typer** framework. Everything you can do in Siyarix is accessible via the `siyarix` command-line binary.

Whether you are running a single scan, automating a massive batch job, or spinning up the interactive chat, this reference guide has you covered.

---

## 🌍 Global Options

You can attach these flags to almost *any* Siyarix command.

```bash
siyarix [OPTIONS] COMMAND [ARGS]...
```

| Option | What it does |
|--------|-------------|
| `--config`, `-c` | Pass in a custom configuration file (YAML/JSON) instead of the default settings. |
| `--batch`, `-b` | Have a script full of Siyarix commands? Point this to your script to run them all! |
| `--mode`, `-m` | Force a specific execution mode (`autonomous`, `integrated`, `offline`, or `registry`). |
| `--target`, `-t` | Pre-set the initial target (IP, URL, or CIDR) for your session. |
| `--session` | Pick up right where you left off by providing a previous Session ID. |
| `--resume` | A shortcut to instantly resume your most recent session. |
| `--version` | Print the current Siyarix version. |
| `--help` | See the help menu for the current command. |

---

## 🎮 The 5 Usage Modes

There is no "wrong" way to use Siyarix. Pick the workflow that fits your task:

1. **Interactive REPL:** `siyarix` *(No subcommand)*
   - Launches our beautiful, context-aware terminal chat interface featuring over 54+ slash commands.
2. **Direct Execution:** `siyarix scan 10.0.0.1`
   - Run a single command, get the result, and exit cleanly. Perfect for quick checks.
3. **Pipe Mode:** `echo "scan 10.0.0.1" | siyarix`
   - Feed commands directly into Siyarix from other terminal tools via standard input.
4. **Batch Mode:** `siyarix --batch script.txt`
   - Execute a sequence of pre-written commands.
5. **Autonomous Agent:** `siyarix agent "enumerate services"`
   - Give Siyarix a high-level goal and let its Observe-Reason-Act loop figure out how to achieve it.

---

## 🚀 Core Commands

These are the commands you will use every single day.

### `init`
Relaunch the interactive 11-step setup wizard to configure your AI providers and terminal preferences.
```bash
siyarix init [--force] [--skip-requirements]
```

### `scan`
Run security scans against one or more targets using the tools installed on your system.
```bash
siyarix scan <targets...> [OPTIONS]

# 💡 Pro-Tip: You can scan hundreds of IPs at once using a file!
siyarix scan @targets.txt
```

**Scan Presets (The Fast Track):**
- `siyarix scan-quick <target>`: Rapid port discovery (Top 100 ports, no deep service detection).
- `siyarix scan-full <target>`: Scans all ports, fingerprints the OS, and runs default scripts.
- `siyarix scan-deep <target>`: A heavy, multi-pass scan for maximum reconnaissance.
- `siyarix scan-web <target>`: Specifically hunts for web application vulnerabilities (runs `nikto`, `whatweb`, `nuclei`).

### `discover`
A lightweight command to map out the assets and services running on a target.
```bash
siyarix discover <target> [--deep] [--export results.json]
```

### `run`
The magic command. Speak to Siyarix in natural language, and it will build and execute a plan.
```bash
siyarix run "scan my network for open ports and output to a table"
```

### `agent`
Unleash the autonomous agent! Tell Siyarix the ultimate goal, and it will iterate through multiple phases (Observe, Reason, Act) until it finishes the job.
```bash
siyarix agent "find all vulnerabilities on our web server" --max-iter 15
```

### `health`
Run a comprehensive diagnostic check on your AI providers, terminal tools, RAM, and CPU.
```bash
siyarix health
```

---

## 🗂️ Management & Utility Commands

### `auth` & `creds`
Manage your encrypted API keys and tool credentials.
```bash
siyarix auth set-key openai      # Securely input an API key
siyarix auth show                # See your active providers
siyarix creds list               # List stored tool credentials
siyarix creds rotate             # Rotate your vault's AES encryption key
```

### `config`
Tweak Siyarix's settings directly from the CLI.
```bash
siyarix config list                  # View all settings
siyarix config set log_level debug   # Change a setting
siyarix config edit                  # Open settings in your text editor
```

### `theme`
Customize the look and feel of the terminal.
```bash
siyarix theme list
siyarix theme set cyber_noir
siyarix theme preview            # Preview what they all look like!
```

### `playbook`
Execute or validate YAML-based Incident Response playbooks.
```bash
siyarix playbook run ./playbooks/incident_response.yaml
siyarix playbook validate ./playbooks/my_draft.yaml
```

### `report`
Generate gorgeous, board-ready assessment reports straight from your scan data.
```bash
siyarix report generate --format html --output pentest_report.html
```

---

## 🛡️ Advanced Operations Subgroups

Siyarix includes dedicated subgroups for specialized security tasks:

- **`siyarix audit`**: Manage tamper-evident audit trails using SHA-256 hash chaining.
- **`siyarix security`**: Manage incidents, track vulnerabilities, and hunt for threats mapped to the MITRE ATT&CK framework.
- **`siyarix compliance`**: Automatically run compliance assessments against frameworks like SOC2, HIPAA, NIST, and GDPR.
- **`siyarix ci-gate`**: Drop Siyarix into a CI/CD pipeline. It will automatically fail the build if security thresholds aren't met!

---

## 🛑 Exit Codes

Integrating Siyarix into a script? Here is what our exit codes mean:

| Exit Code | What it means |
|------|---------|
| **0** | **Success!** Everything ran perfectly. |
| **1** | **General Error.** Usually an unknown command or a missing target. |
| **2** | **Validation Error.** A health check failed, or your syntax was invalid. |
| **3** | **Critical Findings!** We completed the scan and found high-severity issues. |
