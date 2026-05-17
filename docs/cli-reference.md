# CLI Reference

This document lists primary subcommands and flags. The CLI is implemented with Typer; use `nexsec --help` for real-time usage information.

### Core Commands

- **`scan`**: Execute security scanning workflows using registered tools.
  - `--profile <name>`: specify a saved configuration profile.
  - `--output table|json|yaml|csv`: set the primary output format.
  - `--mode registry|autonomous|integrated`: execution engine strategy.

- **`chat`**: Interactive cybersecurity REPL with natural-language execution.
  - `--mode registry|autonomous|integrated`
  - `--target <target>`

- **`run`**: Execute a natural language or direct tool instruction.
  - `nexsec run "scan my network"`

- **`shell`**: Cross-platform shell command helper.
  - `platform`, `translate`, `list-intents`, `list-shells`, `security-cmds`

- **`security`**: Security operations console.
  - `incidents`, `incident`, `incident-create`
  - `vulnerabilities`, `remediation-plan`
  - `hunt`, `queries`, `mitre-coverage`, `dashboard`, `playbooks`

### Configuration

- **`~/.nexsec/settings.toml`**: Global agent settings, API keys, and model provider configuration.
- **`~/.nexsec/audit.json`**: Local enterprise audit trail for compliance verification.
