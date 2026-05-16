# CLI Reference

This document lists primary subcommands and flags. The CLI is implemented with Typer; use `siyarix --help` for real-time usage information.

### Core Commands

- **`scan`**: Execute security scanning workflows using registered tools.
  - `--profile <name>`: specify a saved configuration profile.
  - `--format json|table|csv`: set the primary output format.
  - `--mode registry|autonomous|integrated`: execution engine strategy.

- **`threat hunt`**: Structured threat hunting and result analysis.
  - `--target <target>`: domain, IP range, or CIDR block.
  - `--assist`: enable autonomous assistance for finding correlation.

- **`run`**: Execute a natural language or direct tool instruction.
  - `siyarix run "scan my network"`

- **`planner`**: Manage and execute multi-step security plans.
  - `create`, `list`, `run`, `show` subcommands.

- **`incident`**: Management of security incidents and findings.
  - `list`, `show`, `resolve`, `annotate`.

### Configuration

- **`~/.siyarix/settings.toml`**: Global agent settings, API keys, and model provider configuration.
- **`~/.siyarix/audit.json`**: Local enterprise audit trail for compliance verification.
