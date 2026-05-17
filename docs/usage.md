# Usage — Quick Reference

### Common Workflows

- **Scan a subnet quickly** (uses default tool set):

```bash
nexsec scan 192.168.1.0/24
```

- **Run an autonomous-assisted threat hunt**:

```bash
nexsec security hunt --target example.com
```

- **Create and execute an integrated plan** (planner selects optimal tools and sequence):

```bash
nexsec planner create --target my-app.com
nexsec planner run <PLAN_ID>
```

- **Execute an autonomous instruction**:

```bash
nexsec run "scan 10.0.0.1 with nmap then generate report"
```

- **Manage incidents**:

```bash
nexsec security incidents
nexsec security incident INC-001
nexsec security incident-create --title "SQLi on login" --description "Blind SQLi" --category intrusion --severity high
```

- **Cross-platform shell translation**:

```bash
nexsec shell list-intents
nexsec shell translate dns_lookup --target example.com
nexsec shell list-shells
```

### Output Formatting

- Use `--format json` for structured output suitable for CI/CD pipelines.
- Use `--format table` (default) for rich console output in interactive sessions.

Advanced usage examples are available in `docs/cli-reference.md`.
