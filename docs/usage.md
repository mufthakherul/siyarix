# Usage — Quick Reference

### Common Workflows

- **Scan a subnet quickly** (uses default tool set):

```bash
nexsec scan 192.168.1.0/24
```

- **Run an autonomous-assisted threat hunt**:

```bash
nexsec threat hunt --target example.com --assist
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
nexsec incident list
nexsec incident show INC-001
nexsec incident resolve INC-001 --comment "Resolved via patch"
```

### Output Formatting

- Use `--format json` for structured output suitable for CI/CD pipelines.
- Use `--format table` (default) for rich console output in interactive sessions.

Advanced usage examples are available in `docs/cli-reference.md`.
