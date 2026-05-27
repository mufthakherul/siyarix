# Reporting & Output

Siyarix provides multiple output formats and report generation capabilities.

## Output formats

Set the default output format:

```bash
siyarix config set default_output_format json
```

Supported formats:

| Format | Description |
|--------|-------------|
| `table` | Rich formatted table (default) |
| `json` | JSON output |
| `yaml` | YAML output |
| `csv` | CSV output |

## Report generation

```bash
siyarix report generate --format html --output report.html
```

The report engine collects all findings from the current session and generates structured reports.

### Report formats

| Format | Use case |
|--------|----------|
| HTML | Client-ready reports with formatting |
| JSON | Machine-readable, pipeline integration |
| Markdown | Quick documentation, issue tracking |
| PDF | Formal documentation (if wkhtmltopdf is available) |

### Report sections

Reports include:

- **Executive Summary**: High-level findings overview
- **Scope**: Targets scanned and tools used
- **Findings**: Detailed vulnerability descriptions with severity
- **Evidence**: Command outputs, screenshots (if captured)
- **Remediation**: Suggested fixes for each finding
- **Timeline**: Session chronology

## Audit logging

All actions are logged to an enterprise-grade audit trail:

```bash
siyarix audit-log
```

The audit system features:

- **Tamper evidence**: SHA-256 hash chain linking entries
- **SIEM forwarding**: Send logs to Splunk, ELK, or Azure Sentinel
- **Session tracking**: Every command tied to a session ID
- **Export**: Export logs in JSON or CSV

### Audit record fields

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp |
| `session_id` | Unique session identifier |
| `event_type` | Type of event (command, auth, safety, tool) |
| `severity` | INFO, WARNING, ERROR, CRITICAL |
| `command` | The executed command |
| `user` | User identity (if auth is configured) |
| `provider` | AI provider used (if applicable) |
| `hash` | SHA-256 of previous entry |

## Session logs

Structured session logs are maintained per Chapter 11 specification:

```bash
siyarix session-log
# Shows: command, result, safety events, duration
```

Each session log entry includes:

- Command text and parsed intent
- Execution duration
- Exit code and output summary
- Safety events triggered (if any)
- AI provider used for planning

## Metrics

```bash
siyarix metrics
```

Shows performance statistics:

- Total scans performed
- Average scan duration
- Tools used (counts)
- Planner invocation stats
- AI provider usage distribution
- Cache hit/miss rates

## Health check

```bash
siyarix health
```

Reports:

- Component status (Python, core modules, AI providers)
- Platform information (OS, Python version, shell)
- System state (initialized, configured)
- Storage usage (database size, cache size)
