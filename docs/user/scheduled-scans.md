# Scheduled Scans

Siyarix includes a persistent cron-based scheduler for recurring security scans.

## Schedule management

Jobs are stored in `~/.siyarix/schedules.json` and survive restarts.

### Creating a scheduled scan

```bash
# Daily scan at system-defined interval
siyarix run "schedule a daily scan of 10.0.0.0/24"

# Weekly scan
siyarix run "schedule a weekly vulnerability scan of the web server"
```

### Managing schedules

```bash
# List all scheduled jobs
siyarix scheduler list

# Pause a schedule
siyarix scheduler pause <job-id>

# Resume a schedule
siyarix scheduler resume <job-id>

# Remove a schedule
siyarix scheduler remove <job-id>
```

## Schedule intervals

| Interval | Description |
|----------|-------------|
| `hourly` | Runs every hour |
| `daily` | Runs once per day (default) |
| `weekly` | Runs once per week |

## How it works

The `SiyarixScheduler`:

1. Stores jobs as JSON in `schedules.json`
2. Calculates next run time based on interval
3. On trigger, executes the job via `ExecutionEngine`
4. Logs results to the audit trail
5. Updates last_run and next_run timestamps

### Job data model

```python
@dataclass
class ScheduledJob:
    id: str
    name: str
    target: str
    cron: str         # "hourly", "daily", "weekly"
    command: str       # The scan command to run
    persona: str       # Persona to use for execution
    last_run: str      # ISO 8601 timestamp
    next_run: str      # ISO 8601 timestamp
    active: bool       # Whether the schedule is active
```

## Use cases

- **Continuous monitoring**: Schedule daily port scans of critical infrastructure
- **Compliance**: Run weekly compliance checks for audit readiness
- **Vulnerability management**: Schedule weekly vulnerability scans
- **Change detection**: Compare scan results over time to detect configuration drift

## Audit trail

All scheduled scan executions are logged to the audit log with:

- Job ID and name
- Scheduled time vs actual execution time
- Command executed
- Result summary (findings count, errors)
- Duration
