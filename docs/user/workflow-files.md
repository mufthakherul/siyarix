# Workflow Files

Siyarix supports executing DAG-native workflow files written in YAML or JSON.

## Workflow format

Workflows define a directed acyclic graph (DAG) of steps with dependencies.

### YAML example

```yaml
name: network-assessment
description: Standard network security assessment
steps:
  - id: recon
    instruction: "scan subdomains of {{target}}"
    mode: integrated
    depends_on: []

  - id: port-scan
    instruction: "nmap -sV -p 1-1000 {{target}}"
    mode: registry
    depends_on: [recon]

  - id: vuln-scan
    instruction: "run vulnerability scan on {{target}}"
    mode: integrated
    depends_on: [port-scan]

  - id: report
    instruction: "generate report from findings"
    mode: integrated
    depends_on: [vuln-scan]
    retries: 2
    timeout: 600
```

### JSON example

```json
{
  "name": "quick-scan",
  "steps": [
    {
      "id": "scan",
      "instruction": "nmap -sV target",
      "depends_on": [],
      "retries": 1
    }
  ]
}
```

## Step specification

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | — | Unique step identifier |
| `instruction` | Yes | — | Command or natural language instruction |
| `mode` | No | `integrated` | Execution mode (registry, autonomous, integrated) |
| `depends_on` | No | `[]` | List of step IDs this step depends on |
| `retries` | No | `0` | Number of retries on failure |
| `timeout` | No | `300` | Step timeout in seconds |
| `persist` | No | `true` | Whether to persist results to offline store |

## Execution

```bash
# Run a workflow file
siyarix workflow run assessment.yaml

# Run in dry-run mode (validate without executing)
siyarix workflow run assessment.yaml --dry-run
```

## Workflow states

Each step progresses through these states:

```
PLANNED → QUEUED → RUNNING → COMPLETED
                         ↓
                    WAITING_APPROVAL → RUNNING
                         ↓
                     BLOCKED → RETRYING → RUNNING
                         ↓
                      FAILED / CANCELED
```

## Dependency resolution

Steps are executed in topological order. Steps with no dependencies run first, then their dependents. The runtime uses `asyncio.Semaphore` to bound concurrency.

## Persistence

Workflow results are persisted to the `OfflineStore`:

- Each step's output (findings, errors, duration)
- Overall workflow status and timing
- Plan ID for later retrieval

## Dry-run mode

```bash
siyarix workflow run assessment.yaml --dry-run
```

Validates:

- All step IDs are unique
- All dependency references resolve
- No circular dependencies
- Required fields are present
