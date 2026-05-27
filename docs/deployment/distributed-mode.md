# Distributed Mode

Siyarix supports distributed deployment using a Redis/RQ-backed task queue for multi-node operations.

## Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   Siyarix   │────▶│    Redis/RQ     │◀────│   Worker N   │
│  Dispatcher │     │   Task Queue    │     │  (agent)     │
└──────────────┘     └─────────────────┘     └──────────────┘
                            │
                            ▼
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │  (offline store)│
                    └─────────────────┘
```

## Components

### Task queue backends

| Backend | Type | Use case |
|---------|------|----------|
| `memory` | In-process | Development/testing |
| `redis` | Redis/RQ | Production distributed |

### Distributed orchestrator

The `DistributedOrchestrator` manages:

- Task dispatch across workers
- Handler registration for task types
- Worker heartbeat monitoring
- Result collection and aggregation

### Worker registration

Workers register with the orchestrator and report:

- Worker ID
- Capabilities (supported task types)
- Status (idle, busy, offline)

## Configuration

```bash
# Start a worker
siyarix distributed worker --backend redis --queue siyarix:tasks

# Dispatch a task from another instance
siyarix distributed dispatch --task scan --target 10.0.0.1
```

## Task types

Tasks follow the `DistributedTask` data model:

```python
@dataclass
class DistributedTask:
    task_id: str
    task_type: str       # scan, exploit, recon, etc.
    payload: dict        # Task-specific data
    priority: int        # 0 (low) to 10 (high)
    status: str          # pending, running, completed, failed
    assigned_to: str     # Worker ID
    result: dict         # Task result (populated on completion)
```

## Use cases

- **Multi-network scanning**: Distribute scan jobs across network segments
- **Parallel operations**: Run multiple independent assessments simultaneously
- **Load balancing**: Distribute heavy scans across worker nodes
- **Remote agents**: Deploy workers on different cloud regions or subnets

## Limitations

- Redis/RQ is the only production backend currently implemented
- RabbitMQ, AWS SQS, and Google Pub/Sub backends are extensible via the `TaskQueueBackend` interface
- SQLite is replaced by PostgreSQL for the server role in distributed mode
