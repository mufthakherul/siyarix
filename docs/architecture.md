# Architecture

NexSec is organized as a modular CLI agent with the following layers:

- **CLI Layer (Typer)**: routes subcommands and handles user input, formatting, and interactive feedback.
- **Task Planner**: converts high-level user instructions into a structured execution plan.
- **Execution Engine**: runs tasks using internal analyzers and external tools via the `tool_registry`.
- **Command Interpreters**: heuristic and model-driven interpreters that classify user intent into actionable tasks.
- **Parsers & Plugins**: normalize output from third-party tools into a common security finding format.
- **Data Stores**: managing offline cache, enterprise audit logs, and incident tracking for persistence and compliance.

### Design Principles

- **Decoupled Orchestration**: The planner is independent of the execution engine, allowing for plan verification before execution.
- **Extensible Adapters**: Each tool parser and plugin implements a standardized adapter API, making it easy to add support for new security tools.
- **Safety-First Resolution**: All model-suggested or interpreted commands pass through a safety resolver before being sent to the subprocess executor.
