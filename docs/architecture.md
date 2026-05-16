# Architecture

NexSec is organized as a modular CLI agent with the following layers:

- CLI layer (Typer): routes subcommands and handles user input/format flags.
- Planner (AI): converts high-level user intent into an execution plan composed of tasks.
- Executor (Hybrid Engine): runs tasks using internal analyzers and external tools via the `tool_registry`.
- Parsers & Plugins: normalize output from third-party tools into a common event format.
- Stores: offline cache, audit log, and incident store for persistence and compliance.

Design notes:
- Each plugin/parsers implements a small adapter API so new tool support can be added without touching core logic.
- Plans are expressed as JSON structures and can be stored, replayed, or modified by operators.
