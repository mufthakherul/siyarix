# Interaction Modes

Siyarix supports 9 interaction modes, selected automatically based on CLI context and user preferences.

## Mode dispatcher

The `ModeDispatcher` evaluates a `LaunchContext` to select the appropriate mode:

| Context trigger | Mode selected |
|----------------|---------------|
| No arguments, TTY available | InteractiveShell |
| No arguments, piped input | AIConversational |
| Command + arguments | DirectCommand |
| `--goal` flag present | AutonomousAgent |
| `--workflow` flag present | WorkflowAutomation |
| `--dashboard` flag | TUIDashboard |
| `--wizard` flag | GuidedWizard |
| `--team` flag | TeamCollaboration |
| Headless environment | HeadlessAPI |

## Mode reference

### 1. InteractiveShell

Standard CLI execution mode. User types commands, gets immediate output.

```bash
siyarix              # Launches chat REPL
siyarix scan target  # One-shot command
```

### 2. AIConversational

Multi-turn chat assistant with context retention, slash commands, and AI planning.

```bash
siyarix              # Default launch (chat REPL)
# Inside chat: type natural language, get AI-planned execution
```

### 3. DirectCommand

Natural language one-shot execution. Converts NL to structured plan and executes.

```bash
siyarix run "scan 10.0.0.1 for open ports"
```

### 4. AutonomousAgent

Goal-driven reasoning loop. The system decomposes the objective and executes sub-tasks autonomously.

```bash
siyarix agent "enumerate the network and find vulnerabilities"
```

### 5. WorkflowAutomation

Executes a DAG pipeline from a YAML/JSON workflow file.

```bash
siyarix workflow run assessment.yaml
```

### 6. TUIDashboard

Rich terminal dashboard showing real-time security status, findings, and system health.

```bash
siyarix security dashboard
```

### 7. GuidedWizard

Step-by-step guided setup and configuration wizard for new users.

```bash
siyarix --wizard
```

### 8. TeamCollaboration

Multi-user session with shared context and coordinated operations.

```bash
siyarix --team session-123
```

### 9. HeadlessAPI

Non-interactive mode for CI/CD pipelines and programmatic access. No TTY required.

```bash
siyarix --batch commands.txt
echo "scan target" | siyarix
```

## Mode selection priority

The dispatcher evaluates the `LaunchContext` in this order:

1. **Headless check**: No TTY → HeadlessAPI
2. **Wizard flag**: `--wizard` → GuidedWizard
3. **Goal flag**: `--goal` → AutonomousAgent
4. **Workflow flag**: `--workflow` → WorkflowAutomation
5. **Dashboard flag**: `--dashboard` → TUIDashboard
6. **Team flag**: `--team` → TeamCollaboration
7. **Natural language**: Single instruction → DirectCommand
8. **Interactive**: TTY available → InteractiveShell
9. **Fallback**: AIConversational

## Override

Force a specific mode:

```bash
siyarix --mode autonomous agent "find vulnerabilities"
```
