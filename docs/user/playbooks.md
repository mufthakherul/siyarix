!!! note
    👋 **Hey there!** Siyarix is a personal passion project built by a single developer that is growing and under active development. The feature described on this page is currently **Planned / Under Development** and may not be fully functional in the codebase yet. Stay tuned for updates! 🚀

# 📓 Playbook Engine

Why do the same tasks manually over and over? The Playbook Engine allows you to create reusable, multi-step workflows for incident response, vulnerability assessments, and routine security checks.

Using simple YAML files, you can define steps, variables, and dependencies, and Siyarix's DAG (Directed Acyclic Graph) engine will execute them flawlessly.

---

## 🧱 Step Types

A playbook is made up of individual steps. Currently, Siyarix supports two main types:

| Step Type | What It Does |
|-----------|--------------|
| `tool` | Executes a specific security tool from the Siyarix tool registry. (This is the default type). |
| `agent` | Delegates a complex, sub-goal directly to the autonomous AI agent. |

!!! note
    We are actively working on expanding the step types! Look out for conditional branching, loops, and delays in future releases.

---

## ✍️ Creating Playbooks

Playbooks are written in standard **YAML** format. Here is an example of a web vulnerability scan playbook:

```yaml
name: web-vuln-scan
description: Standard web vulnerability scan workflow
vars:
  target: "example.com"
  port_range: "1-1000"
steps:
  - id: recon
    type: tool
    tool: nmap
    args:
      flags: "-sn"
    depends_on: [] # This runs first!

  - id: port-scan
    type: tool
    tool: nmap
    args:
      flags: "-p {{port_range}} -sV"
    depends_on: [recon] # Waits for 'recon' to finish

  - id: vuln-scan
    type: tool
    tool: nuclei
    args:
      severity: "high,critical"
    depends_on: [port-scan] # Waits for 'port-scan' to finish
```

### 💻 Programmatic Usage

You can load and run playbooks directly via Python:

```python
from siyarix.playbook import PlaybookEngine
from siyarix.workflow import WorkflowEngine

engine = PlaybookEngine(WorkflowEngine())
engine.load("my-playbook.yml")
```

---

## 🔀 Variables

Make your playbooks dynamic! You can inject variables using the `{{variable_name}}` syntax.

```yaml
vars:
  target: "example.com"
  port_range: "1-1000"
steps:
  - id: scan
    tool: nmap
    args:
      flags: "-p {{port_range}} {{target}}"
```

You can easily override these variables at runtime using the `--var` flag:

```bash
siyarix playbook run my-playbook.yml --var target=10.0.0.1 --var port_range=1-5000
```

!!! tip
    You can also access safe environment variables directly in your playbook using `{{env.HOME}}`, `{{env.PATH}}`, etc.

---

## 🏃 Running Playbooks

Executing playbooks via the CLI is simple:

```bash
# 🚀 Run a playbook
siyarix playbook run my-playbook.yml

# 🎯 Run with custom variables
siyarix playbook run assessment.yml --var target=example.com

# 📂 List all available playbooks in a folder
siyarix playbook list --dir playbooks/

# ✅ Check a playbook for syntax errors
siyarix playbook validate my-playbook.yml
```

---

## 🛡️ Error Handling

Security tools fail. Networks drop. Siyarix handles this gracefully.

You can configure automatic retries and timeouts for every step:

```yaml
steps:
  - id: vuln-scan
    tool: nuclei
    retries: 2       # Try up to 3 times total
    timeout: 300     # Kill the tool if it takes longer than 5 minutes
```

Behind the scenes, the `WorkflowEngine` manages the complex DAG scheduling, handles parallel execution safely (limiting to 4 concurrent tasks by default), and enforces strict timeouts.

---

## 🎯 Key Use Cases

Why should you use playbooks?

- **Standardized Assessments**: Ensure junior and senior analysts perform scans exactly the same way.
- **Incident Response**: Execute pre-defined, high-speed containment and analysis workflows during a breach.
- **Onboarding**: Automate the setup process for new team members with a single command.
- **Compliance**: Generate repeatable, consistent evidence for your audit cycles.
