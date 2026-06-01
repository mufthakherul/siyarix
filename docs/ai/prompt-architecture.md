# Prompt Architecture

Prompts are constructed dynamically from system context, user input, and safety constraints.

## Prompt structure

Every AI request follows a structured format:

```
System: {system_context}
User: {user_input}
Context: {session_state}
Constraints: {safety_rules}
Output: {expected_format}
```

## System context

The system context includes:

```json
{
  "platform": "linux|darwin|win32",
  "python_version": "3.11.0",
  "shell": "bash|powershell|zsh",
  "available_tools": ["nmap", "nuclei", "..."]
}
```

This tells the AI what's available on the current system.

## User input

Natural language or structured command from the user:

- "scan 10.0.0.1 for open ports"
- "find vulnerabilities on example.com"
- "/run nmap -sV target"

## Session state

Multi-turn context including:

- Previous commands and their results
- Current knowledge graph state (hosts, ports, vulns discovered)
- Current target

```json
{
  "conversation_history": [
    {"role": "user", "content": "scan 10.0.0.1"},
    {"role": "assistant", "content": "Found ports: 22, 80, 443"}
  ],
  "knowledge_graph": {
    "hosts": ["10.0.0.1"],
    "ports": {"10.0.0.1": [22, 80, 443]}
  }
}
```

## Safety constraints

Attached to every prompt:

```json
{
  "forbidden_commands": ["rm -rf", "dd", "format"],
  "safe_mode": false
}
```

The AI is instructed not to generate dangerous commands and to flag any that slip through.

## Output format

The AI is prompted to return structured JSON:

```json
{
  "intent": "scan",
  "target": "10.0.0.1",
  "tools": ["nmap"],
  "args": ["-sV", "-p", "1-1000"],
  "confidence": 0.95
}
```

## Prompt templates by task type

### Planning

Used by `TaskPlanner` to convert NL to execution plans:

```
You are Siyarix, a senior cybersecurity professional with deep expertise
across the entire security domain. Given the user's security objective,
construct the exact shell commands to run and create an execution plan.
You are NOT limited to any predefined tool list — use any binary on the system.
Target: {target}
User intent: {intent}
```

### Chat

Used by the interactive chat REPL:

```
You are Siyarix, an AI cybersecurity operations assistant.
Session findings: {findings_summary}
User: {message}
```

### Code review

Used by `CoderBridge`:

```
Review this code for security vulnerabilities:
{code}
Focus on: OWASP Top 10, injection flaws, auth bypasses.
```

## Context window management

To prevent overflow:

1. Conversation is truncated oldest-first when exceeding limits
2. Tool outputs are summarized: `nmap output: 5 ports found`
3. Knowledge graph is summarized: `3 hosts, 12 ports, 2 vulns`
4. Large result sets referenced by ID from offline store

## Response parsing

AI responses are parsed and validated:

```python
def parse_ai_response(response: str) -> dict:
    # Try JSON parse
    # Fall back to regex extraction
    # Fall back to rule-based interpretation
    return structured_result
```

If the AI returns malformed output, the `RuleInterpreter` provides fallback parsing.
