# Interactive Chat Mode

The chat REPL is the primary interaction mode. Launch it with:

```bash
siyarix
# or
siyarix chat
```

## Overview

The chat provides a full interactive shell with:

- Multi-turn AI conversation
- Slash commands for built-in actions
- Tab completion
- Command history (persisted to SQLite)
- Session logging
- Natural language → command execution

## Slash commands

| Command | Description |
|---------|-------------|
| `/help` | Show all slash commands |
| `/exit` | Exit the session |
| `/clear` | Clear conversation history |
| `/save` | Save session to file |
| `/load` | Load a saved session |
| `/mode` | Switch interaction mode |
| `/scan` | Run a scan from chat |
| `/run` | Execute a natural language command |
| `/config` | View or change settings |
| `/status` | Show session status |
| `/history` | Show command history |
| `/tools` | List available tools |
| `/persona` | Switch active persona (redteam, blueteam, dfir, etc.) |
| `/model` | Switch AI provider (openai, gemini, anthropic, etc.) |
| `/command` | Toggle command review on/off |
| `/key` | Set or rotate API keys |
| `/theme` | Change terminal color theme |
| `/branch` | Create or switch session branches |
| `/export` | Export session findings to file |

## Natural language input

Type any natural language command and the AI will interpret it:

```
> scan 192.168.1.1
> find all open ports on example.com
> run a vulnerability scan against the web server
> what tools do I have available?
```

The input is processed by the `TaskPlanner` which converts it to structured commands using the configured AI provider.

## Multi-turn conversation

The chat maintains conversation context across turns. The AI remembers:

- Previous commands and their results
- Scan findings from the current session
- The target being investigated
- User preferences expressed during the session

## Session management

Sessions are automatically saved to SQLite (`~/.siyarix/sessions.db`). Each session tracks:

- Commands executed
- AI conversation history
- Findings and results
- Timestamps and duration

## Persona switching

Switch between behavior profiles during a session:

```
/persona offensive    # Aggressive testing approach
/persona defensive    # Safety-first approach
/persona pentester    # Standard penetration testing
/persona soc_analyst  # Monitoring and detection
/persona bug_hunter   # Focused vulnerability discovery
```

Each persona adjusts tool selection, aggressiveness, and safety constraints.

## Pipe and batch mode

Commands can be piped:

```bash
echo "scan 10.0.0.1" | siyarix
echo -e "scan 10.0.0.1\nrun nmap scan on port 80" | siyarix
```

Or loaded from a file:

```bash
siyarix --batch commands.txt
```

## Tips

- Type `/` to see available commands
- Use Tab for auto-completion
- Previous commands are navigable with Up/Down arrows
- Ctrl+C cancels the current operation
- `/save filename` saves the session to `~/.siyarix/sessions/filename.json`
