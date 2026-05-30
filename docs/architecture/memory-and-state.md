# Memory & State

Siyarix uses multiple layers of memory and state management for session continuity, persistence, and learning.

## Memory layers

```
┌─────────────────────────────────────────┐
│         In-Memory (session)             │
│  ┌───────────┐  ┌───────────────────┐  │
│  │ Knowledge  │  │ Conversation      │  │
│  │ Graph      │  │ History (deque)   │  │
│  └───────────┘  └───────────────────┘  │
│  ┌───────────┐  ┌───────────────────┐  │
│  │ Cache     │  │ Masking Context   │  │
│  │ (LRU/TTL) │  │ (bidirectional)   │  │
│  └───────────┘  └───────────────────┘  │
├─────────────────────────────────────────┤
│        SQLite (persistent)              │
│  ┌───────────┐  ┌───────────────────┐  │
│  │ Offline   │  │ Session Manager   │  │
│  │ Store     │  │ (history + meta)  │  │
│  └───────────┘  └───────────────────┘  │
├─────────────────────────────────────────┤
│        File-based (export/import)       │
│  ┌───────────┐  ┌───────────────────┐  │
│  │ Reports   │  │ Knowledge Graph   │  │
│  │ (HTML/PDF)│  │ (JSON export)     │  │
│  └───────────┘  └───────────────────┘  │
└─────────────────────────────────────────┘
```

## In-memory state

### Knowledge graph (`knowledge_graph.py`)

An in-memory directed graph of discovered entities:

- **Nodes**: hosts, ports, services, vulnerabilities, credentials, domains
- **Edges**: relationships (runs_on, has_vuln, uses_credential)
- **Operations**: BFS shortest path, node/edge CRUD
- **Management**: `manage_knowledge_graph()` for manual viewing
- **Persistence**: JSON export/import

### Conversation history

Maintained as a `deque(maxlen=100)` per agent for multi-turn context:

- Messages sent and received
- Tool outputs (summarized)
- User intents and corrections

### Cache manager (`cache_manager.py`)

LRU cache with configurable TTL:

- Caches provider responses (planning results, chat completions)
- Caches tool discovery results
- Caches parsed tool output
- Stats tracking (hit/miss rates)

### Masking context (`masking.py`)

Session-scoped bidirectional token mapping:

- Maps real values → masked tokens for provider calls
- Maps masked tokens → real values for local display
- Cleared at session end

## Persistent state

### Offline store (`offline_store.py`)

SQLite database at `~/.siyarix/offline.db` with WAL mode:

- **Scans**: Target, tool used, timestamps, findings
- **Findings**: Port, service, vulnerability, severity
- **Execution plans**: Plan steps, status, results
- **Step executions**: Per-step logs, outputs, timestamps

### Session manager (`session_manager.py`)

SQLite-backed at `~/.siyarix/sessions.db`:

- **Command history**: Every command with timestamp, exit code
- **Session metadata**: Start/end time, target, mode
- **Session registry**: Active/archived sessions

## State lifecycle

```
Session start
    │
    ├── Load settings from ~/.siyarix/settings.toml
    ├── Initialize knowledge graph (empty)
    ├── Open offline store (SQLite)
    ├── Open session manager (SQLite)
    │
    ▼
Session active
    │
    ├── Knowledge graph populated from tool outputs
    ├── Conversation history grows
    ├── Findings stored in offline store
    ├── Commands logged to session manager
    │
    ▼
Session end
    │
    ├── Save knowledge graph (optional JSON export)
    ├── Generate report (optional)
    ├── Close SQLite connections
    └── Clear in-memory state
```
