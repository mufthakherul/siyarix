# Memory & State Management

Siyarix v3.0.0 uses a multi-layered memory and state management system spanning in-memory runtime state, SQLite-backed persistence, and file-based exports. The system includes a **KnowledgeGraph** for infrastructure relationships, **MemoryManager** with semantic memory and embeddings, **ChatSession** with branching support, **SessionKernel** for persistence, **CacheManager** with LRU + TTL, and a **Context Manager** for LLM context window optimization.

---

## Memory Layers

```
┌────────────────────────────────────────────────────────────┐
│                  In-Memory (Session Runtime)                │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ Knowledge    │  │ MemoryManager    │  │ Context      │ │
│  │ Graph        │  │ (semantic memory │  │ Manager      │ │
│  │ (entities,   │  │  + embeddings)   │  │ (window      │ │
│  │  relations)  │  │  + Continuous    │  │  build/      │ │
│  │              │  │   Learning)      │  │  compress)   │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
│                                                           │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ CacheManager │  │ Conversation     │  │ Masking      │ │
│  │ (LRU + TTL)  │  │ History (deque)  │  │ Context      │ │
│  │              │  │ Session Messages │  │ (bidirectional│ │
│  │              │  │ maxlen=100)      │  │  token map)  │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────────┤
│                  SQLite (Persistent)                       │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ OfflineStore │  │ SessionKernel    │  │ ProviderState│ │
│  │ (scans,      │  │ (session history │  │ Manager      │ │
│  │  findings,   │  │  + metadata)     │  │ (cooldown,   │ │
│  │  plans)      │  │                  │  │  failures)   │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────────┤
│                  File-Based (Export/Import)                 │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ Reports      │  │ ChatSession      │  │ Knowledge    │ │
│  │ (MD/HTML/    │  │ Exports          │  │ Graph JSON   │ │
│  │  JSON/SARIF) │  │ (JSONL tree fmt) │  │ Export       │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
└────────────────────────────────────────────────────────────┘
```

---

## 1. KnowledgeGraph

An in-memory directed graph of discovered infrastructure entities:

### Node Types

| Node | Attributes | Example |
|------|------------|---------|
| `Host` | IP, hostname, OS, MAC | `10.0.0.1` |
| `Port` | Number, protocol, state | `80/tcp open` |
| `Service` | Name, version, banner | `Apache 2.4.41` |
| `Vulnerability` | CVE ID, severity, CVSS | `CVE-2024-1234` |
| `Domain` | FQDN, registrar, DNS | `example.com` |
| `Credential` | Username, type, hash | `admin:$2y$10$...` |
| `Finding` | Tool, description, ref | Nmap finding |

### Edge Types

| Edge | Source → Target | Meaning |
|------|----------------|---------|
| `runs_on` | Service → Host | Service runs on host |
| `has_port` | Host → Port | Host has open port |
| `has_vuln` | Service → Vulnerability | Service has vulnerability |
| `resolves_to` | Domain → Host | Domain resolves to IP |
| `uses_cred` | Service → Credential | Service uses credential |
| `related_to` | Finding → Finding | Related findings |

### Operations

- BFS shortest path between entities
- Subgraph queries by type, attribute, or relationship
- Real-time insertion from tool parser output
- JSON export/import for session persistence

### Compact Integration

The `Compact` system optimizes the KnowledgeGraph for LLM context windows by:
- Summarizing large subgraphs (e.g., "45 hosts discovered")
- Prioritizing high-severity findings
- Truncating oldest/lowest-value entities when token budget is exceeded

---

## 2. MemoryManager

Manages semantic memory with embeddings:

### Semantic Memory

```python
@dataclass
class MemoryEntry:
    id: str
    content: str                     # Raw content
    embedding: list[float]           # Vector embedding
    metadata: dict                   # Source, timestamp, context
    importance: float                # 0.0–1.0
    access_count: int                # Recency/frequency tracking
```



```python
memory = MemoryManager()
await memory.store(
    content="Host 10.0.0.1 has Apache 2.4.41 running on port 80",
    metadata={"source": "nmap", "session_id": "sess-123"}
)
similar = await memory.search("Apache versions", top_k=5)
```

---

## 3. Context Manager

Builds, compresses, and optimizes the LLM context window:

### Context Assembly

```python
context = ContextManager.build(
    conversation_history=[...],       # Recent messages
    knowledge_subgraph={...},         # Relevant entities from KG
    session_state={...},              # Current phase, target, findings
    tool_availability=[...],          # Available tools from ToolRegistry
    memory_entries=[...],             # Relevant semantic memories
    max_tokens=8192                   # Token budget
)
```

### Compression Strategies

| Strategy | Description | Token Reduction |
|----------|-------------|-----------------|
| **Truncation** | Drop oldest conversation turns | 20–40% |
| **Summarization** | LLM-summarized history blocks | 40–60% |
| **KG Pruning** | Keep only high-severity/related entities | 30–50% |
| **Memory Prioritization** | Include only importance > threshold | 50–70% |
| **Deduplication** | Remove redundant tool outputs | 10–20% |

### Compact System

The `Compact` system provides LLM context window optimization:

```python
compact = Compact(max_tokens=4096)
compressed = compact.compress(
    context=raw_context,
    strategy="priority",     # priority | truncate | summarize | hybrid
    preserve_fields=["intent", "targets", "findings"]
)
```

---

## 4. ChatSession

Supports branching conversations with a JSONL tree format:

### Branching Model

```
Session Root
  ├── Branch A (main thread)
  │   ├── Message 1
  │   ├── Message 2
  │   │   └── Branch B (forked from message 2)
  │   │       ├── Message 3
  │   │       └── Message 4
  │   └── Message 5
  └── Branch C (forked from root)
      └── Message 6
```

### JSONL Tree Format

```jsonl
{"id": "msg-1", "parent": null, "role": "user", "content": "scan 10.0.0.1", "ts": "...", "branch": "main"}
{"id": "msg-2", "parent": "msg-1", "role": "assistant", "content": "...", "ts": "...", "branch": "main"}
{"id": "msg-3", "parent": "msg-1", "role": "user", "content": "try different approach", "ts": "...", "branch": "alt"}
{"id": "msg-4", "parent": "msg-3", "role": "assistant", "content": "...", "ts": "...", "branch": "alt"}
```

### BranchingSession

```python
session = BranchingSession(session_id="sess-123")
await session.branch(from_message="msg-2", branch_name="alt-approach")
# Creates a new branch fork from message 2
await session.merge(from_branch="alt-approach", into_branch="main")
# Merges alt-approach findings back into main
```

| Operation | Description |
|-----------|-------------|
| `branch(from_message, branch_name)` | Fork a new branch from any message |
| `merge(from_branch, into_branch)` | Merge branch contents into another |
| `diff(branch_a, branch_b)` | Show differences between branches |
| `prune(branch_name)` | Remove a branch entirely |
| `export()` | Export session as JSONL tree |

---

## 5. SessionKernel

Persistence layer for sessions:

```python
kernel = SessionKernel(db_path="~/.siyarix/sessions.db")
await kernel.save(session)
await kernel.restore(session_id="sess-123")
# Returns: Session with full history, branch structure, KG snapshot
```

- SQLite-backed with WAL mode
- Stores session metadata (start/end time, target, mode)
- Full command history with timestamps and exit codes
- Active/archived session registry
- Session restore with KnowledgeGraph snapshot

---

## 6. CacheManager

LRU + TTL with optional disk persistence:

```python
cache = CacheManager(
    max_size=1000,           # Max cache entries
    ttl=300,                 # Default TTL (seconds)
    persist_path="~/.siyarix/cache.db"  # Disk persistence
)

# Cache types
cache.provider_responses    # AI provider results (planning, chat)
cache.tool_discovery        # Tool availability scans
cache.parsed_outputs        # Parsed tool output
cache.embeddings            # Generated embeddings

# Statistics
stats = cache.get_stats()
# CacheStats(hits=450, misses=30, hit_rate=0.94, size=200, evictions=15)
```

---

## State Lifecycle

```
Session Start
    │
    ├── Load config from ~/.siyarix/settings.toml
    ├── Initialize KnowledgeGraph (empty or restore from last session)
    ├── Initialize MemoryManager (load persisted embeddings)
    ├── Initialize CacheManager (load disk cache)
    ├── Open OfflineStore (SQLite WAL)
    ├── Open SessionKernel (SQLite)
    ├── Open ProviderStateManager (SQLite)
    │
    ▼
Session Active
    │
    ├── KnowledgeGraph populated from tool outputs (real-time)
    ├── MemoryManager updated from tool outputs
    ├── Conversation history appended (deque maxlen=100)
    ├── Findings stored in OfflineStore
    ├── Commands logged to SessionKernel
    ├── Provider state tracked (cooldowns, failures, costs)
    ├── Cache populated/evicted (LRU + TTL)
    │
    ▼
Session End
    │
    ├── Save KnowledgeGraph (optional JSON export)
    ├── Persist MemoryManager embeddings
    ├── Save session to SessionKernel
    ├── Flush CacheManager to disk
    ├── Generate report (optional)
    ├── Close all SQLite connections
    └── Clear in-memory state
```

---

## Integration Points

| Component | Role |
|-----------|------|
| **Context Manager** | Builds/compresses context from KG, memory, history |
| **MemoryManager** | Semantic memory with embeddings |
| **KnowledgeGraph** | Real-time entity relationship graph |
| **ChatSession** | Branching conversation storage (JSONL tree) |
| **SessionKernel** | Session persistence and restore |
| **CacheManager** | LRU + TTL disk-backed caching |
| **OfflineStore** | Offline scan/finding persistence |
| **OfflineQueue** | Offline request queuing |
| **Compact** | Context window optimization for LLM budget |
| **ProviderStateManager** | Provider cooldown/failure persistence |
| **EventBus** | Emits state change events (kg.updated, memory.stored, cache.evicted) |
