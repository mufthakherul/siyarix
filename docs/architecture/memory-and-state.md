# Memory & State Management

Siyarix uses a multi-layered memory and state management system spanning in-memory runtime state, SQLite-backed persistence, and file-based exports. The system includes a **KnowledgeGraph** for infrastructure relationships, **MemoryManager** with semantic memory, **ChatSession** with branching support, **SessionKernel** for JSON/JSONL persistence, **CacheManager** with LRU + TTL, a **Context Manager** for LLM context window optimization, and a **Continuous Learning System** for privacy-preserving skill acquisition.

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
│  │  relations)  │  │                  │  │  build/      │ │
│  │              │  │                  │  │  compress)   │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
│                                                           │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ CacheManager │  │ Conversation     │  │ Continuous   │ │
│  │ (LRU + TTL)  │  │ History (deque)  │  │ Learning     │ │
│  │              │  │ Session Messages │  │ System (CLS) │ │
│  │              │  │ maxlen=300)      │  │ (skill cache)│ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────────┤
│                  SQLite (Persistent)                       │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ OfflineStore │  │ Continuous       │  │ ProviderState│ │
│  │ (scans,      │  │ Learning System  │  │ Manager      │ │
│  │  findings,   │  │ (learning_store  │  │ (cooldown,   │ │
│  │  plans)      │  │  .db)            │  │  failures)   │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────────┤
│                  File-Based (Export/Import)                 │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ Reports      │  │ ChatSession      │  │ Knowledge    │ │
│  │ (MD/HTML/    │  │ Exports          │  │ Graph JSON   │ │
│  │  JSON/SARIF) │  │ (JSONL tree fmt, │  │ Export       │ │
│  │              │  │  PDF, TXT, MD)   │  │              │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
│                                                           │
│  ┌──────────────┐  ┌──────────────────┐                   │
│  │ SessionKernel│  │ Tool Failure     │                   │
│  │ (JSON files) │  │ State            │                   │
│  │              │  │ (tool_failures   │                   │
│  │              │  │  .json)          │                   │
│  └──────────────┘  └──────────────────┘                   │
└────────────────────────────────────────────────────────────┘
```

---

## 1. KnowledgeGraph

An in-memory directed graph of discovered infrastructure entities (`siyarix/knowledge_graph.py`):

### Node Types

| Node | Attributes | Example |
|------|------------|---------|
| `HOST` | IP, hostname, OS, MAC | `10.0.0.1` |
| `PORT` | Number, protocol, state | `80/tcp open` |
| `SERVICE` | Name, version, banner | `Apache 2.4.41` |
| `VULNERABILITY` | CVE ID, severity, CVSS | `CVE-2024-1234` |
| `DOMAIN` | FQDN, registrar, DNS | `example.com` |
| `CREDENTIAL` | Username, type, hash | `admin:$2y$10$...` |
| `FINDING` | Tool, description, ref | Nmap finding |

### Edge Types

| Edge | Source → Target | Meaning |
|------|----------------|---------|
| `RUNS_ON` | Service → Host | Service runs on host |
| `HAS_PORT` | Host → Port | Host has open port |
| `HAS_VULN` | Service → Vulnerability | Service has vulnerability |
| `RESOLVES_TO` | Domain → Host | Domain resolves to IP |
| `USES_CRED` | Service → Credential | Service uses credential |
| `RELATED_TO` | Finding → Finding | Related findings |

### Operations

- BFS shortest path between entities
- Subgraph queries by type, attribute, or relationship
- Real-time insertion from tool parser output
- JSON export/import for session persistence (`save_json` / `load_json`)

---

## 2. MemoryManager

Manages semantic memory with embeddings (`siyarix/memory.py`):

### Core Methods

```python
memory = MemoryManager()
await memory.store(
    content="Host 10.0.0.1 has Apache 2.4.41 running on port 80",
    metadata={"source": "nmap", "session_id": "sess-123"}
)
similar = await memory.search_similar("Apache versions", top_k=5)
context = await memory.get_context(target="10.0.0.1")
```

| Method | Purpose |
|--------|---------|
| `store(content, metadata)` | Store a memory entry |
| `search_similar(query, top_k)` | Find semantically similar memories |
| `get_context(target)` | Retrieve context for a given target |

---

## 3. Context Manager

Builds, compresses, and optimizes the LLM context window (`siyarix/context.py`):

```python
context = ContextManager(memory=memory_manager)

# Add to history
context.add_history("User message", "user")
context.add_history("Assistant response", "assistant")

# Retrieve context
history = context.get_history()
context = context.build_context(
    conversation_history=history,
    knowledge_subgraph=relevant_entities,
    session_state={"mode": "autonomous", "target": "10.0.0.1"},
    tool_availability=available_tools,
    memory_entries=relevant_memories,
    max_tokens=8192,
)
```

### Compression via CompactionEngine

The `CompactionEngine` in `siyarix/compaction.py` provides LLM context window optimization:

```python
compactor = CompactionEngine()
tokens = compactor.analyze_tokens(raw_context)
compressed = compactor.compess_context(raw_context, target_tokens=4096)
```

| Strategy | Description | Token Reduction |
|----------|-------------|-----------------|
| **Truncation** | Drop oldest conversation turns | 20–40% |
| **Summarization** | LLM-summarized history blocks | 40–60% |
| **KG Pruning** | Keep only high-severity/related entities | 30–50% |
| **Memory Prioritization** | Include only importance > threshold | 50–70% |
| **Deduplication** | Remove redundant tool outputs | 10–20% |

---

## 4. ChatSession

Branching conversations with a JSONL tree format (`siyarix/chat/session.py`):

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

### Session Configuration

- `maxlen=300` for conversation history
- Branching via `ChatSession` with JSONL tree format
- Messages stored with `id`, `parent`, `role`, `content`, `timestamp`, `branch`

### Export Formats

`ChatSession.export()` supports multiple formats:

| Format | Description |
|--------|-------------|
| `json` | JSON array of messages |
| `jsonl` | JSONL tree format |
| `pdf` | PDF document |
| `txt` | Plain text transcript |
| `md` | Markdown transcript |
| `html` | HTML document |

---

## 5. SessionKernel

Manages session state and operation cards (`siyarix/compat.py`):

```python
kernel = SessionKernel()
session = kernel.start(
    objective="Scan target network",
    scope="10.0.0.0/24",
    identity="operator-1",
)

# Track operations
op = kernel.add_operation(session, "scan 10.0.0.1", "scan", "medium")
kernel.update_operation(session, op.operation_id, state="completed")

# Persist to JSON
path = kernel.save(session)

# Restore from JSON
restored = kernel.load(session_id)
```

- JSON-based persistence (not SQLite)
- Operation cards track individual instructions with state, mode, risk tier, and artifacts
- Session context includes identity, objective, scope, policy, model, and tool contexts
- Persistence levels: EPHEMERAL, WORKSPACE, ORG_SHARED

---

## 6. CacheManager

LRU + TTL with optional disk persistence (`siyarix/cache_manager.py`):

```python
cache = CacheManager(
    max_size=1000,
    ttl=300,
    persist_path="~/.siyarix/cache.db"
)

# Cache statistics
stats = cache.get_stats()
# CacheStats(hits=450, misses=30, hit_rate=0.94, size=200, evictions=15)
```

---

## 7. Continuous Learning System

The `ContinuousLearningSystem` in `siyarix/learning_system.py` provides privacy-preserving skill acquisition:

### Key Design Principles

- **Privacy First**: Real targets are NEVER stored — every hostname, IP, URL, email, or hash is replaced with `{target}` before persistence
- **Separate Store**: Learning data lives in `learning_store.db` (separate from `offline_store.db`)
- **Zero Dependencies**: Pure stdlib — BM25-style Jaccard similarity over NLP token sets
- **Bayesian Confidence**: Skill confidence uses Bayesian-smoothed formula with time decay and complexity weighting

### Data Models

```python
@dataclass
class LearnedStep:
    tool: str
    command_template: str     # Uses {target} placeholder
    description: str
    args: dict

@dataclass
class LearnedSkill:
    skill_id: str
    intent_pattern: str       # Anonymised command pattern
    steps: list[LearnedStep]
    confidence: float         # Bayesian-smoothed 0.0–1.0
    usage_count: int
    success_count: int
    tokens: list[str]         # NLP tokens for similarity
    source: str               # 'llm' | 'offline' | 'inferred'
```

### Learning Flow

1. **Observe**: `observe_llm_action()` or `observe_offline_plan()` captures execution
2. **Anonymize**: All targets replaced with `{target}` before any storage
3. **Match**: Multi-tier similarity matching (≥0.60 strong, 0.35–0.59 partial, <0.35 new)
4. **Learn**: Update skill confidence, merge steps, extract parameter patterns
5. **Inject**: High-confidence skills can be replayed automatically
6. **Maintain**: Periodic pruning, decay, and merging of redundant skills

### Integration

- **Integrated mode**: Skills with ≥80% confidence trigger automatic pre-execution before LLM consultation
- **Offline mode**: Learned skills augment the heuristic planner
- **Synonyms**: Learned keyword-to-tool mappings enrich the NLP engine

---

## State Lifecycle

```
Session Start
    │
    ├── Load config from ~/.siyarix/settings.toml
    ├── Initialize KnowledgeGraph (empty or restore from JSON)
    ├── Initialize MemoryManager (load persisted embeddings)
    ├── Initialize CacheManager (load disk cache)
    ├── Initialize Continuous Learning System (load skill library)
    ├── Open OfflineStore (SQLite WAL)
    ├── Open ProviderStateManager (JSON file)
    │
    ▼
Session Active
    │
    ├── KnowledgeGraph populated from tool outputs (real-time)
    ├── MemoryManager updated from tool outputs
    ├── Conversation history appended (deque maxlen=300)
    ├── Continuous Learning System observes execution
    ├── Findings stored in OfflineStore
    ├── Commands tracked via SessionKernel
    ├── Provider state tracked (cooldowns, failures, costs)
    ├── Cache populated/evicted (LRU + TTL)
    │
    ▼
Session End
    │
    ├── Save KnowledgeGraph (optional JSON export)
    ├── Persist MemoryManager embeddings
    ├── Save session via SessionKernel (JSON)
    ├── Flush CacheManager to disk
    ├── Generate report (optional)
    ├── Close all SQLite connections
    ├── Run CLS maintenance (prune, decay, merge)
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
| **SessionKernel** | Session persistence and restore (JSON) |
| **CacheManager** | LRU + TTL disk-backed caching |
| **OfflineStore** | Offline scan/finding persistence |
| **OfflineQueue** | Offline request queuing |
| **CompactionEngine** | Context window optimization for LLM budget |
| **Continuous Learning System** | Privacy-preserving skill library |
| **ProviderStateManager** | Provider cooldown/failure persistence (JSON) |
| **ToolCallTracker** | Tool failure state persistence (JSON) |
| **EventBus** | Emits state change events (kg.updated, memory.stored, cache.evicted) |
