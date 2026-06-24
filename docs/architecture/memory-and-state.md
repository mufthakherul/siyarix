# 🧠 Memory & State Management

Welcome to the heart of Siyarix! This document outlines our multi-layered memory and state management system. We designed this architecture to flawlessly handle everything from lightning-fast in-memory processing to rock-solid SQLite persistence and portable file-based exports.

At a high level, the system comprises several specialized components:
- **KnowledgeGraph**: Connects the dots on infrastructure relationships.
- **MemoryManager**: Powers our semantic memory using embeddings.
- **ChatSession**: Handles conversational history with powerful branching capabilities.
- **SessionKernel**: Persists state across sessions using JSON/JSONL.
- **CacheManager**: Keeps things snappy with LRU (Least Recently Used) and TTL (Time-To-Live) caching.
- **Context Manager**: Carefully optimizes what the LLM sees to maximize context window efficiency.
- **Continuous Learning System (CLS)**: Learns new skills dynamically while strictly preserving privacy.

---

## 🥞 Memory Layers

Siyarix categorizes memory into three distinct, robust layers.

> [!NOTE]
> This layered approach ensures that fast, ephemeral data lives in RAM, critical operations persist safely to disk, and shareable insights can be effortlessly exported.

```text
┌────────────────────────────────────────────────────────────┐
│                  ⚡ In-Memory (Session Runtime)            │
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
│                  💾 SQLite (Persistent)                    │
│                                                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ OfflineStore │  │ Continuous       │  │ ProviderState│ │
│  │ (scans,      │  │ Learning System  │  │ Manager      │ │
│  │  findings,   │  │  .db)            │  │ (cooldown,   │ │
│  │  plans)      │  │                  │  │  failures)   │ │
│  └──────────────┘  └──────────────────┘  └──────────────┘ │
├────────────────────────────────────────────────────────────┤
│                  📄 File-Based (Export/Import)             │
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

## 🕸️ 1. KnowledgeGraph

Located at `siyarix/knowledge_graph.py`, the **KnowledgeGraph** is a dynamic, in-memory directed graph. It maps out all discovered infrastructure entities and their intricate relationships.

> [!TIP]
> Think of this as the "brain's map" of the target environment. It allows Siyarix to understand that a specific vulnerability lives on a service, which in turn runs on a particular host.

### 🟢 Node Types

| Node | Attributes | Example |
|------|------------|---------|
| `HOST` | IP, hostname, OS, MAC | `10.0.0.1` |
| `PORT` | Number, protocol, state | `80/tcp open` |
| `SERVICE` | Name, version, banner | `Apache 2.4.41` |
| `VULNERABILITY` | CVE ID, severity, CVSS | `CVE-2024-1234` |
| `DOMAIN` | FQDN, registrar, DNS | `example.com` |
| `CREDENTIAL` | Username, type, hash | `admin:$2y$10$...` |
| `FINDING` | Tool, description, ref | Nmap finding |

### 🔗 Edge Types

| Edge | Source → Target | Meaning |
|------|----------------|---------|
| `RUNS_ON` | Service → Host | Service runs on host |
| `HAS_PORT` | Host → Port | Host has open port |
| `HAS_VULN` | Service → Vulnerability | Service has vulnerability |
| `RESOLVES_TO` | Domain → Host | Domain resolves to IP |
| `USES_CRED` | Service → Credential | Service uses credential |
| `RELATED_TO` | Finding → Finding | Related findings |

### 🛠️ Key Operations

- **Pathfinding**: BFS (Breadth-First Search) to find the shortest path between any two entities.
- **Advanced Querying**: Extract subgraphs by node type, attribute, or relationship.
- **Real-time Parsing**: Instantly inserts new nodes and edges directly from tool parser outputs.
- **Persistence**: Easily export/import state via JSON (`save_json` / `load_json`) so no context is lost between sessions.

---

## 🧠 2. MemoryManager

Located at `siyarix/memory.py`, the **MemoryManager** handles our semantic, long-term memory utilizing vector embeddings. 

> [!IMPORTANT]
> Semantic memory empowers Siyarix to recall past learnings contextually, rather than relying on exact keyword matches.

### 💡 Core Methods

```python
memory = MemoryManager()

# Store a new memory with rich metadata
await memory.store(
    content="Host 10.0.0.1 has Apache 2.4.41 running on port 80",
    metadata={"source": "nmap", "session_id": "sess-123"}
)

# Search for related concepts
similar = await memory.search_similar("Apache versions", top_k=5)

# Grab all relevant context for a specific target
context = await memory.get_context(target="10.0.0.1")
```

| Method | Purpose |
|--------|---------|
| `store(content, metadata)` | Saves a new memory entry into the semantic vault. |
| `search_similar(query, top_k)` | Uses embeddings to find the most conceptually similar memories. |
| `get_context(target)` | Retrieves a consolidated background context for a given target. |

---

## 🗜️ 3. Context Manager

Located at `siyarix/context.py`, the **Context Manager** is the gatekeeper for the LLM. It intelligently builds, compresses, and optimizes the context window so the LLM gets precisely what it needs without overflowing its token budget.

```python
context = ContextManager(memory=memory_manager)

# Log conversation history
context.add_history("User message", "user")
context.add_history("Assistant response", "assistant")

# Build the perfectly sized context payload
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

### 🗜️ Compression via CompactionEngine

When context gets too large, the `CompactionEngine` (`siyarix/compaction.py`) steps in to aggressively yet safely compress the payload.

> [!WARNING]
> Failing to compress context effectively can lead to LLM truncation errors and hallucinations. The CompactionEngine prevents this.

```python
compactor = CompactionEngine()
tokens = compactor.analyze_tokens(raw_context)
compressed = compactor.compress_context(raw_context, target_tokens=4096)
```

| Strategy | Description | Token Reduction |
|----------|-------------|-----------------|
| **Truncation** | Drops the oldest, least relevant conversation turns. | 20–40% |
| **Summarization** | Uses the LLM to summarize older history blocks. | 40–60% |
| **KG Pruning** | Retains only high-severity or immediately related graph entities. | 30–50% |
| **Memory Prioritization** | Filters out memories falling below a calculated importance threshold. | 50–70% |
| **Deduplication** | Strips out redundant tool outputs. | 10–20% |

---

## 💬 4. ChatSession

Located at `siyarix/chat/session.py`, the **ChatSession** manages conversation state. It's not just a flat list—it natively supports complex branching via a JSONL tree structure.

### 🌿 Branching Model

Ever wanted to explore a different train of thought without breaking your current conversation? Siyarix supports conversation forks!

```text
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

### ⚙️ Session Configuration

- Retains a rolling window of history (`maxlen=300`).
- Messages are robustly tracked using unique `id`, `parent`, `role`, `content`, `timestamp`, and `branch` identifiers.

### 📤 Export Formats

Exporting a session is as simple as calling `ChatSession.export()`.

| Format | Description |
|--------|-------------|
| `json` | Standard JSON array of messages. |
| `jsonl` | Advanced JSONL tree format (perfect for reloading). |
| `pdf` | A polished PDF document for reporting. |
| `txt` | A simple, raw plain-text transcript. |
| `md` | Markdown transcript for beautiful rendering. |
| `html` | An interactive HTML document. |

---

## 🎛️ 5. SessionKernel

Located at `siyarix/compat.py`, the **SessionKernel** is the master controller for overarching session state and operational tracking.

```python
kernel = SessionKernel()
session = kernel.start(
    objective="Scan target network",
    scope="10.0.0.0/24",
    identity="operator-1",
)

# Track tactical operations
op = kernel.add_operation(session, "scan 10.0.0.1", "scan", "medium")
kernel.update_operation(session, op.operation_id, state="completed")

# Persist and Restore
path = kernel.save(session)
restored = kernel.load(session_id)
```

> [!NOTE]
> Unlike other modules that use SQLite, the SessionKernel utilizes JSON-based persistence to easily track operation cards, state, mode, risk tier, and related artifacts.

- Supports distinct persistence tiers: `EPHEMERAL`, `WORKSPACE`, and `ORG_SHARED`.

---

## ⏱️ 6. CacheManager

Located at `siyarix/cache_manager.py`, the **CacheManager** speeds up operations by temporarily holding onto frequently accessed data.

```python
cache = CacheManager(
    max_size=1000,
    ttl=300,
    persist_path="~/.siyarix/cache.db"
)

# Easily monitor cache health
stats = cache.get_stats()
# Result: CacheStats(hits=450, misses=30, hit_rate=0.94, size=200, evictions=15)
```

- Implements LRU (Least Recently Used) paired with strict TTL (Time-To-Live).
- Optionally persists to disk to survive reboots.

---

## 🎓 7. Continuous Learning System (CLS)

Located at `siyarix/learning_system.py`, the **Continuous Learning System** is how Siyarix gets smarter over time. It organically acquires new skills by observing operator behavior.

> [!CAUTION]
> **Privacy First Guarantee**: Real targets are NEVER stored. Every hostname, IP, URL, email, or hash is strictly replaced with a `{target}` placeholder *before* any data is saved.

### 🏗️ Key Design Principles

- **Separate Store**: Learning data is completely isolated inside `learning_store.db`.
- **Zero Dependencies**: Relies purely on the Python standard library, employing a BM25-style Jaccard similarity engine over NLP token sets.
- **Bayesian Confidence**: Skills are rated using a Bayesian-smoothed confidence formula that factors in time decay and operational complexity.

### 📦 Data Models

```python
@dataclass
class LearnedStep:
    tool: str
    command_template: str     # E.g., "nmap -sS {target}"
    description: str
    args: dict

@dataclass
class LearnedSkill:
    skill_id: str
    intent_pattern: str       # The anonymised intent
    steps: list[LearnedStep]
    confidence: float         # 0.0 to 1.0 (Bayesian-smoothed)
    usage_count: int
    success_count: int
    tokens: list[str]         # NLP tokens for rapid similarity matching
    source: str               # Origin: 'llm', 'offline', or 'inferred'
```

### 🔄 The Learning Flow

1. **Observe**: Functions like `observe_llm_action()` passively watch the execution.
2. **Anonymize**: Scour and scrub the data, replacing real endpoints with `{target}`.
3. **Match**: Run multi-tier similarity checks (≥0.60 is strong, <0.35 implies a brand new skill).
4. **Learn**: Adjust confidence, extract parameters, and merge overlapping steps.
5. **Inject**: High-confidence skills get promoted and can be executed automatically.
6. **Maintain**: Constantly prune, decay old skills, and merge redundancies.

### 🔌 Integration

- **Integrated Mode**: Skills exceeding 80% confidence trigger automatic execution before the LLM is even consulted.
- **Offline Mode**: Learned skills dramatically enhance the heuristic planner.
- **Synonyms**: Maps human keywords to specific tools to beef up the NLP engine.

---

## ♻️ State Lifecycle

Ever wonder what happens from the moment Siyarix boots up until it safely shuts down? 

```text
🚀 Session Start
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
🔥 Session Active
    │
    ├── KnowledgeGraph populated from tool outputs (real-time)
    ├── MemoryManager updated from tool outputs
    ├── Conversation history appended (deque maxlen=300)
    ├── Continuous Learning System passively observes execution
    ├── Findings continuously stored in OfflineStore
    ├── Commands meticulously tracked via SessionKernel
    ├── Provider state tracked (cooldowns, failures, API costs)
    ├── Cache populated/evicted via LRU + TTL strategies
    │
    ▼
🛑 Session End
    │
    ├── Save KnowledgeGraph to JSON (if configured)
    ├── Persist MemoryManager embeddings safely to disk
    ├── Save comprehensive session via SessionKernel
    ├── Flush CacheManager memory to disk
    ├── Generate polished post-session reports
    ├── Safely close all SQLite connections
    ├── Trigger CLS maintenance (prune, decay, merge)
    └── Clear ephemeral in-memory state gracefully
```

---

## 🧩 Integration Points

Here’s a quick-reference cheat sheet for how everything connects:

| Component | Role |
|-----------|------|
| **Context Manager** | Curates and compresses the LLM context from the KG, memory, and history. |
| **MemoryManager** | Manages vector-based semantic memory. |
| **KnowledgeGraph** | Maps real-time entity relationships. |
| **ChatSession** | Houses branching conversation trees in JSONL. |
| **SessionKernel** | Masters JSON-based session persistence and restoration. |
| **CacheManager** | Disk-backed LRU + TTL caching. |
| **OfflineStore** | Persists offline scans and findings to SQLite. |
| **OfflineQueue** | Queues requests for disconnected execution. |
| **CompactionEngine** | Trims context payload to respect LLM token budgets. |
| **Continuous Learning System** | Siyarix's privacy-first evolving skill library. |
| **ProviderStateManager** | Tracks API provider health, cooldowns, and failures. |
| **ToolCallTracker** | Remembers tool failures to avoid repeated mistakes. |
| **EventBus** | Broadcasts state changes globally (e.g., `kg.updated`, `cache.evicted`). |
