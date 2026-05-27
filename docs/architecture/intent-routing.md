# Intent Routing

The `IntentRouter` is a 4-stage semantic routing pipeline that classifies user input, determines risk level, and selects the appropriate execution mode.

## Routing stages

```
User Input
    │
    ├── Stage 1: Exact pattern match (~0ms)
    │   └── Prefix regex matching against 7 command patterns
    │
    ├── Stage 2: Heuristic interpretation (~1ms)
    │   └── RuleInterpreter with 60+ intent categories
    │
    ├── Stage 3: Keyword similarity (~5ms)
    │   └── Semantic keyword matching with scoring
    │
    └── Stage 4: LLM fallback (~500ms)
        └── AI provider classifies if all else fails
```

### Stage 1: Exact pattern match

Predefined regex patterns for common command structures:

| Pattern | Category | Intent |
|---------|----------|--------|
| `^scan\s+(.+)$` | SCAN | scan_target |
| `^recon\s+(.+)$` | RECON | reconnaissance |
| `^exploit\s+(.+)$` | EXPLOIT | exploit_target |
| `^analyze\s+(.+)$` | ANALYZE | analyze_findings |
| `^report\s*(.*)$` | REPORT | generate_report |
| `^dashboard\s*(.*)$` | MONITOR | dashboard_view |
| `^wizard\s*(.*)$` | CONFIG | onboarding_wizard |

### Stage 2: Heuristic interpretation

The `RuleInterpreter` applies 60+ intent patterns across 6 shell types to match natural language input against known command categories.

### Stage 3: Keyword similarity

Fallback matching using keyword extraction and scoring against known intents.

### Stage 4: LLM fallback

The configured AI provider classifies the instruction semantically. Used only when the first three stages fail to produce a confident match.

## Risk tiers

| Tier | Category examples | Requires confirmation |
|------|-------------------|----------------------|
| `LOW` | CONFIG, REPORT, MONITOR | No |
| `MEDIUM` | SCAN, RECON | Yes |
| `HIGH` | EXPLOIT | Yes |

## IntentRoute output

```python
@dataclass
class IntentRoute:
    instruction: str            # Original input
    mode: str                   # Selected execution mode
    category: str               # TaskCategory value
    confidence: float           # 0.0 to 1.0
    risk_tier: RiskTier         # LOW, MEDIUM, HIGH
    requires_confirmation: bool # Whether user must confirm
    routing_stage: int          # 1, 2, 3, or 4
    metadata: dict              # Extracted targets, tools, flags
```

## Integration with modes

The intent router connects to the mode dispatcher:

```python
route = intent_router.route(instruction)
if route.routing_stage == 1:
    # Fast path — execute directly
elif route.routing_stage >= 3:
    # Slower path — might need user confirmation
```

## Risk-based UX

- **LOW risk** commands (config, reporting) execute without confirmation
- **MEDIUM risk** commands (scan, recon) execute with a confirmation prompt
- **HIGH risk** commands (exploit, dangerous operations) require explicit approval
