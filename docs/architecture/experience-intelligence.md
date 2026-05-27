# Experience Intelligence (XI)

The Experience Intelligence subsystem (`xi/`) provides adaptive learning, context tracking, skill profiling, and predictive recommendations.

## Components

```
xi/
├── context_tracker.py   # Real-time session context tracking
├── skill_profiler.py    # User expertise detection and profiling
├── predictor.py         # Next-action prediction engine
└── service.py           # Recommendation engine
```

## Context tracker

The `ContextTracker` maintains real-time session awareness across 8 operation phases:

| Phase | Description |
|-------|-------------|
| `IDLE` | No active operation |
| `RECON` | Reconnaissance in progress |
| `SCANNING` | Network/service scanning |
| `ENUMERATION` | Service enumeration |
| `EXPLOITATION` | Active exploitation |
| `POST_EXPLOIT` | Post-exploitation activities |
| `REPORTING` | Report generation |
| `CLEANUP` | Session cleanup |

Tracks:

- Current and historical operation phases
- Target inventory (all hosts discovered in session)
- Tool execution history (tools used, frequency)
- Findings accumulation (counts by severity)

### Usage

```python
tracker = ContextTracker()
tracker.update_phase("SCANNING")
tracker.add_finding(port=80, service="http")
current_context = tracker.get_context_summary()
```

## Skill profiler

The `SkillProfiler` evaluates user expertise level based on 5 behavioral factors:

| Factor | What it measures |
|--------|-----------------|
| Tool diversity | Range of different tools used |
| Advanced features | Use of complex flags, custom configurations |
| Command volume | Number of commands executed per session |
| Error rate | Frequency of failed or invalid commands |
| Speed | Time between commands (faster = more experienced) |

### Experience levels

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| `BEGINNER` | New user | Few tools, basic commands, higher error rate |
| `INTERMEDIATE` | Regular user | Multiple tools, some advanced commands |
| `ADVANCED` | Experienced operator | Wide tool range, custom workflows |
| `EXPERT` | Power user | All tools, complex pipelines, minimal errors |

### Usage

```python
profiler = SkillProfiler()
profile = profiler.evaluate_session(session_record)
# Returns: SkillProfile(level="ADVANCED", confidence=0.85)
```

## Predictor

The `Predictor` suggests the next action based on:

1. **Phase-based prediction**: After scanning, suggest enumeration
2. **Tool follow-up**: After running nmap, suggest parsing results
3. **Findings-based**: If vulnerabilities found, suggest exploitation
4. **Learned patterns**: Matches current session against past patterns

### Usage

```python
predictor = Predictor()
prediction = predictor.predict_next(context_tracker)
# Returns: Prediction(action="run vuln scan", confidence=0.78)
```

## Recommendation engine

The `XICoreService` combines all XI components into actionable recommendations:

```python
service = XICoreService()
recs = service.recommend(session_context)
# Returns: [XICoreRecommendation(action="...", reason="...", priority=...)]
```

### Recommendation types

| Type | When triggered |
|------|----------------|
| Risk awareness | Target scope is expanding rapidly |
| Tool suggestion | Relevant tool available but unused |
| Phase advancement | Current phase complete, suggest next |
| Learning tip | User making repeated errors |
| Efficiency gain | Workflow could be automated |

## Use cases

- **Adaptive UI**: Adjust interface complexity based on user skill
- **Smart defaults**: Pre-fill commands based on common patterns
- **Proactive assistance**: Suggest next steps without being asked
- **Skill development**: Identify areas where the user could improve
- **Session handoff**: Provide context summary when resuming a session
