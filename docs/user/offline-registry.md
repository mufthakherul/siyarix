# Offline Response Registry

When no AI provider is connected, Siyarix uses its **Offline Response Registry** to provide natural, context-aware replies. The registry is a collection of response templates stored in JSON files that can be extended, edited, or replaced without modifying core code.

## How it works

1. User types a message in the REPL
2. The engine finds no matching tools — falls back to `_generate_text_response`
3. `OfflineResponder` matches the input against registry entries (exact → regex → fuzzy)
4. The best-matching template is resolved with dynamic variables and returned

## Response pack format

Each pack is a JSON file with a `responses` array. Each entry supports:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | `str` | required | Unique identifier |
| `priority` | `int` | `50` | Higher = preferred on tie |
| `triggers` | `[str]` | `[]` | Exact-match trigger phrases |
| `patterns` | `[str]` | `[]` | Regex patterns (matched case-insensitive) |
| `template` | `str` | `""` | Response text with `{variable}` placeholders |
| `match_threshold` | `float` | `0.75` | Minimum fuzzy similarity (0.0–1.0) |
| `locale` | `str` | `"en"` | Language tag for future localization |

Example entry:

```json
{
  "id": "greeting",
  "priority": 100,
  "triggers": ["hello", "hi", "hey"],
  "patterns": [],
  "template": "Hello {username}. Good {time_of_day}.",
  "match_threshold": 0.7
}
```

## Dynamic variables

These placeholders are resolved at response time:

| Variable | Resolves to |
|----------|-------------|
| `{username}` | Current OS username |
| `{hostname}` | Device hostname |
| `{platform}` | `Linux`, `Windows`, or `macOS` |
| `{time_of_day}` | `morning` / `afternoon` / `evening` / `night` |
| `{current_time}` | Current time (`HH:MM`) |
| `{current_date}` | Current date (`YYYY-MM-DD`) |
| `{version}` | Installed Siyarix version |
| `{repo_url}` | GitHub repository URL |
| `{docs_url}` | Documentation URL |
| `{contribute_url}` | Contributing guide URL |

## Matching order

For each query, entries are evaluated in priority order:

1. **Exact match** against any trigger (case-insensitive) → score `1.0`
2. **Regex match** against any pattern → score `1.0`
3. **Fuzzy match** using `difflib.SequenceMatcher` — requires score ≥ `match_threshold`

The highest-scoring entry wins. On equal score, higher `priority` wins.

## Adding responses

### Default pack

Edit `src/siyarix/offline_registry/responses.json`.

### Community packs

Place additional `.json` files in `src/siyarix/offline_registry/responses/`. They are loaded automatically on startup.

Example community pack (`responses/community.json`):

```json
{
  "version": "1.0",
  "locale": "en",
  "responses": [
    {
      "id": "my_custom",
      "priority": 50,
      "triggers": ["my trigger phrase"],
      "template": "My custom response for {username}."
    }
  ]
}
```

### Hot-reloading

The registry checks file modification times before each response. Edit a pack file while the REPL is running, and changes take effect immediately — no restart needed.

## Programmatic usage

```python
from siyarix.offline_registry import OfflineResponder

responder = OfflineResponder()
reply = responder.respond("hello")
print(reply)
```

To use a custom pack directory:

```python
responder = OfflineResponder(pack_dir="/path/to/my/packs")
```

## Best practices

- Keep response IDs unique across all packs
- Use `priority` 0–100; reserve 80+ for core system responses
- Add multiple trigger variations to catch typos ("helo", "helloo")
- Use regex `patterns` only when `triggers` are insufficient
- Set appropriate `match_threshold` — too low causes false positives
