# Responsible AI Usage Policy

Siyarix integrates AI providers for planning, reasoning, and assistance. This policy governs the responsible use of AI features.

## AI system overview

Siyarix uses AI providers for:

1. **Task planning**: Converting natural language to structured execution plans
2. **Interactive chat**: Multi-turn conversation about security operations
3. **Code review**: Security vulnerability analysis in code
4. **Report generation**: Summarizing findings and suggesting remediation
5. **Tool selection**: Recommending appropriate tools for objectives

## Human oversight

AI-generated plans and commands are subject to:

- **Permission gate**: Every command is validated before execution
- **User confirmation**: Flagged commands require explicit approval
- **Full audit trail**: All actions are logged regardless of how they were initiated

The AI assists but does not replace human judgment.

## Limitations

AI providers may:

- Generate incorrect or incomplete plans
- Suggest tools that are not available on the system
- Misinterpret user intent, especially with ambiguous input
- Hallucinate tool names, arguments, or capabilities

Users should verify AI suggestions before executing them.

## Provider transparency

The system documents which AI provider was used for each operation:

```bash
siyarix audit-log
# Shows: provider used, model, latency, confidence
```

Users can see exactly which provider handled each request.

## Data protection

When using cloud AI providers:

1. **Masking**: IPs, hostnames, credentials, and other sensitive data are redacted or masked before sending
2. **Session scope**: Data is masked within the session context
3. **No persistence**: Provider requests are not stored by Siyarix (response caching is optional and local)
4. **User choice**: Local providers (Ollama, LM Studio) keep all data on the user's machine

## Choice of provider

Users can:

- Choose which AI provider to use (configurable in settings)
- Set a preference order for automatic failover
- Disable AI entirely and use heuristic fallback
- Use local-only providers for air-gapped environments

## Provider-agnostic design

Siyarix is designed to:

- Work with any provider through the standard `Provider` interface
- Function fully offline with heuristic fallback
- Never depend on a single provider
- Degrade gracefully when providers are unavailable

## Reporting AI issues

If the AI behaves unexpectedly or produces harmful output:

- Report via GitHub issues: https://github.com/mufthakherul/siyarix/issues
- Include: input, expected behavior, actual output, provider used
- Do not include sensitive data in bug reports

## Ethical AI use

Users must:

- Not use AI features for social engineering
- Not use AI to generate malware or attack tools
- Not use AI beyond authorized testing scope
- Comply with each provider's usage policies
- Review and verify AI-generated plans before execution
