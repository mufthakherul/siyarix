"""Context compaction system — manages token budgets, summarization, and pruning.

OpenClaw pattern: src/context-engine/, src/agents/compaction*.ts
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_PROMPT_BUDGET_TOKENS = 8000
MIN_PROMPT_BUDGET_RATIO = 0.5
SUMMARIZATION_OVERHEAD_TOKENS = 4096
BASE_CHUNK_RATIO = 0.4
MIN_CHUNK_RATIO = 0.15
SAFETY_MARGIN = 1.2
MAX_COMPACTION_HISTORY = 50

LlmCallable = Callable[..., Coroutine[Any, Any, dict[str, Any]]]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class CompactResult:
    ok: bool
    compacted: bool
    reason: str = ""
    summary: str = ""
    tokens_before: int = 0
    tokens_after: int = 0
    entry_count_before: int = 0
    entry_count_after: int = 0


@dataclass
class AssembleResult:
    messages: list[dict[str, Any]] = field(default_factory=list)
    estimated_tokens: int = 0
    system_prompt_addition: str = ""
    pruned: bool = False


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

def estimate_tokens(text: str) -> int:
    """Rough token estimation (4 chars per token)."""
    return int(len(text) / 4 * SAFETY_MARGIN) + 1


def estimate_messages_tokens(messages: list[dict[str, Any]]) -> int:
    """Estimate total tokens for a list of messages."""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total += estimate_tokens(block.get("text", ""))
        total += 8  # overhead per message
    return total


def split_messages_by_token_share(
    messages: list[dict[str, Any]], budget: int
) -> list[list[dict[str, Any]]]:
    """Split messages into chunks targeting budget tokens each."""
    chunks: list[list[dict[str, Any]]] = [[]]
    chunk_tokens = 0
    target = max(int(budget * BASE_CHUNK_RATIO), int(budget * MIN_CHUNK_RATIO))

    for msg in messages:
        msg_tokens = estimate_messages_tokens([msg])
        if chunk_tokens + msg_tokens > target and chunks[-1]:
            chunks.append([])
            chunk_tokens = 0
        chunks[-1].append(msg)
        chunk_tokens += msg_tokens

    return chunks


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------

SUMMARIZE_SYSTEM_PROMPT = """You are a precise summarization engine. Condense the following conversation while preserving:

1. All identified vulnerabilities, findings, and their severity levels
2. Key IP addresses, hostnames, ports, and service versions discovered
3. Commands run and their critical outputs
4. The current status of the investigation
5. Any actionable items or next steps

Output a concise, structured summary (200-400 tokens)."""


async def summarize_chunks(
    chunks: list[list[dict[str, Any]]],
    llm_call: LlmCallable,
    model: str,
    system_prompt: str = SUMMARIZE_SYSTEM_PROMPT,
) -> str:
    """Summarize chunks iteratively using an LLM.

    OpenClaw: src/agents/compaction.ts summarizeChunks()
    """
    summaries: list[str] = []

    for i, chunk in enumerate(chunks):
        chunk_text = _format_messages_for_summary(chunk)
        user_prompt = f"Summarize chunk {i + 1}/{len(chunks)}:\n\n{chunk_text}"
        try:
            result = await llm_call(system_prompt, user_prompt)
            summaries.append(result.get("content", ""))
        except Exception as exc:
            logger.warning("Compaction summarization chunk %d failed: %s", i, exc)
            summaries.append(f"[Chunk {i + 1} summarization failed]")

    if len(summaries) <= 1:
        return summaries[0] if summaries else ""

    # Merge summaries
    combined = "\n\n".join(summaries)
    try:
        result = await llm_call(
            system_prompt,
            f"Merge these chunk summaries into one coherent summary:\n\n{combined}",
        )
        return result.get("content", combined)
    except Exception as exc:
        logger.warning("Compaction merge failed: %s", exc)
        return combined


async def summarize_with_fallback(
    messages: list[dict[str, Any]],
    llm_call: LlmCallable,
    model: str,
    budget: int,
    system_prompt: str = SUMMARIZE_SYSTEM_PROMPT,
) -> tuple[str, bool]:
    """Summarize messages with progressive fallback.

    OpenClaw: src/agents/compaction.ts summarizeWithFallback()

    Returns (summary, success).
    """
    if not messages:
        return "", True

    total_tokens = estimate_messages_tokens(messages)
    overhead = budget - SUMMARIZATION_OVERHEAD_TOKENS

    if total_tokens <= overhead:
        chunks = split_messages_by_token_share(messages, overhead)
        try:
            summary = await summarize_chunks(chunks, llm_call, model, system_prompt)
            return summary, True
        except Exception as exc:
            logger.warning("Compaction full summarization failed: %s", exc)

    # Fallback 1: exclude oversized messages
    filtered = _filter_oversized_messages(messages, overhead // max(len(messages), 1))
    if filtered:
        chunks = split_messages_by_token_share(filtered, overhead)
        try:
            summary = await summarize_chunks(chunks, llm_call, model, system_prompt)
            note = "[Note: some large messages were excluded from summarization]"
            return f"{note}\n\n{summary}", True
        except Exception:
            logger.warning("Compaction fallback 1 summarization failed")

    # Fallback 2: partial summary
    try:
        sample = messages[:10]
        sample_text = _format_messages_for_summary(sample)
        result = await llm_call(
            system_prompt,
            f"Summarize this partial conversation excerpt:\n\n{sample_text}",
        )
        note = "[Note: partial summary — not all messages were included]"
        result_text = result.get("content", sample_text)
        return f"{note}\n\n{result_text}", True
    except Exception:
        logger.warning("Compaction fallback 2 summarization failed")

    return "", False


# ---------------------------------------------------------------------------
# Compaction engine
# ---------------------------------------------------------------------------

# ── Transcript rewrite request ──────────────────────────────────────────


@dataclass
class TranscriptRewriteRequest:
    """Request to rewrite a portion of the transcript."""
    start_index: int = 0
    end_index: int = 0
    replacement: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""


# ── Context engine runtime ─────────────────────────────────────────────


@dataclass
class ContextEngineRuntime:
    """Runtime context passed to lifecycle hooks."""
    session_id: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    token_usage: dict[str, int] = field(default_factory=dict)


# ── Compaction engine ──────────────────────────────────────────────────


class CompactionEngine:
    """Manages context window budgeting, pruning, and summarization.

    OpenClaw pattern: ContextEngine interface (src/context-engine/types.ts)

    Full lifecycle hooks (all optional):
      bootstrap()   — called when context is first initialised
      maintain()    — periodic maintenance
      ingest()      — called for each new message
      afterTurn()   — called after each assistant turn
      compact()     — context compaction (summarisation)
      assemble()    — assemble context for LLM
      dispose()     — cleanup
    """

    def __init__(
        self,
        llm_call: LlmCallable | None = None,
        model: str = "",
        context_window: int = 128000,
    ) -> None:
        self._llm_call = llm_call
        self._model = model
        self._context_window = context_window
        self._compaction_history: list[CompactResult] = []
        self._bootstrapped = False
        self._runtime: ContextEngineRuntime | None = None

    @property
    def prompt_budget(self) -> int:
        """Maximum tokens available for the prompt."""
        return int(self._context_window * MIN_PROMPT_BUDGET_RATIO)

    @property
    def compaction_count(self) -> int:
        return len(self._compaction_history)

    @property
    def bootstrapped(self) -> bool:
        return self._bootstrapped

    def set_llm(self, llm_call: LlmCallable, model: str) -> None:
        self._llm_call = llm_call
        self._model = model

    # ── lifecycle hooks ──────────────────────────────────────────────

    async def bootstrap(self, runtime: ContextEngineRuntime | None = None) -> None:
        """Initialise the context engine."""
        self._runtime = runtime or ContextEngineRuntime()
        self._bootstrapped = True

    async def maintain(self) -> list[TranscriptRewriteRequest]:
        """Periodic maintenance. Returns rewrite requests if any."""
        return []

    async def ingest(
        self, message: dict[str, Any], runtime: ContextEngineRuntime | None = None
    ) -> list[TranscriptRewriteRequest]:
        """Process a new incoming message."""
        return []

    async def after_turn(
        self, transcript: list[dict[str, Any]]
    ) -> list[TranscriptRewriteRequest]:
        """Called after each assistant turn. Opportunity to rewrite transcript."""
        _budget = self.prompt_budget
        total = estimate_messages_tokens(transcript)
        if total > _budget:
            result = await self.compact(transcript, _budget)
            if result.ok and result.compacted:
                return [
                    TranscriptRewriteRequest(
                        start_index=0,
                        end_index=len(transcript),
                        replacement=[{
                            "role": "system",
                            "content": f"[Compacted context]\n\n{result.summary}",
                        }],
                        reason=result.reason,
                    )
                ]
        return []

    async def ingest_batch(
        self, messages: list[dict[str, Any]], runtime: ContextEngineRuntime | None = None
    ) -> list[TranscriptRewriteRequest]:
        """Process a batch of new messages."""
        requests: list[TranscriptRewriteRequest] = []
        for msg in messages:
            requests.extend(await self.ingest(msg, runtime))
        return requests

    async def prepare_subagent_spawn(
        self, config: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Prepare context for a subagent spawn. Returns context info or None."""
        return None

    async def on_subagent_ended(
        self, result: dict[str, Any]
    ) -> None:
        """Called when a subagent finishes. Records the subagent result in compaction history."""
        summary = result.get("summary", result.get("output", str(result)[:200]))
        if self._runtime:
            self._runtime.token_usage["context_tokens"] = self._runtime.token_usage.get("context_tokens", 0) + 1
        self._compaction_history.append(
            CompactResult(
                ok=result.get("status") == "success" if "status" in result else True,
                compacted=False,
                reason="subagent_ended",
                summary=summary[:500],
            )
        )

    def dispose(self) -> None:
        """Clean up resources."""
        self._compaction_history.clear()
        self._bootstrapped = False
        self._runtime = None

    def estimate_tokens(self, messages: list[dict[str, Any]]) -> int:
        """Estimate tokens for a message list."""
        return estimate_messages_tokens(messages)

    async def compact(
        self,
        messages: list[dict[str, Any]],
        token_budget: int | None = None,
    ) -> CompactResult:
        """Compact a list of messages to fit within a token budget.

        Returns a CompactResult with the summary and metadata.
        """
        if not messages:
            return CompactResult(ok=True, compacted=False, reason="no messages")

        budget = token_budget or self.prompt_budget
        tokens_before = estimate_messages_tokens(messages)

        if tokens_before <= budget:
            return CompactResult(
                ok=True,
                compacted=False,
                reason="within budget",
                tokens_before=tokens_before,
                tokens_after=tokens_before,
                entry_count_before=len(messages),
                entry_count_after=len(messages),
            )

        if not self._llm_call:
            return CompactResult(
                ok=False,
                compacted=False,
                reason="no LLM callable configured",
                tokens_before=tokens_before,
                entry_count_before=len(messages),
            )

        summary, success = await summarize_with_fallback(
            messages, self._llm_call, self._model, budget
        )

        if success and summary:
            summary_tokens = estimate_tokens(summary)
            result = CompactResult(
                ok=True,
                compacted=True,
                reason="summarized",
                summary=summary,
                tokens_before=tokens_before,
                tokens_after=summary_tokens,
                entry_count_before=len(messages),
                entry_count_after=1,
            )
        else:
            # Prune oldest messages (keep last 50%)
            keep_count = max(len(messages) // 2, 5)
            kept = messages[-keep_count:]
            kept_tokens = estimate_messages_tokens(kept)
            result = CompactResult(
                ok=True,
                compacted=True,
                reason="pruned",
                tokens_before=tokens_before,
                tokens_after=kept_tokens,
                entry_count_before=len(messages),
                entry_count_after=len(kept),
            )

        self._compaction_history.append(result)
        if len(self._compaction_history) > MAX_COMPACTION_HISTORY:
            self._compaction_history = self._compaction_history[-MAX_COMPACTION_HISTORY:]

        return result

    def assemble(
        self,
        messages: list[dict[str, Any]],
        token_budget: int | None = None,
    ) -> AssembleResult:
        """Assemble messages within a token budget (prune if needed)."""
        budget = token_budget or self.prompt_budget
        total = estimate_messages_tokens(messages)

        if total <= budget:
            return AssembleResult(
                messages=messages,
                estimated_tokens=total,
            )

        # Sliding window: keep last N messages that fit budget
        pruned: list[dict[str, Any]] = []
        running = 0
        for msg in reversed(messages):
            msg_tokens = estimate_messages_tokens([msg])
            if running + msg_tokens > budget:
                break
            pruned.insert(0, msg)
            running += msg_tokens

        return AssembleResult(
            messages=pruned,
            estimated_tokens=running,
            pruned=True,
        )

    def last_compaction(self) -> CompactResult | None:
        """Return the most recent compaction result."""
        return self._compaction_history[-1] if self._compaction_history else None

    def history(self) -> list[CompactResult]:
        """Return full compaction history."""
        return list(self._compaction_history)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_messages_for_summary(messages: list[dict[str, Any]]) -> str:
    """Format messages as a plain-text conversation for summarization."""
    parts = []
    for msg in messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if isinstance(content, list):
            texts = [
                b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
            ]
            content = "\n".join(texts)
        parts.append(f"[{role.upper()}]\n{content}")
    return "\n\n".join(parts)


def _filter_oversized_messages(
    messages: list[dict[str, Any]], max_tokens_per_msg: int
) -> list[dict[str, Any]]:
    """Remove messages that exceed the per-message token budget."""
    return [
        m for m in messages if estimate_messages_tokens([m]) <= max_tokens_per_msg
    ]

__all__ = [
    "MIN_PROMPT_BUDGET_TOKENS",
    "MIN_PROMPT_BUDGET_RATIO",
    "SUMMARIZATION_OVERHEAD_TOKENS",
    "BASE_CHUNK_RATIO",
    "MIN_CHUNK_RATIO",
    "SAFETY_MARGIN",
    "MAX_COMPACTION_HISTORY",
    "CompactResult",
    "AssembleResult",
    "estimate_tokens",
    "estimate_messages_tokens",
    "split_messages_by_token_share",
    "SUMMARIZE_SYSTEM_PROMPT",
    "TranscriptRewriteRequest",
    "ContextEngineRuntime",
    "CompactionEngine",
]
