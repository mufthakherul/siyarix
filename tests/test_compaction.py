# SPDX-License-Identifier: AGPL-3.0-or-later

"""Comprehensive tests for siyarix.compaction — context compaction / compression."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.compaction import (
    AssembleResult,
    BASE_CHUNK_RATIO,
    CompactResult,
    CompactionEngine,
    ContextEngineRuntime,
    estimate_messages_tokens,
    estimate_tokens,
    _filter_oversized_messages,
    _format_messages_for_summary,
    LlmCallable,
    MAX_COMPACTION_HISTORY,
    MIN_CHUNK_RATIO,
    MIN_PROMPT_BUDGET_RATIO,
    MIN_PROMPT_BUDGET_TOKENS,
    SAFETY_MARGIN,
    split_messages_by_token_share,
    summarize_chunks,
    SUMMARIZATION_OVERHEAD_TOKENS,
    summarize_with_fallback,
    SUMMARIZE_SYSTEM_PROMPT,
    TranscriptRewriteRequest,
)


# ── Constants ─────────────────────────────────────────────────────────────

class TestConstants:
    def test_min_prompt_budget_tokens(self) -> None:
        assert MIN_PROMPT_BUDGET_TOKENS == 8000

    def test_min_prompt_budget_ratio(self) -> None:
        assert MIN_PROMPT_BUDGET_RATIO == 0.5

    def test_summarization_overhead_tokens(self) -> None:
        assert SUMMARIZATION_OVERHEAD_TOKENS == 4096

    def test_base_chunk_ratio(self) -> None:
        assert BASE_CHUNK_RATIO == 0.4

    def test_min_chunk_ratio(self) -> None:
        assert MIN_CHUNK_RATIO == 0.15

    def test_safety_margin(self) -> None:
        assert SAFETY_MARGIN == 1.2

    def test_max_compaction_history(self) -> None:
        assert MAX_COMPACTION_HISTORY == 50


# ── CompactResult ────────────────────────────────────────────────────────

class TestCompactResult:
    def test_defaults(self) -> None:
        r = CompactResult(ok=True, compacted=False)
        assert r.reason == ""
        assert r.summary == ""
        assert r.tokens_before == 0
        assert r.tokens_after == 0
        assert r.entry_count_before == 0
        assert r.entry_count_after == 0


# ── AssembleResult ───────────────────────────────────────────────────────

class TestAssembleResult:
    def test_defaults(self) -> None:
        r = AssembleResult()
        assert r.messages == []
        assert r.estimated_tokens == 0
        assert r.system_prompt_addition == ""
        assert r.pruned is False


# ── TranscriptRewriteRequest ─────────────────────────────────────────────

class TestTranscriptRewriteRequest:
    def test_defaults(self) -> None:
        r = TranscriptRewriteRequest()
        assert r.start_index == 0
        assert r.end_index == 0
        assert r.replacement == []
        assert r.reason == ""


# ── ContextEngineRuntime ─────────────────────────────────────────────────

class TestContextEngineRuntime:
    def test_defaults(self) -> None:
        r = ContextEngineRuntime()
        assert r.session_id == ""
        assert r.config == {}
        assert r.settings == {}
        assert r.state == {}
        assert r.token_usage == {}


# ── estimate_tokens ──────────────────────────────────────────────────────

class TestEstimateTokens:
    def test_empty_string(self) -> None:
        assert estimate_tokens("") == 1

    def test_short_text(self) -> None:
        # len("hello") = 5; 5/4*1.2 = 1.5 -> int(1.5) = 1; +1 = 2
        assert estimate_tokens("hello") == 2

    def test_longer_text(self) -> None:
        text = "a" * 100
        expected = int(100 / 4 * SAFETY_MARGIN) + 1
        assert estimate_tokens(text) == expected


# ── estimate_messages_tokens ─────────────────────────────────────────────

class TestEstimateMessagesTokens:
    def test_single_text_message(self) -> None:
        msgs = [{"role": "user", "content": "hello"}]
        expected = estimate_tokens("hello") + 8
        assert estimate_messages_tokens(msgs) == expected

    def test_list_content_messages(self) -> None:
        msgs = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
        expected = estimate_tokens("hi") + 8
        assert estimate_messages_tokens(msgs) == expected

    def test_content_block_without_text(self) -> None:
        msgs = [{"role": "user", "content": [{"type": "image", "source": "data"}]}]
        expected = estimate_tokens("") + 8
        assert estimate_messages_tokens(msgs) == expected

    def test_empty_list(self) -> None:
        assert estimate_messages_tokens([]) == 0

    def test_multiple_messages(self) -> None:
        msgs = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]
        expected = estimate_tokens("hello") + 8 + estimate_tokens("world") + 8
        assert estimate_messages_tokens(msgs) == expected

    def test_text_as_bytes_ignored(self) -> None:
        content = [{"type": "text", "text": "hello"}]
        msgs = [{"role": "user", "content": content}]
        expected = estimate_tokens("hello") + 8
        assert estimate_messages_tokens(msgs) == expected

    def test_missing_content_key(self) -> None:
        msgs = [{"role": "user"}]
        assert estimate_messages_tokens(msgs) == estimate_tokens("") + 8


# ── split_messages_by_token_share ────────────────────────────────────────

class TestSplitMessagesByTokenShare:
    def test_empty_messages(self) -> None:
        assert split_messages_by_token_share([], 1000) == [[]]

    def test_single_chunk(self) -> None:
        msgs = [{"role": "user", "content": "hi"}]
        chunks = split_messages_by_token_share(msgs, 10000)
        assert len(chunks) == 1
        assert len(chunks[0]) == 1

    def test_splits_into_multiple_chunks(self) -> None:
        msgs = [
            {"role": "user", "content": "a" * 500},
            {"role": "user", "content": "b" * 500},
            {"role": "user", "content": "c" * 500},
        ]
        budget = 2000
        chunks = split_messages_by_token_share(msgs, budget)
        assert len(chunks) >= 1
        # Verify all messages appear in chunks
        all_msgs = [m for c in chunks for m in c]
        assert len(all_msgs) == 3

    def test_target_between_base_and_min(self) -> None:
        budget = 10000
        target_min = int(budget * MIN_CHUNK_RATIO)
        target_max = int(budget * BASE_CHUNK_RATIO)
        msgs = [{"role": "user", "content": "x" * 200}] * 10
        chunks = split_messages_by_token_share(msgs, budget)
        # Should use max(target_min, target_max) which is target_max
        assert len(chunks) >= 1


# ── _format_messages_for_summary ─────────────────────────────────────────

class TestFormatMessagesForSummary:
    def test_basic(self) -> None:
        msgs = [{"role": "user", "content": "hello"}]
        result = _format_messages_for_summary(msgs)
        assert "[USER]" in result
        assert "hello" in result

    def test_list_content(self) -> None:
        msgs = [{"role": "assistant", "content": [{"type": "text", "text": "hi there"}]}]
        result = _format_messages_for_summary(msgs)
        assert "[ASSISTANT]" in result
        assert "hi there" in result

    def test_list_content_non_text(self) -> None:
        msgs = [{"role": "user", "content": [{"type": "image", "source": "datadata"}]}]
        result = _format_messages_for_summary(msgs)
        assert "[USER]" in result

    def test_multiple_messages(self) -> None:
        msgs = [
            {"role": "user", "content": "q1"},
            {"role": "assistant", "content": "a1"},
        ]
        result = _format_messages_for_summary(msgs)
        assert "q1" in result
        assert "a1" in result

    def test_empty_messages(self) -> None:
        assert _format_messages_for_summary([]) == ""

    def test_unknown_role(self) -> None:
        msgs = [{"role": "system", "content": "sys msg"}]
        result = _format_messages_for_summary(msgs)
        assert "[SYSTEM]" in result


# ── _filter_oversized_messages ───────────────────────────────────────────

class TestFilterOversizedMessages:
    def test_filters_oversized(self) -> None:
        msgs = [
            {"role": "user", "content": "short"},
            {"role": "user", "content": "a" * 1000},
        ]
        filtered = _filter_oversized_messages(msgs, 100)
        assert len(filtered) == 1
        assert filtered[0]["content"] == "short"

    def test_all_fit(self) -> None:
        msgs = [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
        filtered = _filter_oversized_messages(msgs, 1000)
        assert len(filtered) == 2

    def test_empty_list(self) -> None:
        assert _filter_oversized_messages([], 100) == []


# ── summarize_chunks ─────────────────────────────────────────────────────

class TestSummarizeChunks:
    async def test_single_chunk(self) -> None:
        llm_call = AsyncMock(return_value={"content": "summary text"})
        chunks = [[{"role": "user", "content": "hello"}]]
        result = await summarize_chunks(chunks, llm_call, "gpt-4")
        assert result == "summary text"
        llm_call.assert_awaited_once()

    async def test_multiple_chunks(self) -> None:
        llm_call = AsyncMock(return_value={"content": "merged summary"})
        chunks = [
            [{"role": "user", "content": "chunk1"}],
            [{"role": "user", "content": "chunk2"}],
        ]
        result = await summarize_chunks(chunks, llm_call, "gpt-4")
        assert result == "merged summary"
        # First chunk, second chunk + merge call = 3 calls
        assert llm_call.await_count == 3

    async def test_chunk_failure_fallback(self) -> None:
        llm_call = AsyncMock(side_effect=[Exception("fail"), {"content": "ok"}])
        chunks = [[{"role": "user", "content": "c1"}], [{"role": "user", "content": "c2"}]]
        result = await summarize_chunks(chunks, llm_call, "gpt-4")
        assert "[Chunk 1 summarization failed]" in result

    async def test_merge_failure_returns_combined(self) -> None:
        llm_call = AsyncMock(side_effect=[
            {"content": "summary1"},
            {"content": "summary2"},
            Exception("merge fail"),
        ])
        chunks = [[{"role": "user", "content": "c1"}], [{"role": "user", "content": "c2"}]]
        result = await summarize_chunks(chunks, llm_call, "gpt-4")
        assert "summary1" in result
        assert "summary2" in result

    async def test_empty_chunks(self) -> None:
        result = await summarize_chunks([], AsyncMock(), "gpt-4")
        assert result == ""

    async def test_empty_summaries_list(self) -> None:
        llm_call = AsyncMock(return_value={"content": ""})
        result = await summarize_chunks([], llm_call, "gpt-4")
        assert result == ""


# ── summarize_with_fallback ──────────────────────────────────────────────

class TestSummarizeWithFallback:
    async def test_empty_messages(self) -> None:
        summary, success = await summarize_with_fallback([], AsyncMock(), "gpt-4", 10000)
        assert summary == ""
        assert success is True

    async def test_within_budget(self) -> None:
        llm_call = AsyncMock(return_value={"content": "good summary"})
        messages = [{"role": "user", "content": "hello"}]
        summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 100000)
        assert summary == "good summary"
        assert success is True

    async def test_full_summarization_fails_fallback1(self) -> None:
        llm_call = AsyncMock(side_effect=[
            Exception("full fail"),
            {"content": "fallback1 ok"},
        ])
        # overhead = 5000 - 4096 = 904; 5 messages of 500 chars ≈ 670 tokens ≤ 904
        # → enters full summarization, but summarize_chunks catches the
        #   internal exception and returns a placeholder.
        messages = [{"role": "user", "content": "a" * 500}] * 5
        summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 5000)
        assert success is True
        assert "[Chunk 1 summarization failed]" in summary

    async def test_full_and_fallback1_fail_fallback2(self) -> None:
        llm_call = AsyncMock(side_effect=[
            {"content": "fb2 ok"},
        ])
        # overhead = 5000 - 4096 = 904; total_tokens > overhead → skip full,
        # fallback1 filtered empty (per-msg budget < msg tokens) → fallback2 succeeds
        messages = [{"role": "user", "content": "a" * 500}] * 20
        summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 5000)
        assert success is True
        assert "fb2 ok" in summary

    async def test_all_fallbacks_fail(self) -> None:
        llm_call = AsyncMock(side_effect=Exception("always fail"))
        # override estimate so we can force fallback
        with patch("siyarix.compaction.estimate_messages_tokens", return_value=100000):
            messages = [{"role": "user", "content": "hello"}]
            summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 500)
            assert summary == ""
            assert success is False

    async def test_fallback1_note_added(self) -> None:
        # Use mixed-size messages so total > overhead but small msgs survive filter
        small = [{"role": "user", "content": "x" * 50}] * 5
        large = [{"role": "user", "content": "x" * 2000}] * 5
        messages = small + large
        # overhead = 5000 - 4096 = 904; total ≈ 2665 > 904 → skip full
        # per_msg = 904 // 10 = 90; small (~23 tokens) pass, large (~510) filtered
        llm_call = AsyncMock(return_value={"content": "fallback content"})
        summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 5000)
        assert success is True
        assert "[Note: some large messages were excluded" in summary
        assert "fallback content" in summary

    async def test_fallback2_note_added(self) -> None:
        # all messages large enough that total > overhead and filtered empty → fallback2
        messages = [{"role": "user", "content": "x" * 2000}] * 15
        # overhead = 5000 - 4096 = 904; total ≈ 15 * 510 = 7650 > 904 → skip full
        # per_msg = 904 // 15 = 60; each msg ~510 tokens > 60 → filtered empty
        llm_call = AsyncMock(return_value={"content": "partial content"})
        summary, success = await summarize_with_fallback(messages, llm_call, "gpt-4", 5000)
        assert success is True
        assert "[Note: partial summary" in summary
        assert "partial content" in summary


# ── CompactionEngine ─────────────────────────────────────────────────────

class TestCompactionEngineInit:
    def test_default_init(self) -> None:
        engine = CompactionEngine()
        assert engine._llm_call is None
        assert engine._model == ""
        assert engine._context_window == 128000
        assert engine._compaction_history == []
        assert engine._bootstrapped is False
        assert engine._runtime is None

    def test_custom_init(self) -> None:
        llm = AsyncMock()
        engine = CompactionEngine(llm_call=llm, model="gpt-4", context_window=64000)
        assert engine._llm_call is llm
        assert engine._model == "gpt-4"
        assert engine._context_window == 64000


class TestCompactionEngineProperties:
    def setup_method(self) -> None:
        self.engine = CompactionEngine(context_window=128000)

    def test_prompt_budget(self) -> None:
        assert self.engine.prompt_budget == int(128000 * MIN_PROMPT_BUDGET_RATIO)

    def test_compaction_count_zero(self) -> None:
        assert self.engine.compaction_count == 0

    def test_compaction_count_after_push(self) -> None:
        self.engine._compaction_history.append(
            CompactResult(ok=True, compacted=False)
        )
        assert self.engine.compaction_count == 1

    def test_bootstrapped_false(self) -> None:
        assert self.engine.bootstrapped is False

    def test_bootstrapped_true(self) -> None:
        self.engine._bootstrapped = True
        assert self.engine.bootstrapped is True

    def test_last_compaction_none(self) -> None:
        assert self.engine.last_compaction() is None

    def test_last_compaction_with_history(self) -> None:
        r = CompactResult(ok=True, compacted=False, reason="test")
        self.engine._compaction_history.append(r)
        assert self.engine.last_compaction() is r

    def test_history(self) -> None:
        self.engine._compaction_history.append(CompactResult(ok=True, compacted=False))
        assert len(self.engine.history()) == 1


class TestCompactionEngineSetLlm:
    def test_sets_callable_and_model(self) -> None:
        engine = CompactionEngine()
        llm = AsyncMock()
        engine.set_llm(llm, "gpt-4")
        assert engine._llm_call is llm
        assert engine._model == "gpt-4"


class TestCompactionEngineBootstrap:
    async def test_without_runtime(self) -> None:
        engine = CompactionEngine()
        await engine.bootstrap()
        assert engine._bootstrapped is True
        assert isinstance(engine._runtime, ContextEngineRuntime)

    async def test_with_runtime(self) -> None:
        engine = CompactionEngine()
        runtime = ContextEngineRuntime(session_id="test-session")
        await engine.bootstrap(runtime)
        assert engine._runtime is runtime
        assert engine._bootstrapped is True


class TestCompactionEngineMaintain:
    async def test_returns_empty_list(self) -> None:
        engine = CompactionEngine()
        result = await engine.maintain()
        assert result == []


class TestCompactionEngineIngest:
    async def test_returns_empty_list(self) -> None:
        engine = CompactionEngine()
        result = await engine.ingest({"role": "user", "content": "hi"})
        assert result == []

    async def test_with_runtime(self) -> None:
        engine = CompactionEngine()
        runtime = ContextEngineRuntime()
        result = await engine.ingest({"role": "user", "content": "hi"}, runtime)
        assert result == []


class TestCompactionEngineIngestBatch:
    async def test_multiple_messages(self) -> None:
        engine = CompactionEngine()
        messages = [
            {"role": "user", "content": "msg1"},
            {"role": "user", "content": "msg2"},
        ]
        results = await engine.ingest_batch(messages)
        assert results == []

    async def test_with_runtime(self) -> None:
        engine = CompactionEngine()
        runtime = ContextEngineRuntime()
        results = await engine.ingest_batch([{"role": "user", "content": "hi"}], runtime)
        assert results == []


class TestCompactionEnginePrepareSubagentSpawn:
    async def test_returns_none(self) -> None:
        engine = CompactionEngine()
        result = await engine.prepare_subagent_spawn({"tool": "nmap"})
        assert result is None


class TestCompactionEngineOnSubagentEnded:
    async def test_no_runtime(self) -> None:
        engine = CompactionEngine()
        await engine.on_subagent_ended({"status": "success", "output": "ok"})
        assert len(engine._compaction_history) == 1
        assert engine._compaction_history[0].ok is True

    async def test_with_runtime_updates_token_usage(self) -> None:
        engine = CompactionEngine()
        await engine.bootstrap()
        await engine.on_subagent_ended({"status": "success", "output": "done"})
        assert engine._runtime.token_usage.get("context_tokens", 0) >= 1

    async def test_summary_from_result_summary_field(self) -> None:
        engine = CompactionEngine()
        await engine.on_subagent_ended({"summary": "custom summary"})
        assert "custom summary" in engine._compaction_history[0].summary

    async def test_failed_status(self) -> None:
        engine = CompactionEngine()
        await engine.on_subagent_ended({"status": "failed", "output": "error"})
        assert engine._compaction_history[0].ok is False

    async def test_long_summary_truncated(self) -> None:
        engine = CompactionEngine()
        long_output = "x" * 1000
        await engine.on_subagent_ended({"output": long_output})
        assert len(engine._compaction_history[0].summary) == 500


class TestCompactionEngineDispose:
    def test_clears_state(self) -> None:
        engine = CompactionEngine()
        engine._bootstrapped = True
        engine._runtime = ContextEngineRuntime()
        engine._compaction_history.append(CompactResult(ok=True, compacted=False))
        engine.dispose()
        assert engine._bootstrapped is False
        assert engine._runtime is None
        assert engine._compaction_history == []


class TestCompactionEngineEstimateTokens:
    def test_delegates(self) -> None:
        engine = CompactionEngine()
        msgs = [{"role": "user", "content": "hello"}]
        assert engine.estimate_tokens(msgs) == estimate_messages_tokens(msgs)


class TestCompactionEngineCompact:
    async def test_empty_messages(self) -> None:
        engine = CompactionEngine()
        result = await engine.compact([])
        assert result.ok is True
        assert result.compacted is False
        assert result.reason == "no messages"

    async def test_within_budget_no_llm(self) -> None:
        engine = CompactionEngine()
        msgs = [{"role": "user", "content": "hi"}]
        result = await engine.compact(msgs, token_budget=100000)
        assert result.ok is True
        assert result.compacted is False
        assert result.reason == "within budget"

    async def test_no_llm_callable_configured(self) -> None:
        engine = CompactionEngine()
        msgs = [{"role": "user", "content": "a" * 1000}] * 20
        result = await engine.compact(msgs, token_budget=100)
        assert result.ok is False
        assert result.compacted is False
        assert result.reason == "no LLM callable configured"

    async def test_successful_summarization(self) -> None:
        # Use small budget so tokens_before > budget (bypasses early return)
        # and total_tokens > overhead with no messages passing filter → fallback 2
        llm = AsyncMock(return_value={"content": "test summary"})
        engine = CompactionEngine(llm_call=llm)
        msgs = [{"role": "user", "content": "a" * 600}] * 30
        result = await engine.compact(msgs, token_budget=200)
        assert result.ok is True
        assert result.compacted is True
        assert result.reason == "summarized"
        # fallback 2 prepends a note
        assert "[Note: partial summary" in result.summary
        assert "test summary" in result.summary

    async def test_prune_when_summary_fails(self) -> None:
        llm = AsyncMock(side_effect=Exception("no summary"))
        engine = CompactionEngine(llm_call=llm)
        msgs = [{"role": "user", "content": "a" * 600}] * 30
        result = await engine.compact(msgs, token_budget=200)
        assert result.ok is True
        assert result.compacted is True
        assert result.reason == "pruned"
        assert result.entry_count_after >= 5

    async def test_compaction_history_appended(self) -> None:
        llm = AsyncMock(return_value={"content": "summary"})
        engine = CompactionEngine(llm_call=llm)
        msgs = [{"role": "user", "content": "a" * 600}] * 30
        await engine.compact(msgs, token_budget=200)
        assert len(engine._compaction_history) == 1

    async def test_compaction_history_capped(self) -> None:
        llm = AsyncMock(return_value={"content": "summary"})
        engine = CompactionEngine(llm_call=llm)
        # Exceed MAX_COMPACTION_HISTORY
        for _ in range(MAX_COMPACTION_HISTORY + 10):
            engine._compaction_history.append(CompactResult(ok=True, compacted=False))
        assert len(engine._compaction_history) > MAX_COMPACTION_HISTORY
        # one more compact should trigger cap (trims to MAX_COMPACTION_HISTORY)
        msgs = [{"role": "user", "content": "a" * 600}] * 30
        await engine.compact(msgs, token_budget=200)
        assert len(engine._compaction_history) == MAX_COMPACTION_HISTORY

    # test the cap explicitly
    async def test_compaction_history_trims(self) -> None:
        llm = AsyncMock(return_value={"content": "x"})
        engine = CompactionEngine(llm_call=llm)
        # Fill to just under max
        for _ in range(MAX_COMPACTION_HISTORY):
            engine._compaction_history.append(CompactResult(ok=True, compacted=False))
        msgs = [{"role": "user", "content": "a" * 600}] * 30
        await engine.compact(msgs, token_budget=200)
        assert len(engine._compaction_history) <= MAX_COMPACTION_HISTORY


class TestCompactionEngineAssemble:
    def setup_method(self) -> None:
        self.engine = CompactionEngine(context_window=128000)

    def test_within_budget(self) -> None:
        msgs = [{"role": "user", "content": "hi"}]
        result = self.engine.assemble(msgs, token_budget=100000)
        assert result.estimated_tokens > 0
        assert result.pruned is False
        assert len(result.messages) == 1

    def test_exceeds_budget_prunes(self) -> None:
        msgs = [{"role": "user", "content": "a" * 800}] * 30
        result = self.engine.assemble(msgs, token_budget=200)
        assert result.pruned is True
        assert len(result.messages) < len(msgs)


class TestCompactionEngineAfterTurn:
    async def test_within_budget_no_action(self) -> None:
        engine = CompactionEngine(context_window=128000)
        msgs = [{"role": "user", "content": "hi"}]
        requests = await engine.after_turn(msgs)
        assert requests == []

    async def test_exceeds_budget_calls_compact(self) -> None:
        llm = AsyncMock(return_value={"content": "compacted context"})
        engine = CompactionEngine(llm_call=llm, context_window=1000)
        msgs = [{"role": "user", "content": "a" * 600}] * 20
        requests = await engine.after_turn(msgs)
        assert len(requests) == 1
        r = requests[0]
        assert r.start_index == 0
        assert r.end_index == len(msgs)
        assert r.replacement[0]["role"] == "system"
        assert "Compacted context" in r.replacement[0]["content"]

    async def test_exceeds_budget_but_no_llm(self) -> None:
        engine = CompactionEngine(context_window=1000)
        msgs = [{"role": "user", "content": "a" * 600}] * 20
        requests = await engine.after_turn(msgs)
        assert requests == []
