from __future__ import annotations
from siyarix.context import ContextChunk
from siyarix.context import ContextManager
from siyarix.context import ContextWindow
from siyarix.context import compress_context
from unittest.mock import MagicMock

# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.context — context compression."""


class TestCompressContext:
    def test_empty_context(self) -> None:
        result = compress_context({})
        assert result == {}

    def test_passthrough_small_context(self) -> None:
        ctx = {
            "available_tools": ["tool1", "tool2"],
            "conversation_history": "short",
            "xi_context": {"recent_executions": ["a", "b"]},
            "xi_recommendations": ["r1"],
        }
        result = compress_context(ctx, max_tokens=8000)
        assert result == ctx

    def test_truncates_tools_over_20(self) -> None:
        tools = [f"tool{i}" for i in range(30)]
        ctx = {"available_tools": tools}
        result = compress_context(ctx)
        assert len(result["available_tools"]) == 20
        assert result["_tools_truncated"] == 10

    def test_does_not_truncate_tools_under_20(self) -> None:
        tools = [f"tool{i}" for i in range(15)]
        ctx = {"available_tools": tools}
        result = compress_context(ctx)
        assert len(result["available_tools"]) == 15
        assert "_tools_truncated" not in result

    def test_tools_not_a_list(self) -> None:
        ctx = {"available_tools": "not_a_list"}
        result = compress_context(ctx)
        assert result["available_tools"] == "not_a_list"
        assert "_tools_truncated" not in result

    def test_truncates_history_when_over_max_tokens(self) -> None:
        lines = [f"line{i}" for i in range(100)]
        ctx = {"conversation_history": "\n".join(lines)}
        result = compress_context(ctx, max_tokens=50)
        assert result["_history_truncated"] == 60
        assert result["conversation_history"].count("\n") == 39

    def test_does_not_truncate_history_when_under_limit(self) -> None:
        ctx = {"conversation_history": "short text"}
        result = compress_context(ctx)
        assert result["conversation_history"] == "short text"
        assert "_history_truncated" not in result

    def test_history_not_a_string(self) -> None:
        ctx = {"conversation_history": ["not", "a", "string"]}
        result = compress_context(ctx)
        assert result["conversation_history"] == ["not", "a", "string"]
        assert "_history_truncated" not in result

    def test_truncates_xi_recent_executions_to_10(self) -> None:
        execs = [f"exec{i}" for i in range(20)]
        ctx = {"xi_context": {"recent_executions": execs}}
        result = compress_context(ctx)
        assert len(result["xi_context"]["recent_executions"]) == 10

    def test_xi_context_not_a_dict(self) -> None:
        ctx = {"xi_context": "not_a_dict"}
        result = compress_context(ctx)
        assert result["xi_context"] == "not_a_dict"

    def test_xi_context_missing_recent_executions(self) -> None:
        ctx = {"xi_context": {"other": "data"}}
        result = compress_context(ctx)
        assert result["xi_context"] == {"other": "data"}

    def test_truncates_xi_recommendations_to_5(self) -> None:
        recs = [f"rec{i}" for i in range(10)]
        ctx = {"xi_recommendations": recs}
        result = compress_context(ctx)
        assert len(result["xi_recommendations"]) == 5

    def test_does_not_truncate_recommendations_under_5(self) -> None:
        recs = [f"rec{i}" for i in range(3)]
        ctx = {"xi_recommendations": recs}
        result = compress_context(ctx)
        assert len(result["xi_recommendations"]) == 3

    def test_recommendations_not_a_list(self) -> None:
        ctx = {"xi_recommendations": "not_a_list"}
        result = compress_context(ctx)
        assert result["xi_recommendations"] == "not_a_list"

    def test_all_truncations_together(self) -> None:
        tools = [f"tool{i}" for i in range(30)]
        lines = [f"line{i}" for i in range(100)]
        execs = [f"exec{i}" for i in range(20)]
        recs = [f"rec{i}" for i in range(10)]
        ctx = {
            "available_tools": tools,
            "conversation_history": "\n".join(lines),
            "xi_context": {"recent_executions": execs},
            "xi_recommendations": recs,
        }
        result = compress_context(ctx, max_tokens=50)
        assert len(result["available_tools"]) == 20
        assert result["_tools_truncated"] == 10
        assert result["_history_truncated"] == 60
        assert len(result["xi_context"]["recent_executions"]) == 10
        assert len(result["xi_recommendations"]) == 5


class TestContextCore:
    """Cover missing context.py lines."""

    def test_context_chunk_auto_assigns_ids(self):
        from siyarix.context import ContextChunk

        c = ContextChunk(content="hello world test data chunk")
        assert len(c.chunk_id) == 12
        assert c.token_estimate > 0

    def test_context_window_needs_compression(self):
        from siyarix.context import ContextWindow

        w = ContextWindow(max_tokens=100, system_prompt_tokens=90)
        assert w.needs_compression is True

    def test_context_window_usage_pct_max_tokens_zero(self):
        from siyarix.context import ContextWindow

        w = ContextWindow(max_tokens=0, system_prompt_tokens=50)
        assert w.usage_pct == 100.0

    def test_context_manager_init_from_memory(self):
        from siyarix.context import ContextManager

        mock_mem = MagicMock()
        mock_mem.load_context.return_value = [{"role": "user", "content": "hello"}]
        cm = ContextManager(memory=mock_mem)
        assert len(cm._chunks) == 1
        assert cm._window.history_tokens > 0

    def test_add_history_saves_to_memory(self):
        from siyarix.context import ContextManager

        mock_mem = MagicMock()
        cm = ContextManager(memory=mock_mem)
        cm.add_history("test content", role="user")
        mock_mem.save_context.assert_called_once()

    def test_add_tool_output_truncates(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        cm.add_tool_output("nmap", "x" * 5000, max_length=100)
        assert len(cm._chunks) == 1
        assert cm._chunks[0].content.endswith("...")

    def test_add_finding(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        cm.add_finding({"type": "vuln", "message": "critical issue"})
        assert len(cm._chunks) == 1

    def test_compress_empty(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        assert cm.compress() == ""

    def test_compress_full(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        for i in range(10):
            cm.add_history(f"message {i}", "user")
        summary = cm.compress()
        assert "Context summary" in summary
        assert cm._compression_count == 1

    def test_build_context_with_compressed(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        cm._compressed_summaries = ["sum1", "sum2"]
        ctx = cm.build_context()
        assert any("Previous context" in m["content"] for m in ctx)

    def test_get_relevant_context(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        cm.add_history("scan target example.com with nmap", "user")
        cm.add_history("check port 80", "user")
        results = cm.get_relevant_context("nmap", limit=5)
        assert len(results) >= 1

    def test_clear_resets_state(self):
        from siyarix.context import ContextManager

        cm = ContextManager()
        cm.add_history("test", "user")
        cm.clear()
        assert cm._total_tokens == 0

    def test_compress_context_truncates_tools(self):
        from siyarix.context import compress_context

        tools = [{"name": f"tool{i}"} for i in range(30)]
        result = compress_context({"available_tools": tools})
        assert len(result["available_tools"]) == 20

    def test_compress_context_truncates_history(self):
        from siyarix.context import compress_context

        lines = "\n".join(f"line{i}" for i in range(100))
        result = compress_context({"conversation_history": lines}, max_tokens=10)
        assert "_history_truncated" in result

    def test_compress_context_truncates_xi(self):
        from siyarix.context import compress_context

        execs = [{"cmd": f"cmd{i}"} for i in range(20)]
        result = compress_context({"xi_context": {"recent_executions": execs}})
        assert len(result["xi_context"]["recent_executions"]) == 10

    def test_compress_context_truncates_recommendations(self):
        from siyarix.context import compress_context

        recs = [f"rec{i}" for i in range(10)]
        result = compress_context({"xi_recommendations": recs})
        assert len(result["xi_recommendations"]) == 5


# ═══════════════════════════════════════════════════════════════════
# core/__init__.py (83% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
class TestContextEdgeCases:
    """Cover remaining context.py uncovered lines."""

    def test_context_chunk_post_init_empty_chunk_id(self):
        c = ContextChunk(content="hello world")
        assert len(c.chunk_id) == 12

    def test_context_chunk_post_init_zero_token_estimate(self):
        c = ContextChunk(content="hello", token_estimate=0)
        assert c.token_estimate >= 1

    def test_context_chunk_post_init_skips_if_provided(self):
        c = ContextChunk(content="hello", chunk_id="custom", token_estimate=50)
        assert c.chunk_id == "custom"
        assert c.token_estimate == 50

    def test_window_available_tokens_negative_returns_zero(self):
        w = ContextWindow(max_tokens=100, system_prompt_tokens=200)
        assert w.available_tokens == 0

    def test_window_usage_pct_overflow(self):
        w = ContextWindow(max_tokens=100, history_tokens=150)
        assert w.usage_pct == 100.0

    def test_context_manager_should_compress_true(self):
        cm = ContextManager(max_tokens=50)
        cm.add_system_prompt("x" * 200)
        assert cm.should_compress() is True

    def test_context_manager_add_history_no_memory(self):
        cm = ContextManager()
        cm.add_history("test")
        assert len(cm._chunks) == 1

    def test_build_context_with_tool_source(self):
        cm = ContextManager()
        cm.add_tool_output("nmap", "open ports: 22, 80")
        ctx = cm.build_context()
        assert any(m["role"] == "tool" for m in ctx)

    def test_get_relevant_context_zero_score_skips(self):
        cm = ContextManager()
        from siyarix.context import ContextChunk

        cm._chunks.append(ContextChunk(content="irrelevant", source="history:user", priority=0.0))
        results = cm.get_relevant_context("zzzzz_nonexistent", limit=5)
        assert len(results) == 0

    def test_get_relevant_context_word_match_boost(self):
        cm = ContextManager()
        cm.add_history("nmap scan target 10.0.0.1")
        results = cm.get_relevant_context("scan nmap", limit=5)
        assert len(results) >= 1

    def test_compress_context_no_tools_list(self):
        result = compress_context({"available_tools": "not_a_list"})
        assert result["available_tools"] == "not_a_list"

    def test_compress_context_no_history_dict(self):
        result = compress_context({"conversation_history": 42})
        assert result["conversation_history"] == 42

    def test_compress_context_xi_not_dict(self):
        result = compress_context({"xi_context": "string"})
        assert result["xi_context"] == "string"

    def test_compress_context_xi_execs_not_list(self):
        result = compress_context({"xi_context": {"recent_executions": "string"}})
        assert result["xi_context"]["recent_executions"] == "string"

    def test_compress_context_recs_not_list(self):
        result = compress_context({"xi_recommendations": "string"})
        assert result["xi_recommendations"] == "string"
