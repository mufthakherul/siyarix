# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for siyarix.context — context compression."""

from __future__ import annotations

from siyarix.context import compress_context


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
