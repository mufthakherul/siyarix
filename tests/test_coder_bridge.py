"""Tests for siyarix.coder_bridge — AI code generation and review."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch


from siyarix.coder_bridge import CodeReview, CoderBridge


class TestCodeReview:
    def test_to_panel_with_issues(self) -> None:
        review = CodeReview(
            file_path="test.py",
            score=5,
            issues=[
                {"severity": "critical", "message": "eval is dangerous"},
                {"severity": "high", "message": "hardcoded password"},
                {"severity": "medium", "message": "line too long"},
                {"severity": "low", "message": "TODO found"},
                {"severity": "unknown", "message": "weird issue"},
            ],
        )
        panel = review.to_panel()
        text = panel.renderable
        assert "test.py" in text
        assert "5/10" in text
        assert "CRITICAL" in text
        assert "HIGH" in text
        assert "MEDIUM" in text
        assert "LOW" in text

    def test_to_panel_no_issues(self) -> None:
        review = CodeReview(file_path="clean.py", score=10)
        panel = review.to_panel()
        text = panel.renderable
        assert "clean.py" in text
        assert "10/10" in text
        assert "Issues" not in text

    def test_to_panel_more_than_10_issues(self) -> None:
        issues = [{"severity": "low", "message": f"issue {i}"} for i in range(15)]
        review = CodeReview(file_path="big.py", issues=issues, score=0)
        panel = review.to_panel()
        text = panel.renderable
        assert "big.py" in text
        assert all(f"issue {i}" in text for i in range(10))


class TestCoderBridgeGenerate:
    @patch("siyarix.coder_bridge.console")
    async def test_without_provider(self, mock_console: MagicMock) -> None:
        bridge = CoderBridge()
        result = await bridge.generate("write hello world", "python")
        assert result == ""
        mock_console.print.assert_called_once()

    async def test_with_provider(self) -> None:
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = 'print("hello")'
        bridge = CoderBridge(provider=mock_provider)
        result = await bridge.generate("write hello world", "python")
        assert result == 'print("hello")'
        mock_provider.generate.assert_called_once()
        assert "Generate python code" in mock_provider.generate.call_args[0][0]

    async def test_with_provider_different_language(self) -> None:
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = 'console.log("hello")'
        bridge = CoderBridge(provider=mock_provider)
        result = await bridge.generate("write hello world", "javascript")
        assert result == 'console.log("hello")'
        assert "Generate javascript code" in mock_provider.generate.call_args[0][0]


class TestCoderBridgeReview:
    async def test_clean_code(self) -> None:
        bridge = CoderBridge()
        review = await bridge.review("clean.py", 'print("hello")\n')
        assert review.file_path == "clean.py"
        assert review.score == 10
        assert len(review.issues) == 0

    async def test_detects_todo_fixme(self) -> None:
        bridge = CoderBridge()
        review = await bridge.review("todo.py", "# TODO: fix this\n# FIXME: also this\nok()\n")
        assert review.score == 8
        assert len(review.issues) == 2
        assert any("TODO" in i["message"] for i in review.issues)

    async def test_detects_hardcoded_credential(self) -> None:
        bridge = CoderBridge()
        review = await bridge.review("creds.py", 'password = "secret123"\n')
        assert any("hardcoded credential" in i["message"] for i in review.issues)
        assert review.score == 9

    async def test_detects_eval_exec(self) -> None:
        bridge = CoderBridge()
        review = await bridge.review("danger.py", "eval(user_input)\nexec(code)\n")
        assert len(review.issues) == 2
        assert all(i["severity"] == "critical" for i in review.issues)

    async def test_detects_long_lines(self) -> None:
        bridge = CoderBridge()
        code = "x = " + ("a" * 130) + "\n"
        review = await bridge.review("long.py", code)
        assert any("Line too long" in i["message"] for i in review.issues)
        assert any(i["severity"] == "medium" for i in review.issues)

    async def test_multiple_issues_score_floor(self) -> None:
        bridge = CoderBridge()
        bad_code = "# TODO\n" * 15
        review = await bridge.review("bad.py", bad_code)
        assert review.score == 0
