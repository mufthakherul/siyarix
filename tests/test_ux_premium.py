from unittest.mock import MagicMock, patch

from rich.layout import Layout

from siyarix.core.pipeline import CommandPipeline
from siyarix.ux import SmartAutocomplete, SplitPane


def test_smart_autocomplete():
    autocomplete = SmartAutocomplete()

    # Test slash commands completion
    doc = MagicMock()
    doc.text_before_cursor = "/"
    doc.get_word_before_cursor.return_value = "/"
    completions = list(autocomplete.get_completions(doc))
    assert len(completions) > 0
    assert any(c.text == "/help" for c in completions)

    # Test first word completion
    doc.text_before_cursor = "w"
    doc.get_word_before_cursor.return_value = "w"
    completions = list(autocomplete.get_completions(doc))
    assert any(c.text == "workflow" for c in completions)

    # Test tool completion inside run/scan command
    doc.text_before_cursor = "run n"
    doc.get_word_before_cursor.return_value = "n"
    completions = list(autocomplete.get_completions(doc))
    assert any(c.text == "nmap" for c in completions)

    # Test AI suggestions
    doc.text_before_cursor = "run nmap "
    doc.get_word_before_cursor.return_value = ""
    completions = list(autocomplete.get_completions(doc))
    assert any(
        "AI Suggestion"
        in (
            c.display_meta
            if isinstance(c.display_meta, str)
            else "".join(part[1] for part in c.display_meta if isinstance(part, tuple))
        )
        for c in completions
    )


def test_split_pane_layout():
    sp = SplitPane()
    left_renderable = "Operational Logs"
    layout = sp.generate_layout(
        left_renderable=left_renderable, right_type="attack_map"
    )

    assert isinstance(layout, Layout)
    assert layout["left"] is not None
    assert layout["right"] is not None

    # Test other right types
    layout_timeline = sp.generate_layout(
        left_renderable=left_renderable, right_type="timeline"
    )
    assert layout_timeline["right"] is not None

    layout_metrics = sp.generate_layout(
        left_renderable=left_renderable, right_type="metrics"
    )
    assert layout_metrics["right"] is not None

    layout_cheatsheet = sp.generate_layout(
        left_renderable=left_renderable, right_type="cheatsheet"
    )
    assert layout_cheatsheet["right"] is not None


def test_command_pipeline_parsing():
    pipeline = CommandPipeline()
    steps = pipeline.parse("scan 192.168.1.1 | analyze | report")
    assert len(steps) == 3
    assert steps[0].instruction == "scan 192.168.1.1"
    assert steps[1].instruction == "analyze"
    assert steps[2].instruction == "report"

    # Test natural language sequence
    steps_nl = pipeline.parse("scan target.com then gobuster then nuclei")
    assert len(steps_nl) == 3
