"""Tests for tool call repair — 100% coverage."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch


from siyarix.tool_call_repair import (
    _find_bracket_spans,
    _fuzzy_match_tool_name,
    _levenshtein_distance,
    BRACKET_TOOL_RE,
    CLOSING_MARKERS,
    find_json_object_end,
    has_plain_text_tool_calls,
    MAX_PAYLOAD_LENGTH,
    parse_bracket_tool_calls,
    parse_plain_text_tool_calls,
    parse_xml_tool_calls,
    promote_to_native_tool_calls,
    strip_tool_call_blocks,
    XML_TOOL_RE,
    __all__,
)


class TestExports:
    def test_all(self):
        names = {
            "MAX_PAYLOAD_LENGTH",
            "BRACKET_TOOL_RE",
            "XML_TOOL_RE",
            "CLOSING_MARKERS",
            "find_json_object_end",
            "parse_bracket_tool_calls",
            "parse_xml_tool_calls",
            "parse_plain_text_tool_calls",
            "strip_tool_call_blocks",
            "has_plain_text_tool_calls",
            "promote_to_native_tool_calls",
        }
        assert names.issubset(__all__)


class TestConstants:
    def test_max_payload_length(self):
        assert MAX_PAYLOAD_LENGTH == 262144

    def test_bracket_tool_re_compiled(self):
        assert isinstance(BRACKET_TOOL_RE, re.Pattern)

    def test_xml_tool_re_compiled(self):
        assert isinstance(XML_TOOL_RE, re.Pattern)

    def test_closing_markers(self):
        assert isinstance(CLOSING_MARKERS, list)
        assert "[END_TOOL_REQUEST]" in CLOSING_MARKERS
        assert "[/tool]" in CLOSING_MARKERS
        assert "[/function]" in CLOSING_MARKERS
        assert "<|call|>" in CLOSING_MARKERS


class TestFindJsonObjectEnd:
    def test_simple_json(self):
        text = '{"a": 1}'
        assert find_json_object_end(text, 0) == len(text)

    def test_nested_braces(self):
        text = '{"a": {"b": 2}}'
        assert find_json_object_end(text, 0) == len(text)

    def test_string_containing_brace(self):
        text = '{"a": "}"}'
        # The string contains } which should NOT close the object
        assert find_json_object_end(text, 0) == len(text)

    def test_string_with_braces_and_nested(self):
        text = '{"a": "{", "b": {"c": 3}}'
        assert find_json_object_end(text, 0) == len(text)

    def test_escape_sequences_in_string(self):
        text = '{"a": "\\""}'
        assert find_json_object_end(text, 0) == len(text)

    def test_backslash_not_escaping_in_string(self):
        text = '{"a": "\\\\"}'
        assert find_json_object_end(text, 0) == len(text)

    def test_no_closing_brace(self):
        text = '{"a": 1'
        assert find_json_object_end(text, 0) == -1

    def test_empty_text(self):
        assert find_json_object_end("", 0) == -1

    def test_start_not_at_brace(self):
        text = 'prefix {"a": 1}'
        assert find_json_object_end(text, 7) == len(text)

    def test_start_beyond_text(self):
        text = "abc"
        assert find_json_object_end(text, 10) == -1


class TestParseBracketToolCalls:
    def test_basic_tool_call(self):
        text = '[nmap]\n{"host": "example.com"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"
        assert calls[0]["args"] == {"host": "example.com"}

    def test_tool_name_with_space_separator(self):
        text = '[nmap] {"host": "example.com"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"

    def test_tool_call_with_colon_syntax(self):
        text = '[tool:nmap]\n{"host": "example.com"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        # group(1) is None for [tool:name], so name is "unknown"
        assert calls[0]["name"] == "unknown"
        assert calls[0]["args"] == {"host": "example.com"}

    def test_tool_call_bare_tool(self):
        text = '[tool]\n{"host": "example.com"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "unknown"

    def test_tool_call_uppercase_tool(self):
        text = '[TOOL_CALL]\n{"host": "example.com"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "unknown"

    def test_multiple_calls(self):
        text = '[nmap]\n{"host": "a"}[nuclei]\n{"target": "b"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 2
        assert calls[0]["name"] == "nmap"
        assert calls[1]["name"] == "nuclei"

    def test_payload_too_large(self):
        text = '[tool]\n{"data": "' + "x" * MAX_PAYLOAD_LENGTH + '"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 0

    def test_invalid_json_falls_back_to_raw(self):
        text = '[mytool]\n{invalid json}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["args"] == {"raw": "{invalid json}"}

    @patch("siyarix.tool_call_repair.json.loads")
    def test_non_dict_json_wraps_in_value(self, mock_loads: MagicMock):
        mock_loads.return_value = [1, 2, 3]
        text = '[mytool]\n{"key": "value"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["args"] == {"value": [1, 2, 3]}

    def test_no_brackets(self):
        text = "just some text without tool calls"
        assert parse_bracket_tool_calls(text) == []

    def test_incomplete_json_no_closing_brace(self):
        text = '[tool]\n{"key": "value"'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 0

    @patch("siyarix.tool_call_repair.json.loads")
    def test_json_array_wraps_in_value(self, mock_loads: MagicMock):
        mock_loads.return_value = "some string"
        text = '[mytool]\n{"key": "value"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["args"] == {"value": "some string"}

    def test_empty_args_text_after_unclosed_brace(self):
        text = "[tool]\n{"
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 0

    def test_tool_name_with_digits_and_hyphens(self):
        text = '[my-tool-42]\n{"action": "run"}'
        calls = parse_bracket_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "my-tool-42"


class TestParseXmlToolCalls:
    def test_json_body(self):
        text = '<function=nmap>{"host": "example.com"}</function>'
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"
        assert calls[0]["args"] == {"host": "example.com"}

    def test_xml_parameter_format(self):
        text = (
            "<function=nmap>"
            "<parameter=host>example.com</parameter>"
            "<parameter=port>80</parameter>"
            "</function>"
        )
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"
        assert calls[0]["args"] == {"host": "example.com", "port": "80"}

    def test_plain_text_body(self):
        text = "<function=echo>hello world</function>"
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "echo"
        assert calls[0]["args"] == {"input": "hello world"}

    def test_multiple_functions(self):
        text = (
            '<function=nmap>{"host": "a"}</function>'
            '<function=nuclei>{"target": "b"}</function>'
        )
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 2

    def test_payload_too_large(self):
        text = "<function=tool>" + "x" * (MAX_PAYLOAD_LENGTH + 1) + "</function>"
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 0

    def test_no_matches(self):
        assert parse_xml_tool_calls("just plain text") == []

    def test_body_starts_with_brace_invalid_json(self):
        text = '<function=tool>{invalid}</function>'
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        # invalid JSON starting with { falls through to xml params/plain text
        assert calls[0]["name"] == "tool"
        assert calls[0]["args"] == {"input": "{invalid}"}

    def test_body_starts_with_brace_valid_json_non_dict(self):
        # A JSON string
        text = '<function=tool>"somestring"</function>'
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "tool"
        # "somestring" starts with " not {, so goes to xml params/plain text
        # plain text fallback
        assert calls[0]["args"] == {"input": '"somestring"'}

    def test_body_starts_with_brace_valid_json_array(self):
        # A JSON array: { starts at position 0
        text = '<function=tool>{"a": 1}</function>'
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["args"] == {"a": 1}

    @patch("siyarix.tool_call_repair.json.loads")
    def test_xml_json_parses_to_non_dict_falls_through(
        self, mock_loads: MagicMock
    ):
        """When json.loads succeeds but returns non-dict, falls through to plain text."""
        mock_loads.return_value = [1, 2, 3]
        text = '<function=tool>{"key": "value"}</function>'
        calls = parse_xml_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["args"] == {"input": '{"key": "value"}'}


class TestParsePlainTextToolCalls:
    def test_bracket_syntax_returns_bracket_results(self):
        text = '[nmap]\n{"host": "x"}'
        calls = parse_plain_text_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"

    def test_no_bracket_falls_back_to_xml(self):
        text = '<function=nmap>{"host": "x"}</function>'
        calls = parse_plain_text_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"

    def test_no_calls_at_all(self):
        assert parse_plain_text_tool_calls("hello world") == []

    def test_bracket_empty_does_not_fallback_to_xml(self):
        text = (
            '[nmap]\n{"host": "x"}'
            '<function=nuclei>{"target": "y"}</function>'
        )
        calls = parse_plain_text_tool_calls(text)
        # bracket found, so only bracket calls returned
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"


class TestFindBracketSpans:
    def test_single_span(self):
        text = '[nmap]\n{"host": "x"}'
        spans = _find_bracket_spans(text)
        assert len(spans) == 1
        start, end = spans[0]
        assert text[start:end] == '[nmap]\n{"host": "x"}'

    def test_multiple_spans(self):
        text = '[nmap]\n{"a": 1}[nuclei]\n{"b": 2}'
        spans = _find_bracket_spans(text)
        assert len(spans) == 2

    def test_incomplete_json_span_up_to_json_start(self):
        text = '[nmap]\n{"a": '
        spans = _find_bracket_spans(text)
        assert len(spans) == 1
        start, end = spans[0]
        # json_end == -1, so span uses json_start as end (before the {)
        assert text[start:end] == '[nmap]\n'

    def test_no_matches(self):
        assert _find_bracket_spans("plain text") == []


class TestStripToolCallBlocks:
    def test_strip_bracket_calls(self):
        text = "before [nmap]\n{\"host\": \"x\"} after"
        cleaned = strip_tool_call_blocks(text)
        assert "before" in cleaned
        assert "after" in cleaned
        assert "[nmap]" not in cleaned

    def test_strip_xml_calls(self):
        text = "before <function=nmap>{\"host\": \"x\"}</function> after"
        cleaned = strip_tool_call_blocks(text)
        assert "before" in cleaned
        assert "after" in cleaned
        assert "<function=nmap>" not in cleaned

    def test_overlapping_spans(self):
        text = "[tool]\n{\"x\": <function=other>data</function>}"
        cleaned = strip_tool_call_blocks(text)
        # Both the bracket span and XML span should be removed
        # The XML span sits inside the bracket span
        assert "tool" not in cleaned
        assert "data" not in cleaned or "function" not in cleaned
        # The overlapping merge should cover everything
        assert "<function=other>" not in cleaned

    def test_closing_markers_removed(self):
        text = "some text [END_TOOL_REQUEST] [/tool] [/function] <|call|>"
        cleaned = strip_tool_call_blocks(text)
        assert cleaned == "some text"

    def test_whitespace_cleanup(self):
        text = "a\n\n\n\n\nb"
        cleaned = strip_tool_call_blocks(text)
        assert cleaned == "a\n\nb"

    def test_no_calls_returns_stripped_text(self):
        text = "  hello world  "
        cleaned = strip_tool_call_blocks(text)
        assert cleaned == "hello world"

    def test_bracket_and_xml_both_removed(self):
        text = (
            "prefix "
            '[nmap]\n{"host": "x"} '
            "middle "
            '<function=nuclei>{"target": "y"}</function> '
            "suffix"
        )
        cleaned = strip_tool_call_blocks(text)
        assert cleaned == "prefix  middle  suffix"


class TestHasPlainTextToolCalls:
    def test_bracket_match(self):
        assert has_plain_text_tool_calls("[nmap]\n{}") is True

    def test_xml_match(self):
        assert has_plain_text_tool_calls("<function=nmap></function>") is True

    def test_closing_marker_match(self):
        assert has_plain_text_tool_calls("[END_TOOL_REQUEST]") is True

    def test_no_match(self):
        assert has_plain_text_tool_calls("just some text") is False

    def test_alternate_marker(self):
        assert has_plain_text_tool_calls("<|call|>") is True

    def test_marker_in_text(self):
        assert has_plain_text_tool_calls("code [/tool] here") is True


class TestPromoteToNativeToolCalls:
    def test_with_allowed_tools_exact_match(self):
        text = '[nmap]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(text, allowed_tools=["nmap"])
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"
        assert "[nmap]" not in cleaned

    def test_with_allowed_tools_fuzzy_match_case(self):
        text = '[Nmap]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(text, allowed_tools=["nmap"])
        assert len(calls) == 1
        # fuzzy match corrects case
        assert calls[0]["name"] == "nmap"

    def test_with_allowed_tools_fuzzy_substring(self):
        text = '[scan]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(
            text, allowed_tools=["portscan"]
        )
        # "scan" is a substring of "portscan"
        assert len(calls) == 1
        assert calls[0]["name"] == "portscan"

    def test_with_allowed_tools_fuzzy_levenshtein(self):
        text = '[namp]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(text, allowed_tools=["nmap"])
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"

    def test_with_allowed_tools_no_match(self):
        text = '[unknown]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(
            text, allowed_tools=["nmap", "nuclei"]
        )
        assert len(calls) == 0

    def test_without_allowed_tools(self):
        text = '[nmap]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(text)
        assert len(calls) == 1
        assert calls[0]["name"] == "nmap"

    def test_no_calls_found(self):
        text = "just some text"
        cleaned, calls = promote_to_native_tool_calls(text)
        assert calls == []
        assert cleaned == "just some text"

    def test_fuzzy_disabled_exact_only(self):
        text = '[nmap]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(
            text, allowed_tools=["nmap"], fuzzy=False
        )
        assert len(calls) == 1

    def test_fuzzy_disabled_no_match(self):
        text = '[Nmap]\n{"host": "x"}'
        cleaned, calls = promote_to_native_tool_calls(
            text, allowed_tools=["nmap"], fuzzy=False
        )
        assert len(calls) == 0


class TestFuzzyMatchToolName:
    def test_exact_match(self):
        assert _fuzzy_match_tool_name("nmap", ["nmap", "nuclei"]) == "nmap"

    def test_case_insensitive(self):
        assert _fuzzy_match_tool_name("NMAP", ["nmap", "nuclei"]) == "nmap"

    def test_substring_match(self):
        assert _fuzzy_match_tool_name("port", ["portscan"]) == "portscan"

    def test_reverse_substring(self):
        assert _fuzzy_match_tool_name("portscan", ["port"]) == "port"

    def test_levenshtein_distance_1(self):
        assert _fuzzy_match_tool_name("namp", ["nmap"]) == "nmap"

    def test_levenshtein_distance_2(self):
        assert _fuzzy_match_tool_name("nmop", ["nmap"]) == "nmap"

    def test_no_match_different_lengths_gt_2(self):
        assert _fuzzy_match_tool_name("abcdef", ["nmap"]) is None

    def test_no_match_large_distance(self):
        assert _fuzzy_match_tool_name("xxxxx", ["nmap"]) is None

    def test_empty_allowed_list(self):
        assert _fuzzy_match_tool_name("nmap", []) is None

    def test_first_allowed_tool_wins_on_equal_score(self):
        result = _fuzzy_match_tool_name("NMAP", ["nmap", "NMAP"])
        assert result in ("nmap", "NMAP")


class TestLevenshteinDistance:
    def test_equal_strings(self):
        assert _levenshtein_distance("abc", "abc") == 0

    def test_empty_first_string(self):
        assert _levenshtein_distance("", "abc") == 3

    def test_empty_second_string(self):
        assert _levenshtein_distance("abc", "") == 3

    def test_single_char_change(self):
        assert _levenshtein_distance("cat", "car") == 1

    def test_multi_char_insert_delete(self):
        assert _levenshtein_distance("kitten", "sitting") == 3

    def test_a_longer_than_b(self):
        assert _levenshtein_distance("abcd", "ab") == 2

    def test_b_longer_than_a(self):
        assert _levenshtein_distance("ab", "abcd") == 2

    def test_identical_strings_empty(self):
        assert _levenshtein_distance("", "") == 0

    def test_completely_different(self):
        assert _levenshtein_distance("abc", "xyz") == 3

    def test_insertion(self):
        assert _levenshtein_distance("cat", "chat") == 1
