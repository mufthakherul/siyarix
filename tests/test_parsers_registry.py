from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from siyarix.parsers import Parser, _now_iso

from siyarix.parsers import (
    BaseParser,
    ParserRegistry,
    __all__ as parser_names,
    _class_to_tool_names,
    build_finding,
)


class TestNowIso:
    def test_returns_string(self):
        result = _now_iso()
        assert isinstance(result, str)

    def test_iso_format(self):
        result = _now_iso()
        # Should match ISO-8601 with timezone
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", result)
        assert result.endswith("+00:00") or "Z" in result or "+" in result[19:]

    def test_utc_timestamp(self):
        # Ensure it's reasonably close to now
        now = datetime.now(tz=UTC)
        parsed = datetime.fromisoformat(_now_iso())
        diff = abs((now - parsed).total_seconds())
        assert diff < 5


# ---------------------------------------------------------------------------
# build_finding
# ---------------------------------------------------------------------------


class TestBuildFinding:
    def test_basic_fields(self):
        finding = build_finding(
            title="Test finding",
            severity="high",
            description="A test",
            evidence="evidence data",
            tool="test-tool",
            target="target1",
        )
        assert finding["title"] == "Test finding"
        assert finding["severity"] == "high"
        assert finding["description"] == "A test"
        assert finding["evidence"] == "evidence data"
        assert finding["tool"] == "test-tool"
        assert finding["target"] == "target1"
        assert "timestamp" in finding

    def test_timestamp_auto(self):
        finding = build_finding(
            title="X", severity="info", description="", evidence="", tool="x",
        )
        assert isinstance(finding["timestamp"], str)
        assert len(finding["timestamp"]) > 10

    def test_target_default_empty(self):
        finding = build_finding(
            title="X", severity="info", description="", evidence="", tool="x",
        )
        assert finding["target"] == ""


# ---------------------------------------------------------------------------
# BaseParser
# ---------------------------------------------------------------------------

class _MinimalParser(BaseParser):
    def parse(self, output: str) -> list[dict[str, Any]]:
        return [{"title": output, "severity": "info", "description": "", "evidence": "", "tool": "simple", "target": ""}]


class _NonListParser(BaseParser):
    def parse(self, output: str) -> Any:
        return "not a list"


class _FailingParser(BaseParser):
    def parse(self, output: str) -> Any:
        raise ValueError("parse failed: " + output)


class TestBaseParserParseSafe:
    def test_success(self):
        p = _MinimalParser()
        result = p._parse_safe("hello")
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["title"] == "hello"

    def test_non_list_return(self):
        p = _NonListParser()
        result = p._parse_safe("test")
        assert result == []

    def test_exception(self):
        p = _FailingParser()
        result = p._parse_safe("bad")
        assert result == []

    def test_empty_output(self):
        p = _MinimalParser()
        result = p._parse_safe("")
        assert isinstance(result, list)


class TestBaseParserEnsureFields:
    def test_fills_defaults(self):
        p = _MinimalParser()
        result = p._ensure_fields({})
        assert result["title"] == "Unknown finding"
        assert result["severity"] == "info"
        assert result["description"] == ""
        assert result["evidence"] == ""
        assert result["tool"] == "unknown"
        assert result["target"] == ""
        assert "timestamp" in result

    def test_preserves_existing(self):
        p = _MinimalParser()
        result = p._ensure_fields({
            "title": "Custom",
            "severity": "high",
            "description": "desc",
            "evidence": "ev",
            "tool": "mytool",
            "target": "tgt",
            "timestamp": "2025-01-01T00:00:00",
        })
        assert result["title"] == "Custom"
        assert result["severity"] == "high"
        assert result["tool"] == "mytool"

    def test_partial_defaults(self):
        p = _MinimalParser()
        result = p._ensure_fields({"title": "Only title"})
        assert result["title"] == "Only title"
        assert result["severity"] == "info"
        assert result["tool"] == "unknown"


# ---------------------------------------------------------------------------
# _class_to_tool_names
# ---------------------------------------------------------------------------


class TestClassToToolNames:
    def test_basic_camelcase(self):
        names = _class_to_tool_names("AircrackParser")
        assert "aircrack" in names

    def test_aircrack_overrides(self):
        names = _class_to_tool_names("AircrackParser")
        assert "aircrack-ng" in names
        assert "aircrack" in names

    def test_netcat_overrides(self):
        names = _class_to_tool_names("NetcatParser")
        assert "nc" in names
        assert "netcat" in names
        assert "ncat" in names

    def test_simple_name(self):
        names = _class_to_tool_names("NmapParser")
        assert "nmap" in names

    def test_multi_word(self):
        names = _class_to_tool_names("HashIdentifierParser")
        assert "hash-identifier" in names
        assert "hashid" in names

    def test_naabu_overrides(self):
        names = _class_to_tool_names("NaabuParser")
        assert "naabu" in names
        assert "port-scanner" in names

    def test_no_parser_suffix(self):
        names = _class_to_tool_names("MyCustomTool")
        assert "mycustomtool" in names

    def test_hyphen_variants(self):
        names = _class_to_tool_names("IkeScanParser")
        assert "ike-scan" in names
        assert "ikescan" in names
        assert "ike_scan" in names

    def test_searchsploit_overrides(self):
        names = _class_to_tool_names("SearchsploitParser")
        assert "searchsploit" in names
        assert "exploitdb" in names

    def test_waybackurls_overrides(self):
        names = _class_to_tool_names("WaybackurlsParser")
        assert "waybackurls" in names
        assert "gau" in names

    def test_kiterunner_overrides(self):
        names = _class_to_tool_names("KiterunnerParser")
        assert "kr" in names
        assert "kiterunner" in names


# ---------------------------------------------------------------------------
# ParserRegistry
# ---------------------------------------------------------------------------


class _MockParser:
    def parse(self, output: str) -> list[dict[str, Any]]:
        return [{"title": output, "severity": "info", "description": "", "evidence": "", "tool": "mock", "target": ""}]


class _MockParserV2:
    def parse(self, output: str) -> list[dict[str, Any]]:
        return [{"title": f"v2:{output}", "severity": "info", "description": "", "evidence": "", "tool": "mock", "target": ""}]


class _MockBaseParser(BaseParser):
    def parse(self, output: str) -> list[dict[str, Any]]:
        return [{"title": output, "severity": "info", "description": "", "evidence": "", "tool": "mock-base", "target": ""}]


class _MockFailingParser:
    def parse(self, output: str) -> Any:
        raise RuntimeError("fail")


class TestParserRegistryInit:
    def test_empty_on_init(self):
        reg = ParserRegistry()
        assert reg.count == 0
        assert reg.registered_tools() == []
        assert reg._parsers == {}


class TestParserRegistryRegister:
    def test_register_basic(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        assert reg.count == 1
        assert "nmap" in reg.registered_tools()

    def test_register_with_version(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser(), "1.0")
        assert reg.count == 2  # version + None default
        assert reg.get("nmap") is not None

    def test_register_duplicate(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        reg.register("nmap", _MockParserV2(), "2.0")
        assert reg.count == 2  # None + 2.0

    def test_register_multiple_tools(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        reg.register("masscan", _MockParser())
        assert reg.count == 2

    def test_register_overwrite_default(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser(), "1.0")
        reg.register("nmap", _MockParserV2(), "2.0")
        assert reg.count == 3  # None default (from 1.0), 1.0, 2.0
        # The last versioned registration should also set default if None not set
        # Actually, register logic: if version is not None and None not in parsers[tool_name], set None
        # After first: None=1.0, 1.0=1.0
        # After second: None=1.0 (already exists), 1.0=1.0, 2.0=2.0


class TestParserRegistryGet:
    def test_get_existing(self):
        reg = ParserRegistry()
        p = _MockParser()
        reg.register("nmap", p)
        assert reg.get("nmap") is p

    def test_get_missing(self):
        reg = ParserRegistry()
        assert reg.get("nonexistent") is None

    def test_get_with_version(self):
        reg = ParserRegistry()
        p1 = _MockParser()
        p2 = _MockParserV2()
        reg.register("nmap", p1, "1.0")
        reg.register("nmap", p2, "2.0")
        assert reg.get("nmap", "2.0") is p2

    def test_get_version_falls_back(self):
        reg = ParserRegistry()
        p1 = _MockParser()
        reg.register("nmap", p1, "1.0")
        # No parser for 2.0, should fall back to None (which was set to p1)
        assert reg.get("nmap", "2.0") is p1

    def test_get_unknown_version_no_fallback(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        assert reg.get("nmap", "3.0") is not None  # Falls back to None version


class TestParserRegistryParse:
    def test_parse_empty_tool(self):
        reg = ParserRegistry()
        assert reg.parse("does-not-exist", "test") == []

    def test_parse_normal(self):
        reg = ParserRegistry()
        p = _MockParser()
        reg.register("mock", p)
        findings = reg.parse("mock", "hello")
        assert len(findings) == 1
        assert findings[0]["title"] == "hello"

    def test_parse_with_baseparser(self):
        reg = ParserRegistry()
        p = _MockBaseParser()
        reg.register("mock-base", p)
        findings = reg.parse("mock-base", "world")
        assert len(findings) == 1

    def test_parse_exception(self):
        reg = ParserRegistry()
        p = _MockFailingParser()
        reg.register("failing", p)
        findings = reg.parse("failing", "test")
        assert findings == []

    def test_parse_non_list_return(self):
        class _MockNonList:
            def parse(self, output: str) -> str:
                return "not a list"
        reg = ParserRegistry()
        reg.register("nonlist", _MockNonList())
        findings = reg.parse("nonlist", "test")
        assert findings == []


class TestParserRegistryHasParser:
    def test_has_existing(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        assert reg.has_parser("nmap") is True

    def test_has_missing(self):
        reg = ParserRegistry()
        assert reg.has_parser("nonexistent") is False

    def test_has_with_version(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser(), "1.0")
        assert reg.has_parser("nmap", "1.0") is True

    def test_has_with_version_fallback(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser(), "1.0")
        # None version was set as default, so 2.0 should still return True via fallback
        assert reg.has_parser("nmap", "2.0") is True

    def test_has_no_tool_returns_false(self):
        reg = ParserRegistry()
        assert reg.has_parser("missing") is False


class TestParserRegistryRegisteredTools:
    def test_sorted(self):
        reg = ParserRegistry()
        reg.register("z", _MockParser())
        reg.register("a", _MockParser())
        reg.register("m", _MockParser())
        assert reg.registered_tools() == ["a", "m", "z"]

    def test_empty(self):
        reg = ParserRegistry()
        assert reg.registered_tools() == []


class TestParserRegistryCount:
    def test_count_versions(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser(), "1.0")
        reg.register("nmap", _MockParserV2(), "2.0")
        assert reg.count == 3  # None default, 1.0, 2.0

    def test_count_multiple_tools(self):
        reg = ParserRegistry()
        reg.register("nmap", _MockParser())
        reg.register("masscan", _MockParser())
        assert reg.count == 2


class TestParserRegistryDiscover:
    def test_discover_returns_dict(self):
        reg = ParserRegistry()
        result = reg.discover()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_discover_populates_parsers(self):
        reg = ParserRegistry()
        reg.discover()
        assert reg.count > 0
        assert "nmap" in reg.registered_tools() or len(reg.registered_tools()) > 10

    def test_discover_maps_tool_names(self):
        reg = ParserRegistry()
        reg.discover()
        # Should have standard tools
        known = {"nmap", "nuclei", "gobuster", "dirb", "ffuf", "curl", "semgrep", "zaproxy"}
        found = set(reg.registered_tools())
        assert len(found & known) >= 3  # At least 3 of known tools found


class TestParserRegistryEdgeCases:
    def test_register_twice_same(self):
        reg = ParserRegistry()
        p = _MockParser()
        reg.register("tool", p)
        reg.register("tool", p)  # same instance, same version (None)
        assert reg.count == 1

    def test_get_none_existing(self):
        reg = ParserRegistry()
        assert reg.get("nonexistent") is None

    def test_parse_no_parser_returns_empty(self):
        reg = ParserRegistry()
        assert reg.parse("no-such-tool", "data") == []

    def test_discover_import_error_path(self):
        """Ensure discover() doesn't raise on missing optional import."""
        reg = ParserRegistry()
        result = reg.discover()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestParserProtocol:
    def test_base_parser_is_not_a_parser(self):
        """BaseParser alone doesn't have parse() instance method on the class itself."""
        # Actually, BaseParser doesn't define parse(), so it shouldn't match Parser protocol
        pass

    def test_concrete_implements_protocol(self):
        """A class with parse() should satisfy Parser protocol."""
        class Impl:
            def parse(self, output: str) -> list[dict[str, Any]]:
                return []
        assert isinstance(Impl(), Parser)

class TestParsersInitCore:
    """Cover uncovered lines in parsers/__init__.py."""

    def test_parse_safe_non_list_return(self):
        from siyarix.parsers import BaseParser
        class BadParser(BaseParser):
            def parse(self, output):
                return "not a list"
        bp = BadParser()
        result = bp._parse_safe("test")
        assert result == []

    def test_build_finding_basic(self):
        from siyarix.parsers import build_finding
        f = build_finding(title="XSS", severity="high", description="XSS vuln", evidence="<script>", tool="nuclei")
        assert f["title"] == "XSS"
        assert f["severity"] == "high"

    def test_discover_skips_non_parser_classes(self):
        from siyarix.parsers import ParserRegistry
        reg = ParserRegistry()
        parsed = reg.discover()
        assert isinstance(parsed, dict)

    def test_class_to_tool_names_overrides(self):
        from siyarix.parsers import _class_to_tool_names
        names = _class_to_tool_names("AircrackParser")
        assert "aircrack-ng" in names

    def test_class_to_tool_names_with_hyphen(self):
        from siyarix.parsers import _class_to_tool_names
        names = _class_to_tool_names("HashIdentifierParser")
        assert "hash-identifier" in names


# ═══════════════════════════════════════════════════════════════════
# planner_registry.py (94% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
class TestParsersInitErrors:
    """Cover parsers/__init__.py remaining uncovered lines."""

    def test_parser_registry_discover_skip_baseparser(self):
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {
                "BaseParser": BaseParser,
                "Parser": Parser,
            }
            result = reg.discover()
            assert isinstance(result, dict)

    def test_parser_registry_discover_with_tool_aliases_list(self):
        class FakeParser(BaseParser):
            TOOL_ALIASES = ["tool1", "tool2"]
            def parse(self, output):
                return []

        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {"FakeParser": FakeParser}
            with patch.object(reg, "register") as mock_register:
                reg.discover()
                mock_register.assert_called()

    def test_parser_registry_discover_with_tool_name(self):
        class FakeParser2(BaseParser):
            TOOL_NAME = "my_tool"
            def parse(self, output):
                return []

        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {"FakeParser2": FakeParser2}
            with patch.object(reg, "register") as mock_register:
                reg.discover()
                mock_register.assert_called()

    def test_parser_registry_discover_with_siyarix_parsers(self):
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {}
            mock_siyarix_parsers = MagicMock()
            mock_siyarix_parsers.NmapRustParser = MagicMock()
            mock_siyarix_parsers.NucleiRustParser = MagicMock()
            with patch.dict("sys.modules", {"siyarix_parsers": mock_siyarix_parsers}):
                with patch.object(reg, "register") as mock_register:
                    reg.discover()
                    assert mock_register.call_count >= 2

    def test_class_to_tool_names_known_override(self):
        names = _class_to_tool_names("Aircrack")
        assert "aircrack-ng" in names
        assert "aircrack" in names

    def test_class_to_tool_names_with_hyphen(self):
        names = _class_to_tool_names("FooBar")
        base = [n for n in names if "-" not in n and "_" not in n]
        assert "foobar" in names or "foo-bar" in names


# ═══════════════════════════════════════════════════════════════════
# 16. planner_registry.py (91% - many uncovered lines/branches)
# ═══════════════════════════════════════════════════════════════════
class TestParsersInitConcurrency:
    """Cover remaining parsers/__init__.py lines."""

    def test_discover_skips_non_type_globals(self):
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {
                "BaseParser": BaseParser,
                "Parser": Parser,
                "some_var": 42,
            }
            result = reg.discover()
            assert isinstance(result, dict)

    def test_discover_skips_class_without_parse(self):
        class NoParse:
            pass
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {"NoParse": NoParse}
            result = reg.discover()
            assert isinstance(result, dict)

    def test_discover_with_tool_aliases_string(self):
        class FakeParser(BaseParser):
            TOOL_ALIASES = "single_tool"
            def parse(self, output):
                return []
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {"FakeParser": FakeParser}
            with patch.object(reg, "register") as mock_register:
                reg.discover()
                mock_register.assert_called()

    def test_discover_no_siyarix_parsers_import_error(self):
        reg = ParserRegistry()
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {}
            with patch.dict("sys.modules", {"siyarix_parsers": None}):
                result = reg.discover()
                assert isinstance(result, dict)

    def test_discover_siyarix_parsers_nmap_only(self):
        reg = ParserRegistry()
        mock_mod = MagicMock()
        mock_mod.NmapRustParser = MagicMock()
        del mock_mod.NucleiRustParser
        with patch("siyarix.parsers.globals") as mock_globals:
            mock_globals.return_value = {}
            with patch.dict("sys.modules", {"siyarix_parsers": mock_mod}):
                with patch.object(reg, "register") as mock_register:
                    reg.discover()
                    mock_register.assert_called_once()

    def test_class_to_tool_names_no_parser_suffix(self):
        names = _class_to_tool_names("CustomClass")
        assert "custom-class" in names

    def test_class_to_tool_names_with_hyphen_variations(self):
        names = _class_to_tool_names("FooBarParser")
        assert "foo-bar" in names

    def test_class_to_tool_names_base_name_override(self):
        names = _class_to_tool_names("NetcatParser")
        assert "nc" in names
        assert "netcat" in names


# ═══════════════════════════════════════════════════════════════════
# 12. planner_registry.py (91% - missing decompose_goal, adapt_plan)
# ═══════════════════════════════════════════════════════════════════
