"""Tests for cross-parser edge cases, malformed input, and boundary conditions."""
from __future__ import annotations

from siyarix.parsers.nuclei_parser import NucleiParser
from siyarix.parsers.subfinder_parser import SubfinderParser
from siyarix.parsers.masscan_parser import MasscanParser
from siyarix.parsers.gobuster_parser import GobusterParser


class TestParserEdgeCases:
    """Test edge cases across parsers."""

    def test_malformed_input(self):
        p = NucleiParser()
        assert p.parse("not json at all {{") == []

    def test_unicode_input(self):
        p = SubfinderParser()
        result = p.parse(chr(252) + "ber.example.com\n")
        assert len(result) >= 1

    def test_very_long_output(self):
        p = MasscanParser()
        lines = [f"Discovered open port {p}/tcp on 10.0.0.1" for p in range(1, 1000)]
        result = p.parse("\n".join(lines))
        assert len(result) == 999

    def test_mixed_content(self):
        p = GobusterParser()
        output = "Url: http://example.com\nsome noise here\n/admin (Status: 200)\n[Footer]\n"
        findings = p.parse(output)
        assert len(findings) >= 1
