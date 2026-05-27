"""Tests for rust_accel.py — Rust acceleration hooks (28 stmts, ~46% covered)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from siyarix.rust_accel import parse_nmap_xml, rust_available


class TestRustAvailable:
    def test_not_available(self):
        with patch("siyarix.rust_accel._rust", None):
            assert rust_available() is False

    def test_available(self):
        with patch("siyarix.rust_accel._rust", MagicMock()):
            assert rust_available() is True


class TestParseNmapXml:
    def test_rust_not_available_returns_none(self):
        with patch("siyarix.rust_accel._rust", None):
            result = parse_nmap_xml("<xml></xml>")
            assert result is None

    def test_rust_returns_valid_list(self):
        mock_rust = MagicMock()
        mock_rust.parse_nmap_xml.return_value = [
            {"port": 80, "service": "http"},
            {"port": 22, "service": "ssh"},
        ]
        with patch("siyarix.rust_accel._rust", mock_rust):
            result = parse_nmap_xml("<xml></xml>")
            assert result is not None
            assert len(result) == 2
            assert result[0]["port"] == 80

    def test_rust_returns_non_dict_items(self):
        mock_rust = MagicMock()
        mock_rust.parse_nmap_xml.return_value = [
            {"port": 80},
            "not a dict",
            123,
        ]
        with patch("siyarix.rust_accel._rust", mock_rust):
            result = parse_nmap_xml("<xml></xml>")
            assert result is not None
            assert len(result) == 1  # only the dict passes through

    def test_rust_returns_non_list(self):
        mock_rust = MagicMock()
        mock_rust.parse_nmap_xml.return_value = "not a list"
        with patch("siyarix.rust_accel._rust", mock_rust):
            result = parse_nmap_xml("<xml></xml>")
            assert result is None

    def test_rust_raises_exception(self):
        mock_rust = MagicMock()
        mock_rust.parse_nmap_xml.side_effect = RuntimeError("parse failed")
        with patch("siyarix.rust_accel._rust", mock_rust):
            result = parse_nmap_xml("<xml></xml>")
            assert result is None

    def test_rust_returns_empty_list(self):
        mock_rust = MagicMock()
        mock_rust.parse_nmap_xml.return_value = []
        with patch("siyarix.rust_accel._rust", mock_rust):
            result = parse_nmap_xml("<xml></xml>")
            assert result == []

    def test_runtime_import_failure(self):
        import builtins
        real_import = builtins.__import__
        def fake_import(name, *args, **kwargs):
            if name == "_rust_core":
                raise ImportError("no rust module")
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=fake_import):
            import importlib
            import siyarix.rust_accel
            importlib.reload(siyarix.rust_accel)
            assert siyarix.rust_accel.rust_available() is False

    def test_parse_nmap_xml_import_error_logged(self):
        # Test that when _rust is None at module level, parse_nmap_xml returns None
        with patch("siyarix.rust_accel._rust", None):
            result = parse_nmap_xml("<xml/>")
            assert result is None
