# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest.mock import patch

from rich.console import Console

from siyarix.branding import (
    _SEVERITY_STYLES,
    available_themes,
    design_token,
    print_banner,
    print_theme_preview,
    resolve_theme,
    severity_label,
    severity_style,
)


class TestBranding:
    def test_available_themes(self):
        themes = available_themes()
        assert "cyber-noir" in themes
        assert "matrix" in themes
        assert "bloodmoon" in themes
        assert "arctic" in themes
        assert "goldenrod" in themes
        assert "eclipse" in themes
        assert "synthwave" in themes

    def test_resolve_theme_none(self):
        assert resolve_theme(None) == "cyber-noir"

    def test_resolve_theme_empty_string(self):
        assert resolve_theme("") == "cyber-noir"

    def test_resolve_theme_direct(self):
        assert resolve_theme("matrix") == "matrix"

    def test_resolve_theme_alias_monokai(self):
        assert resolve_theme("monokai") == "synthwave"

    def test_resolve_theme_alias_solarized(self):
        assert resolve_theme("solarized") == "arctic"

    def test_resolve_theme_alias_cyberpunk(self):
        assert resolve_theme("cyberpunk") == "cyber-noir"

    def test_resolve_theme_alias_hacker(self):
        assert resolve_theme("hacker") == "matrix"

    def test_resolve_theme_alias_red(self):
        assert resolve_theme("red") == "bloodmoon"

    def test_resolve_theme_alias_blue(self):
        assert resolve_theme("blue") == "arctic"

    def test_resolve_theme_alias_gold(self):
        assert resolve_theme("gold") == "goldenrod"

    def test_resolve_theme_alias_dark(self):
        assert resolve_theme("dark") == "cyber-noir"

    def test_resolve_theme_alias_light(self):
        assert resolve_theme("light") == "arctic"

    def test_resolve_theme_alias_neon(self):
        assert resolve_theme("neon") == "synthwave"

    def test_resolve_theme_alias_minimal(self):
        assert resolve_theme("minimal") == "eclipse"

    def test_resolve_theme_alias_system(self):
        assert resolve_theme("system") == "cyber-noir"

    def test_resolve_theme_alias_case_insensitive(self):
        assert resolve_theme("Monokai") == "synthwave"
        assert resolve_theme("SOLARIZED") == "arctic"

    def test_resolve_theme_unknown_fallback(self):
        assert resolve_theme("completely-unknown-theme") == "cyber-noir"

    def test_design_token(self):
        assert design_token("matrix", "accent") == "bright_green"
        assert design_token("unknown", "accent") == "bright_cyan"
        assert design_token("eclipse", "muted") == "dim"

    def test_design_token_missing_key(self):
        assert design_token("cyber-noir", "nonexistent") == ""

    def test_severity_style(self):
        assert severity_style("matrix", "critical") == "bold bright_red"
        assert severity_style("unknown", "critical") == "bold bright_red"

    def test_severity_style_unknown_severity(self):
        assert severity_style("cyber-noir", "unknown") == ""

    def test_severity_style_case_insensitive(self):
        assert severity_style("cyber-noir", "CRITICAL") == "bold bright_red"

    def test_severity_label_eclipse(self):
        label = severity_label("eclipse", "critical")
        assert label == "CRITICAL"

    def test_severity_label_normal_theme(self):
        label = severity_label("matrix", "critical")
        assert "CRITICAL" in label
        assert "🔴" in label

    def test_severity_label_warning_severity(self):
        label = severity_label("cyber-noir", "warning")
        assert "WARNING" in label
        assert "⚠️" in label

    def test_severity_label_finding_severity(self):
        label = severity_label("cyber-noir", "finding")
        assert "FINDING" in label

    def test_severity_label_unknown_severity(self):
        label = severity_label("cyber-noir", "unknown")
        assert "UNKNOWN" in label

    def test_print_banner(self):
        console = Console()
        print_banner(console, "matrix", subtitle="Custom Subtitle")

    @patch("importlib.metadata.version", return_value="3.0.0")
    def test_print_banner_with_version(self, mock_version):
        console = Console()
        print_banner(console, "cyber-noir")
        mock_version.assert_called_with("siyarix")

    @patch("importlib.metadata.version", side_effect=Exception("no package"))
    def test_print_banner_version_fallback(self, mock_version):
        console = Console()
        print_banner(console, "arctic")

    def test_print_theme_preview(self):
        console = Console()
        print_theme_preview(console, "synthwave")

    def test_print_theme_preview_eclipse(self):
        console = Console()
        print_theme_preview(console, "eclipse")

    def test_all_themes_have_required_keys(self):
        required = {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "accent",
            "primary",
            "muted",
            "success",
            "border",
        }
        for theme, styles in _SEVERITY_STYLES.items():
            missing = required - set(styles.keys())
            assert not missing, f"Theme '{theme}' missing keys: {missing}"

    def test_severity_style_with_unknown_theme_falls_back(self):
        assert severity_style("nonexistent", "high") == "bold red"

    def test_design_token_unknown_theme_falls_back(self):
        assert design_token("nonexistent", "primary") == "cyan"
