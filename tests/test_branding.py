from cosmicsec_agent.branding import (
    available_themes,
    canonical_theme,
    resolve_theme,
    severity_label,
)

def test_available_themes_contains_expected_values() -> None:
    themes = available_themes()
    assert "default" in themes
    assert "minimal" in themes
    assert "neon" in themes

def test_canonical_theme_resolves_aliases() -> None:
    assert canonical_theme("monokai") == "neon"
    assert canonical_theme("solarized") == "dark"
    assert canonical_theme("unknown-theme") is None

def test_severity_label_minimal_theme_has_no_icons() -> None:
    label = severity_label("minimal", "critical")
    assert label == "CRITICAL"

def test_resolve_theme_fallbacks_to_default() -> None:
    assert resolve_theme("unknown-theme") == "default"
