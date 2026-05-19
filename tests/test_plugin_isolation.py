from nexsec.plugins import PluginManager


def test_plugin_isolation(tmp_path):
    # Create a plugin that raises during register
    plugins_root = tmp_path / "plugins"
    plugins_root.mkdir()

    bad_plugin = plugins_root / "badplugin"
    bad_plugin.mkdir()
    (bad_plugin / "plugin.yaml").write_text("name: badplugin\nenabled: true\n")
    (bad_plugin / "commands.py").write_text(
        "def register(app):\n    raise RuntimeError('plugin failure')\n",
        encoding="utf-8",
    )

    manager = PluginManager(root=plugins_root)

    # Loading command plugins should not raise even though the plugin register raises
    loaded = manager.load_command_plugins(app=None)
    assert isinstance(loaded, list)
    assert "badplugin" not in loaded

    # Parser plugin that raises on import
    bad_parser = plugins_root / "badparser"
    bad_parser.mkdir()
    (bad_parser / "plugin.yaml").write_text("name: badparser\nenabled: true\n")
    (bad_parser / "parser.py").write_text(
        "raise Exception('failed during import')\n\ndef parse_tool_output(s):\n    return []\n",
        encoding="utf-8",
    )

    parsers = manager.load_parser_plugins()
    assert isinstance(parsers, dict)
    assert "badparser" not in parsers
