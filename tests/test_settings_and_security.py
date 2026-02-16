import hashlib
import json
from pathlib import Path

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.plugins.manager import PluginManager
from sentinel_x_defense_suite.security.validators import validate_capture_filter, validate_ip


def test_default_config_roundtrip(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.yaml"
    SettingsLoader.dump_default(cfg)
    loaded = SettingsLoader.load(cfg)
    assert loaded.app_name == "SENTINEL X DEFENSE SUITE"
    assert loaded.database.driver == "sqlite"
    assert loaded.plugins.dynamic_plugins_enabled is True


def test_validators() -> None:
    assert validate_ip("192.168.1.1")
    assert not validate_ip("999.1.1.1")
    assert validate_capture_filter("tcp.port == 443 and ip.src == 10.0.0.2")
    assert not validate_capture_filter("tcp.port == 443; rm -rf /")


def _plugin_source(name: str) -> str:
    return (
        f"class Plugin:\n"
        f"    name = '{name}'\n"
        f"    def on_packet(self, packet):\n"
        f"        return None\n"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_plugin_allowlist_loads_valid_plugin(tmp_path: Path, caplog) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    plugin = plugin_dir / "good_plugin.py"
    plugin.write_text(_plugin_source("good"), encoding="utf-8")
    manifest = plugin_dir / "allowlist.json"
    manifest.write_text(json.dumps({plugin.name: _sha256(plugin)}), encoding="utf-8")

    manager = PluginManager(str(plugin_dir), allowlist_manifest_path=manifest)
    manager.load()

    assert len(manager.plugins) == 1
    assert manager.plugins[0].name == "good"
    assert "plugin_load_rejected" not in caplog.text


def test_plugin_allowlist_rejects_altered_plugin(tmp_path: Path, caplog) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    plugin = plugin_dir / "tampered_plugin.py"
    plugin.write_text(_plugin_source("tampered"), encoding="utf-8")
    original_hash = _sha256(plugin)
    plugin.write_text(_plugin_source("tampered") + "\n# modified\n", encoding="utf-8")

    manifest = plugin_dir / "allowlist.json"
    manifest.write_text(json.dumps({plugin.name: original_hash}), encoding="utf-8")

    manager = PluginManager(str(plugin_dir), allowlist_manifest_path=manifest)
    manager.load()

    assert manager.plugins == []
    assert "plugin_hash_mismatch" in caplog.text


def test_plugin_allowlist_rejects_non_allowlisted_plugin(tmp_path: Path, caplog) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    plugin = plugin_dir / "unknown_plugin.py"
    plugin.write_text(_plugin_source("unknown"), encoding="utf-8")

    manifest = plugin_dir / "allowlist.json"
    manifest.write_text(json.dumps({"different.py": "0" * 64}), encoding="utf-8")

    manager = PluginManager(str(plugin_dir), allowlist_manifest_path=manifest)
    manager.load()

    assert manager.plugins == []
    assert "plugin_not_allowlisted" in caplog.text


def test_dynamic_plugins_can_be_disabled(tmp_path: Path, caplog) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    plugin = plugin_dir / "blocked_plugin.py"
    plugin.write_text(_plugin_source("blocked"), encoding="utf-8")

    manager = PluginManager(str(plugin_dir), dynamic_plugins_enabled=False)
    manager.load()

    assert manager.plugins == []
    assert "dynamic_plugins_disabled" in caplog.text
