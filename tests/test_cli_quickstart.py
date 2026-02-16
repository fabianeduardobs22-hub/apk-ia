import sys
import types
from pathlib import Path

from sentinel_x_defense_suite.cli import app as cli_app


def test_quickstart_is_default_command(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "sentinel_test.yaml"
    launched = {"value": False}

    fake_gui_module = types.ModuleType("sentinel_x_defense_suite.gui.main_window")

    def _fake_launch_gui() -> None:
        launched["value"] = True

    fake_gui_module.launch_gui = _fake_launch_gui
    monkeypatch.setitem(sys.modules, "sentinel_x_defense_suite.gui.main_window", fake_gui_module)
    monkeypatch.setattr(sys, "argv", ["sentinel-x", "--config", str(config_path)])

    cli_app.main()

    assert config_path.exists()
    assert launched["value"]


def test_explicit_quickstart_command(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "explicit_quickstart.yaml"
    launched = {"value": 0}

    fake_gui_module = types.ModuleType("sentinel_x_defense_suite.gui.main_window")

    def _fake_launch_gui() -> None:
        launched["value"] += 1

    fake_gui_module.launch_gui = _fake_launch_gui
    monkeypatch.setitem(sys.modules, "sentinel_x_defense_suite.gui.main_window", fake_gui_module)
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinel-x", "--config", str(config_path), "quickstart"],
    )

    cli_app.main()

    assert config_path.exists()
    assert launched["value"] == 1
