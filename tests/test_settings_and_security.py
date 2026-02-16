from pathlib import Path

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.security.validators import validate_capture_filter, validate_ip


def test_default_config_roundtrip(tmp_path: Path) -> None:
    cfg = tmp_path / "sentinel.yaml"
    SettingsLoader.dump_default(cfg)
    loaded = SettingsLoader.load(cfg)
    assert loaded.app_name == "SENTINEL X DEFENSE SUITE"
    assert loaded.database.driver == "sqlite"


def test_validators() -> None:
    assert validate_ip("192.168.1.1")
    assert not validate_ip("999.1.1.1")
    assert validate_capture_filter("tcp.port == 443 and ip.src == 10.0.0.2")
    assert not validate_capture_filter("tcp.port == 443; rm -rf /")
