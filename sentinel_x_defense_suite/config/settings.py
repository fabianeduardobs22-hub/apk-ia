from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - fallback en entornos offline
    yaml = None


@dataclass(slots=True)
class DatabaseSettings:
    driver: str = "sqlite"
    sqlite_path: str = "sentinel_x.db"
    postgres_dsn: str = ""
    encrypt_at_rest: bool = False


@dataclass(slots=True)
class CaptureSettings:
    interface: str = "any"
    bpf_filter: str = ""
    queue_maxsize: int = 5000
    replay_pcap: str | None = None
    simulate: bool = False


@dataclass(slots=True)
class DetectionSettings:
    max_connections_per_ip: int = 400
    brute_force_window_s: int = 120
    brute_force_threshold: int = 25
    beaconing_interval_tolerance_s: int = 3
    enable_ml_module: bool = False


@dataclass(slots=True)
class AppSettings:
    app_name: str = "SENTINEL X DEFENSE SUITE"
    log_level: str = "INFO"
    timezone: str = "UTC"
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)


class SettingsLoader:
    @staticmethod
    def _loads(text: str) -> dict[str, Any]:
        if yaml is not None:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("Configuración inválida")
        return data

    @staticmethod
    def _dumps(payload: dict[str, Any]) -> str:
        if yaml is not None:
            return yaml.safe_dump(payload, sort_keys=False)
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @staticmethod
    def load(path: str | Path) -> AppSettings:
        content = SettingsLoader._loads(Path(path).read_text(encoding="utf-8"))

        db = DatabaseSettings(**content.get("database", {}))
        capture = CaptureSettings(**content.get("capture", {}))
        detection = DetectionSettings(**content.get("detection", {}))

        return AppSettings(
            app_name=content.get("app_name", "SENTINEL X DEFENSE SUITE"),
            log_level=content.get("log_level", "INFO"),
            timezone=content.get("timezone", "UTC"),
            database=db,
            capture=capture,
            detection=detection,
        )

    @staticmethod
    def dump_default(path: str | Path) -> None:
        defaults = AppSettings()
        payload: dict[str, Any] = {
            "app_name": defaults.app_name,
            "log_level": defaults.log_level,
            "timezone": defaults.timezone,
            "database": asdict(defaults.database),
            "capture": asdict(defaults.capture),
            "detection": asdict(defaults.detection),
        }
        Path(path).write_text(SettingsLoader._dumps(payload), encoding="utf-8")
