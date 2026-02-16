from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from sentinel_x_defense_suite.config.settings import SettingsLoader
from sentinel_x_defense_suite.core.logging_setup import configure_logging
from sentinel_x_defense_suite.core.orchestrator import run_default
from sentinel_x_defense_suite.forensics.repository import ForensicsRepository
from sentinel_x_defense_suite.security.runtime import PrivilegeError, enforce_live_capture_privileges


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-x", description="SENTINEL X DEFENSE SUITE")
    parser.add_argument("--config", default="sentinel_x.yaml", help="Ruta del archivo YAML")

    sub = parser.add_subparsers(dest="command", required=False)

    p_run = sub.add_parser("run", help="Monitoreo en tiempo real")
    p_run.add_argument("--max-packets", type=int, default=500)

    sub.add_parser("gui", help="Lanzar interfaz PyQt6")

    p_export = sub.add_parser("export-alerts", help="Exporta alertas a JSON")
    p_export.add_argument("--output", required=True)

    sub.add_parser("init-config", help="Genera YAML por defecto")
    sub.add_parser("quickstart", help="Prepara configuración inicial y lanza GUI")
    return parser


def _ensure_config(config_path: str) -> None:
    config_file = Path(config_path)
    if config_file.exists():
        return
    SettingsLoader.dump_default(config_path)
    print(f"[quickstart] Configuración base creada en {config_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    command = args.command or "quickstart"

    if command == "quickstart":
        _ensure_config(args.config)
        command = "gui"

    if command == "init-config":
        SettingsLoader.dump_default(args.config)
        print(f"Configuración creada en {args.config}")
        return

    settings = SettingsLoader.load(args.config)
    configure_logging(settings.log_level)

    if command == "run":
        try:
            enforce_live_capture_privileges(settings.capture.interface, settings.capture.replay_pcap)
        except PrivilegeError as exc:
            parser.error(str(exc))

        asyncio.run(
            run_default(
                db_path=settings.database.sqlite_path,
                plugin_dir="plugins",
                interface=settings.capture.interface,
                bpf_filter=settings.capture.bpf_filter,
                max_packets=args.max_packets,
            )
        )
    elif command == "gui":
        from sentinel_x_defense_suite.gui.main_window import launch_gui

        launch_gui()
    elif command == "export-alerts":
        data = ForensicsRepository(settings.database.sqlite_path).export_json()
        Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Alertas exportadas: {args.output}")


if __name__ == "__main__":
    main()
