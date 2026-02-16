#!/usr/bin/env python3
"""DECKTROY runtime monitor.

Verificador simple de ejecución integral para confirmar que los flujos
principales de DECKTROY responden correctamente sin modificar la arquitectura
ni forzar acciones destructivas.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CLI = ROOT / "decktroy_cli.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_step(name: str, cmd: list[str], timeout: int = 25, ok_codes: tuple[int, ...] = (0, 1, 2)) -> dict[str, Any]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return {
        "name": name,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "ok": proc.returncode in ok_codes,
        "stdout": (proc.stdout or "")[:2500],
        "stderr": (proc.stderr or "")[:1500],
        "ts": utc_now(),
    }


def build_monitor_payload(output_path: str | None = None) -> dict[str, Any]:
    checks = [
        run_step("cli_help", [sys.executable, str(CLI), "--help"], timeout=15, ok_codes=(0,)),
        run_step("inventory", [sys.executable, str(CLI), "inventory"], timeout=20, ok_codes=(0,)),
        run_step("assess", [sys.executable, str(CLI), "assess"], timeout=20, ok_codes=(0, 2)),
        run_step("startup", [sys.executable, str(CLI), "startup", "-o", "/tmp/decktroy_startup_runtime.json"], timeout=30, ok_codes=(0, 1, 2)),
        run_step("connection_guard", [sys.executable, str(CLI), "connection-guard", "--mode", "analyze", "--duration", "3"], timeout=20, ok_codes=(0, 2)),
        run_step("incident_list", [sys.executable, str(CLI), "incident", "list"], timeout=20, ok_codes=(0,)),
        run_step("selftest", [sys.executable, str(CLI), "selftest"], timeout=60, ok_codes=(0, 2)),
    ]

    payload = {
        "generated_at": utc_now(),
        "tool": "decktroy-runtime-monitor",
        "checks_total": len(checks),
        "checks_ok": sum(1 for item in checks if item["ok"]),
        "checks_failed": sum(1 for item in checks if not item["ok"]),
        "status": "ok" if all(item["ok"] for item in checks) else "warning",
        "checks": checks,
        "notes": [
            "El monitor valida disponibilidad operativa de comandos clave.",
            "Códigos 1/2 pueden ser esperados en entornos sin systemd/firewall/IDS completos.",
            "No ejecuta acciones ofensivas ni cambios destructivos por defecto.",
        ],
    }

    if output_path:
        Path(output_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor de ejecución integral de DECKTROY.")
    parser.add_argument("-o", "--output", help="Ruta opcional para guardar reporte JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_monitor_payload(output_path=args.output)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if args.output:
        print(f"Reporte runtime guardado en {args.output}")
    return 0 if payload["checks_failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())

