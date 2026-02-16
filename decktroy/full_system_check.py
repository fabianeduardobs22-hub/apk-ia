#!/usr/bin/env python3
"""DECKTROY full startup self-check (defensive)."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLI = ROOT / "decktroy_cli.py"


def run(cmd: list[str], timeout: int = 25) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return {
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[:3000],
        "stderr": (proc.stderr or "")[:2000],
        "ok": proc.returncode in (0, 1, 2),
    }


def main() -> int:
    generated = datetime.now(timezone.utc).isoformat()
    tests = [
        run([sys.executable, str(CLI), "inventory"]),
        run([sys.executable, str(CLI), "assess"]),
        run([sys.executable, str(CLI), "advisor", "--environment", "auto"]),
        run([sys.executable, str(CLI), "threat-feed", "--environment", "auto", "--lines", "200"]),
        run([sys.executable, str(CLI), "services", "--action", "list"]),
        run([sys.executable, str(CLI), "connection-guard", "--mode", "analyze", "--duration", "5"]),
        run([sys.executable, str(CLI), "incident", "list"]),
        run([sys.executable, str(CLI), "startup", "-o", "/tmp/decktroy_startup_check.json"]),
        run([sys.executable, str(CLI), "playbook", "list"]),
        run([sys.executable, str(CLI), "web", "--help"]),
        run([sys.executable, str(CLI), "execute", "journalctl", "-p", "warning", "-n", "50"]),
    ]

    payload = {
        "generated_at": generated,
        "total": len(tests),
        "passed": sum(1 for t in tests if t["ok"]),
        "failed": sum(1 for t in tests if not t["ok"]),
        "results": tests,
    }

    report_file = Path("decktroy_full_system_check.json")
    report_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"Reporte guardado en {report_file}")

    return 0 if payload["failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
