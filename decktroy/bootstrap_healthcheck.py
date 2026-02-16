#!/usr/bin/env python3
"""DECKTROY bootstrap health-check (defensive only)."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class CheckResult:
    module: str
    status: str
    detail: str
    recommendation: str


class HealthCheck:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def add(self, module: str, status: str, detail: str, recommendation: str = "") -> None:
        self.results.append(CheckResult(module, status, detail, recommendation))

    def run_command(self, command: list[str], timeout: int = 4) -> tuple[bool, str]:
        try:
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (process.stdout or process.stderr).strip()
            return process.returncode == 0, output[:300] if output else "ok"
        except Exception as exc:  # pylint: disable=broad-except
            return False, str(exc)

    def check_binary(self, label: str, binary: str, recommendation: str) -> None:
        path = shutil.which(binary)
        if path:
            self.add(label, "pass", f"{binary} disponible en {path}")
        else:
            self.add(label, "warn", f"{binary} no encontrado", recommendation)

    def check_firewall(self) -> None:
        if shutil.which("ufw"):
            ok, output = self.run_command(["ufw", "status"])
            self.add(
                "firewall.ufw",
                "pass" if ok else "warn",
                output,
                "Activar y endurecer reglas de UFW" if not ok else "",
            )
            return

        if shutil.which("iptables"):
            ok, output = self.run_command(["iptables", "-S"])
            self.add(
                "firewall.iptables",
                "pass" if ok else "warn",
                output,
                "Verificar permisos/root y reglas base de iptables" if not ok else "",
            )
            return

        self.add(
            "firewall",
            "fail",
            "No se detectó UFW ni iptables",
            "Instalar y configurar un firewall de host",
        )

    def check_service(self, label: str, service_name: str, binary: str, recommendation: str) -> None:
        if not shutil.which(binary):
            self.add(label, "warn", f"{binary} no instalado", recommendation)
            return

        if shutil.which("systemctl"):
            ok, output = self.run_command(["systemctl", "is-active", service_name])
            status = "pass" if ok and "active" in output else "warn"
            self.add(label, status, f"systemd: {output}", recommendation if status != "pass" else "")
            return

        self.add(label, "pass", f"{binary} instalado (sin verificación systemd)")

    def check_alert_channel(self, host: str = "api.telegram.org", port: int = 443) -> None:
        try:
            with socket.create_connection((host, port), timeout=3):
                self.add(
                    "alerts.connectivity",
                    "pass",
                    f"Conectividad saliente validada hacia {host}:{port}",
                )
        except OSError as exc:
            self.add(
                "alerts.connectivity",
                "warn",
                f"Sin conectividad hacia {host}:{port}: {exc}",
                "Revisar salida HTTPS para integraciones Slack/Telegram/email",
            )

    def run(self) -> None:
        self.check_firewall()
        self.check_service(
            "intrusion.suricata",
            "suricata",
            "suricata",
            "Instalar/activar Suricata o conectar IDS equivalente",
        )
        self.check_service(
            "intrusion.fail2ban",
            "fail2ban",
            "fail2ban-client",
            "Instalar/activar Fail2Ban para control de fuerza bruta",
        )
        self.check_binary(
            "resource.python3",
            "python3",
            "Instalar Python 3 para módulo de monitoreo",
        )
        self.check_binary(
            "network.tcpdump",
            "tcpdump",
            "Instalar tcpdump/Wireshark para observabilidad de red",
        )
        self.check_alert_channel()

    def summary(self) -> dict[str, int]:
        counts = {"pass": 0, "warn": 0, "fail": 0}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return counts

    def exit_code(self) -> int:
        summary = self.summary()
        if summary.get("fail", 0) > 0:
            return 2
        if summary.get("warn", 0) > 0:
            return 1
        return 0

    def payload(self) -> dict:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(),
            "results": [asdict(r) for r in self.results],
            "exit_code": self.exit_code(),
        }

    def to_json(self) -> str:
        return json.dumps(self.payload(), indent=2, ensure_ascii=False)


def run_healthcheck() -> dict:
    checker = HealthCheck()
    checker.run()
    return checker.payload()


def main() -> int:
    payload = run_healthcheck()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return int(payload["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
