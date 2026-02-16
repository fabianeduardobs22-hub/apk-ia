#!/usr/bin/env python3
"""Bluetooth Guardian CLI: auditoría defensiva Bluetooth para entornos autorizados.

Esta utilidad NO explota vulnerabilidades ni obtiene acceso no autorizado.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List


@dataclass
class Device:
    mac: str
    name: str
    source: str


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    recommendation: str


@dataclass
class AuditResult:
    device: Device
    info: Dict[str, str] = field(default_factory=dict)
    services: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def banner() -> str:
    return color(
        """
╔════════════════════════════════════════════════════════════════╗
║                    BLUETOOTH GUARDIAN CLI                    ║
║            Auditoría defensiva interactiva de laboratorio     ║
╚════════════════════════════════════════════════════════════════╝
""".strip("\n"),
        "96",
    )


def progress(title: str, steps: int = 20, delay: float = 0.03) -> None:
    print(color(f"\n▶ {title}", "93"))
    for i in range(steps + 1):
        width = 34
        filled = int((i / steps) * width)
        bar = "█" * filled + "░" * (width - filled)
        percent = int((i / steps) * 100)
        sys.stdout.write(f"\r   [{bar}] {percent:3d}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def run_command(cmd: List[str], timeout: int = 20) -> str:
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
        return output.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def parse_bluetoothctl_devices(output: str, source: str) -> List[Device]:
    devices: List[Device] = []
    for line in output.splitlines():
        if line.startswith("Device "):
            parts = line.split(maxsplit=2)
            if len(parts) >= 3:
                devices.append(Device(mac=parts[1], name=parts[2], source=source))
    return devices


def parse_hcitool_scan(output: str) -> List[Device]:
    devices: List[Device] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("scanning"):
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) >= 2:
            devices.append(Device(mac=parts[0], name=parts[1], source="hcitool"))
    return devices


def unique_devices(devices: List[Device]) -> List[Device]:
    seen: Dict[str, Device] = {}
    for d in devices:
        key = d.mac.upper()
        if key not in seen:
            seen[key] = d
    return sorted(seen.values(), key=lambda x: x.mac)


def scan_devices() -> List[Device]:
    progress("Escaneando entorno Bluetooth", steps=18)
    found: List[Device] = []

    out_btctl = run_command(["bluetoothctl", "devices"])
    if out_btctl:
        found.extend(parse_bluetoothctl_devices(out_btctl, "bluetoothctl"))

    out_paired = run_command(["bluetoothctl", "paired-devices"])
    if out_paired:
        found.extend(parse_bluetoothctl_devices(out_paired, "paired-devices"))

    out_hci = run_command(["hcitool", "scan"], timeout=25)
    if out_hci:
        found.extend(parse_hcitool_scan(out_hci))

    return unique_devices(found)


def parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def get_device_info(mac: str) -> Dict[str, str]:
    output = run_command(["bluetoothctl", "info", mac])
    return parse_key_values(output) if output else {}


def get_device_services(mac: str) -> List[str]:
    output = run_command(["sdptool", "browse", "--tree", mac], timeout=20)
    if not output:
        return []

    services: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('"') and line.endswith('"'):
            services.append(line.strip('"'))

    if not services:
        pattern = re.compile(r"Service Name:\s*(.+)")
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                services.append(match.group(1).strip())

    return sorted(set(services))


def analyze_attack_surface(device: Device, info: Dict[str, str], services: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    if info.get("Trusted", "no").lower() == "yes":
        findings.append(
            Finding(
                severity="medium",
                title="Dispositivo marcado como Trusted",
                detail="La confianza persistente puede facilitar reconexiones automáticas no deseadas.",
                recommendation="Revisar y revocar confianza cuando no sea estrictamente necesaria.",
            )
        )

    if info.get("Paired", "no").lower() == "yes":
        findings.append(
            Finding(
                severity="info",
                title="Dispositivo emparejado",
                detail="Existe vínculo de emparejamiento previo en el host local.",
                recommendation="Validar que el emparejamiento siga siendo legítimo y vigente.",
            )
        )

    surface_map = {
        "OBEX": "Transferencia de archivos puede exponer fuga de información.",
        "Serial Port": "Canales seriales RFCOMM deben auditar autenticación y autorización.",
        "Human Interface Device": "Perfiles de entrada requieren control estricto de trust.",
        "Audio Sink": "Perfiles de audio pueden abrir vectores de fingerprinting/abuso de pairing.",
    }

    joined = " | ".join(services)
    for keyword, risk in surface_map.items():
        if keyword.lower() in joined.lower():
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Superficie expuesta detectada: {keyword}",
                    detail=risk,
                    recommendation="Restringir visibilidad, verificar parches y endurecer políticas de emparejamiento.",
                )
            )

    if not services:
        findings.append(
            Finding(
                severity="info",
                title="Sin respuesta de servicios SDP",
                detail=f"No fue posible enumerar servicios en {device.mac}.",
                recommendation="Confirmar que sdptool esté disponible y repetir en ventana autorizada.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Sin hallazgos críticos en chequeo básico",
                detail="No se detectaron señales claras de mala configuración en la revisión no intrusiva.",
                recommendation="Mantener monitoreo continuo y actualización de BlueZ/firmware.",
            )
        )

    return findings


def print_devices(devices: List[Device]) -> None:
    print(color("\nDispositivos detectados", "92"))
    print("-" * 74)
    print(f"{'#':<4}{'MAC':<22}{'Nombre':<30}{'Fuente':<16}")
    print("-" * 74)
    if not devices:
        print(color("No se detectaron dispositivos.", "91"))
    for idx, dev in enumerate(devices, start=1):
        print(f"{idx:<4}{dev.mac:<22}{dev.name[:28]:<30}{dev.source:<16}")
    print("-" * 74)


def print_findings(findings: List[Finding]) -> None:
    severity_color = {"high": "91", "medium": "93", "info": "96"}
    print(color("\nHallazgos del análisis", "94"))
    for finding in findings:
        sev = color(f"[{finding.severity.upper()}]", severity_color.get(finding.severity, "97"))
        print(f"  {sev} {finding.title}")
        print(f"      Detalle: {finding.detail}")
        print(f"      Acción : {finding.recommendation}")


def export_json(results: List[AuditResult], output: Path) -> None:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "tool": "Bluetooth Guardian CLI",
        "purpose": "auditoria_defensiva",
        "results": [
            {
                "device": asdict(result.device),
                "info": result.info,
                "services": result.services,
                "findings": [asdict(f) for f in result.findings],
            }
            for result in results
        ],
    }
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(color(f"\nReporte JSON exportado: {output}", "92"))


def export_html(results: List[AuditResult], output: Path) -> None:
    cards: List[str] = []
    for result in results:
        finding_rows = "".join(
            f"<li><strong>[{f.severity.upper()}]</strong> {f.title}<br><small>{f.detail}</small></li>"
            for f in result.findings
        ) or "<li>Sin hallazgos.</li>"
        services_rows = "".join(f"<li>{s}</li>" for s in result.services) or "<li>Sin respuesta SDP.</li>"
        cards.append(
            f"""
            <section class='card'>
              <h2>{result.device.name} <span>{result.device.mac}</span></h2>
              <p><strong>Fuente:</strong> {result.device.source}</p>
              <h3>Servicios detectados</h3>
              <ul>{services_rows}</ul>
              <h3>Hallazgos</h3>
              <ul>{finding_rows}</ul>
            </section>
            """
        )

    html = f"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Bluetooth Guardian Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #06080f; color: #d4f6ff; margin: 0; padding: 24px; }}
    .title {{ text-align: center; padding: 20px; border: 1px solid #ff365e; background: linear-gradient(90deg,#17000a,#0d0d2d); }}
    .title h1 {{ margin: 0; color: #ff4f79; text-transform: uppercase; letter-spacing: 2px; }}
    .title p {{ color: #9ef7ff; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(360px,1fr)); gap: 16px; margin-top: 18px; }}
    .card {{ border: 1px solid #2de2e6; padding: 14px; border-radius: 10px; background: #0a1225; box-shadow: 0 0 20px rgba(45,226,230,.15); }}
    h2 {{ color: #2de2e6; margin: 0 0 8px 0; }}
    h2 span {{ font-size: 12px; color: #9ef7ff; }}
    h3 {{ color: #ffb703; margin-bottom: 6px; }}
    li {{ margin-bottom: 6px; }}
    footer {{ margin-top: 22px; color: #8bb5be; text-align: center; font-size: 12px; }}
  </style>
</head>
<body>
  <div class="title">
    <h1>Bluetooth Guardian // Security Report</h1>
    <p>Visual estilo cyber-lab (solo estética), uso defensivo y autorizado.</p>
  </div>
  <div class="grid">{''.join(cards)}</div>
  <footer>Generado: {datetime.utcnow().isoformat()}Z</footer>
</body>
</html>
"""
    output.write_text(html, encoding="utf-8")
    print(color(f"Reporte HTML exportado: {output}", "92"))


def dependency_status() -> None:
    print(color("\nEstado de dependencias", "95"))
    for cmd in ("bluetoothctl", "hcitool", "sdptool"):
        path = shutil.which(cmd)
        if path:
            print(color(f"  ✔ {cmd:<12} en {path}", "92"))
        else:
            print(color(f"  ✖ {cmd:<12} no instalado", "91"))


def menu() -> str:
    options = [
        "1) Escanear dispositivos",
        "2) Auditar dispositivo por número",
        "3) Exportar reporte JSON",
        "4) Exportar reporte HTML",
        "5) Salir",
    ]
    print(color("\nPanel interactivo", "96"))
    for item in options:
        time.sleep(0.08)
        print(color(f"  {item}", "97"))
    return input(color("\nSelecciona una opción: ", "93")).strip()


def pick_device(devices: List[Device]) -> Device | None:
    if not devices:
        print(color("Primero debes ejecutar el escaneo.", "91"))
        return None
    print_devices(devices)
    raw = input(color("Ingresa el número del dispositivo a auditar: ", "93")).strip()
    if not raw.isdigit():
        print(color("Entrada inválida.", "91"))
        return None
    idx = int(raw)
    if idx < 1 or idx > len(devices):
        print(color("Número fuera de rango.", "91"))
        return None
    return devices[idx - 1]

def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auditoría Bluetooth defensiva con interfaz interactiva.")
    parser.add_argument("--non-interactive", action="store_true", help="Ejecuta escaneo rápido y termina.")
    return parser.parse_args()


def main() -> int:
    args = cli()
    print(banner())
    print(color("Uso permitido: laboratorio propio y pentest autorizado.", "93"))
    print(color("No realiza explotación, bypass de autenticación ni reverse shell.", "91"))

    dependency_status()
    devices: List[Device] = []
    results: List[AuditResult] = []

    if args.non_interactive:
        devices = scan_devices()
        print_devices(devices)
        return 0

    while True:
        choice = menu()

        if choice == "1":
            devices = scan_devices()
            print_devices(devices)
        elif choice == "2":
            selected = pick_device(devices)
            if not selected:
                continue
            progress(f"Analizando superficie de {selected.mac}", steps=14)
            info = get_device_info(selected.mac)
            services = get_device_services(selected.mac)
            findings = analyze_attack_surface(selected, info, services)
            print_findings(findings)
            results = [r for r in results if r.device.mac != selected.mac]
            results.append(AuditResult(device=selected, info=info, services=services, findings=findings))
        elif choice == "3":
            if not results:
                print(color("No hay auditorías para exportar. Audita un dispositivo primero.", "91"))
                continue
            export_json(results, Path("audit_report.json"))
        elif choice == "4":
            if not results:
                print(color("No hay auditorías para exportar. Audita un dispositivo primero.", "91"))
                continue
            export_html(results, Path("audit_report.html"))
        elif choice == "5":
            print(color("\nFinalizado.", "96"))
            return 0
        else:
            print(color("Opción inválida. Intenta de nuevo.", "91"))


if __name__ == "__main__":
    raise SystemExit(main())
