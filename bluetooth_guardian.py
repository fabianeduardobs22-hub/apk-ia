#!/usr/bin/env python3
"""Guardian CLI: auditoría defensiva Bluetooth + WiFi para entornos autorizados."""

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
from typing import Dict, Iterable, List


@dataclass
class Device:
    mac: str
    name: str
    source: str
    protocol: str
    signal: str = "n/a"
    channel: str = "n/a"
    security: str = "n/a"


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
║                    GUARDIAN NETWORK CLI                       ║
║      Auditoría defensiva Bluetooth + WiFi (Termux/Linux)      ║
╚════════════════════════════════════════════════════════════════╝
""".strip("\n"),
        "96",
    )


def progress(title: str, steps: int = 20, delay: float = 0.025, style: str = "radar") -> None:
    frames = {
        "radar": ["◜", "◠", "◝", "◞", "◡", "◟"],
        "pulse": ["◐", "◓", "◑", "◒"],
    }
    seq = frames.get(style, frames["radar"])
    print(color(f"\n▶ {title}", "93"))
    for i in range(steps + 1):
        width = 34
        filled = int((i / max(steps, 1)) * width)
        bar = "█" * filled + "░" * (width - filled)
        percent = int((i / max(steps, 1)) * 100)
        frame = seq[i % len(seq)]
        sys.stdout.write(f"\r   {frame} [{bar}] {percent:3d}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def run_command(cmd: List[str], timeout: int = 20) -> str:
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def command_available(*names: str) -> str | None:
    for name in names:
        if shutil.which(name):
            return name
    return None


def is_termux() -> bool:
    return "TERMUX_VERSION" in __import__("os").environ or bool(shutil.which("termux-info"))


def unique_devices(devices: Iterable[Device]) -> List[Device]:
    seen: Dict[str, Device] = {}
    for dev in devices:
        key = f"{dev.protocol}:{dev.mac.upper()}"
        if key not in seen:
            seen[key] = dev
    return sorted(seen.values(), key=lambda d: (d.protocol, d.mac))


def parse_bluetoothctl_devices(output: str, source: str) -> List[Device]:
    found: List[Device] = []
    for line in output.splitlines():
        if line.startswith("Device "):
            parts = line.split(maxsplit=2)
            if len(parts) >= 3:
                found.append(Device(mac=parts[1], name=parts[2], source=source, protocol="bluetooth"))
    return found


def parse_hcitool_scan(output: str) -> List[Device]:
    found: List[Device] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("scanning"):
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) >= 2:
            found.append(Device(mac=parts[0], name=parts[1], source="hcitool", protocol="bluetooth"))
    return found


def parse_btmgmt_find(output: str) -> List[Device]:
    found: List[Device] = []
    pattern = re.compile(r"dev_found\s+([0-9A-F:]{17}).*?name\s+(.+)", re.IGNORECASE)
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            found.append(Device(mac=match.group(1), name=match.group(2).strip(), source="btmgmt", protocol="bluetooth"))
    return found


def parse_termux_bt(output: str) -> List[Device]:
    found: List[Device] = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    mac = item.get("address") or item.get("mac")
                    if mac:
                        found.append(
                            Device(
                                mac=str(mac),
                                name=str(item.get("name") or item.get("alias") or "unknown"),
                                source="termux-bluetooth-scan",
                                protocol="bluetooth",
                            )
                        )
    except json.JSONDecodeError:
        for line in output.splitlines():
            mac = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
            if mac:
                found.append(Device(mac=mac.group(1), name="unknown", source="termux-bluetooth-scan", protocol="bluetooth"))
    return found


def scan_bluetooth_devices() -> List[Device]:
    progress("Escaneando entorno Bluetooth", steps=16)
    found: List[Device] = []

    if command_available("termux-bluetooth-scan"):
        out = run_command(["termux-bluetooth-scan"], timeout=15)
        if out:
            found.extend(parse_termux_bt(out))

    if command_available("hcitool"):
        out = run_command(["hcitool", "scan"], timeout=25)
        if out:
            found.extend(parse_hcitool_scan(out))

    if command_available("btmgmt"):
        out = run_command(["btmgmt", "find"], timeout=12)
        if out:
            found.extend(parse_btmgmt_find(out))

    if command_available("bluetoothctl"):
        out_devices = run_command(["bluetoothctl", "devices"])
        out_paired = run_command(["bluetoothctl", "paired-devices"])
        found.extend(parse_bluetoothctl_devices(out_devices, "bluetoothctl"))
        found.extend(parse_bluetoothctl_devices(out_paired, "paired-devices"))

    return unique_devices(found)


def parse_nmcli_wifi(output: str) -> List[Device]:
    found: List[Device] = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        bssid, ssid, signal, channel, security = [p.strip() or "n/a" for p in parts[:5]]
        if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
            found.append(
                Device(
                    mac=bssid,
                    name=ssid or "hidden",
                    source="nmcli",
                    protocol="wifi",
                    signal=f"{signal}%" if signal != "n/a" else "n/a",
                    channel=channel,
                    security=security,
                )
            )
    return found


def parse_iw_scan(output: str, source: str) -> List[Device]:
    blocks = re.split(r"\nBSS ", "\n" + output)
    found: List[Device] = []
    for block in blocks:
        bssid_match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", block)
        if not bssid_match:
            continue
        bssid = bssid_match.group(1)
        ssid = re.search(r"\sSSID:\s*(.+)", block)
        signal = re.search(r"\ssignal:\s*([\-0-9\.]+\s*dBm)", block)
        channel = re.search(r"\sDS Parameter set: channel\s*(\d+)", block)
        security = "OPEN"
        if "RSN:" in block:
            security = "WPA2/WPA3"
        elif "WPA:" in block:
            security = "WPA"
        found.append(
            Device(
                mac=bssid,
                name=(ssid.group(1).strip() if ssid else "hidden"),
                source=source,
                protocol="wifi",
                signal=(signal.group(1) if signal else "n/a"),
                channel=(channel.group(1) if channel else "n/a"),
                security=security,
            )
        )
    return found


def parse_termux_wifi(output: str) -> List[Device]:
    found: List[Device] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return found

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            bssid = str(item.get("bssid") or "")
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                continue
            found.append(
                Device(
                    mac=bssid,
                    name=str(item.get("ssid") or "hidden"),
                    source="termux-wifi-scaninfo",
                    protocol="wifi",
                    signal=str(item.get("level") or item.get("signal") or "n/a"),
                    channel=str(item.get("frequency") or "n/a"),
                    security=str(item.get("capabilities") or "OPEN"),
                )
            )
    return found


def wifi_interfaces() -> List[str]:
    output = run_command(["sh", "-c", "ls /sys/class/net"], timeout=5)
    if not output:
        return []
    candidates = [iface.strip() for iface in output.splitlines() if iface.strip()]
    return [i for i in candidates if i.startswith(("wl", "wlan", "wifi"))]


def scan_wifi_networks() -> List[Device]:
    progress("Escaneando redes WiFi", steps=16)
    found: List[Device] = []

    if command_available("termux-wifi-scaninfo"):
        out = run_command(["termux-wifi-scaninfo"], timeout=20)
        if out:
            found.extend(parse_termux_wifi(out))

    if command_available("nmcli"):
        out = run_command(["nmcli", "-t", "-f", "BSSID,SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"], timeout=18)
        if out:
            found.extend(parse_nmcli_wifi(out))

    if command_available("iw"):
        for iface in wifi_interfaces() or ["wlan0"]:
            out = run_command(["iw", "dev", iface, "scan"], timeout=20)
            if out:
                found.extend(parse_iw_scan(out, f"iw:{iface}"))

    if command_available("iwlist"):
        for iface in wifi_interfaces() or ["wlan0"]:
            out = run_command(["iwlist", iface, "scanning"], timeout=20)
            if out:
                found.extend(parse_iw_scan(out, f"iwlist:{iface}"))

    return unique_devices(found)


def parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def get_bluetooth_info(mac: str) -> Dict[str, str]:
    if command_available("bluetoothctl"):
        output = run_command(["bluetoothctl", "info", mac])
        return parse_key_values(output) if output else {}
    return {}


def get_bluetooth_services(mac: str) -> List[str]:
    if not command_available("sdptool"):
        return []
    output = run_command(["sdptool", "browse", "--tree", mac], timeout=20)
    if not output:
        return []

    services: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('"') and line.endswith('"'):
            services.append(line.strip('"'))
    if not services:
        for line in output.splitlines():
            match = re.search(r"Service Name:\s*(.+)", line)
            if match:
                services.append(match.group(1).strip())
    return sorted(set(services))


def analyze_bluetooth_surface(device: Device, info: Dict[str, str], services: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    if info.get("Trusted", "no").lower() == "yes":
        findings.append(Finding("medium", "Dispositivo Trusted", "Confianza persistente activa.", "Revocar trust cuando no sea necesario."))
    if info.get("Paired", "no").lower() == "yes":
        findings.append(Finding("info", "Dispositivo emparejado", "Existe vínculo guardado.", "Verificar legitimidad del emparejamiento."))

    surface_map = {
        "OBEX": "Riesgo de fuga de archivos.",
        "Serial Port": "Canal RFCOMM requiere controles fuertes.",
        "Human Interface Device": "Revisar trust para perfiles de entrada.",
        "Audio Sink": "Mitigar pairing no autorizado y fingerprinting.",
    }
    joined = " | ".join(services)
    for k, risk in surface_map.items():
        if k.lower() in joined.lower():
            findings.append(Finding("medium", f"Superficie expuesta: {k}", risk, "Aplicar hardening y parches."))

    if not services:
        findings.append(Finding("info", "Sin respuesta SDP", f"No se pudieron listar servicios en {device.mac}.", "Repetir con permisos adecuados."))
    if not findings:
        findings.append(Finding("info", "Sin hallazgos críticos", "Chequeo básico sin señales de mala configuración.", "Mantener monitoreo continuo."))
    return findings


def analyze_wifi_surface(device: Device) -> List[Finding]:
    findings: List[Finding] = []
    sec = (device.security or "").upper()
    if "OPEN" in sec or sec.strip() in {"", "--"}:
        findings.append(Finding("high", "Red abierta detectada", "No usa autenticación robusta.", "Configurar WPA2/WPA3 con clave fuerte."))
    if "WEP" in sec:
        findings.append(Finding("high", "Cifrado WEP detectado", "WEP está obsoleto y es vulnerable.", "Migrar a WPA2/WPA3 de inmediato."))
    if device.signal not in {"n/a", ""}:
        findings.append(Finding("info", "Nivel de señal", f"Señal reportada: {device.signal}.", "Validar cobertura y potencia según política."))
    findings.append(Finding("info", "Canal reportado", f"Canal/frecuencia: {device.channel}.", "Optimizar canal para minimizar interferencias."))
    return findings


def print_devices(devices: List[Device]) -> None:
    print(color("\nActivos detectados", "92"))
    print("-" * 112)
    print(f"{'#':<4}{'Tipo':<12}{'MAC/BSSID':<22}{'Nombre/SSID':<28}{'Señal':<14}{'Canal':<10}{'Seguridad':<14}{'Fuente':<12}")
    print("-" * 112)
    if not devices:
        print(color("No se detectaron activos.", "91"))
    for idx, dev in enumerate(devices, start=1):
        print(
            f"{idx:<4}{dev.protocol:<12}{dev.mac:<22}{dev.name[:26]:<28}{dev.signal[:12]:<14}{dev.channel[:8]:<10}{dev.security[:12]:<14}{dev.source[:10]:<12}"
        )
    print("-" * 112)


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
        "tool": "Guardian Network CLI",
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
        findings_html = "".join(
            f"<li><strong>[{f.severity.upper()}]</strong> {f.title}<br><small>{f.detail}</small></li>" for f in result.findings
        ) or "<li>Sin hallazgos.</li>"
        services_html = "".join(f"<li>{s}</li>" for s in result.services) or "<li>N/A</li>"
        cards.append(
            f"""
            <section class='card'>
              <h2>{result.device.name} <span>{result.device.mac}</span></h2>
              <p><strong>Tipo:</strong> {result.device.protocol} | <strong>Fuente:</strong> {result.device.source}</p>
              <p><strong>Señal:</strong> {result.device.signal} | <strong>Canal:</strong> {result.device.channel} | <strong>Seguridad:</strong> {result.device.security}</p>
              <h3>Servicios / metadata</h3>
              <ul>{services_html}</ul>
              <h3>Hallazgos</h3>
              <ul>{findings_html}</ul>
            </section>
            """
        )

    html = f"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Guardian Network Report</title>
  <style>
    body {{ font-family: Inter, Arial, sans-serif; margin: 0; padding: 24px; background: #030712; color: #e2e8f0; }}
    .title {{ text-align: center; border: 1px solid #22d3ee; padding: 20px; border-radius: 12px; background: linear-gradient(120deg,#111827,#1f2937); }}
    .title h1 {{ margin: 0; color: #22d3ee; letter-spacing: 1px; }}
    .title p {{ color: #93c5fd; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(360px,1fr)); gap: 16px; margin-top: 18px; }}
    .card {{ border: 1px solid #334155; border-radius: 12px; background: #0f172a; padding: 14px; box-shadow: 0 0 16px rgba(34,211,238,.12); }}
    h2 {{ margin: 0 0 8px 0; color: #5eead4; }}
    h2 span {{ font-size: 12px; color: #bfdbfe; }}
    h3 {{ margin: 10px 0 6px 0; color: #fcd34d; }}
    footer {{ margin-top: 20px; text-align: center; color: #64748b; font-size: 12px; }}
  </style>
</head>
<body>
  <div class="title">
    <h1>Guardian Network // Reporte Defensivo</h1>
    <p>Bluetooth + WiFi, inventario y hardening en entornos autorizados.</p>
  </div>
  <div class="grid">{''.join(cards)}</div>
  <footer>Generado: {datetime.utcnow().isoformat()}Z</footer>
</body>
</html>
"""
    output.write_text(html, encoding="utf-8")
    print(color(f"Reporte HTML exportado: {output}", "92"))


def dependency_status() -> None:
    print(color("\nEstado de dependencias (no obligatorias)", "95"))
    deps = ("termux-bluetooth-scan", "termux-wifi-scaninfo", "hcitool", "btmgmt", "sdptool", "nmcli", "iw", "iwlist", "bluetoothctl")
    for cmd in deps:
        path = shutil.which(cmd)
        msg = f"  ✔ {cmd:<22} {path}" if path else f"  ⚠ {cmd:<22} no instalado"
        print(color(msg, "92" if path else "93"))


def menu() -> str:
    options = [
        "1) Escaneo Bluetooth",
        "2) Escaneo WiFi",
        "3) Escaneo combinado (Bluetooth + WiFi)",
        "4) Auditar activo por número",
        "5) Exportar reporte JSON",
        "6) Exportar reporte HTML",
        "7) Salir",
    ]
    print(color("\nPanel interactivo", "96"))
    for item in options:
        print(color(f"  {item}", "97"))
    return input(color("\nSelecciona una opción: ", "93")).strip()


def pick_device(devices: List[Device]) -> Device | None:
    if not devices:
        print(color("Primero ejecuta un escaneo.", "91"))
        return None
    print_devices(devices)
    raw = input(color("Ingresa el número del activo a auditar: ", "93")).strip()
    if not raw.isdigit():
        print(color("Entrada inválida.", "91"))
        return None
    idx = int(raw)
    if idx < 1 or idx > len(devices):
        print(color("Número fuera de rango.", "91"))
        return None
    return devices[idx - 1]


def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auditoría defensiva Bluetooth + WiFi para Termux y Linux.")
    parser.add_argument("--non-interactive", action="store_true", help="Ejecuta escaneo combinado y termina.")
    return parser.parse_args()


def main() -> int:
    args = cli()
    print(banner())
    print(color("Uso permitido: laboratorio propio y pentest autorizado.", "93"))
    print(color("No realiza explotación, acceso no autorizado ni denegación de servicio.", "91"))
    dependency_status()

    devices: List[Device] = []
    results: List[AuditResult] = []

    if args.non_interactive:
        devices = unique_devices(scan_bluetooth_devices() + scan_wifi_networks())
        print_devices(devices)
        return 0

    while True:
        choice = menu()

        if choice == "1":
            devices = scan_bluetooth_devices()
            print_devices(devices)
        elif choice == "2":
            devices = scan_wifi_networks()
            print_devices(devices)
        elif choice == "3":
            devices = unique_devices(scan_bluetooth_devices() + scan_wifi_networks())
            print_devices(devices)
        elif choice == "4":
            selected = pick_device(devices)
            if not selected:
                continue
            progress(f"Analizando {selected.protocol.upper()} {selected.mac}", steps=12, style="pulse")
            if selected.protocol == "bluetooth":
                info = get_bluetooth_info(selected.mac)
                services = get_bluetooth_services(selected.mac)
                findings = analyze_bluetooth_surface(selected, info, services)
            else:
                info = {
                    "signal": selected.signal,
                    "channel": selected.channel,
                    "security": selected.security,
                    "ssid": selected.name,
                }
                services = [f"Source: {selected.source}"]
                findings = analyze_wifi_surface(selected)
            print_findings(findings)
            results = [r for r in results if (r.device.protocol, r.device.mac) != (selected.protocol, selected.mac)]
            results.append(AuditResult(device=selected, info=info, services=services, findings=findings))
        elif choice == "5":
            if not results:
                print(color("No hay auditorías para exportar. Audita un activo primero.", "91"))
                continue
            export_json(results, Path("audit_report.json"))
        elif choice == "6":
            if not results:
                print(color("No hay auditorías para exportar. Audita un activo primero.", "91"))
                continue
            export_html(results, Path("audit_report.html"))
        elif choice == "7":
            print(color("\nFinalizado.", "96"))
            return 0
        else:
            print(color("Opción inválida. Intenta de nuevo.", "91"))


if __name__ == "__main__":
    raise SystemExit(main())
