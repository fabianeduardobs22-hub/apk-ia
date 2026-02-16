#!/usr/bin/env python3
"""Bluetooth Guardian CLI: auditoría defensiva Bluetooth para entornos autorizados.

Esta utilidad NO explota vulnerabilidades ni obtiene acceso no autorizado.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import importlib
import importlib.util
import asyncio
from dataclasses import dataclass, field
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


EXTERNAL_TOOL_CANDIDATES: Dict[str, List[List[str]]] = {
    # Soporte defensivo: solamente inventario/descubrimiento y parseo de salida.
    "BTScanner": [["btscanner", "-h"], ["btscanner", "-s"]],
    "ScannerBleah": [["bleah", "scan"], ["bleah", "-h"]],
    "BlueBorne": [["python3", "blueborne_scan.py", "--help"]],
}


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def banner() -> str:
    return color(
        """
╔═══════════════════════════════════════════════════════════════════════╗
║                         BLUETOOTH GUARDIAN CLI                       ║
║         Suite defensiva unificada (inventario + postura + parseo)    ║
╚═══════════════════════════════════════════════════════════════════════╝
""".strip("\n"),
        "96",
    )


def progress(title: str, steps: int = 20, delay: float = 0.025, style: str = "matrix") -> None:
    print(color(f"\n▶ {title}", "93"))
    symbols = {
        "matrix": ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"],
        "pulse": ["◐", "◓", "◑", "◒"],
        "radar": ["◜", "◠", "◝", "◞", "◡", "◟"],
    }
    anim = symbols.get(style, symbols["matrix"])
    for i in range(steps + 1):
        width = 34
        filled = int((i / steps) * width)
        frame = anim[i % len(anim)]
        bar = "█" * filled + "░" * (width - filled)
        percent = int((i / steps) * 100)
        sys.stdout.write(f"\r   {frame} [{bar}] {percent:3d}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def run_command(cmd: List[str], timeout: int = 20) -> str:
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
        return output.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def parse_mac_lines(text: str, source_name: str) -> List[Device]:
    pattern = re.compile(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})(?:\s+([^\n\r]+))?", re.I)
    devices: List[Device] = []
    for line in text.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        mac = m.group(1).upper()
        name = (m.group(2) or "unknown").strip()
        devices.append(Device(mac=mac, name=name[:42], source=source_name))
    return devices


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


def parse_btmgmt_find(output: str) -> List[Device]:
    devices: List[Device] = []
    pattern = re.compile(
        r"dev_found\s+([0-9A-F:]{17})\s+type\s+\S+\s+rssi\s+[-0-9]+\s+flags\s+\S+\s+eir_len\s+\d+\s+name\s+(.+)",
        re.I,
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            devices.append(Device(mac=m.group(1).upper(), name=m.group(2).strip(), source="btmgmt"))
    return devices


def unique_devices(devices: List[Device]) -> List[Device]:
    seen: Dict[str, Device] = {}
    for d in devices:
        key = d.mac.upper()
        if key not in seen:
            seen[key] = d
    return sorted(seen.values(), key=lambda x: x.mac)


def bluetoothctl_active_scan(seconds: int = 8) -> List[Device]:
    if not shutil.which("bluetoothctl"):
        return []
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert proc.stdin is not None
        proc.stdin.write("scan on\n")
        proc.stdin.flush()
        time.sleep(max(3, seconds))
        proc.stdin.write("devices\n")
        proc.stdin.write("scan off\n")
        proc.stdin.write("quit\n")
        proc.stdin.flush()
        output, _ = proc.communicate(timeout=14)
        return parse_bluetoothctl_devices(output, "bluetoothctl-active")
    except (subprocess.SubprocessError, OSError):
        return []


def scan_with_bleak(timeout_seconds: int = 8) -> List[Device]:
    """Escaneo usando librería Python bleak (si está disponible)."""
    if importlib.util.find_spec("bleak") is None:
        return []

    try:
        bleak = importlib.import_module("bleak")
    except Exception:
        return []

    async def _run() -> List[Device]:
        devices: List[Device] = []
        try:
            scanner = bleak.BleakScanner()
            discovered = await scanner.discover(timeout=timeout_seconds)
            for d in discovered:
                mac = (getattr(d, "address", "") or "").upper()
                if not mac:
                    continue
                name = (getattr(d, "name", None) or "unknown").strip()
                devices.append(Device(mac=mac, name=name, source="python-bleak"))
        except Exception:
            return []
        return devices

    try:
        return asyncio.run(_run())
    except Exception:
        return []


def scan_with_pybluez() -> List[Device]:
    """Escaneo usando pybluez (módulo bluetooth) si está disponible."""
    if importlib.util.find_spec("bluetooth") is None:
        return []

    try:
        bluetooth = importlib.import_module("bluetooth")
    except Exception:
        return []

    try:
        nearby = bluetooth.discover_devices(duration=8, lookup_names=True)
    except Exception:
        return []

    devices: List[Device] = []
    for item in nearby:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            mac = str(item[0]).upper().strip()
            name = str(item[1]).strip() if item[1] else "unknown"
        else:
            mac = str(item).upper().strip()
            name = "unknown"
        if mac:
            devices.append(Device(mac=mac, name=name, source="python-pybluez"))
    return devices


def termux_scan_devices() -> List[Device]:
    """Escaneo Bluetooth en Termux usando termux-api (si está disponible)."""
    if shutil.which("termux-bluetooth-scan") is None:
        return []

    # Algunas versiones aceptan --help, otras solo ejecución directa.
    output = run_command(["termux-bluetooth-scan"], timeout=25)
    if not output:
        return []

    devices: List[Device] = []
    try:
        payload = json.loads(output)
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                mac = (item.get("address") or item.get("mac") or "").upper().strip()
                if not mac:
                    continue
                name = (item.get("name") or item.get("alias") or "unknown").strip()
                devices.append(Device(mac=mac, name=name, source="termux-bluetooth-scan"))
    except json.JSONDecodeError:
        # fallback por si la salida no es JSON estructurado
        devices.extend(parse_mac_lines(output, "termux-bluetooth-scan"))

    return devices


def scan_devices() -> List[Device]:
    progress("Escaneando entorno Bluetooth (multi-motor)", steps=20, style="radar")
    found: List[Device] = []

    # 1) Backends Python puros (sin depender de binarios del sistema)
    progress("Motor Python: bleak", steps=6, style="pulse", delay=0.012)
    found.extend(scan_with_bleak(timeout_seconds=6))

    progress("Motor Python: pybluez", steps=6, style="pulse", delay=0.012)
    found.extend(scan_with_pybluez())

    # 2) Termux API
    if detect_platform() == "termux":
        progress("Motor Termux: termux-bluetooth-scan", steps=6, style="pulse", delay=0.012)
        found.extend(termux_scan_devices())

    # 3) Herramientas del sistema Linux (si están disponibles)
    out_btctl = run_command(["bluetoothctl", "devices"])
    if out_btctl:
        found.extend(parse_bluetoothctl_devices(out_btctl, "bluetoothctl"))

    out_paired = run_command(["bluetoothctl", "paired-devices"])
    if out_paired:
        found.extend(parse_bluetoothctl_devices(out_paired, "paired-devices"))

    found.extend(bluetoothctl_active_scan(seconds=6))

    out_hci = run_command(["hcitool", "scan"], timeout=30)
    if out_hci:
        found.extend(parse_hcitool_scan(out_hci))

    out_btmgmt = run_command(["btmgmt", "find"], timeout=12)
    if out_btmgmt:
        found.extend(parse_btmgmt_find(out_btmgmt))

    return unique_devices(found)


def run_external_tool_adapter() -> List[Device]:
    """Intenta comandos de herramientas externas y parsea inventario no intrusivo."""
    progress("Intentando adaptadores de herramientas externas", steps=10, style="matrix")
    merged: List[Device] = []

    for tool_name, commands in EXTERNAL_TOOL_CANDIDATES.items():
        got_output = False
        for cmd in commands:
            if shutil.which(cmd[0]) is None and not Path(cmd[0]).exists():
                continue
            output = run_command(cmd, timeout=15)
            if output:
                got_output = True
                merged.extend(parse_mac_lines(output, f"adapter:{tool_name}"))
                break
        if got_output:
            print(color(f"  ✔ Adaptador {tool_name} produjo salida parseable", "92"))
        else:
            print(color(f"  ⚠ Adaptador {tool_name} no disponible/sin salida", "93"))

    return unique_devices(merged)


def parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def get_device_info(mac: str) -> Dict[str, str]:
    if detect_platform() == "termux":
        # Termux no siempre provee "info" detallado por MAC; se intenta derivar desde escaneo.
        for d in termux_scan_devices():
            if d.mac.upper() == mac.upper():
                return {"Address": d.mac, "Name": d.name, "Source": d.source}
        return {}

    output = run_command(["bluetoothctl", "info", mac])
    return parse_key_values(output) if output else {}


def get_device_services(mac: str) -> List[str]:
    if detect_platform() == "termux":
        # En Termux normalmente no está sdptool; se devuelve vacío con enfoque no intrusivo.
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
        pattern = re.compile(r"Service Name:\s*(.+)")
        for line in output.splitlines():
            m = pattern.search(line)
            if m:
                services.append(m.group(1).strip())

    return sorted(set(services))


def detect_platform() -> str:
    if "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    return "linux"


def discover_host_network() -> Dict[str, str]:
    info: Dict[str, str] = {
        "platform": detect_platform(),
        "public_ip": "no-disponible",
        "wifi_ssid": "no-disponible",
        "wifi_bssid": "no-disponible",
        "interface": "no-disponible",
        "gateway": "no-disponible",
    }

    ip_route = run_command(["ip", "route"]) or run_command(["route", "-n"])
    if ip_route:
        default_line = ""
        for line in ip_route.splitlines():
            if line.startswith("default ") or line.startswith("0.0.0.0"):
                default_line = line
                break
        if default_line:
            parts = default_line.split()
            if "via" in parts:
                info["gateway"] = parts[parts.index("via") + 1]
            if "dev" in parts:
                info["interface"] = parts[parts.index("dev") + 1]

    ssid = run_command(["iwgetid", "-r"])
    if ssid:
        info["wifi_ssid"] = ssid

    nmcli = run_command(["nmcli", "-t", "-f", "active,ssid,bssid", "dev", "wifi"])
    if nmcli:
        for line in nmcli.splitlines():
            if line.startswith("yes:"):
                cols = line.split(":")
                if len(cols) >= 3:
                    info["wifi_ssid"] = cols[1] or info["wifi_ssid"]
                    info["wifi_bssid"] = cols[2] or info["wifi_bssid"]
                break

    termux_wifi = run_command(["termux-wifi-connectioninfo"])
    if termux_wifi:
        try:
            parsed = json.loads(termux_wifi)
            info["wifi_ssid"] = parsed.get("ssid") or info["wifi_ssid"]
            info["wifi_bssid"] = parsed.get("bssid") or info["wifi_bssid"]
            info["interface"] = parsed.get("interface") or info["interface"]
        except json.JSONDecodeError:
            pass

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as resp:
            info["public_ip"] = resp.read().decode().strip()
    except Exception:
        pass

    return info


def blueborne_posture_assessment() -> List[Finding]:
    findings: List[Finding] = []
    kernel = platform.release()
    bluez_version = run_command(["bluetoothd", "-v"]) or "desconocida"

    findings.append(
        Finding(
            severity="info",
            title="Versión de kernel detectada",
            detail=f"Kernel local: {kernel}",
            recommendation="Comparar con advisories de tu distro y aplicar parches.",
        )
    )
    findings.append(
        Finding(
            severity="info",
            title="Versión de bluetoothd/BlueZ detectada",
            detail=f"BlueZ reportado: {bluez_version}",
            recommendation="Mantener BlueZ actualizado para reducir exposición a CVEs conocidas.",
        )
    )

    if bluez_version != "desconocida":
        nums = re.findall(r"\d+", bluez_version)
        if len(nums) >= 2:
            major, minor = int(nums[0]), int(nums[1])
            if major < 5 or (major == 5 and minor < 48):
                findings.append(
                    Finding(
                        severity="high",
                        title="Stack BlueZ potencialmente obsoleto",
                        detail="Versiones antiguas pueden quedar expuestas a fallos históricos.",
                        recommendation="Actualizar paquete bluez y reiniciar servicio Bluetooth.",
                    )
                )
    return findings


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
        "OBEX": "Transferencia de archivos puede aumentar riesgo de fuga de información.",
        "Serial Port": "Canales RFCOMM deben auditar autenticación y autorización.",
        "Human Interface Device": "Perfiles de entrada requieren control estricto de trust.",
        "Audio Sink": "Perfiles de audio pueden abrir vectores de abuso de pairing.",
        "Heart Rate": "Servicio BLE expuesto: revisar si era esperado en este activo.",
        "Battery Service": "Servicio BLE visible; validar minimización de anuncios.",
    }

    joined = " | ".join(services)
    for keyword, risk in surface_map.items():
        if keyword.lower() in joined.lower():
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Superficie expuesta detectada: {keyword}",
                    detail=risk,
                    recommendation="Restringir visibilidad y endurecer políticas de emparejamiento.",
                )
            )

    if not services:
        findings.append(
            Finding(
                severity="info",
                title="Sin respuesta de servicios SDP",
                detail=f"No fue posible enumerar servicios en {device.mac}.",
                recommendation="Confirmar permisos/herramientas y repetir en ventana autorizada.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Sin hallazgos críticos en chequeo básico",
                detail="No se detectaron señales claras de mala configuración.",
                recommendation="Mantener monitoreo continuo y actualizar BlueZ/firmware.",
            )
        )

    return findings


def print_devices(devices: List[Device]) -> None:
    print(color("\nDispositivos detectados", "92"))
    print("-" * 80)
    print(f"{'#':<4}{'MAC':<22}{'Nombre':<34}{'Fuente':<20}")
    print("-" * 80)
    if not devices:
        print(color("No se detectaron dispositivos.", "91"))
    for idx, dev in enumerate(devices, start=1):
        print(f"{idx:<4}{dev.mac:<22}{dev.name[:32]:<34}{dev.source:<20}")
    print("-" * 80)


def print_findings(findings: List[Finding]) -> None:
    severity_color = {"high": "91", "medium": "93", "info": "96"}
    print(color("\nHallazgos del análisis", "94"))
    for finding in findings:
        sev = color(f"[{finding.severity.upper()}]", severity_color.get(finding.severity, "97"))
        print(f"  {sev} {finding.title}")
        print(f"      Detalle: {finding.detail}")
        print(f"      Acción : {finding.recommendation}")


def print_host_network_info(network_info: Dict[str, str]) -> None:
    print(color("\nContexto de red del host local", "95"))
    print("  (Datos del equipo auditor, no del dispositivo remoto)")
    for key in ["platform", "public_ip", "interface", "gateway", "wifi_ssid", "wifi_bssid"]:
        print(f"  • {key:<10}: {network_info.get(key, 'no-disponible')}")


def print_session_summary(results: List[AuditResult], network_info: Dict[str, str]) -> None:
    print(color("\nResumen de sesión (salida en terminal)", "96"))
    print("=" * 80)
    print(color("Contexto de red del host:", "95"))
    for key, value in network_info.items():
        print(f"  - {key}: {value}")

    print(color(f"\nAuditorías ejecutadas: {len(results)}", "92"))
    for idx, result in enumerate(results, start=1):
        print(f"\n[{idx}] {result.device.name} ({result.device.mac}) via {result.device.source}")
        print(f"    Servicios detectados: {len(result.services)}")
        for finding in result.findings:
            print(f"    - [{finding.severity.upper()}] {finding.title}")
    print("=" * 80)


def dependency_status() -> None:
    progress("Verificando dependencias del entorno", steps=8, style="matrix", delay=0.015)
    print(color("\nEstado de dependencias", "95"))

    current_platform = detect_platform()
    if current_platform == "termux":
        deps = ["termux-bluetooth-scan", "termux-wifi-connectioninfo", "python3", "git"]
        for cmd in deps:
            path = shutil.which(cmd)
            if path:
                print(color(f"  ✔ {cmd:<24} en {path}", "92"))
            else:
                print(color(f"  ✖ {cmd:<24} no instalado", "91"))

        # Mostrar estado de herramientas Linux clásicas como informativo en Termux.
        bleak_ok = importlib.util.find_spec("bleak") is not None
        pybluez_ok = importlib.util.find_spec("bluetooth") is not None
        print(color(f"  {'✔' if bleak_ok else '✖'} {'python bleak':<24} {'instalado' if bleak_ok else 'no instalado'}", '92' if bleak_ok else '91'))
        print(color(f"  {'✔' if pybluez_ok else '✖'} {'python bluetooth':<24} {'instalado' if pybluez_ok else 'no instalado'}", '92' if pybluez_ok else '91'))

        for cmd in ["bluetoothctl", "hcitool", "sdptool"]:
            path = shutil.which(cmd)
            if path:
                print(color(f"  ✔ {cmd:<24} en {path}", "92"))
            else:
                print(color(f"  ⚠ {cmd:<24} no disponible en Termux (limitación Android/paquetes)", "93"))
        return

    bleak_ok = importlib.util.find_spec("bleak") is not None
    pybluez_ok = importlib.util.find_spec("bluetooth") is not None
    print(color(f"  {'✔' if bleak_ok else '✖'} {'python bleak':<24} {'instalado' if bleak_ok else 'no instalado'}", '92' if bleak_ok else '91'))
    print(color(f"  {'✔' if pybluez_ok else '✖'} {'python bluetooth':<24} {'instalado' if pybluez_ok else 'no instalado'}", '92' if pybluez_ok else '91'))

    deps = ["bluetoothctl", "hcitool", "sdptool", "btmgmt", "nmcli", "iwgetid", "bluetoothd"]
    for cmd in deps:
        path = shutil.which(cmd)
        if path:
            print(color(f"  ✔ {cmd:<24} en {path}", "92"))
        else:
            print(color(f"  ✖ {cmd:<24} no instalado", "91"))


def menu() -> str:
    options = [
        "1) Escanear dispositivos Bluetooth (unificado)",
        "2) Auditar dispositivo por número",
        "3) Ver contexto de red del host local",
        "4) Evaluar postura BlueBorne (defensivo)",
        "5) Importar hallazgos externos desde archivo",
        "6) Ejecutar adaptadores externos (BTScanner/Bluetooth/ScannerBleah)",
        "7) Ver resumen de sesión en terminal",
        "8) Salir",
    ]
    print(color("\nPanel interactivo", "96"))
    for item in options:
        time.sleep(0.05)
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


def import_external_findings() -> List[Device]:
    path = input(color("Ruta del archivo de hallazgos externos: ", "93")).strip()
    if not path:
        print(color("Ruta vacía.", "91"))
        return []
    source_name = input(color("Origen (ej: BTScanner/ScannerBleah): ", "93")).strip() or "external"
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        print(color("No se pudo leer el archivo indicado.", "91"))
        return []
    parsed = parse_mac_lines(text, source_name)
    if not parsed:
        print(color("No se detectaron entradas parseables (MAC) en el archivo.", "91"))
    return parsed


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
    network_info: Dict[str, str] = {}

    if args.non_interactive:
        devices = scan_devices()
        print_devices(devices)
        progress("Recolectando contexto de red del host", steps=10, style="pulse")
        network_info = discover_host_network()
        print_host_network_info(network_info)
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
            progress(f"Analizando superficie de {selected.mac}", steps=14, style="pulse")
            info = get_device_info(selected.mac)
            services = get_device_services(selected.mac)
            findings = analyze_attack_surface(selected, info, services)
            print_findings(findings)
            results = [r for r in results if r.device.mac != selected.mac]
            results.append(AuditResult(device=selected, info=info, services=services, findings=findings))
        elif choice == "3":
            progress("Recolectando contexto de red del host", steps=10, style="pulse")
            network_info = discover_host_network()
            print_host_network_info(network_info)
        elif choice == "4":
            progress("Evaluando postura BlueBorne defensiva", steps=10, style="matrix")
            print_findings(blueborne_posture_assessment())
        elif choice == "5":
            progress("Importando hallazgos externos", steps=8, style="radar")
            imported = import_external_findings()
            if imported:
                devices = unique_devices(devices + imported)
                print(color(f"Se importaron {len(imported)} registro(s).", "92"))
                print_devices(devices)
        elif choice == "6":
            ext = run_external_tool_adapter()
            if ext:
                devices = unique_devices(devices + ext)
                print(color(f"Adaptadores externos añadieron {len(ext)} dispositivo(s).", "92"))
                print_devices(devices)
        elif choice == "7":
            if not results:
                print(color("No hay auditorías para resumir. Audita un dispositivo primero.", "91"))
                continue
            if not network_info:
                network_info = discover_host_network()
            progress("Generando resumen de sesión", steps=8, style="pulse")
            print_session_summary(results, network_info)
        elif choice == "8":
            print(color("\nFinalizado.", "96"))
            return 0
        else:
            print(color("Opción inválida. Intenta de nuevo.", "91"))


if __name__ == "__main__":
    raise SystemExit(main())
