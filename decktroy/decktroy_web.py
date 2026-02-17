#!/usr/bin/env python3
"""Enhanced DECKTROY web dashboard (defensive-only)."""

from __future__ import annotations

import hashlib
import os
import json
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(command: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except Exception as exc:  # pylint: disable=broad-except
        return 1, "", str(exc)


def get_binary_version(binary: str, version_arg: str = "--version") -> str:
    path = shutil.which(binary)
    if not path:
        return "not-installed"
    code, out, err = run_command([binary, version_arg], timeout=4)
    if code != 0:
        return f"error: {err[:80] or out[:80]}"
    first_line = (out.splitlines() or [out])[0].strip()
    return first_line[:160]


def parse_listening_sockets() -> list[dict[str, str]]:
    if not shutil.which("ss"):
        return []

    code, out, _ = run_command(["ss", "-tulpen"], timeout=8)
    if code != 0 or not out:
        return []

    parsed: list[dict[str, str]] = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 6:
            continue
        proto, state = parts[0], parts[1]
        local = parts[4]
        peer = parts[5]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""
        port = local.rsplit(":", 1)[-1] if ":" in local else "unknown"
        parsed.append(
            {
                "proto": proto,
                "state": state,
                "local": local,
                "peer": peer,
                "port": port,
                "process": process[:160],
            }
        )
    return parsed[:300]


def read_security_logs() -> dict[str, Any]:
    logs: list[str] = []
    if shutil.which("journalctl"):
        code, out, _ = run_command(["journalctl", "-n", "250", "--no-pager"], timeout=10)
        if code == 0:
            logs = out.splitlines()

    if not logs:
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                logs = auth_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-250:]
            except Exception:  # pylint: disable=broad-except
                logs = []

    keywords_danger = ["failed password", "denied", "attack", "ddos", "xss", "sql", "exploit", "brute"]
    keywords_rare = ["segfault", "kernel panic", "oom", "traceback", "critical"]

    dangerous = [l for l in logs if any(k in l.lower() for k in keywords_danger)]
    rare = [l for l in logs if any(k in l.lower() for k in keywords_rare)]
    highlighted = sorted(set((dangerous[-40:] + rare[-20:])))

    return {
        "total_lines": len(logs),
        "dangerous": dangerous[-80:],
        "rare": rare[-80:],
        "highlighted": highlighted[-120:],
    }


def get_firewall_status() -> dict[str, Any]:
    if shutil.which("ufw"):
        code, out, err = run_command(["ufw", "status", "verbose"], timeout=5)
        return {"engine": "ufw", "ok": code == 0, "output": (out or err)[:2400]}
    if shutil.which("nft"):
        code, out, err = run_command(["nft", "list", "ruleset"], timeout=6)
        return {"engine": "nftables", "ok": code == 0, "output": (out or err)[:2400]}
    if shutil.which("iptables"):
        code, out, err = run_command(["iptables", "-S"], timeout=6)
        return {"engine": "iptables", "ok": code == 0, "output": (out or err)[:2400]}
    return {"engine": None, "ok": False, "output": "No firewall engine detected"}


def get_system_metrics() -> dict[str, Any]:
    try:
        import psutil  # type: ignore

        return {
            "cpu_percent": psutil.cpu_percent(interval=0.2),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "net_io": psutil.net_io_counters()._asdict(),
        }
    except Exception as exc:  # pylint: disable=broad-except
        return {"warning": str(exc)}


def get_versions() -> dict[str, str]:
    return {
        "python": get_binary_version("python3"),
        "php": get_binary_version("php", "-v"),
        "mysql": get_binary_version("mysql", "--version"),
        "psql": get_binary_version("psql", "--version"),
        "nginx": get_binary_version("nginx", "-v"),
        "apache2": get_binary_version("apache2", "-v"),
        "suricata": get_binary_version("suricata", "--build-info"),
        "fail2ban": get_binary_version("fail2ban-client", "--version"),
    }


def run_bootstrap_healthcheck() -> dict[str, Any]:
    script = Path(__file__).with_name("bootstrap_healthcheck.py")
    code, out, err = run_command([sys.executable, str(script)], timeout=20)
    if code not in (0, 1, 2):
        return {
            "generated_at": utc_now(),
            "summary": {"pass": 0, "warn": 0, "fail": 1},
            "results": [{"module": "bootstrap", "status": "fail", "detail": err or out}],
            "exit_code": 2,
        }
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {
            "generated_at": utc_now(),
            "summary": {"pass": 0, "warn": 0, "fail": 1},
            "results": [{"module": "bootstrap", "status": "fail", "detail": "invalid-json"}],
            "exit_code": 2,
        }


def get_playbooks() -> dict[str, dict[str, Any]]:
    return {
        "isolate-service": {
            "description": "Aislar un servicio comprometido y preservar evidencia.",
            "commands": ["sudo ss -tulpen", "sudo ufw deny <puerto>/tcp", "sudo systemctl stop <servicio>"],
        },
        "bruteforce-shield": {
            "description": "Contener fuerza bruta con jails y políticas adaptativas.",
            "commands": ["sudo fail2ban-client status", "sudo fail2ban-client status sshd"],
        },
        "ddos-rate-limit": {
            "description": "Mitigar picos de tráfico con limitación de tasa y upstream.",
            "commands": ["sudo nft list ruleset", "sudo ufw limit <puerto>/tcp"],
        },
    }





def ip_to_geo_estimate(ip: str) -> dict[str, float]:
    h = hashlib.sha256(ip.encode('utf-8')).hexdigest()
    a = int(h[:8], 16)
    b = int(h[8:16], 16)
    lat = (a / 0xFFFFFFFF) * 180.0 - 90.0
    lon = (b / 0xFFFFFFFF) * 360.0 - 180.0
    return {"lat": round(lat, 4), "lon": round(lon, 4)}


def build_attack_feed_from_logs(logs: dict[str, Any]) -> dict[str, Any]:
    import re

    candidates = logs.get("dangerous", []) + logs.get("highlighted", [])
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    events: list[dict[str, Any]] = []

    def sev(line: str) -> str:
        l = line.lower()
        if any(k in l for k in ["critical", "rce", "exploit", "root", "sql injection", "xss", "ddos"]):
            return "high"
        if any(k in l for k in ["failed password", "invalid user", "denied", "unauthorized", "brute"]):
            return "medium"
        return "low"

    def typ(line: str) -> str:
        l = line.lower()
        if "ddos" in l or "flood" in l or "too many requests" in l:
            return "ddos"
        if "failed password" in l or "invalid user" in l or "brute" in l:
            return "bruteforce"
        if "xss" in l or "sql" in l or "injection" in l:
            return "web_injection"
        if "sudo" in l or "unauthorized" in l:
            return "privilege_abuse"
        return "suspicious_activity"

    for line in candidates[-300:]:
        ips = ip_re.findall(line)
        if not ips:
            continue
        ip = ips[0]
        events.append(
            {
                "source_ip": ip,
                "severity": sev(line),
                "type": typ(line),
                "geo": ip_to_geo_estimate(ip),
                "raw": line[:220],
            }
        )

    by_ip: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for e in events:
        by_ip[e["source_ip"]] = by_ip.get(e["source_ip"], 0) + 1
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1

    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:20]
    top_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)

    return {
        "events": events,
        "summary": {"total_events": len(events), "severity": by_sev},
        "tables": {
            "top_source_ips": [{"ip": k, "count": v} for k, v in top_ips],
            "top_attack_types": [{"type": k, "count": v} for k, v in top_types],
        },
        "note": "Mapa con geolocalización estimada (hash local) si no hay GeoIP disponible.",
    }

def build_defensive_advisor_from_status(assessment: dict[str, Any], logs: dict[str, Any]) -> dict[str, Any]:
    summary = assessment.get("summary", {})
    dangerous_count = len(logs.get("dangerous", []))
    rare_count = len(logs.get("rare", []))

    scenario = "hardening-gap"
    actions = [
        "Completar baseline de firewall + IDS + anti-bruteforce.",
        "Centralizar logs y activar alertas automáticas.",
        "Ejecutar selftest y cerrar hallazgos críticos.",
    ]

    danger_text = "\n".join(logs.get("dangerous", [])).lower()
    if "failed password" in danger_text or "invalid user" in danger_text:
        scenario = "bruteforce"
        actions = [
            "Endurecer SSH (MFA/keys-only) y activar Fail2Ban.",
            "Aplicar bloqueos temporales por origen y revisar auth logs.",
            "Rotar credenciales potencialmente comprometidas.",
        ]
    elif "ddos" in danger_text or "too many requests" in danger_text or "flood" in danger_text:
        scenario = "ddos"
        actions = [
            "Aplicar rate limiting en WAF/reverse proxy.",
            "Escalar mitigación a proveedor upstream anti-DDoS.",
            "Documentar origen/ASN para proceso legal.",
        ]
    elif "xss" in danger_text or "sql" in danger_text or "injection" in danger_text:
        scenario = "web_injection"
        actions = [
            "Activar reglas WAF (OWASP) y validar inputs.",
            "Aislar endpoint vulnerable y desplegar parche.",
            "Conservar evidencia para cadena de custodia.",
        ]

    return {
        "scenario": scenario,
        "risk_summary": summary,
        "dangerous_events": dangerous_count,
        "rare_events": rare_count,
        "recommended_actions": actions,
        "legal_note": "Respuesta legal: preservar evidencia, hash, timeline UTC y escalar a CSIRT/autoridad.",
        "strict_mode": "defensive-only",
    }



def list_services_snapshot() -> list[dict[str, str]]:
    services = ["ssh", "sshd", "nginx", "apache2", "mysql", "postgresql", "fail2ban", "suricata", "docker"]
    if shutil.which("systemctl") is None:
        return [{"name": s, "status": "unknown", "detail": "systemctl no disponible"} for s in services]
    output: list[dict[str, str]] = []
    for svc in services:
        code, out, err = run_command(["systemctl", "is-active", svc], timeout=4)
        output.append({"name": svc, "status": out.strip() if code == 0 else (out.strip() or err.strip() or "inactive")})
    return output


def perform_service_action(name: str, action: str, enable_service_control: bool = False) -> dict[str, Any]:
    allowed_services = {"ssh", "sshd", "nginx", "apache2", "mysql", "postgresql", "fail2ban", "suricata", "docker"}
    allowed_actions = {"status", "start", "stop", "restart"}
    if name not in allowed_services:
        return {"ok": False, "message": f"Servicio no permitido: {name}"}
    if action not in allowed_actions:
        return {"ok": False, "message": f"Acción no permitida: {action}"}
    if shutil.which("systemctl") is None:
        return {"ok": False, "message": "systemctl no disponible"}

    if action == "status":
        code, out, err = run_command(["systemctl", "status", name, "--no-pager"], timeout=6)
        return {"ok": code == 0, "message": (out or err)[:3000], "applied": False}

    if not enable_service_control:
        return {
            "ok": False,
            "message": "Control de servicios deshabilitado. Inicia web con --enable-service-control.",
            "applied": False,
        }

    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        return {"ok": False, "message": "Se requiere root para start/stop/restart.", "applied": False}

    code, out, err = run_command(["systemctl", action, name], timeout=8)
    return {"ok": code == 0, "message": (out or err or "ok")[:3000], "applied": True}





def load_incident_center_module():
    try:
        from decktroy import incident_center as ic  # type: ignore
        return ic
    except ModuleNotFoundError:
        import importlib.util

        module_path = Path(__file__).with_name("incident_center.py")
        spec = importlib.util.spec_from_file_location("incident_center", module_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        import sys as _sys
        _sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

def load_connection_guard_module():
    try:
        from decktroy import connection_guard as cg  # type: ignore
        return cg
    except ModuleNotFoundError:
        import importlib.util

        module_path = Path(__file__).with_name("connection_guard.py")
        spec = importlib.util.spec_from_file_location("connection_guard", module_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        import sys as _sys
        _sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

def build_status_payload() -> dict[str, Any]:
    sockets = parse_listening_sockets()
    firewall = get_firewall_status()
    logs = read_security_logs()
    assessment = {
        "summary": {
            "high": 1 if not firewall.get("ok") else 0,
            "medium": 1 if not shutil.which("fail2ban-client") else 0,
            "low": 1 if not shutil.which("tcpdump") else 0,
        }
    }
    advisor = build_defensive_advisor_from_status(assessment=assessment, logs=logs)
    connection_guard = {}
    cg = load_connection_guard_module()
    if cg is not None:
        connection_guard = cg.run_guard(mode="analyze", interval=3, duration=6, apply_block=False)

    incidents = []
    ic = load_incident_center_module()
    if ic is not None:
        incidents = ic.list_incidents()

    return {
        "generated_at": utc_now(),
        "host": {
            "hostname": socket.gethostname(),
            "platform": sys.platform,
        },
        "metrics": get_system_metrics(),
        "firewall": firewall,
        "versions": get_versions(),
        "services": list_services_snapshot(),
        "connections": sockets,
        "assessment": assessment,
        "advisor": advisor,
        "connection_guard": connection_guard,
        "attack_feed": build_attack_feed_from_logs(logs),
        "bootstrap_healthcheck": run_bootstrap_healthcheck(),
        "logs": logs,
        "playbooks": get_playbooks(),
        "command_catalog": {"safe_defense": ["decktroy advisor --environment auto", "decktroy threat-feed --environment auto --lines 300", "decktroy playbook list", "decktroy services --action list", "decktroy connection-guard --mode analyze --duration 10", "decktroy incident from-guard", "decktroy startup -o decktroy_startup_status.json"]},
        "incidents": incidents,
    }




def perform_safe_execute(command: str) -> dict[str, Any]:
    allowed = {
        "ss -tulpen": ["ss", "-tulpen"],
        "ufw status verbose": ["ufw", "status", "verbose"],
        "journalctl -p warning -n 50": ["journalctl", "-p", "warning", "-n", "50"],
        "fail2ban-client status": ["fail2ban-client", "status"],
        "systemctl list-units --type=service --state=running": ["systemctl", "list-units", "--type=service", "--state=running"],
    }
    if command not in allowed:
        return {"ok": False, "message": "Comando no permitido por política defensiva.", "output": ""}

    argv = allowed[command]
    if shutil.which(argv[0]) is None:
        return {"ok": False, "message": f"Binario no disponible: {argv[0]}", "output": ""}

    code, out, err = run_command(argv, timeout=12)
    return {
        "ok": code == 0,
        "message": "ok" if code == 0 else "command-failed",
        "output": (out or err or "")[:5000],
        "command": command,
    }

def _html(refresh_seconds: int) -> str:
    return f"""<!doctype html>
<html lang='es'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>DECKTROY Command Center</title>
<style>
:root{{--bg:#040812;--bg2:#0b1428;--panel:#101b35;--panel2:#17284e;--text:#e7eeff;--muted:#9cb2e8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--accent:#5a8cff;--line:#2a3f73;--glow:0 0 0 1px #2b4a8d inset,0 14px 28px rgba(0,0,0,.35)}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 14% -25%,#223f86 0,#0a1b42 32%,#010b22 78%,#010816 100%);color:var(--text)}}
header{{padding:16px 22px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#13244b,#0b1630);position:sticky;top:0;z-index:30;display:flex;justify-content:space-between;align-items:center;gap:14px}}
.brand h1{{margin:0;font-size:20px;letter-spacing:1px;text-transform:uppercase}}
.sub{{color:var(--muted);font-size:12px;margin-top:4px}}
.pill{{padding:8px 12px;border-radius:999px;background:#132a55;border:1px solid #3b5da8;font-size:12px}}
.layout{{display:grid;grid-template-columns:300px 1fr 320px;min-height:calc(100vh - 78px)}}
nav{{border-right:1px solid var(--line);background:linear-gradient(180deg,#09132a,#081126);padding:12px;overflow:auto}}
.nav-head{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin:8px 4px}}
nav button{{width:100%;text-align:left;margin:6px 0;padding:10px 12px;border-radius:10px;border:1px solid #2d467f;background:#0f2147;color:#dcebff;cursor:pointer;transition:.2s;display:flex;align-items:center;gap:8px}}
nav button:hover{{background:#14306a;transform:translateY(-1px)}}
nav button.active{{background:linear-gradient(180deg,#2951ad,#1a3d83);border-color:#7ba3ff}}
main{{padding:14px;display:grid;gap:12px}}
.top-ops{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.top-ops input{{flex:1;min-width:320px;background:#081736;border:1px solid #3559a0;border-radius:10px;color:#d9e8ff;padding:10px;font-size:13px}}
.quick-actions{{display:flex;gap:8px;flex-wrap:wrap}}
.page{{display:none}} .page.active{{display:block}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}}
.card{{background:linear-gradient(180deg,#0b1e49,#0a1a40);border:1px solid #2f63b8;border-radius:16px;padding:12px;box-shadow:0 0 0 1px rgba(37,92,185,.25) inset,0 18px 28px rgba(0,0,0,.35)}}
.title{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px}}
.value{{font-size:29px;font-weight:700;margin:6px 0 2px}}
.small{{font-size:12px;color:var(--muted)}}
.kpi{{display:flex;flex-wrap:wrap;gap:8px}}
.badge{{padding:5px 10px;border-radius:999px;font-size:11px;font-weight:700}}
.ok{{background:#143a25;color:#8bf0b0}} .warn{{background:#4f390e;color:#ffd88c}} .bad{{background:#511919;color:#ffafb3}}
canvas{{width:100%;height:88px;background:linear-gradient(180deg,#132549,#0b1731);border:1px solid #2e4b8d;border-radius:10px}}
.text-block{{white-space:pre-line;background:#071026;border:1px solid #2d467f;padding:10px;border-radius:10px;max-height:330px;overflow:auto;line-height:1.4}}
.table{{width:100%;border-collapse:collapse;font-size:12px}}
.table th,.table td{{border-bottom:1px solid #2a447d;padding:8px;text-align:left}}
.table tr:hover{{background:#132a55;cursor:pointer}}
.inline{{display:grid;grid-template-columns:1.2fr 1fr;gap:12px}}
.mini-kpi{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}}
.mini{{padding:10px;border-radius:10px;background:#0d1d3d;border:1px solid #314f8f}}
.mini .n{{font-size:23px;font-weight:700}}
button.action{{border:1px solid #4f82d3;background:#1b3f86;color:#e4eeff;padding:7px 12px;border-radius:10px;cursor:pointer}}
button.action:hover{{background:#2250a8}}
.terminal{{background:#03080f;border:1px solid #355ca8;border-radius:10px;padding:10px;color:#9ef29e;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;min-height:180px;max-height:360px;overflow:auto}}
.modal-bg{{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:50}}
.modal{{width:min(860px,92vw);max-height:86vh;overflow:auto;background:#0e1a34;border:1px solid #3a5ea9;border-radius:14px;padding:14px}}
.modal h3{{margin-top:0}}
.toast{{position:fixed;right:16px;bottom:16px;background:#123066;border:1px solid #4f79d5;padding:10px 12px;border-radius:10px;display:none;z-index:60}}
.context{{border-left:1px solid var(--line);padding:14px 12px;background:linear-gradient(180deg,#081227,#09152d);display:grid;gap:12px;align-content:start}}
.help-tip{{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:999px;background:#4f3ca0;color:#ded6ff;font-size:11px;margin-left:6px;cursor:help}}
.quick-logs{{position:fixed;left:0;right:0;bottom:0;padding:8px 14px;background:#040b18;border-top:1px solid #2a447d;display:flex;gap:10px;align-items:center;z-index:40}}
.quick-logs .text-block{{margin:0;max-height:88px;flex:1}}
@media (max-width:1400px){{.layout{{grid-template-columns:300px 1fr}} .context{{display:none}}}}
@media (max-width:1180px){{.layout{{grid-template-columns:1fr}} nav{{border-right:none;border-bottom:1px solid var(--line)}} .inline{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header>
  <div class='brand'>
    <h1>DECKTROY · Centro de Comando Defensivo</h1>
    <div class='sub'>Refresh {refresh_seconds}s · Blue-team + cumplimiento legal/forense · Perfil táctico SOC</div>
  </div>
  <div class='pill' id='clockPill'>UTC --:--:--</div>
</header>
<div class='layout'>
  <nav>
    <div class='nav-head'>Navegación SOC completa</div>
    <button class='tab active' data-page='dashboard' title='Vista global, estado general y nivel de amenaza.'>🏠 Dashboard Principal</button>
    <button class='tab' data-page='incidents' title='Incidentes activos, historial y escalamiento.'>🔥 Centro de Incidentes</button>
    <button class='tab' data-page='services' title='Firewall, bloqueos dinámicos, DDoS y WAF.'>🛡️ Defensa Perimetral</button>
    <button class='tab' data-page='connections' title='Detecciones, firmas y sensibilidad IDS/IPS.'>🕵️ IDS / IPS</button>
    <button class='tab' data-page='advisor' title='Perfilado conductual, modelos activos y alertas predictivas.'>🧠 Motor IA y Anomalías</button>
    <button class='tab' data-page='server' title='Hosts monitoreados, procesos e integridad endpoint.'>💻 Protección Endpoint (EDR)</button>
    <button class='tab' data-page='playbooks' title='Playbooks, ejecución activa e historial SOAR.'>🔄 Respuesta Automatizada (SOAR)</button>
    <button class='tab' data-page='logs' title='Eventos en tiempo real, auditoría y exportación forense.'>🗃️ Logs y Auditoría</button>
    <button class='tab' data-page='mapa' title='Mapa de red, microsegmentación y flujo.'>🌐 Mapa de Red</button>
    <button class='tab' data-page='settings' title='Usuarios, roles, MFA, sesiones y políticas IAM.'>🔑 Gestión de Identidad (IAM)</button>
    <button class='tab' data-page='conn-guard' title='IOC, feeds externos y correlación global.'>📊 Inteligencia de Amenazas</button>
    <button class='tab' data-page='settings' title='Parámetros, políticas, API e integraciones.'>⚙️ Configuración del Sistema</button>
    <button class='tab' data-page='dashboard' title='Reportes automáticos, panel ejecutivo y métricas.'>📈 Reportes y Análisis</button>
    <button class='tab' data-page='incidents' title='Simulación de ataque y entrenamiento SOC.'>🧪 Simulación y Entrenamiento</button>
    <button class='tab' data-page='strategy' title='Mini tutoriales, glosario y explicación contextual.'>📘 Centro de Ayuda</button>
  </nav>
  <main>
    <div class='card top-ops'>
      <input id='queryBar' value='host:SRV01 AND severity:critical AND last:24h' title='Motor de búsqueda avanzado con filtros.'>
      <div class='quick-actions'>
        <button class='action' onclick="toast('Prevalidación: aislar host SRV01')">Aislar host</button>
        <button class='action' onclick="toast('Prevalidación: bloquear IP 203.0.113.10')">Bloquear IP</button>
        <button class='action' onclick="toast('Prevalidación: revocar credenciales')">Revocar credenciales</button>
        <button class='action' onclick="toast('Prevalidación: activar monitoreo intensivo')">Monitoreo intensivo</button>
        <button class='action' onclick="toast('Prevalidación: ejecutar playbook')">Ejecutar playbook</button>
      </div>
    </div>
    <section id='dashboard' class='page active'>
      <div class='grid'>
        <div class='card'><div class='title'>CPU<span class='help-tip' title='Consumo actual del host en ventana de refresco.'>?</span></div><div class='value' id='cpuV'>-</div><canvas id='cpuC'></canvas></div>
        <div class='card'><div class='title'>Memoria</div><div class='value' id='memV'>-</div><canvas id='memC'></canvas></div>
        <div class='card'><div class='title'>Disco</div><div class='value' id='diskV'>-</div><canvas id='diskC'></canvas></div>
        <div class='card'><div class='title'>Riesgo global SOC<span class='help-tip' title='Combina severidad, exposición y hallazgos de hardening.'>?</span></div><div class='kpi' id='riskBadges'></div><div class='small' id='bootCode'></div></div>
      </div>
      <div class='inline' style='grid-template-columns:1.2fr 1fr;'>
        <div class='card'>
          <h3>Resumen de amenazas</h3>
          <div class='mini-kpi'>
            <div class='mini'><div class='small'>Eventos</div><div class='n' id='eventsCount'>0</div></div>
            <div class='mini'><div class='small'>Alta severidad</div><div class='n' id='eventsHigh'>0</div></div>
            <div class='mini'><div class='small'>Conexiones monitorizadas</div><div class='n' id='connCount'>0</div></div>
          </div>
          <canvas id='sevC'></canvas>
        </div>
        <div class='card'><h3>Resumen operacional</h3><div class='text-block' id='opsSummary'></div></div>
      </div>
    </section>

    <section id='server' class='page'>
      <div class='grid'>
        <div class='card'><h3>Host</h3><div class='text-block' id='hostBox'></div></div>
        <div class='card'><h3>Versiones</h3><div class='text-block' id='versionsBox'></div></div>
      </div>
      <div class='card'><h3>Firewall</h3><div class='text-block' id='firewallBox'></div></div>
    </section>

    <section id='connections' class='page'>
      <div class='card'><h3>Conexiones en tiempo real</h3><table class='table' id='connTable'><thead><tr><th>Proto</th><th>Estado</th><th>Local</th><th>Puerto</th><th>Proceso</th></tr></thead><tbody></tbody></table></div>
      <div class='card'><h3>Detalle</h3><div class='text-block' id='connDetail'>Selecciona una conexión para analizar.</div></div>
    </section>

    <section id='logs' class='page'>
      <div class='card'><h3>Eventos destacados</h3><div class='text-block' id='logHighlighted'></div></div>
      <div class='grid'>
        <div class='card'><h3>Raros</h3><div class='text-block' id='logRare'></div></div>
        <div class='card'><h3>Peligrosos</h3><div class='text-block' id='logDanger'></div></div>
      </div>
    </section>

    <section id='playbooks' class='page'><div class='card'><h3>Playbooks</h3><div class='text-block' id='playbooksBox'></div></div></section>
    <section id='advisor' class='page'><div class='card'><h3>Asistente IA defensiva</h3><div class='text-block' id='advisorBox'></div></div></section>

    <section id='mapa' class='page'>
      <div class='card'><h3>Mapa global 3D (esfera + silueta continental)</h3><canvas id='globeCanvas' style='height:380px'></canvas><div class='small'>Tip: usa las tablas para priorizar origenes/tipos más frecuentes.</div></div>
      <div class='grid'>
        <div class='card'><h3>Top IPs</h3><div class='text-block' id='mapTopIps'></div></div>
        <div class='card'><h3>Top tipos</h3><div class='text-block' id='mapTopTypes'></div></div>
      </div>
    </section>

    <section id='services' class='page'>
      <div class='card'><h3>Servicios</h3><table class='table' id='svcTable'><thead><tr><th>Servicio</th><th>Estado</th><th>Acciones</th></tr></thead><tbody></tbody></table></div>
      <div class='card'><h3>Resultado acción</h3><div class='text-block' id='svcResult'></div></div>
    </section>

    <section id='settings' class='page'>
      <div class='grid'>
        <div class='card'><h3>Comandos defensivos</h3><div class='text-block' id='cmdCatalog'></div></div>
        <div class='card'><h3>Versiones</h3><div class='text-block' id='verCatalog'></div></div>
      </div>
      <div class='card'>
        <h3>Terminal visual (ejecución segura)</h3>
        <div class='small'>Solo comandos allowlist de observabilidad defensiva.</div>
        <div style='display:flex;gap:8px;flex-wrap:wrap;margin:8px 0'>
          <button class='action' onclick="runSafeCmd('ss -tulpen')">ss -tulpen</button>
          <button class='action' onclick="runSafeCmd('ufw status verbose')">ufw status verbose</button>
          <button class='action' onclick="runSafeCmd('journalctl -p warning -n 50')">journalctl warnings</button>
          <button class='action' onclick="runSafeCmd('fail2ban-client status')">fail2ban status</button>
          <button class='action' onclick="runSafeCmd('systemctl list-units --type=service --state=running')">services running</button>
        </div>
        <div class='terminal' id='terminalBox'>[READY] terminal defensiva disponible...</div>
      </div>
    </section>

    <section id='conn-guard' class='page'>
      <div class='grid'>
        <div class='card'><h3>Resumen guardia</h3><div class='text-block' id='guardSummary'></div></div>
        <div class='card'><h3>Acciones sugeridas</h3><div class='text-block' id='guardActions'></div></div>
      </div>
      <div class='card'><h3>Alertas</h3><div class='text-block' id='guardAlerts'></div></div>
    </section>

    <section id='incidents' class='page'>
      <div class='card'><h3>Registro de incidentes</h3><div class='text-block' id='incidentList'></div></div>
      <div class='card'><h3>Crear desde guardia</h3><button class='action' onclick='incidentFromGuard()'>Crear incidentes</button> <button class='action' onclick="openModal('incidentModal')">Ver ayuda rápida</button><div class='text-block' id='incidentResult'></div></div>
    </section>

    <section id='strategy' class='page'>
      <div class='card'><h3>Arquitectura UX/UI estratégica</h3><div class='text-block'>Arquitectura:
1) Menú lateral fijo/colapsable
2) Barra superior de estado + búsqueda query
3) Área central modular con widgets SOC
4) Panel contextual derecho con detalle/acciones
5) Barra inferior de logs rápidos

Flujo de navegación:
Detección > análisis contextual > acción rápida > confirmación > auditoría automática.

Wireframe textual:
[Sidebar] [Topbar+Query] [Widgets KPI | Timeline | Alertas]
[Mapa Red / IDS] [Panel contextual IA] [Quick logs]

Guía visual:
- Verde normal
- Amarillo advertencia
- Rojo crítico
- Azul informativo
- Morado IA

Ayudas inteligentes:
- Tooltips contextuales
- Modo aprendizaje asistido
- Indicador de impacto previo a acciones críticas.</div></div>
    </section>
  </main>
  <aside class='context'>
    <div class='card'><h3>Panel contextual</h3><div class='text-block' id='contextInfo'>Selecciona un módulo o evento para ver detalle ampliado.</div></div>
    <div class='card'><h3>Historial asociado</h3><div class='text-block' id='contextHistory'>Sin selección activa.</div></div>
    <div class='card'><h3>Recomendaciones IA</h3><div class='text-block' id='contextReco'>Modo aprendizaje asistido habilitado.</div></div>
  </aside>
</div>

<div class='quick-logs'>
  <div class='small'>Logs rápidos SOC</div>
  <div class='text-block' id='quickLogBar'>Esperando eventos...</div>
</div>

<div class='modal-bg' id='incidentModal'>
  <div class='modal'>
    <h3>Guía rápida de incidentes</h3>
    <p class='small'>1) Revisar alertas en Guardia conexiones. 2) Crear incidente. 3) Adjuntar evidencia y hash SHA-256. 4) Escalar a CSIRT legal.</p>
    <button class='action' onclick="closeModal('incidentModal')">Cerrar</button>
  </div>
</div>
<div class='toast' id='toast'></div>

<script>
const hist={{cpu:[],mem:[],disk:[]}}; const maxPts=70;
function toast(msg){{const t=document.getElementById('toast'); t.textContent=msg; t.style.display='block'; setTimeout(()=>t.style.display='none',2200);}}
function openModal(id){{document.getElementById(id).style.display='flex';}}
function closeModal(id){{document.getElementById(id).style.display='none';}}

function toLines(items){{
  return (items||[]).map((x)=>`• ${{x}}`).join('\\n') || 'Sin datos.';
}}

function linesFromPairs(pairs){{
  return (pairs||[]).map(([k,v])=>`${{k}}: ${{v ?? '-'}}`).join('\\n');
}}

function serviceResultText(d){{
  return linesFromPairs([
    ['Resultado', d.ok ? 'Correcto' : 'Error'],
    ['Acción aplicada', d.applied ? 'Sí' : 'No'],
    ['Detalle', d.message || 'Sin detalle']
  ]);
}}

function incidentResultText(d){{
  return linesFromPairs([
    ['Resultado', d.ok ? 'Correcto' : 'Error'],
    ['Mensaje', d.message || 'Sin mensaje'],
    ['Incidentes creados', d.created || 0]
  ]);
}}

function drawSeries(id,arr,color){{
  const c=document.getElementById(id); const ctx=c.getContext('2d'); c.width=c.clientWidth; c.height=c.clientHeight; ctx.clearRect(0,0,c.width,c.height);
  ctx.strokeStyle='#2b4782'; for(let i=1;i<5;i++){{const y=(c.height/5)*i; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(c.width,y); ctx.stroke();}}
  if(!arr.length) return; ctx.strokeStyle=color; ctx.lineWidth=2.4; ctx.beginPath();
  arr.forEach((v,i)=>{{const x=(i/(maxPts-1))*c.width; const y=c.height-(Math.max(0,Math.min(100,v))/100)*c.height; if(i===0)ctx.moveTo(x,y); else ctx.lineTo(x,y);}});
  ctx.stroke();
}}

function drawSeverity(sev){{
  const c=document.getElementById('sevC'); const ctx=c.getContext('2d'); c.width=c.clientWidth; c.height=c.clientHeight; ctx.clearRect(0,0,c.width,c.height);
  const vals=[sev.high||0,sev.medium||0,sev.low||0]; const cols=['#ff4d4d','#ffb020','#ffd66b']; const lbl=['HIGH','MED','LOW']; const w=(c.width-80)/3;
  vals.forEach((v,i)=>{{const h=Math.min(c.height-24,v*12); const x=24+i*(w+12); const y=c.height-h-16; ctx.fillStyle=cols[i]; ctx.fillRect(x,y,w,h); ctx.fillStyle='#dbe8ff'; ctx.fillText(String(v),x+8,y-5); ctx.fillStyle='#9cb2e8'; ctx.fillText(lbl[i],x+6,c.height-4);}});
}}

function drawContinents(ctx,cx,cy,r,rot){{
  const polys=[
    [[-0.15,0.58],[-0.05,0.52],[0.02,0.48],[0.08,0.40],[0.15,0.30],[0.12,0.18],[0.04,0.10],[-0.03,0.05],[-0.10,0.00],[-0.14,-0.12],[-0.11,-0.25],[-0.08,-0.38],[-0.03,-0.48],[0.04,-0.57],[0.12,-0.60],[0.18,-0.54],[0.22,-0.44],[0.18,-0.32],[0.12,-0.22],[0.05,-0.08],[-0.01,0.07],[-0.08,0.20],[-0.16,0.38]],
    [[0.30,0.52],[0.40,0.56],[0.50,0.52],[0.55,0.43],[0.57,0.32],[0.53,0.22],[0.47,0.16],[0.40,0.12],[0.35,0.18],[0.30,0.30],[0.27,0.44]],
    [[0.40,-0.02],[0.52,0.02],[0.62,-0.02],[0.69,-0.12],[0.72,-0.23],[0.68,-0.34],[0.58,-0.36],[0.48,-0.30],[0.40,-0.21],[0.36,-0.11]],
    [[-0.47,-0.12],[-0.40,-0.06],[-0.33,-0.10],[-0.31,-0.19],[-0.35,-0.27],[-0.43,-0.30],[-0.49,-0.24],[-0.51,-0.17]],
  ];
  ctx.fillStyle='rgba(70,132,219,0.55)';
  for(const poly of polys){{
    let started=false; ctx.beginPath();
    for(const p of poly){{
      const lat=p[1]*Math.PI/2, lon=p[0]*Math.PI+rot;
      const x=Math.cos(lat)*Math.sin(lon), y=Math.sin(lat), z=Math.cos(lat)*Math.cos(lon);
      if(z<0){{started=false; continue;}}
      const px=cx+x*r, py=cy-y*r;
      if(!started){{ctx.moveTo(px,py); started=true;}} else ctx.lineTo(px,py);
    }}
    ctx.closePath(); ctx.fill();
  }}
}}

function renderGlobe(feed){{
  const c=document.getElementById('globeCanvas'); const ctx=c.getContext('2d'); c.width=c.clientWidth; c.height=c.clientHeight;
  const cx=c.width/2, cy=c.height/2, r=Math.min(c.width,c.height)*0.36;
  ctx.clearRect(0,0,c.width,c.height);
  const grad=ctx.createRadialGradient(cx-r*0.35,cy-r*0.45,r*0.2,cx,cy,r); grad.addColorStop(0,'#2e64c6'); grad.addColorStop(1,'#0b1838');
  ctx.fillStyle=grad; ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2); ctx.fill();
  ctx.strokeStyle='#3e67bc'; ctx.lineWidth=2; ctx.stroke();
  const rot=(Date.now()/9000)%(Math.PI*2);
  drawContinents(ctx,cx,cy,r,rot);

  const events=(feed.events||[]).slice(-220);
  for(const e of events){{
    const lat=(e.geo?.lat||0)*Math.PI/180, lon=(e.geo?.lon||0)*Math.PI/180+rot;
    const x=Math.cos(lat)*Math.sin(lon), y=Math.sin(lat), z=Math.cos(lat)*Math.cos(lon);
    if(z<0) continue;
    const px=cx+x*r, py=cy-y*r, sev=e.severity||'low';
    ctx.fillStyle=sev==='high'?'#ff3b3b':(sev==='medium'?'#ffb020':'#ffd66b');
    const size=sev==='high'?5.0:(sev==='medium'?3.8:2.6);
    ctx.beginPath(); ctx.arc(px,py,size,0,Math.PI*2); ctx.fill();
  }}
}}

async function runSafeCmd(command){{
  const r=await fetch('/api/execute-safe?command='+encodeURIComponent(command));
  const d=await r.json();
  const box=document.getElementById('terminalBox');
  box.textContent += `

$ ${{command}}
${{d.output || d.message || ''}}`;
  box.scrollTop=box.scrollHeight;
  toast(d.ok ? 'Comando ejecutado' : 'Comando no ejecutado');
}}

async function incidentFromGuard(){{
  const r = await fetch('/api/incident-from-guard', {{method:'POST'}});
  const d = await r.json();
  document.getElementById('incidentResult').textContent = incidentResultText(d);
  toast('Incidentes actualizados');
  await refreshData();
}}

async function serviceAction(name, action){{
  const r = await fetch('/api/service-action?name='+encodeURIComponent(name)+'&action='+encodeURIComponent(action));
  const d = await r.json();
  document.getElementById('svcResult').textContent = serviceResultText(d);
  toast('Acción de servicio completada');
  await refreshData();
}}

async function refreshData(){{
  const r=await fetch('/api/status'); const d=await r.json();
  document.getElementById('clockPill').textContent='UTC '+new Date().toISOString().slice(11,19);

  const m=d.metrics||{{}}; const cpu=Number(m.cpu_percent||0), mem=Number(m.memory_percent||0), disk=Number(m.disk_percent||0);
  document.getElementById('cpuV').textContent=cpu.toFixed(1)+'%'; document.getElementById('memV').textContent=mem.toFixed(1)+'%'; document.getElementById('diskV').textContent=disk.toFixed(1)+'%';
  hist.cpu.push(cpu); hist.mem.push(mem); hist.disk.push(disk); ['cpu','mem','disk'].forEach(k=>{{if(hist[k].length>maxPts) hist[k].shift();}});
  drawSeries('cpuC',hist.cpu,'#80adff'); drawSeries('memC',hist.mem,'#6ee7ac'); drawSeries('diskC',hist.disk,'#ffc26d');

  const summary=d.assessment?.summary||{{high:0,medium:0,low:0}};
  document.getElementById('riskBadges').innerHTML=`<span class='badge bad'>HIGH ${{summary.high||0}}</span> <span class='badge warn'>MEDIUM ${{summary.medium||0}}</span> <span class='badge ok'>LOW ${{summary.low||0}}</span>`;
  document.getElementById('bootCode').textContent='Bootstrap exit code: '+(d.bootstrap_healthcheck?.exit_code ?? 'n/a');

  const feed=d.attack_feed||{{summary:{{severity:{{high:0,medium:0,low:0}}}},events:[],tables:{{top_source_ips:[],top_attack_types:[]}}}};
  document.getElementById('eventsCount').textContent=String(feed.summary?.total_events||0);
  document.getElementById('eventsHigh').textContent=String(feed.summary?.severity?.high||0);
  document.getElementById('connCount').textContent=String(d.connection_guard?.total_connections||0);
  drawSeverity(feed.summary?.severity||{{high:0,medium:0,low:0}});

  document.getElementById('opsSummary').textContent=linesFromPairs([
    ['Host', d.host?.hostname || d.host?.fqdn || 'N/D'],
    ['Firewall activo', d.firewall?.ok ? 'Sí' : 'No'],
    ['Servicios monitoreados', (d.services||[]).length],
    ['Incidentes abiertos', (d.incidents||[]).filter(x=>x.status==='open').length],
    ['Conexiones altas', d.connection_guard?.counts?.high || 0]
  ]);

  document.getElementById('hostBox').textContent=linesFromPairs([['Hostname', d.host?.hostname || 'N/D'], ['SO', d.host?.os || 'N/D'], ['Kernel', d.host?.kernel || 'N/D'], ['IP principal', d.host?.primary_ip || 'N/D']]);
  document.getElementById('versionsBox').textContent=Object.entries(d.versions||{{}}).map(([k,v])=>`• ${{k}}: ${{v}}`).join('\n') || 'Sin versiones detectadas.';
  document.getElementById('firewallBox').textContent=linesFromPairs([['Motor', d.firewall?.engine || 'No detectado'], ['Estado', d.firewall?.ok ? 'Operativo' : 'Revisar'], ['Resumen', (d.firewall?.output||'Sin salida').slice(0,280)]]);

  const tbody=document.querySelector('#connTable tbody'); tbody.innerHTML='';
  (d.connections||[]).forEach(c=>{{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${{c.proto||''}}</td><td>${{c.state||''}}</td><td>${{c.local||''}}</td><td>${{c.port||''}}</td><td>${{(c.process||'').slice(0,90)}}</td>`;
    tr.onclick=()=>document.getElementById('connDetail').textContent=linesFromPairs([['Protocolo',c.proto],['Estado',c.state],['Local',c.local],['Puerto',c.port],['Proceso',c.process]]);
    tbody.appendChild(tr);
  }});

  document.getElementById('logHighlighted').textContent=toLines(d.logs?.highlighted||[]);
  document.getElementById('logRare').textContent=toLines(d.logs?.rare||[]);
  document.getElementById('logDanger').textContent=toLines(d.logs?.dangerous||[]);
  document.getElementById('playbooksBox').textContent=Object.entries(d.playbooks||{{}}).map(([k,v])=>`• ${{k}}
  - Objetivo: ${{v.description||'N/D'}}
  - Comandos: ${{(v.commands||[]).join(', ')}}`).join('\n\n') || 'Sin playbooks.';
  document.getElementById('advisorBox').textContent=toLines(d.advisor?.recommended_actions||[]);
  document.getElementById('mapTopIps').textContent=(feed.tables?.top_source_ips||[]).map((x)=>`• ${{x.ip}}: ${{x.count}} eventos`).join('\n') || 'Sin IPs relevantes.';
  document.getElementById('mapTopTypes').textContent=(feed.tables?.top_attack_types||[]).map((x)=>`• ${{x.type}}: ${{x.count}}`).join('\n') || 'Sin tipos relevantes.';
  renderGlobe(feed);

  const svcBody=document.querySelector('#svcTable tbody'); svcBody.innerHTML='';
  (d.services||[]).forEach(svc=>{{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${{svc.name}}</td><td>${{(svc.status||'').slice(0,100)}}</td><td><button class='action' onclick="serviceAction('${{svc.name}}','status')">Status</button> <button class='action' onclick="serviceAction('${{svc.name}}','restart')">Restart</button> <button class='action' onclick="serviceAction('${{svc.name}}','stop')">Stop</button></td>`;
    svcBody.appendChild(tr);
  }});

  document.getElementById('cmdCatalog').textContent=toLines(d.command_catalog?.safe_defense||[]);
  document.getElementById('verCatalog').textContent=Object.entries(d.versions||{{}}).map(([k,v])=>`• ${{k}}: ${{v}}`).join('\n') || 'Sin datos.';
  const g=d.connection_guard||{{}};
  document.getElementById('guardSummary').textContent=linesFromPairs([['Modo',g.mode||'N/D'],['Conexiones totales',g.total_connections||0],['Nivel alto',g.counts?.high||0],['Muestras baseline',g.baseline_samples||0]]);
  document.getElementById('guardAlerts').textContent=toLines((g.alerts||[]).map((x)=>x.message || x.type || 'Alerta'));
  document.getElementById('guardActions').textContent=toLines((g.auto_actions||[]).map((x)=>x.description || x.action || 'Acción recomendada'));
  document.getElementById('incidentList').textContent=toLines((d.incidents||[]).map((x)=>`${{x.id||'INC'}} | ${{x.status||'open'}} | ${{x.title||x.type||'Incidente'}}`));
  document.getElementById('quickLogBar').textContent=toLines((d.logs?.highlighted||[]).slice(-5));
  document.getElementById('contextInfo').textContent=linesFromPairs([['Host', d.host?.hostname || 'N/D'], ['Riesgo alto', summary.high||0], ['Riesgo medio', summary.medium||0], ['Eventos', feed.summary?.total_events||0]]);
  document.getElementById('contextHistory').textContent=toLines((d.incidents||[]).slice(-5).map((x)=>`${{x.id||'INC'}} - ${{x.status||'open'}}`));
  document.getElementById('contextReco').textContent=toLines(d.advisor?.recommended_actions||[]);
}}

for (const b of document.querySelectorAll('.tab')){{
  b.addEventListener('click', ()=>{{
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); b.classList.add('active');
    document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
    const page=document.getElementById(b.dataset.page);
    if(page) page.classList.add('active');
    document.getElementById('contextInfo').textContent=linesFromPairs([['Módulo', b.textContent.trim()], ['Descripción', b.title || 'Sin detalle'], ['Hora', new Date().toISOString()]]);
  }});
}}

document.getElementById('queryBar').addEventListener('keydown', (e)=>{{
  if(e.key==='Enter'){{
    toast('Consulta aplicada: '+e.target.value);
    document.getElementById('contextReco').textContent=toLines(['Autocompletado inteligente activo','Sugerencia: severity:high AND blocked:false','Historial de consultas disponible']);
  }}
}});

window.addEventListener('click', (e)=>{{ if(e.target.classList.contains('modal-bg')) e.target.style.display='none'; }});
refreshData(); setInterval(refreshData, {refresh_seconds}*1000);
</script>
</body>
</html>"""


def run_dashboard(host: str = "127.0.0.1", port: int = 8080, refresh_seconds: int = 5, enable_service_control: bool = False) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                body = _html(refresh_seconds).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/api/status":
                payload = json.dumps(build_status_payload(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if self.path.startswith("/api/service-action"):
                qs = parse_qs(urlparse(self.path).query)
                name = (qs.get("name") or ["nginx"])[0]
                action = (qs.get("action") or ["status"])[0]
                result = perform_service_action(name=name, action=action, enable_service_control=enable_service_control)
                payload = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if self.path.startswith("/api/execute-safe"):
                qs = parse_qs(urlparse(self.path).query)
                command = (qs.get("command") or [""])[0]
                result = perform_safe_execute(command=command)
                payload = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(404)
            self.end_headers()


        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/incident-from-guard":
                ic = load_incident_center_module()
                cg = load_connection_guard_module()
                payload_data: dict[str, Any] = {"ok": False, "message": "Módulos no disponibles"}
                if ic is not None and cg is not None:
                    guard = cg.run_guard(mode="analyze", interval=3, duration=6, apply_block=False)
                    created = ic.create_from_guard_alerts(guard.get("alerts", []))
                    payload_data = {"ok": True, "guard": guard, "created_incidents": created}
                payload = json.dumps(payload_data, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(404)
            self.end_headers()

        def log_message(self, *_: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Dashboard DECKTROY disponible en http://{host}:{port}")
    server.serve_forever()
