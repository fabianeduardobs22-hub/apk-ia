#!/usr/bin/env python3
"""DECKTROY CLI (defensive security operations for Linux)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str


def run_command(command: list[str], timeout: int = 5) -> tuple[int, str, str]:
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


def read_recent_security_logs(max_lines: int = 200) -> list[str]:
    if shutil.which("journalctl"):
        code, out, _ = run_command(["journalctl", "-n", str(max_lines), "--no-pager"], timeout=10)
        if code == 0 and out:
            return out.splitlines()

    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        try:
            return auth_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
        except Exception:  # pylint: disable=broad-except
            return []
    return []


def classify_threat_from_logs(logs: list[str]) -> dict[str, int]:
    patterns = {
        "bruteforce": ["failed password", "authentication failure", "invalid user"],
        "ddos": ["rate limit", "flood", "too many requests", "ddos"],
        "web_injection": ["xss", "sql", "injection", "union select", "<script"],
        "privilege_abuse": ["sudo", "permission denied", "unauthorized"],
    }

    score = {k: 0 for k in patterns}
    lowered = [line.lower() for line in logs]
    for line in lowered:
        for threat, keys in patterns.items():
            if any(k in line for k in keys):
                score[threat] += 1
    return score




def _ip_to_geo_estimate(ip: str) -> dict[str, float]:
    import hashlib

    h = hashlib.sha256(ip.encode('utf-8')).hexdigest()
    a = int(h[:8], 16)
    b = int(h[8:16], 16)
    lat = (a / 0xFFFFFFFF) * 180.0 - 90.0
    lon = (b / 0xFFFFFFFF) * 360.0 - 180.0
    return {"lat": round(lat, 4), "lon": round(lon, 4)}


def build_threat_feed(logs: list[str]) -> dict[str, Any]:
    import re

    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    events: list[dict[str, Any]] = []

    def sev(line: str) -> str:
        l = line.lower()
        if any(k in l for k in ["critical", "rce", "exploit", "root", "sql injection", "xss", "ddos"]):
            return "high"
        if any(k in l for k in ["failed password", "invalid user", "denied", "unauthorized", "brute"]):
            return "medium"
        return "low"

    def attack_type(line: str) -> str:
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

    for line in logs[-300:]:
        ips = ip_re.findall(line)
        if not ips:
            continue
        source_ip = ips[0]
        t = attack_type(line)
        severity = sev(line)
        geo = _ip_to_geo_estimate(source_ip)
        events.append(
            {
                "timestamp": utc_now(),
                "source_ip": source_ip,
                "type": t,
                "severity": severity,
                "geo": geo,
                "raw": line[:260],
            }
        )

    # tables
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
        "events": events[-500:],
        "summary": {
            "total_events": len(events),
            "severity": by_sev,
        },
        "tables": {
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "top_attack_types": [{"type": t, "count": c} for t, c in top_types],
        },
        "note": "Geolocalización estimada por hash local para visualización defensiva cuando no hay GeoIP real.",
    }

def build_advisor_payload(snapshot: dict[str, Any], assessment: dict[str, Any], environment: str = "auto") -> dict[str, Any]:
    logs = read_recent_security_logs()
    score = classify_threat_from_logs(logs)
    top_threat = max(score, key=score.get) if score else "unknown"
    top_score = score.get(top_threat, 0)

    if top_score == 0:
        top_threat = "hardening-gap"

    # Defensive-only recommendations (no counter-hacking / no intrusion)
    defensive_matrix: dict[str, dict[str, Any]] = {
        "bruteforce": {
            "priority": "high",
            "actions": [
                "Verificar/activar Fail2Ban y revisar jail del servicio afectado.",
                "Aplicar MFA y rotación de credenciales expuestas.",
                "Restringir SSH por IP/VPN y deshabilitar password auth cuando aplique.",
            ],
            "commands": [
                "sudo fail2ban-client status",
                "sudo fail2ban-client status sshd",
                "sudo journalctl -u ssh --since '1 hour ago'",
            ],
        },
        "ddos": {
            "priority": "high",
            "actions": [
                "Aplicar rate limiting en reverse proxy/WAF.",
                "Coordinar mitigación con proveedor upstream anti-DDoS.",
                "Bloquear temporalmente orígenes de abuso con evidencia previa.",
            ],
            "commands": [
                "sudo ufw status verbose",
                "sudo nft list ruleset",
                "sudo journalctl -u nginx --since '15 min ago'",
            ],
        },
        "web_injection": {
            "priority": "high",
            "actions": [
                "Activar reglas WAF/OWASP CRS y validación de entrada.",
                "Revisar logs de aplicación y rutas comprometidas.",
                "Aislar endpoint vulnerable y desplegar parche inmediato.",
            ],
            "commands": [
                "sudo journalctl -u nginx --since '30 min ago'",
                "sudo journalctl -u apache2 --since '30 min ago'",
            ],
        },
        "privilege_abuse": {
            "priority": "high",
            "actions": [
                "Revisar eventos sudo/sesiones y revocar tokens/llaves sospechosas.",
                "Aplicar principio de mínimo privilegio en cuentas y roles.",
                "Abrir incidente forense y preservar cadena de custodia.",
            ],
            "commands": [
                "sudo journalctl -p warning -n 200",
                "sudo ss -tulpen",
            ],
        },
        "hardening-gap": {
            "priority": "medium",
            "actions": [
                "Completar baseline de firewall + IDS + anti-bruteforce.",
                "Habilitar telemetría centralizada y alertas automáticas.",
                "Ejecutar selftest y remediar módulos en warning/fail.",
            ],
            "commands": [
                "python3 decktroy/decktroy_cli.py startup -o decktroy_startup_status.json",
                "python3 decktroy/decktroy_cli.py selftest",
            ],
        },
    }

    selected = defensive_matrix.get(top_threat, defensive_matrix["hardening-gap"])

    legal_pack = {
        "objective": "Preservar evidencia para respuesta legal y cumplimiento.",
        "steps": [
            "Capturar logs inmutables y sellar hash SHA-256 del artefacto.",
            "Registrar línea temporal UTC de eventos críticos.",
            "Documentar IP/ASN/origen sin intentar acceso no autorizado al atacante.",
            "Escalar a CSIRT/autoridad competente según jurisdicción.",
        ],
    }

    return {
        "generated_at": utc_now(),
        "environment": environment,
        "threat_scores": score,
        "detected_primary_scenario": top_threat,
        "priority": selected["priority"],
        "recommended_actions": selected["actions"],
        "recommended_commands": selected["commands"],
        "legal_response": legal_pack,
        "notes": [
            "DECKTROY opera en modo estrictamente defensivo.",
            "No se recomienda ni soporta contraataque intrusivo u ofensivo.",
        ],
        "assessment_summary": assessment.get("summary", {}),
        "host": snapshot.get("hostname", "unknown"),
        "threat_feed": build_threat_feed(logs),
    }


def run_bootstrap_healthcheck() -> dict[str, Any]:
    healthcheck_script = Path(__file__).with_name("bootstrap_healthcheck.py")
    code, out, err = run_command([sys.executable, str(healthcheck_script)], timeout=15)
    if code not in (0, 1, 2):
        return {
            "generated_at": utc_now(),
            "summary": {"pass": 0, "warn": 0, "fail": 1},
            "results": [
                {
                    "module": "bootstrap.runner",
                    "status": "fail",
                    "detail": err or out or "No se pudo ejecutar bootstrap_healthcheck.py",
                    "recommendation": "Verificar instalación de Python y permisos de ejecución.",
                }
            ],
            "exit_code": 2,
        }

    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        payload = {
            "generated_at": utc_now(),
            "summary": {"pass": 0, "warn": 0, "fail": 1},
            "results": [
                {
                    "module": "bootstrap.parser",
                    "status": "fail",
                    "detail": out or err or "Salida inválida de bootstrap_healthcheck.py",
                    "recommendation": "Revisar script de healthcheck y su salida JSON.",
                }
            ],
            "exit_code": 2,
        }
    return payload




def list_services() -> list[dict[str, str]]:
    services = [
        "ssh",
        "sshd",
        "nginx",
        "apache2",
        "mysql",
        "postgresql",
        "fail2ban",
        "suricata",
        "docker",
    ]
    if shutil.which("systemctl") is None:
        return [{"name": name, "status": "unknown", "detail": "systemctl no disponible"} for name in services]

    output: list[dict[str, str]] = []
    for name in services:
        code, out, err = run_command(["systemctl", "is-active", name], timeout=4)
        status = out.strip() if code == 0 else (out.strip() or err.strip() or "inactive")
        output.append({"name": name, "status": status, "detail": ""})
    return output


def service_action(name: str, action: str, apply: bool = False) -> dict[str, Any]:
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
        return {"ok": code == 0, "message": (out or err)[:3000], "dry_run": False}

    if not apply:
        return {
            "ok": True,
            "dry_run": True,
            "message": f"Dry-run: usar --apply para ejecutar '{action}' en {name}",
            "command": f"sudo systemctl {action} {name}",
        }

    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        return {"ok": False, "message": "Se requieren privilegios root para aplicar cambios de servicio."}

    code, out, err = run_command(["systemctl", action, name], timeout=8)
    return {"ok": code == 0, "dry_run": False, "message": (out or err or "ok")[:3000]}



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


def load_notifier_module():
    try:
        from decktroy import notifier as nt  # type: ignore
        return nt
    except ModuleNotFoundError:
        import importlib.util

        module_path = Path(__file__).with_name("notifier.py")
        spec = importlib.util.spec_from_file_location("notifier", module_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        import sys as _sys
        _sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

def detect_binaries() -> dict[str, str | None]:
    required = [
        "python3",
        "iptables",
        "nft",
        "ufw",
        "fail2ban-client",
        "suricata",
        "snort",
        "tcpdump",
        "ss",
        "systemctl",
        "journalctl",
    ]
    return {binary: shutil.which(binary) for binary in required}


def collect_system_snapshot() -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "generated_at": utc_now(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "cwd": str(Path.cwd()),
        "binaries": detect_binaries(),
        "services": list_services(),
    }

    if shutil.which("ss"):
        code, out, err = run_command(["ss", "-tulpen"], timeout=6)
        snapshot["listening_sockets"] = out.splitlines()[:200] if code == 0 else [err or "error"]
    else:
        snapshot["listening_sockets"] = ["ss no disponible"]

    if shutil.which("ufw"):
        code, out, err = run_command(["ufw", "status", "verbose"])
        snapshot["firewall"] = {"engine": "ufw", "ok": code == 0, "output": out or err}
    elif shutil.which("nft"):
        code, out, err = run_command(["nft", "list", "ruleset"])
        snapshot["firewall"] = {"engine": "nftables", "ok": code == 0, "output": (out or err)[:2000]}
    elif shutil.which("iptables"):
        code, out, err = run_command(["iptables", "-S"])
        snapshot["firewall"] = {"engine": "iptables", "ok": code == 0, "output": out or err}
    else:
        snapshot["firewall"] = {"engine": None, "ok": False, "output": "No firewall tool detected"}

    try:
        import psutil  # type: ignore

        snapshot["metrics"] = {
            "cpu_percent": psutil.cpu_percent(interval=0.2),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "net_io": psutil.net_io_counters()._asdict(),
        }
    except Exception as exc:  # pylint: disable=broad-except
        snapshot["metrics"] = {"warning": f"psutil no disponible: {exc}"}

    return snapshot


def evaluate_findings(snapshot: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    fw = snapshot.get("firewall", {})
    if not fw.get("ok", False):
        findings.append(
            Finding(
                category="firewall",
                severity="high",
                title="Firewall no verificable",
                detail=str(fw.get("output", "sin detalle")),
                recommendation="Instalar y aplicar baseline en UFW/nftables/iptables.",
            )
        )

    bins: dict[str, str | None] = snapshot.get("binaries", {})
    if not bins.get("fail2ban-client"):
        findings.append(
            Finding(
                category="anti-bruteforce",
                severity="medium",
                title="Fail2Ban ausente",
                detail="No se encontró fail2ban-client en el sistema.",
                recommendation="Instalar Fail2Ban y configurar jails para SSH, paneles y APIs.",
            )
        )
    if not (bins.get("suricata") or bins.get("snort")):
        findings.append(
            Finding(
                category="ids",
                severity="medium",
                title="IDS/IPS ausente",
                detail="No se detectó Suricata ni Snort.",
                recommendation="Habilitar un IDS con reglas actualizadas y envío de logs al SIEM.",
            )
        )
    if not bins.get("tcpdump"):
        findings.append(
            Finding(
                category="observability",
                severity="low",
                title="Herramienta de captura no detectada",
                detail="tcpdump no está disponible.",
                recommendation="Instalar tcpdump o integrar sensor de red equivalente.",
            )
        )

    return findings


def get_playbooks() -> dict[str, dict[str, Any]]:
    return {
        "isolate-service": {
            "description": "Aisla un servicio retirando su exposición de red (guía operativa).",
            "steps": [
                "Identificar PID y unidad del servicio impactado.",
                "Aplicar regla temporal de deny-list en firewall para puerto comprometido.",
                "Si persiste impacto, detener servicio y activar modo mantenimiento.",
                "Conservar evidencia (logs/pcap) antes de reiniciar.",
            ],
            "commands": [
                "sudo ss -tulpen",
                "sudo ufw deny <puerto>/tcp",
                "sudo systemctl stop <servicio>",
            ],
        },
        "bruteforce-shield": {
            "description": "Contención de intentos repetidos de autenticación fallida.",
            "steps": [
                "Verificar eventos en auth.log / journalctl.",
                "Confirmar jail de Fail2Ban para el servicio afectado.",
                "Incrementar bantime y reducir maxretry temporalmente.",
                "Forzar MFA y rotación de credenciales comprometidas.",
            ],
            "commands": [
                "sudo fail2ban-client status",
                "sudo fail2ban-client status sshd",
                "sudo fail2ban-client set sshd bantime 3600",
            ],
        },
        "ddos-rate-limit": {
            "description": "Mitigación inicial ante picos de tráfico con controles de tasa.",
            "steps": [
                "Confirmar patrón de pico por origen, ASN o path.",
                "Activar limitación de tasa en reverse proxy/WAF.",
                "Aplicar bloqueo temporal por IP/ASN de alto abuso.",
                "Escalar a proveedor anti-DDoS upstream.",
            ],
            "commands": [
                "sudo nft list ruleset",
                "sudo ufw limit <puerto>/tcp",
                "sudo journalctl -u nginx --since '10 min ago'",
            ],
        },
    }


def build_assessment_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = evaluate_findings(snapshot)
    return {
        "generated_at": utc_now(),
        "summary": {
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [asdict(f) for f in findings],
    }


def cmd_inventory(args: argparse.Namespace) -> int:
    snapshot = collect_system_snapshot()
    text = json.dumps(snapshot, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Inventario guardado en {args.output}")
    else:
        print(text)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    payload = build_assessment_payload(collect_system_snapshot())
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Evaluación guardada en {args.output}")
    else:
        print(text)
    return 0 if payload["summary"]["high"] == 0 else 2


def cmd_advisor(args: argparse.Namespace) -> int:
    snapshot = collect_system_snapshot()
    assessment = build_assessment_payload(snapshot)
    payload = build_advisor_payload(snapshot=snapshot, assessment=assessment, environment=args.environment)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Recomendaciones guardadas en {args.output}")
    else:
        print(text)
    return 0








def cmd_connection_guard(args: argparse.Namespace) -> int:
    cg = load_connection_guard_module()
    if cg is None:
        print("No se pudo cargar connection_guard.py")
        return 1

    payload = cg.run_guard(
        mode=args.mode,
        interval=args.interval,
        duration=args.duration,
        apply_block=args.apply_block,
    )

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Connection guard guardado en {args.output}")
    else:
        print(text)

    return 0 if payload.get("counts", {}).get("high", 0) == 0 else 2



def cmd_incident(args: argparse.Namespace) -> int:
    ic = load_incident_center_module()
    if ic is None:
        print("No se pudo cargar incident_center.py")
        return 1

    if args.incident_cmd == "list":
        print(json.dumps({"generated_at": utc_now(), "incidents": ic.list_incidents()}, ensure_ascii=False, indent=2))
        return 0

    if args.incident_cmd == "create":
        inc = ic.create_incident(
            title=args.title,
            severity=args.severity,
            source=args.source,
            details=args.details,
            tags=args.tags,
        )
        print(json.dumps({"generated_at": utc_now(), "incident": inc}, ensure_ascii=False, indent=2))
        return 0

    if args.incident_cmd == "status":
        inc = ic.update_incident_status(args.id, args.status, note=args.note)
        if inc is None:
            print(json.dumps({"error": "incident not found"}, ensure_ascii=False))
            return 1
        print(json.dumps({"generated_at": utc_now(), "incident": inc}, ensure_ascii=False, indent=2))
        return 0

    if args.incident_cmd == "evidence":
        inc = ic.add_evidence(args.id, args.path, note=args.note)
        if inc is None:
            print(json.dumps({"error": "incident not found or evidence file missing"}, ensure_ascii=False))
            return 1
        print(json.dumps({"generated_at": utc_now(), "incident": inc}, ensure_ascii=False, indent=2))
        return 0

    if args.incident_cmd == "from-guard":
        cg = load_connection_guard_module()
        if cg is None:
            print("No se pudo cargar connection_guard.py")
            return 1
        guard = cg.run_guard(mode="analyze", interval=args.interval, duration=args.duration, apply_block=False)
        created = ic.create_from_guard_alerts(guard.get("alerts", []))
        print(json.dumps({"generated_at": utc_now(), "guard": guard, "created_incidents": created}, ensure_ascii=False, indent=2))
        return 0

    return 1


def cmd_alert_notify(args: argparse.Namespace) -> int:
    nt = load_notifier_module()
    if nt is None:
        print("No se pudo cargar notifier.py")
        return 1

    payload = {
        "generated_at": utc_now(),
        "source": "decktroy",
        "level": args.level,
        "title": args.title,
        "message": args.message,
    }
    result = nt.send_webhook(args.webhook, payload)
    print(json.dumps({"payload": payload, "result": result}, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1



def cmd_runtime_monitor(args: argparse.Namespace) -> int:
    try:
        from decktroy import runtime_monitor as rm  # type: ignore
    except ModuleNotFoundError:
        import importlib.util

        module_path = Path(__file__).with_name("runtime_monitor.py")
        spec = importlib.util.spec_from_file_location("runtime_monitor", module_path)
        if spec is None or spec.loader is None:
            print("No se pudo cargar runtime_monitor.py")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rm = module

    payload = rm.build_monitor_payload(output_path=args.output)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if args.output:
        print(f"Reporte runtime guardado en {args.output}")
    return 0 if payload.get("checks_failed", 1) == 0 else 2

def cmd_services(args: argparse.Namespace) -> int:
    if args.action == "list":
        payload = {"generated_at": utc_now(), "services": list_services()}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    result = service_action(name=args.name, action=args.action, apply=args.apply)
    print(json.dumps({"generated_at": utc_now(), "result": result}, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1

def cmd_threat_feed(args: argparse.Namespace) -> int:
    logs = read_recent_security_logs(max_lines=args.lines)
    payload = {
        "generated_at": utc_now(),
        "environment": args.environment,
        "feed": build_threat_feed(logs),
        "defensive_commands": [
            "python3 decktroy/decktroy_cli.py advisor --environment auto",
            "python3 decktroy/decktroy_cli.py playbook list",
            "python3 decktroy/decktroy_cli.py startup -o decktroy_startup_status.json",
        ],
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Threat feed guardado en {args.output}")
    else:
        print(text)
    return 0

def cmd_playbook_list(_: argparse.Namespace) -> int:
    playbooks = get_playbooks()
    print("Playbooks defensivos disponibles:\n")
    for name, pb in playbooks.items():
        print(f"- {name}: {pb['description']}")
    return 0


def cmd_playbook_show(args: argparse.Namespace) -> int:
    playbook = get_playbooks().get(args.name)
    if not playbook:
        print(f"Playbook no encontrado: {args.name}")
        return 1

    print(f"Playbook: {args.name}")
    print(f"Descripción: {playbook['description']}\n")
    print("Pasos:")
    for idx, step in enumerate(playbook["steps"], start=1):
        print(f"  {idx}. {step}")

    print("\nComandos sugeridos (defensivos, ejecución manual):")
    for command in playbook["commands"]:
        print(f"  - {command}")

    return 0


def cmd_execute(args: argparse.Namespace) -> int:
    allowed = {
        "ss -tulpen",
        "ufw status",
        "ufw status verbose",
        "fail2ban-client status",
        "journalctl -p warning -n 50",
        "systemctl status nginx --no-pager",
    }

    command = " ".join(args.exec_cmd)
    if command not in allowed:
        print("Comando no permitido por política segura.")
        print("Use `playbook show <nombre>` o `advisor` para recomendaciones operativas.")
        return 1

    executable = args.exec_cmd[0]
    if shutil.which(executable) is None:
        print(f"Comando no disponible en este host: {executable}")
        return 1

    code, out, err = run_command(args.exec_cmd, timeout=8)
    print(out if out else err)
    return code


def cmd_startup(args: argparse.Namespace) -> int:
    snapshot = collect_system_snapshot()
    assessment = build_assessment_payload(snapshot)
    bootstrap = run_bootstrap_healthcheck()
    advisor = build_advisor_payload(snapshot=snapshot, assessment=assessment, environment="startup")
    connection_guard = {}
    cg = load_connection_guard_module()
    if cg is not None:
        connection_guard = cg.run_guard(mode="analyze", interval=3, duration=6, apply_block=False)

    incident_open = 0
    ic = load_incident_center_module()
    if ic is not None:
        incident_open = sum(1 for x in ic.list_incidents() if x.get("status") == "open")

    status_payload = {
        "generated_at": utc_now(),
        "mode": "startup-status",
        "linux_compatible": platform.system().lower() == "linux",
        "snapshot": snapshot,
        "assessment": assessment,
        "advisor": advisor,
        "connection_guard": connection_guard,
        "incident_open_count": incident_open,
        "bootstrap_healthcheck": bootstrap,
    }

    output_path = Path(args.status_file)
    output_path.write_text(json.dumps(status_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Estado de inicio guardado en {output_path}")

    if not status_payload["linux_compatible"]:
        print("Advertencia: esta CLI está optimizada para Linux.")
        return 1

    critical = assessment["summary"]["high"]
    bootstrap_exit = int(bootstrap.get("exit_code", 2))
    if critical > 0 or bootstrap_exit == 2:
        return 2
    if bootstrap_exit == 1:
        return 1
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    try:
        from decktroy.decktroy_web import run_dashboard
    except ModuleNotFoundError:
        import importlib.util

        module_path = Path(__file__).with_name("decktroy_web.py")
        spec = importlib.util.spec_from_file_location("decktroy_web", module_path)
        if spec is None or spec.loader is None:
            print("No se pudo cargar decktroy_web.py")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run_dashboard = module.run_dashboard

    run_dashboard(host=args.host, port=args.port, refresh_seconds=args.refresh, enable_service_control=args.enable_service_control)
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    checker = Path(__file__).with_name("full_system_check.py")
    code, out, err = run_command([sys.executable, str(checker)], timeout=120)
    print(out if out else err)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decktroy",
        description="DECKTROY CLI para operaciones defensivas de seguridad en Linux.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    inventory = sub.add_parser("inventory", help="Recolecta inventario técnico y snapshot local.")
    inventory.add_argument("-o", "--output", help="Ruta de salida JSON.")
    inventory.set_defaults(func=cmd_inventory)

    assess = sub.add_parser("assess", help="Evalúa baseline defensivo y genera hallazgos.")
    assess.add_argument("-o", "--output", help="Ruta de salida JSON.")
    assess.set_defaults(func=cmd_assess)

    advisor = sub.add_parser("advisor", help="Asistente de respuesta defensiva según contexto y logs.")
    advisor.add_argument("--environment", default="auto", help="Contexto del entorno: auto/prod/staging/lab.")
    advisor.add_argument("-o", "--output", help="Ruta de salida JSON para recomendaciones.")
    advisor.set_defaults(func=cmd_advisor)

    threat = sub.add_parser("threat-feed", help="Genera feed de ciberataques detectados en logs recientes.")
    threat.add_argument("--environment", default="auto", help="Contexto del entorno: auto/prod/staging/lab.")
    threat.add_argument("--lines", type=int, default=300, help="Líneas de log a analizar.")
    threat.add_argument("-o", "--output", help="Ruta de salida JSON del feed.")
    threat.set_defaults(func=cmd_threat_feed)

    conn_guard = sub.add_parser("connection-guard", help="Automatiza análisis de conexiones y detección de anomalías.")
    conn_guard.add_argument("--mode", choices=["learn", "analyze", "watch"], default="analyze")
    conn_guard.add_argument("--interval", type=int, default=5, help="Intervalo de muestreo en segundos para modo watch.")
    conn_guard.add_argument("--duration", type=int, default=30, help="Duración total en segundos.")
    conn_guard.add_argument("--apply-block", action="store_true", help="Aplica bloqueo defensivo real (requiere root+ufw).")
    conn_guard.add_argument("-o", "--output", help="Ruta de salida JSON.")
    conn_guard.set_defaults(func=cmd_connection_guard)

    services = sub.add_parser("services", help="Inspección y control de servicios del sistema (defensivo).")
    services.add_argument("--action", choices=["list", "status", "start", "stop", "restart"], default="list")
    services.add_argument("--name", default="nginx", help="Nombre del servicio para status/start/stop/restart.")
    services.add_argument("--apply", action="store_true", help="Aplicar cambios reales (requiere root).")
    services.set_defaults(func=cmd_services)

    incident = sub.add_parser("incident", help="Gestión de incidentes y evidencia forense.")
    incident_sub = incident.add_subparsers(dest="incident_cmd", required=True)

    incident_list = incident_sub.add_parser("list", help="Lista incidentes registrados.")
    incident_list.set_defaults(func=cmd_incident)

    incident_create = incident_sub.add_parser("create", help="Crea incidente manual.")
    incident_create.add_argument("--title", required=True)
    incident_create.add_argument("--severity", choices=["low", "medium", "high"], default="medium")
    incident_create.add_argument("--source", default="manual")
    incident_create.add_argument("--details", default="")
    incident_create.add_argument("--tags", nargs="*", default=[])
    incident_create.set_defaults(func=cmd_incident)

    incident_status = incident_sub.add_parser("status", help="Actualiza estado de incidente.")
    incident_status.add_argument("--id", required=True)
    incident_status.add_argument("--status", choices=["open", "investigating", "contained", "closed"], required=True)
    incident_status.add_argument("--note", default="")
    incident_status.set_defaults(func=cmd_incident)

    incident_evidence = incident_sub.add_parser("evidence", help="Adjunta evidencia con hash SHA256.")
    incident_evidence.add_argument("--id", required=True)
    incident_evidence.add_argument("--path", required=True)
    incident_evidence.add_argument("--note", default="")
    incident_evidence.set_defaults(func=cmd_incident)

    incident_guard = incident_sub.add_parser("from-guard", help="Genera incidentes desde connection-guard.")
    incident_guard.add_argument("--interval", type=int, default=5)
    incident_guard.add_argument("--duration", type=int, default=20)
    incident_guard.set_defaults(func=cmd_incident)

    notify = sub.add_parser("notify", help="Envía alerta defensiva por webhook.")
    notify.add_argument("--webhook", required=True)
    notify.add_argument("--level", choices=["info", "warning", "critical"], default="warning")
    notify.add_argument("--title", required=True)
    notify.add_argument("--message", required=True)
    notify.set_defaults(func=cmd_alert_notify)

    runtime = sub.add_parser("runtime-monitor", help="Valida ejecución integral de módulos clave.")
    runtime.add_argument("-o", "--output", help="Ruta opcional para guardar el reporte JSON.")
    runtime.set_defaults(func=cmd_runtime_monitor)

    startup = sub.add_parser(
        "startup",
        help="Genera estado integral al iniciar software y valida módulos.",
    )
    startup.add_argument(
        "-o",
        "--status-file",
        default="decktroy_startup_status.json",
        help="Archivo JSON de estado de inicio.",
    )
    startup.set_defaults(func=cmd_startup)

    web = sub.add_parser("web", help="Inicia dashboard web para ejecución y control defensivo.")
    web.add_argument("--host", default="127.0.0.1", help="Host de escucha (ej. 0.0.0.0).")
    web.add_argument("--port", type=int, default=8080, help="Puerto HTTP del dashboard.")
    web.add_argument("--refresh", type=int, default=5, help="Refresco automático en segundos.")
    web.add_argument("--enable-service-control", action="store_true", help="Habilita start/stop/restart desde UI (root recomendado).")
    web.set_defaults(func=cmd_web)

    selftest = sub.add_parser("selftest", help="Ejecuta verificación completa de módulos y comandos.")
    selftest.set_defaults(func=cmd_selftest)

    pb = sub.add_parser("playbook", help="Gestiona playbooks de respuesta defensiva.")
    pb_sub = pb.add_subparsers(dest="playbook_cmd", required=True)

    pb_list = pb_sub.add_parser("list", help="Lista playbooks disponibles.")
    pb_list.set_defaults(func=cmd_playbook_list)

    pb_show = pb_sub.add_parser("show", help="Muestra detalle de un playbook.")
    pb_show.add_argument("name", help="Nombre del playbook.")
    pb_show.set_defaults(func=cmd_playbook_show)

    execute = sub.add_parser("execute", help="Ejecutor restringido a comandos defensivos permitidos.")
    execute.add_argument("exec_cmd", nargs=argparse.REMAINDER, help="Comando exacto permitido.")
    execute.set_defaults(func=cmd_execute)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.action == "execute" and not args.exec_cmd:
        parser.error("Debe proporcionar un comando para execute")

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
