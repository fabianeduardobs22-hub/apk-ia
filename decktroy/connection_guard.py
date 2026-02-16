#!/usr/bin/env python3
"""DECKTROY Connection Guard (defensive-only).

Automated connection inventory, baseline learning, anomaly detection,
scanner-pattern detection (e.g., Nmap-like behavior), and optional defensive
blocking (strictly host-defense, never offensive counter-intrusion).
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(command: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except Exception as exc:  # pylint: disable=broad-except
        return 1, "", str(exc)


@dataclass
class ConnectionEvent:
    ts: str
    proto: str
    state: str
    local_ip: str
    local_port: str
    remote_ip: str
    remote_port: str
    process: str


@dataclass
class Alert:
    severity: str
    category: str
    source_ip: str
    detail: str
    recommended_commands: list[str]
    mitre_refs: list[str]


BASELINE_FILE = Path("decktroy_connection_baseline.json")


MITRE_MAP = {
    "scanner_pattern": ["TA0043", "T1595"],
    "unknown_pattern": ["TA0001", "T1190"],
}


def parse_addr(addr: str) -> tuple[str, str]:
    if not addr or addr in {"*", "-"}:
        return "0.0.0.0", "0"
    if addr.startswith("[") and "]" in addr:
        # [::1]:443
        try:
            host = addr[1 : addr.rfind("]")]
            port = addr.split(":")[-1]
            return host, port
        except Exception:  # pylint: disable=broad-except
            return addr, "0"
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
        return host, port
    return addr, "0"


def collect_connections() -> list[ConnectionEvent]:
    if shutil.which("ss"):
        code, out, _ = run_command(["ss", "-tunap"], timeout=8)
        if code == 0 and out:
            return parse_ss_output(out)

    # Fallback
    if shutil.which("netstat"):
        code, out, _ = run_command(["netstat", "-tunap"], timeout=8)
        if code == 0 and out:
            return parse_netstat_output(out)

    return []


def parse_ss_output(out: str) -> list[ConnectionEvent]:
    lines = out.splitlines()
    events: list[ConnectionEvent] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, state = parts[0], parts[1]
        local, remote = parts[4], parts[5]
        process = " ".join(parts[6:]) if len(parts) > 6 else ""
        local_ip, local_port = parse_addr(local)
        remote_ip, remote_port = parse_addr(remote)
        events.append(
            ConnectionEvent(
                ts=utc_now(),
                proto=proto,
                state=state,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                process=process[:180],
            )
        )
    return events


def parse_netstat_output(out: str) -> list[ConnectionEvent]:
    events: list[ConnectionEvent] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0]
        local = parts[3]
        remote = parts[4]
        state = parts[5] if len(parts) > 5 else "UNKNOWN"
        process = parts[6] if len(parts) > 6 else ""
        local_ip, local_port = parse_addr(local)
        remote_ip, remote_port = parse_addr(remote)
        events.append(
            ConnectionEvent(
                ts=utc_now(),
                proto=proto,
                state=state,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                process=process[:180],
            )
        )
    return events


def conn_key(evt: ConnectionEvent) -> str:
    # generalize remote endpoint to /24-ish for baseline resilience
    remote = evt.remote_ip
    if remote.count(".") == 3:
        parts = remote.split(".")
        remote = ".".join(parts[:3] + ["0/24"])
    return f"{evt.proto}|{evt.local_port}|{evt.state}|{remote}"


def load_baseline() -> dict[str, Any]:
    if not BASELINE_FILE.exists():
        return {"created_at": utc_now(), "samples": 0, "counts": {}}
    try:
        return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except Exception:  # pylint: disable=broad-except
        return {"created_at": utc_now(), "samples": 0, "counts": {}}


def save_baseline(data: dict[str, Any]) -> None:
    BASELINE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def learn_baseline(events: list[ConnectionEvent]) -> dict[str, Any]:
    baseline = load_baseline()
    counts = baseline.get("counts", {})
    for evt in events:
        key = conn_key(evt)
        counts[key] = counts.get(key, 0) + 1
    baseline["counts"] = counts
    baseline["samples"] = int(baseline.get("samples", 0)) + len(events)
    baseline["updated_at"] = utc_now()
    save_baseline(baseline)
    return baseline


def detect_nmap_like(events: list[ConnectionEvent]) -> dict[str, int]:
    # Heuristic: same source touches many local ports in short sample
    src_to_ports: dict[str, set[str]] = {}
    for evt in events:
        if evt.remote_ip in {"0.0.0.0", "*", "::"}:
            continue
        src_to_ports.setdefault(evt.remote_ip, set()).add(evt.local_port)
    return {ip: len(ports) for ip, ports in src_to_ports.items() if len(ports) >= 8}


def detect_anomalies(events: list[ConnectionEvent], baseline: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    counts = baseline.get("counts", {})

    # 1) Unknown patterns against baseline
    unknown_by_src: dict[str, int] = {}
    for evt in events:
        key = conn_key(evt)
        if key not in counts and evt.remote_ip not in {"0.0.0.0", "*", "::"}:
            unknown_by_src[evt.remote_ip] = unknown_by_src.get(evt.remote_ip, 0) + 1

    for src, qty in unknown_by_src.items():
        sev = "high" if qty >= 15 else "medium"
        alerts.append(
            Alert(
                severity=sev,
                category="unknown_pattern",
                source_ip=src,
                detail=f"{qty} conexiones fuera de baseline detectadas.",
                recommended_commands=[
                    "python3 decktroy/decktroy_cli.py advisor --environment auto",
                    f"sudo ufw deny from {src}",
                    "python3 decktroy/decktroy_cli.py playbook show bruteforce-shield",
                ],
                mitre_refs=MITRE_MAP.get("unknown_pattern", []),
            )
        )

    # 2) Nmap-like / scanner-like behavior
    scanners = detect_nmap_like(events)
    for src, port_count in scanners.items():
        alerts.append(
            Alert(
                severity="high",
                category="scanner_pattern",
                source_ip=src,
                detail=f"Patrón tipo escaneo: {port_count} puertos distintos tocados en ventana corta.",
                recommended_commands=[
                    f"sudo ufw deny from {src}",
                    "sudo journalctl -p warning -n 200",
                    "python3 decktroy/decktroy_cli.py playbook show ddos-rate-limit",
                ],
                mitre_refs=MITRE_MAP.get("scanner_pattern", []),
            )
        )

    return alerts


def defensive_block_ip(ip: str, apply_block: bool = False) -> dict[str, Any]:
    if not apply_block:
        return {"ok": True, "dry_run": True, "command": f"sudo ufw deny from {ip}"}

    if shutil.which("ufw") is None:
        return {"ok": False, "dry_run": False, "message": "ufw no disponible"}

    if hasattr(socket, "gethostname") and hasattr(__import__("os"), "geteuid"):
        import os

        if os.geteuid() != 0:
            return {"ok": False, "dry_run": False, "message": "Se requiere root para aplicar bloqueo."}

    code, out, err = run_command(["ufw", "deny", "from", ip], timeout=10)
    return {"ok": code == 0, "dry_run": False, "message": (out or err or "ok")[:400]}


def run_guard(mode: str = "analyze", interval: int = 5, duration: int = 30, apply_block: bool = False) -> dict[str, Any]:
    cycles = max(1, duration // max(1, interval)) if mode == "watch" else 1
    all_events: list[ConnectionEvent] = []

    for _ in range(cycles):
        all_events.extend(collect_connections())
        if mode == "watch":
            time.sleep(interval)

    if mode == "learn":
        baseline = learn_baseline(all_events)
        return {
            "generated_at": utc_now(),
            "mode": mode,
            "total_connections": len(all_events),
            "baseline": baseline,
            "alerts": [],
            "auto_actions": [],
        }

    baseline = load_baseline()
    alerts = detect_anomalies(all_events, baseline)

    auto_actions: list[dict[str, Any]] = []
    for alert in alerts:
        if alert.severity == "high":
            auto_actions.append(
                {
                    "source_ip": alert.source_ip,
                    "category": alert.category,
                    "block": defensive_block_ip(alert.source_ip, apply_block=apply_block),
                }
            )

    return {
        "generated_at": utc_now(),
        "mode": mode,
        "hostname": socket.gethostname(),
        "total_connections": len(all_events),
        "baseline_samples": int(load_baseline().get("samples", 0)),
        "alerts": [asdict(a) for a in alerts],
        "auto_actions": auto_actions,
        "counts": {
            "high": sum(1 for a in alerts if a.severity == "high"),
            "medium": sum(1 for a in alerts if a.severity == "medium"),
            "low": sum(1 for a in alerts if a.severity == "low"),
        },
    }
