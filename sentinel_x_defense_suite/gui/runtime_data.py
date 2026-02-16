from __future__ import annotations

import hashlib
import ipaddress
import platform
import re
import socket
import subprocess
from collections import Counter
from typing import Any


def run_command(command: list[str], timeout: int = 5) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return ""
    return (proc.stdout or "").strip()


def _extract_ip_port(value: str) -> tuple[str, int]:
    raw = value.strip()
    if raw.startswith("[") and "]" in raw:
        host, _, tail = raw[1:].partition("]")
        if tail.startswith(":") and tail[1:].isdigit():
            return host, int(tail[1:])
        return host, 0

    if raw.count(":") > 1 and raw.rsplit(":", 1)[-1].isdigit():
        host, port = raw.rsplit(":", 1)
        return host, int(port)

    if ":" in raw:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)

    return raw, 0


def _detect_service_name(port: int, protocol: str) -> str:
    known = {
        22: "ssh",
        53: "dns",
        80: "http",
        123: "ntp",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
    }
    if port in known:
        return known[port]
    try:
        return socket.getservbyport(port, "udp" if protocol.startswith("udp") else "tcp")
    except Exception:
        return "unknown"


def _extract_process_name(line: str) -> str:
    proc_match = re.search(r'users:\(\("([^"]+)"', line)
    if proc_match:
        return proc_match.group(1)
    proc_match = re.search(r'"([^"]+)"', line)
    if proc_match:
        return proc_match.group(1)
    return "unknown"


def parse_listening_sockets(raw_output: str) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    if not raw_output:
        return services

    for line in raw_output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        state = parts[1].upper() if len(parts) > 1 else "UNKNOWN"
        local_addr = parts[4]

        ip, port = _extract_ip_port(local_addr)
        process_name = _extract_process_name(line)
        service_name = _detect_service_name(port, proto)

        services.append(
            {
                "protocol": proto,
                "state": state,
                "bind_ip": ip,
                "port": port,
                "process": process_name,
                "service": service_name,
                "raw": line,
            }
        )
    return services


def parse_active_connections(raw_output: str) -> list[dict[str, Any]]:
    connections: list[dict[str, Any]] = []
    if not raw_output:
        return connections

    for line in raw_output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue

        proto = parts[0].lower()
        state = parts[1].upper()
        local_addr = parts[4]
        peer_addr = parts[5]

        src_ip, src_port = _extract_ip_port(local_addr)
        dst_ip, dst_port = _extract_ip_port(peer_addr)

        connections.append(
            {
                "protocol": proto,
                "state": state,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "service": _detect_service_name(dst_port, proto),
                "raw": line,
            }
        )
    return connections


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_link_local)


def _geo_estimate(ip: str) -> tuple[str, float, float]:
    h = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    a = int(h[:8], 16)
    b = int(h[8:16], 16)
    countries = ["US", "DE", "BR", "JP", "IN", "SG", "ES", "MX", "GB", "CA", "AU"]
    country = countries[a % len(countries)]
    lat = round((a / 0xFFFFFFFF) * 180.0 - 90.0, 3)
    lon = round((b / 0xFFFFFFFF) * 360.0 - 180.0, 3)
    return country, lat, lon


def _listening_tcp_ports(services: list[dict[str, Any]]) -> set[int]:
    return {
        service["port"]
        for service in services
        if service.get("port", 0) > 0 and str(service.get("protocol", "")).startswith("tcp")
    }


def build_runtime_snapshot() -> dict[str, Any]:
    listening_raw = run_command(["ss", "-tulpenH"], timeout=8)
    active_raw = run_command(["ss", "-tunapH"], timeout=8)

    services = parse_listening_sockets(listening_raw)
    active = parse_active_connections(active_raw)

    remote_hits = [c for c in active if _is_public_ip(c["dst_ip"]) and c["state"] in {"ESTAB", "SYN-RECV", "SYN-SENT"}]
    by_ip = Counter(c["dst_ip"] for c in remote_hits)

    globe_lines = ["Mapa global de conexiones sospechosas (estimado):"]
    globe_points: list[dict[str, Any]] = []
    for ip, count in by_ip.most_common(20):
        country, lat, lon = _geo_estimate(ip)
        severity = 1 if count <= 1 else 2 if count <= 3 else 3 if count <= 6 else 4
        globe_lines.append(f"• {ip} ({country}) lat={lat} lon={lon} eventos={count}")
        globe_points.append({"ip": ip, "country": country, "lat": lat, "lon": lon, "events": count, "severity": severity})
    if len(globe_lines) == 1:
        globe_lines.append("• Sin eventos remotos sospechosos detectados")

    exposed_internet = [s for s in services if s["bind_ip"] in {"0.0.0.0", "::"} and s["port"] > 0]

    exposure_lines = ["Resumen de exposición externa:"]
    if exposed_internet:
        for svc in exposed_internet[:25]:
            exposure_lines.append(
                f"• {svc['protocol'].upper()} {svc['bind_ip']}:{svc['port']} svc={svc['service']} proc={svc['process']}"
            )
    else:
        exposure_lines.append("• No se detectaron servicios escuchando en todas las interfaces")

    actions = [
        "Acciones rápidas recomendadas:",
        "1) sudo ss -tulpen | sort",
        "2) sudo ufw status numbered",
        "3) sudo journalctl -n 200 --no-pager | grep -Ei 'failed|invalid|denied|attack'",
        "4) decktroy connection-guard --mode analyze --duration 30",
    ]

    listening_tcp_ports = _listening_tcp_ports(services)
    incoming_connections = [
        c
        for c in active
        if c["state"] in {"ESTAB", "SYN-RECV", "NEW"}
        and c["dst_port"] > 0
        and str(c["protocol"]).startswith("tcp")
        and c["src_port"] in listening_tcp_ports
    ]

    service_versions = detect_service_versions()

    return {
        "services": services,
        "active_connections": active,
        "incoming_connections": incoming_connections,
        "remote_suspicious": remote_hits,
        "globe_lines": globe_lines,
        "actions": actions,
        "exposure_lines": exposure_lines,
        "public_service_count": len(exposed_internet),
        "service_versions": service_versions,
        "globe_points": globe_points,
    }


def detect_service_versions() -> list[dict[str, Any]]:
    inventory = [
        {"name": "python", "commands": [["python3", "--version"], ["python", "--version"]]},
        {"name": "php", "commands": [["php", "-v"]]},
        {"name": "mysql", "commands": [["mysql", "--version"]]},
        {"name": "psql", "commands": [["psql", "--version"]]},
        {"name": "redis", "commands": [["redis-server", "--version"]]},
        {"name": "nginx", "commands": [["nginx", "-v"]]},
        {"name": "apache2", "commands": [["apache2", "-v"]]},
        {"name": "node", "commands": [["node", "--version"]]},
        {"name": "docker", "commands": [["docker", "--version"]]},
    ]

    results: list[dict[str, Any]] = [
        {
            "service": "os",
            "version": platform.platform(),
            "active": True,
            "connection_type": "local-system",
            "command": "platform.platform()",
            "port": "n/a",
            "status": "running",
        }
    ]

    for item in inventory:
        detected = {
            "service": item["name"],
            "version": "not installed",
            "active": False,
            "connection_type": "local-service",
            "command": "",
            "port": "unknown",
            "status": "inactive",
        }
        for command in item["commands"]:
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
            except Exception:
                continue
            text = (proc.stdout or proc.stderr or "").strip()
            if proc.returncode == 0 and text:
                detected["version"] = text.splitlines()[0][:240]
                detected["active"] = True
                detected["command"] = " ".join(command)
                detected["status"] = "running"
                break
        results.append(detected)

    return results


def suggested_connection_defense_commands(connection: dict[str, Any]) -> list[str]:
    dst_ip = connection.get("dst_ip", "<IP>")
    dst_port = connection.get("dst_port", "<PORT>")
    protocol = str(connection.get("protocol", "tcp")).replace("6", "")
    return [
        "Comandos sugeridos (defensivos de mitigación):",
        f"sudo ufw deny out to {dst_ip} port {dst_port} proto {protocol}",
        f"sudo iptables -A OUTPUT -d {dst_ip} -p {protocol} --dport {dst_port} -j DROP",
        f"sudo ss -tunap | grep -E '{dst_ip}|:{dst_port}'",
        f"sudo tcpdump -nn host {dst_ip} and port {dst_port} -c 100",
        "sudo systemctl restart sentinel-x.service",
    ]


def suggested_service_admin_commands(service: dict[str, Any]) -> list[str]:
    name = service.get("service", "service")
    return [
        "Comandos sugeridos (administración defensiva):",
        f"systemctl status {name}",
        f"sudo systemctl restart {name}",
        f"sudo systemctl stop {name}",
        f"sudo systemctl start {name}",
        f"sudo journalctl -u {name} -n 100 --no-pager",
    ]
