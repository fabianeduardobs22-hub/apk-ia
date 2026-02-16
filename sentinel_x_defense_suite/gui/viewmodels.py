from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass(slots=True)
class RowMetrics:
    src_ip: str
    dst_ip: str
    protocol: str
    risk_level: str
    country: str


@dataclass(slots=True)
class DashboardMetrics:
    threat_level: str
    threat_resume: str
    protocol_lines: list[str]
    geo_lines: list[str]
    topology_lines: list[str]


def compute_dashboard_metrics(rows: list[RowMetrics]) -> DashboardMetrics:
    by_level = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    by_proto: Counter[str] = Counter()
    geo: Counter[str] = Counter()
    edges: Counter[str] = Counter()

    for row in rows:
        level = row.risk_level.upper()
        by_level[level] = by_level.get(level, 0) + 1
        by_proto[row.protocol.upper()] += 1
        geo[row.country] += 1
        edges[f"{row.src_ip} -> {row.dst_ip}"] += 1

    if by_level["CRITICAL"]:
        threat_level = "CRITICAL"
        threat_resume = "Resumen de prueba: actividad grave, activar contención inmediata"
    elif by_level["HIGH"]:
        threat_level = "HIGH"
        threat_resume = "Resumen de prueba: riesgo elevado, aislar activos objetivo"
    elif by_level["MEDIUM"]:
        threat_level = "MEDIUM"
        threat_resume = "Resumen de prueba: anomalías moderadas, intensificar monitoreo"
    else:
        threat_level = "LOW"
        threat_resume = "Resumen de prueba: telemetría estable, vigilancia continua"

    protocol_lines = [f"Conexiones visibles: {len(rows)}"]
    for proto in ["TCP", "UDP", "DNS", "ICMP"]:
        count = by_proto.get(proto, 0)
        protocol_lines.append(f"{proto:<5}: {count:>4} {'▮' * min(24, count)}")

    protocol_lines.extend(
        [
            f"LOW: {by_level['LOW']}",
            f"MEDIUM: {by_level['MEDIUM']}",
            f"HIGH: {by_level['HIGH']}",
            f"CRITICAL: {by_level['CRITICAL']}",
        ]
    )

    geo_lines = ["Conexiones geolocalizadas:"]
    top_geo = geo.most_common(5)
    for country, count in top_geo:
        geo_lines.append(f"• {country:<12} -> Datacenter ({count})")
    if not top_geo:
        geo_lines.append("• Sin datos")
    geo_lines.append("Representación táctica en texto plano para precisión operativa.")

    topology_lines = ["Topología dinámica (enlaces más activos):"]
    top_edges = edges.most_common(8)
    for edge, count in top_edges:
        topology_lines.append(f"- {edge} [{count}]")
    if not top_edges:
        topology_lines.append("- Nodo local -> Gateway -> Servicios externos")

    return DashboardMetrics(
        threat_level=threat_level,
        threat_resume=threat_resume,
        protocol_lines=protocol_lines,
        geo_lines=geo_lines,
        topology_lines=topology_lines,
    )
