from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinel_x_defense_suite.models.events import DetectionAlert, PacketRecord, RiskScore, Severity


@dataclass(slots=True)
class DetectionConfig:
    max_connections_per_ip: int = 400
    brute_force_window_s: int = 120
    brute_force_threshold: int = 25
    beaconing_interval_tolerance_s: int = 3


class HybridDetectionEngine:
    """Motor híbrido (reglas + comportamiento), estrictamente defensivo."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._connections = defaultdict(set)
        self._failed_like = defaultdict(deque)
        self._ip_scores: dict[str, float] = defaultdict(float)
        self._beacon_times = defaultdict(deque)

    def evaluate(self, packet: PacketRecord) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        src = packet.src_ip
        dst_tuple = (packet.dst_ip, packet.dst_port, packet.protocol)
        self._connections[src].add(dst_tuple)

        if len(self._connections[src]) > self.config.max_connections_per_ip:
            alerts.append(
                self._mk_alert(
                    "RULE_CONN_SPIKE",
                    "Exceso de conexiones simultáneas",
                    "Se observó un número anormalmente alto de destinos desde una sola IP.",
                    Severity.HIGH,
                    packet,
                    0.85,
                )
            )
            self._ip_scores[src] += 25

        if packet.protocol.upper() == "TCP" and packet.dst_port in (22, 3389, 21):
            wins = self._failed_like[src]
            now = datetime.now(tz=timezone.utc)
            wins.append(now)
            cutoff = now - timedelta(seconds=self.config.brute_force_window_s)
            while wins and wins[0] < cutoff:
                wins.popleft()
            if len(wins) >= self.config.brute_force_threshold:
                alerts.append(
                    self._mk_alert(
                        "RULE_BRUTE_PATTERN",
                        "Patrón de fuerza bruta",
                        "Múltiples intentos repetitivos sobre servicios de autenticación.",
                        Severity.CRITICAL,
                        packet,
                        0.9,
                    )
                )
                self._ip_scores[src] += 35

        beacon_deque = self._beacon_times[(src, packet.dst_ip, packet.dst_port)]
        beacon_deque.append(packet.timestamp)
        if len(beacon_deque) >= 4:
            intervals = [
                (beacon_deque[i] - beacon_deque[i - 1]).total_seconds()
                for i in range(1, len(beacon_deque))
            ]
            if max(intervals) - min(intervals) <= self.config.beaconing_interval_tolerance_s:
                alerts.append(
                    self._mk_alert(
                        "RULE_BEACONING",
                        "Beaconing sospechoso",
                        "Intervalos de conexión altamente regulares detectados.",
                        Severity.MEDIUM,
                        packet,
                        0.75,
                    )
                )
                self._ip_scores[src] += 15
            if len(beacon_deque) > 8:
                beacon_deque.popleft()

        return alerts

    def get_risk(self, ip: str) -> RiskScore:
        score = self._ip_scores.get(ip, 0.0)
        if score >= 80:
            level = Severity.CRITICAL
        elif score >= 50:
            level = Severity.HIGH
        elif score >= 20:
            level = Severity.MEDIUM
        else:
            level = Severity.LOW
        return RiskScore(ip=ip, score=score, level=level)

    @staticmethod
    def _mk_alert(
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        packet: PacketRecord,
        confidence: float,
    ) -> DetectionAlert:
        return DetectionAlert(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            confidence=confidence,
            details={"dst_port": packet.dst_port, "protocol": packet.protocol},
        )
