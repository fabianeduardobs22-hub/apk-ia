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
    inactivity_ttl_s: int = 900
    cleanup_every_n_packets: int = 64
    max_tracked_ips: int = 10_000
    max_tracked_flows: int = 20_000


class HybridDetectionEngine:
    """Motor híbrido (reglas + comportamiento), estrictamente defensivo."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._connections = defaultdict(set)
        self._failed_like = defaultdict(deque)
        self._ip_scores: dict[str, float] = defaultdict(float)
        self._beacon_times = defaultdict(deque)
        self._ip_last_seen: dict[str, datetime] = {}
        self._flow_last_seen: dict[tuple[str, str, int], datetime] = {}
        self._packets_since_cleanup = 0
        self._metrics: dict[str, int] = {
            "cleanup_runs": 0,
            "evicted_ips": 0,
            "evicted_flows": 0,
            "ttl_expired_ips": 0,
            "ttl_expired_flows": 0,
            "capacity_evicted_ips": 0,
            "capacity_evicted_flows": 0,
        }

    def evaluate(self, packet: PacketRecord) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        now = packet.timestamp
        self._packets_since_cleanup += 1
        if self._packets_since_cleanup >= self.config.cleanup_every_n_packets:
            self._cleanup_inactive(now)
            self._packets_since_cleanup = 0

        src = packet.src_ip
        self._track_ip(src, now)
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

        flow_key = (src, packet.dst_ip, packet.dst_port)
        self._track_flow(flow_key, now)
        beacon_deque = self._beacon_times[flow_key]
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

    def get_internal_metrics(self) -> dict[str, int]:
        return {
            **self._metrics,
            "tracked_ips": len(self._ip_last_seen),
            "tracked_flows": len(self._flow_last_seen),
        }

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

    def _cleanup_inactive(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.config.inactivity_ttl_s)

        expired_ips = [ip for ip, last_seen in self._ip_last_seen.items() if last_seen < cutoff]
        for ip in expired_ips:
            self._evict_ip(ip, ttl_expired=True)

        expired_flows = [
            flow_key
            for flow_key, last_seen in self._flow_last_seen.items()
            if last_seen < cutoff
        ]
        for flow_key in expired_flows:
            self._evict_flow(flow_key, ttl_expired=True)

        self._metrics["cleanup_runs"] += 1

    def _track_ip(self, ip: str, now: datetime) -> None:
        self._ip_last_seen[ip] = now
        self._ensure_ip_capacity()

    def _track_flow(self, flow_key: tuple[str, str, int], now: datetime) -> None:
        self._flow_last_seen[flow_key] = now
        self._ensure_flow_capacity()

    def _ensure_ip_capacity(self) -> None:
        while len(self._ip_last_seen) > self.config.max_tracked_ips:
            oldest_ip = min(self._ip_last_seen, key=self._ip_last_seen.get)
            self._evict_ip(oldest_ip, ttl_expired=False)
            self._metrics["capacity_evicted_ips"] += 1

    def _ensure_flow_capacity(self) -> None:
        while len(self._flow_last_seen) > self.config.max_tracked_flows:
            oldest_flow = min(self._flow_last_seen, key=self._flow_last_seen.get)
            self._evict_flow(oldest_flow, ttl_expired=False)
            self._metrics["capacity_evicted_flows"] += 1

    def _evict_ip(self, ip: str, ttl_expired: bool) -> None:
        self._connections.pop(ip, None)
        self._failed_like.pop(ip, None)
        self._ip_scores.pop(ip, None)
        self._ip_last_seen.pop(ip, None)
        self._metrics["evicted_ips"] += 1
        if ttl_expired:
            self._metrics["ttl_expired_ips"] += 1

    def _evict_flow(self, flow_key: tuple[str, str, int], ttl_expired: bool) -> None:
        self._beacon_times.pop(flow_key, None)
        self._flow_last_seen.pop(flow_key, None)
        self._metrics["evicted_flows"] += 1
        if ttl_expired:
            self._metrics["ttl_expired_flows"] += 1
