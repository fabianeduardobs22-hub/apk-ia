from datetime import datetime, timedelta, timezone

from sentinel_x_defense_suite.detection.engine import DetectionConfig, HybridDetectionEngine
from sentinel_x_defense_suite.models.events import PacketRecord


def test_detects_connection_spike() -> None:
    engine = HybridDetectionEngine(DetectionConfig(max_connections_per_ip=2))
    alerts = []
    for port in (80, 81, 82):
        pkt = PacketRecord.now("10.0.0.1", "1.1.1.1", 12345, port, "TCP", 100)
        alerts = engine.evaluate(pkt)
    assert any(a.rule_id == "RULE_CONN_SPIKE" for a in alerts)


def test_detects_beaconing_pattern() -> None:
    engine = HybridDetectionEngine(DetectionConfig(beaconing_interval_tolerance_s=1))
    base = datetime.now(tz=timezone.utc)
    alerts = []
    for i in range(4):
        pkt = PacketRecord(
            timestamp=base + timedelta(seconds=i * 10),
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            length=120,
        )
        alerts = engine.evaluate(pkt)
    assert any(a.rule_id == "RULE_BEACONING" for a in alerts)
