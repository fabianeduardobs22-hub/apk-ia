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


def test_state_is_bounded_by_capacity_under_many_unique_ips() -> None:
    engine = HybridDetectionEngine(
        DetectionConfig(
            max_tracked_ips=50,
            max_tracked_flows=70,
            cleanup_every_n_packets=10_000,
            inactivity_ttl_s=86_400,
        )
    )
    base = datetime.now(tz=timezone.utc)

    for i in range(2_000):
        pkt = PacketRecord(
            timestamp=base + timedelta(seconds=i),
            src_ip=f"10.10.{i // 255}.{i % 255}",
            dst_ip="203.0.113.10",
            src_port=40000 + (i % 1000),
            dst_port=443,
            protocol="TCP",
            length=128,
        )
        engine.evaluate(pkt)

    metrics = engine.get_internal_metrics()
    assert metrics["tracked_ips"] <= 50
    assert metrics["tracked_flows"] <= 70
    assert metrics["capacity_evicted_ips"] > 0
    assert metrics["capacity_evicted_flows"] > 0


def test_ttl_cleanup_evicts_inactive_keys() -> None:
    engine = HybridDetectionEngine(
        DetectionConfig(
            inactivity_ttl_s=5,
            cleanup_every_n_packets=1,
            max_tracked_ips=1_000,
            max_tracked_flows=1_000,
        )
    )
    base = datetime.now(tz=timezone.utc)

    first = PacketRecord(
        timestamp=base,
        src_ip="10.0.0.10",
        dst_ip="198.51.100.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        length=100,
    )
    second = PacketRecord(
        timestamp=base + timedelta(seconds=10),
        src_ip="10.0.0.20",
        dst_ip="198.51.100.2",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        length=100,
    )

    engine.evaluate(first)
    engine.evaluate(second)

    metrics = engine.get_internal_metrics()
    assert metrics["tracked_ips"] == 1
    assert metrics["tracked_flows"] == 1
    assert metrics["ttl_expired_ips"] >= 1
    assert metrics["ttl_expired_flows"] >= 1
