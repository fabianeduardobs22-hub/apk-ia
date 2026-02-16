from pathlib import Path

from sentinel_x_defense_suite.forensics.repository import ForensicsRepository
from sentinel_x_defense_suite.models.events import DetectionAlert, PacketRecord, Severity


def test_persist_packet_and_alert(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    repo = ForensicsRepository(str(db))
    repo.save_packet(PacketRecord.now("10.0.0.1", "8.8.8.8", 44444, 443, "TCP", 90))
    repo.save_alert(
        DetectionAlert(
            rule_id="RULE_TEST",
            title="test",
            description="desc",
            severity=Severity.LOW,
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            confidence=0.8,
        )
    )
    exported = repo.export_json()
    assert len(exported) == 1
    assert exported[0]["rule_id"] == "RULE_TEST"
    assert exported[0]["record_hash"]
