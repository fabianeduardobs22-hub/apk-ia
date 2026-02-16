from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sentinel_x_defense_suite.models.events import PacketRecord


@dataclass(slots=True)
class TrafficStats:
    packets_total: int = 0
    bytes_total: int = 0
    by_protocol: Counter[str] = field(default_factory=Counter)


class PacketProcessor:
    def __init__(self) -> None:
        self.stats = TrafficStats()

    def process(self, packet: PacketRecord) -> PacketRecord:
        self.stats.packets_total += 1
        self.stats.bytes_total += packet.length
        self.stats.by_protocol[packet.protocol.upper()] += 1

        # Clasificación de servicio basada en puerto
        service_map = {53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 445: "SMB"}
        packet.metadata["service"] = service_map.get(packet.dst_port, "UNKNOWN")
        packet.metadata["direction"] = "outbound" if packet.src_ip.startswith("10.") else "inbound"
        return packet
