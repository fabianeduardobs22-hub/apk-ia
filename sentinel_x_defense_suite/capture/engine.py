from __future__ import annotations

import asyncio
import logging
import random
from typing import AsyncIterator

from sentinel_x_defense_suite.models.events import PacketRecord

logger = logging.getLogger(__name__)


class PacketCaptureEngine:
    """Motor defensivo de captura. Usa scapy si está disponible, con fallback sintético."""

    def __init__(self, interface: str = "any", bpf_filter: str = "") -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter

    async def stream(self) -> AsyncIterator[PacketRecord]:
        try:
            from scapy.all import AsyncSniffer  # type: ignore

            queue: asyncio.Queue[PacketRecord] = asyncio.Queue(maxsize=2000)

            def on_packet(pkt: object) -> None:
                try:
                    src_ip = getattr(pkt, "src", "0.0.0.0")
                    dst_ip = getattr(pkt, "dst", "0.0.0.0")
                    proto = getattr(pkt, "name", "UNKNOWN")
                    length = len(bytes(pkt))
                    packet = PacketRecord.now(src_ip, dst_ip, 0, 0, proto, length, bytes(pkt))
                    queue.put_nowait(packet)
                except Exception as exc:  # defensivo
                    logger.debug("Error normalizando paquete: %s", exc)

            sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter or None, prn=on_packet, store=False)
            sniffer.start()
            logger.info("Captura iniciada en %s", self.interface)
            try:
                while True:
                    yield await queue.get()
            finally:
                sniffer.stop()
        except Exception:
            logger.warning("Scapy/libpcap no disponible; usando generador sintético de telemetría")
            while True:
                await asyncio.sleep(0.1)
                yield PacketRecord.now(
                    src_ip=f"10.0.0.{random.randint(1, 254)}",
                    dst_ip="172.16.0.10",
                    src_port=random.randint(1025, 65535),
                    dst_port=random.choice([53, 80, 443, 22, 445]),
                    protocol=random.choice(["TCP", "UDP", "DNS"]),
                    length=random.randint(60, 1500),
                    payload=b"sample",
                )
