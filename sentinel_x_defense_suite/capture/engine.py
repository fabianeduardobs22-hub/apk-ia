from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path
from typing import AsyncIterator, Literal

from sentinel_x_defense_suite.models.events import PacketRecord

logger = logging.getLogger(__name__)
CaptureStatus = Literal["live", "replay", "simulated", "error"]


class CaptureRuntimeError(RuntimeError):
    """Raised when capture runtime cannot initialize in the requested mode."""

def resolve_capture_status(interface: str, replay_pcap: str | None, simulate: bool) -> CaptureStatus:
    if simulate:
        return "simulated"
    if replay_pcap:
        return "replay"
    if interface.lower() in {"", "none", "offline"}:
        return "error"
    return "live"


class PacketCaptureEngine:
    """Motor defensivo de captura con modos explícitos (live/replay/simulated)."""

    def __init__(
        self,
        interface: str = "any",
        bpf_filter: str = "",
        replay_pcap: str | None = None,
        simulate: bool = False,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.replay_pcap = replay_pcap
        self.simulate = simulate
        self.capture_status: CaptureStatus = resolve_capture_status(interface, replay_pcap, simulate)

    def _set_error_status(self) -> None:
        self.capture_status = "error"

    def _require_scapy(self) -> None:
        try:
            import scapy.all  # noqa: F401
        except Exception as exc:
            self._set_error_status()
            raise CaptureRuntimeError(
                "No se pudo iniciar captura operativa: Scapy/libpcap no está disponible. "
                "Instale scapy con soporte libpcap o use --simulate para telemetría sintética explícita."
            ) from exc

    async def _stream_simulated(self) -> AsyncIterator[PacketRecord]:
        self.capture_status = "simulated"
        logger.warning("Captura en modo simulación explícita")
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

    async def _stream_replay(self) -> AsyncIterator[PacketRecord]:
        self._require_scapy()
        replay_path = Path(self.replay_pcap or "")
        if not replay_path.exists():
            self._set_error_status()
            raise CaptureRuntimeError(f"Archivo PCAP no encontrado: {replay_path}")

        from scapy.utils import PcapReader  # type: ignore

        self.capture_status = "replay"
        logger.info("Captura en modo replay desde %s", replay_path)
        with PcapReader(str(replay_path)) as reader:
            for pkt in reader:
                try:
                    src_ip = getattr(pkt, "src", "0.0.0.0")
                    dst_ip = getattr(pkt, "dst", "0.0.0.0")
                    proto = getattr(pkt, "name", "UNKNOWN")
                    payload = bytes(pkt)
                    yield PacketRecord.now(src_ip, dst_ip, 0, 0, proto, len(payload), payload)
                except Exception as exc:  # defensivo
                    logger.debug("Error normalizando paquete de replay: %s", exc)
                await asyncio.sleep(0)

    async def _stream_live(self) -> AsyncIterator[PacketRecord]:
        self._require_scapy()
        from scapy.all import AsyncSniffer  # type: ignore

        queue: asyncio.Queue[PacketRecord] = asyncio.Queue(maxsize=2000)

        def on_packet(pkt: object) -> None:
            try:
                src_ip = getattr(pkt, "src", "0.0.0.0")
                dst_ip = getattr(pkt, "dst", "0.0.0.0")
                proto = getattr(pkt, "name", "UNKNOWN")
                payload = bytes(pkt)
                packet = PacketRecord.now(src_ip, dst_ip, 0, 0, proto, len(payload), payload)
                queue.put_nowait(packet)
            except Exception as exc:  # defensivo
                logger.debug("Error normalizando paquete: %s", exc)

        sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter or None, prn=on_packet, store=False)

        try:
            sniffer.start()
            self.capture_status = "live"
            logger.info("Captura iniciada en %s", self.interface)
            while True:
                yield await queue.get()
        except Exception as exc:
            self._set_error_status()
            raise CaptureRuntimeError(
                "Fallo al iniciar captura en vivo. Verifique interfaz, permisos y soporte libpcap."
            ) from exc
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass

    async def stream(self) -> AsyncIterator[PacketRecord]:
        if self.simulate:
            async for packet in self._stream_simulated():
                yield packet
            return
        if self.replay_pcap:
            async for packet in self._stream_replay():
                yield packet
            return
        async for packet in self._stream_live():
            yield packet
