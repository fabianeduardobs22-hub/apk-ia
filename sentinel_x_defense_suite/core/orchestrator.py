from __future__ import annotations

import logging
from collections import deque

from sentinel_x_defense_suite.analysis.processor import PacketProcessor
from sentinel_x_defense_suite.capture.engine import PacketCaptureEngine
from sentinel_x_defense_suite.detection.engine import DetectionConfig, HybridDetectionEngine
from sentinel_x_defense_suite.forensics.repository import ForensicsRepository
from sentinel_x_defense_suite.plugins.manager import PluginManager

logger = logging.getLogger(__name__)


class SentinelOrchestrator:
    def __init__(
        self,
        capture: PacketCaptureEngine,
        processor: PacketProcessor,
        detector: HybridDetectionEngine,
        forensics: ForensicsRepository,
        plugins: PluginManager,
    ) -> None:
        self.capture = capture
        self.processor = processor
        self.detector = detector
        self.forensics = forensics
        self.plugins = plugins
        self.recent_alerts = deque(maxlen=300)

    @classmethod
    def from_defaults(
        cls,
        db_path: str,
        plugin_dir: str,
        interface: str,
        bpf_filter: str,
        replay_pcap: str | None = None,
        simulate: bool = False,
    ) -> "SentinelOrchestrator":
        capture = PacketCaptureEngine(interface=interface, bpf_filter=bpf_filter, replay_pcap=replay_pcap, simulate=simulate)
        processor = PacketProcessor()
        detector = HybridDetectionEngine(DetectionConfig())
        forensics = ForensicsRepository(db_path=db_path)
        plugins = PluginManager(plugins_dir=plugin_dir)
        plugins.load()
        return cls(capture, processor, detector, forensics, plugins)

    async def run(self, max_packets: int | None = None) -> None:
        processed = 0
        async for packet in self.capture.stream():
            packet = self.processor.process(packet)
            self.forensics.save_packet(packet)
            self.plugins.dispatch_packet(packet)
            for alert in self.detector.evaluate(packet):
                self.forensics.save_alert(alert)
                self.recent_alerts.append(alert)
                logger.warning("Alerta %s [%s] %s -> %s", alert.rule_id, alert.severity, alert.src_ip, alert.dst_ip)

            processed += 1
            if max_packets is not None and processed >= max_packets:
                break


async def run_default(
    db_path: str = "data/sentinel_x.db",
    plugin_dir: str = "plugins",
    interface: str = "any",
    bpf_filter: str = "",
    replay_pcap: str | None = None,
    simulate: bool = False,
    max_packets: int | None = None,
) -> None:
    orchestrator = SentinelOrchestrator.from_defaults(db_path, plugin_dir, interface, bpf_filter, replay_pcap, simulate)
    await orchestrator.run(max_packets=max_packets)
