import time
from typing import Callable, List, Optional
from sentinel_ids.core.packet import PacketDecoder, ParsedPacket
from sentinel_ids.core.flow import FlowTracker
from sentinel_ids.core.pcap import PcapReader
from sentinel_ids.alerts import Alert
from sentinel_ids.detectors.base import BaseDetector
from sentinel_ids.detectors.port_scan import PortScanDetector
from sentinel_ids.detectors.syn_flood import SynFloodDetector
from sentinel_ids.detectors.arp_spoof import ArpSpoofDetector
from sentinel_ids.detectors.dns_tunnel import DnsTunnelDetector


class SentinelEngine:
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        self.flow_tracker = FlowTracker()
        self.detectors: List[BaseDetector] = detectors or [
            PortScanDetector(),
            SynFloodDetector(),
            ArpSpoofDetector(),
            DnsTunnelDetector()
        ]
        self.total_packets = 0
        self.alerts: List[Alert] = []
        self.protocols_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

    def process_raw_packet(self, raw_bytes: bytes, timestamp: float = 0.0) -> List[Alert]:
        self.total_packets += 1
        packet = PacketDecoder.decode(raw_bytes, timestamp=timestamp)

        # Count protocols
        proto = packet.protocol_name
        if proto in self.protocols_count:
            self.protocols_count[proto] += 1
        else:
            self.protocols_count["OTHER"] += 1

        flow = self.flow_tracker.process(packet)

        new_alerts = []
        for detector in self.detectors:
            triggered = detector.analyze(packet, flow, self.flow_tracker)
            if triggered:
                new_alerts.extend(triggered)

        self.alerts.extend(new_alerts)
        return new_alerts

    def analyze_pcap(self, pcap_path: str, alert_callback: Optional[Callable[[Alert], None]] = None) -> List[Alert]:
        reader = PcapReader(pcap_path)
        for raw_bytes, ts in reader:
            detected = self.process_raw_packet(raw_bytes, timestamp=ts)
            if alert_callback:
                for alert in detected:
                    alert_callback(alert)
        return self.alerts

    def get_stats(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_flows": len(self.flow_tracker.flows),
            "total_alerts": len(self.alerts),
            "protocols": self.protocols_count
        }
