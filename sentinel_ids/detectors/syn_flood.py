import time
from collections import defaultdict
from typing import Dict, List, Optional, Set
from sentinel_ids.core.packet import ParsedPacket
from sentinel_ids.core.flow import FlowTracker, Flow
from sentinel_ids.alerts import Alert, Severity
from .base import BaseDetector


class SynFloodDetector(BaseDetector):
    def __init__(self, threshold_syn_rate: int = 25, window_seconds: float = 3.0):
        super().__init__(
            name="SynFloodDetector",
            description="Detects TCP SYN Flood DoS attacks via half-open connection rate anomalies"
        )
        self.threshold_syn_rate = threshold_syn_rate
        self.window_seconds = window_seconds
        # dst_ip -> [timestamp]
        self.syn_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.alerted_victims: Set[str] = set()

    def analyze(self, packet: ParsedPacket, flow: Optional[Flow], tracker: FlowTracker) -> List[Alert]:
        alerts = []
        if not packet.ip or not packet.tcp:
            return alerts

        tcp = packet.tcp
        # Check if pure SYN packet (initial handshake request without ACK)
        if tcp.syn and not tcp.ack:
            now = packet.timestamp or time.time()
            dst_ip = packet.ip.dst_ip
            self.syn_timestamps[dst_ip].append(now)

            cutoff = now - self.window_seconds
            self.syn_timestamps[dst_ip] = [ts for ts in self.syn_timestamps[dst_ip] if ts >= cutoff]

            syn_count = len(self.syn_timestamps[dst_ip])
            if syn_count >= self.threshold_syn_rate:
                if dst_ip not in self.alerted_victims:
                    self.alerted_victims.add(dst_ip)
                    alerts.append(Alert(
                        timestamp=now,
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title="Potential TCP SYN Flood / DoS Detected",
                        description=f"Target {dst_ip} received {syn_count} unacknowledged SYN packets within {self.window_seconds}s.",
                        source_ip=packet.ip.src_ip,
                        destination_ip=dst_ip,
                        destination_port=tcp.dst_port,
                        metadata={
                            "syn_count_in_window": syn_count,
                            "window_seconds": self.window_seconds,
                            "rate_per_sec": round(syn_count / self.window_seconds, 2)
                        }
                    ))

        return alerts
