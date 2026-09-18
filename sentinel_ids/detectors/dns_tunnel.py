import math
import time
from collections import Counter
from typing import List, Optional, Set
from sentinel_ids.core.packet import ParsedPacket
from sentinel_ids.core.flow import FlowTracker, Flow
from sentinel_ids.alerts import Alert, Severity
from .base import BaseDetector


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DnsTunnelDetector(BaseDetector):
    def __init__(self, entropy_threshold: float = 3.6, min_label_length: int = 24):
        super().__init__(
            name="DnsTunnelDetector",
            description="Detects DNS covert channel exfiltration using domain name Shannon entropy and length heuristics"
        )
        self.entropy_threshold = entropy_threshold
        self.min_label_length = min_label_length
        self.alerted_domains: Set[str] = set()

    def analyze(self, packet: ParsedPacket, flow: Optional[Flow], tracker: FlowTracker) -> List[Alert]:
        alerts = []
        if not packet.dns or not packet.dns.queries:
            return alerts

        now = packet.timestamp or time.time()
        for query in packet.dns.queries:
            domain = query.name
            if not domain or domain in self.alerted_domains:
                continue

            # Analyze subdomains / labels
            parts = domain.split(".")
            for label in parts:
                if len(label) >= self.min_label_length:
                    ent = shannon_entropy(label.lower())
                    if ent >= self.entropy_threshold:
                        self.alerted_domains.add(domain)
                        src_ip = packet.ip.src_ip if packet.ip else "unknown"
                        dst_ip = packet.ip.dst_ip if packet.ip else "unknown"
                        alerts.append(Alert(
                            timestamp=now,
                            detector=self.name,
                            severity=Severity.HIGH,
                            title="Suspected DNS Tunneling / Exfiltration",
                            description=f"High-entropy DNS query detected: '{label}' in '{domain}' (Entropy: {ent:.2f}).",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            destination_port=53,
                            metadata={
                                "domain": domain,
                                "label": label,
                                "label_length": len(label),
                                "entropy": round(ent, 3),
                                "qtype": query.qtype
                            }
                        ))
                        break

        return alerts
