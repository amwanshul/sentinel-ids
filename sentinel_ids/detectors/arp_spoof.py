import time
from typing import Dict, List, Optional, Set
from sentinel_ids.core.packet import ParsedPacket
from sentinel_ids.core.flow import FlowTracker, Flow
from sentinel_ids.alerts import Alert, Severity
from .base import BaseDetector


class ArpSpoofDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="ArpSpoofDetector",
            description="Detects ARP cache poisoning and conflicting MAC-to-IP bindings"
        )
        # ip -> mac
        self.ip_to_mac_table: Dict[str, str] = {}
        self.alerted_pairs: Set[str] = set()

    def analyze(self, packet: ParsedPacket, flow: Optional[Flow], tracker: FlowTracker) -> List[Alert]:
        alerts = []
        if not packet.arp:
            return alerts

        arp = packet.arp
        # Focus on ARP replies (opcode = 2) or requests claiming bindings
        sender_ip = arp.sender_ip
        sender_mac = arp.sender_mac.lower()
        now = packet.timestamp or time.time()

        if sender_ip in self.ip_to_mac_table:
            known_mac = self.ip_to_mac_table[sender_ip]
            if known_mac != sender_mac:
                key = f"{sender_ip}:{sender_mac}"
                if key not in self.alerted_pairs:
                    self.alerted_pairs.add(key)
                    alerts.append(Alert(
                        timestamp=now,
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title="ARP Cache Poisoning / Spoofing Detected",
                        description=f"Conflicting MAC binding for IP {sender_ip}. Previous MAC: {known_mac}, New Sender MAC: {sender_mac}.",
                        source_ip=sender_ip,
                        metadata={
                            "ip": sender_ip,
                            "legitimate_mac": known_mac,
                            "spoofed_mac": sender_mac,
                            "arp_opcode": arp.opcode
                        }
                    ))
        else:
            self.ip_to_mac_table[sender_ip] = sender_mac

        return alerts
