import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from sentinel_ids.core.packet import ParsedPacket
from sentinel_ids.core.flow import FlowTracker, Flow
from sentinel_ids.alerts import Alert, Severity
from .base import BaseDetector


class PortScanDetector(BaseDetector):
    def __init__(self, threshold_ports: int = 10, window_seconds: float = 10.0):
        super().__init__(
            name="PortScanDetector",
            description="Detects vertical (single target, multiple ports) and horizontal port scanning"
        )
        self.threshold_ports = threshold_ports
        self.window_seconds = window_seconds
        # (src_ip, dst_ip) -> [(timestamp, dst_port)]
        self.vertical_history: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
        # (src_ip, dst_port) -> [(timestamp, dst_ip)]
        self.horizontal_history: Dict[Tuple[str, int], List[Tuple[float, str]]] = defaultdict(list)
        self.alerted_vertical: Set[Tuple[str, str]] = set()

    def analyze(self, packet: ParsedPacket, flow: Optional[Flow], tracker: FlowTracker) -> List[Alert]:
        alerts = []
        if not packet.ip or not (packet.tcp or packet.udp):
            return alerts

        # Focus primarily on TCP SYN or UDP probes
        is_probe = False
        dst_port = 0
        if packet.tcp and packet.tcp.syn and not packet.tcp.ack:
            is_probe = True
            dst_port = packet.tcp.dst_port
        elif packet.udp:
            is_probe = True
            dst_port = packet.udp.dst_port

        if not is_probe:
            return alerts

        now = packet.timestamp or time.time()
        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip

        # 1. Vertical Port Scan Check: one attacker scanning many ports on one victim
        v_key = (src_ip, dst_ip)
        self.vertical_history[v_key].append((now, dst_port))
        # Evict old events
        cutoff = now - self.window_seconds
        self.vertical_history[v_key] = [item for item in self.vertical_history[v_key] if item[0] >= cutoff]

        unique_ports = {item[1] for item in self.vertical_history[v_key]}
        if len(unique_ports) >= self.threshold_ports:
            if v_key not in self.alerted_vertical:
                self.alerted_vertical.add(v_key)
                alerts.append(Alert(
                    timestamp=now,
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Vertical Port Scan Detected",
                    description=f"Host {src_ip} probed {len(unique_ports)} distinct ports on {dst_ip} within {self.window_seconds}s.",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=dst_port,
                    metadata={"distinct_ports_count": len(unique_ports), "scanned_ports": sorted(list(unique_ports))[:20]}
                ))

        # 2. Horizontal Port Scan Check: one attacker scanning same port across many victims
        h_key = (src_ip, dst_port)
        self.horizontal_history[h_key].append((now, dst_ip))
        self.horizontal_history[h_key] = [item for item in self.horizontal_history[h_key] if item[0] >= cutoff]

        unique_hosts = {item[1] for item in self.horizontal_history[h_key]}
        if len(unique_hosts) >= self.threshold_ports:
            alerts.append(Alert(
                timestamp=now,
                detector=self.name,
                severity=Severity.MEDIUM,
                title="Horizontal Network Sweep / Sweep Scan Detected",
                description=f"Host {src_ip} scanned port {dst_port} across {len(unique_hosts)} different hosts.",
                source_ip=src_ip,
                destination_port=dst_port,
                metadata={"distinct_hosts_count": len(unique_hosts)}
            ))

        return alerts
