from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple
from .packet import ParsedPacket


class TcpState(str, Enum):
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"
    RESET = "RESET"


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def canonical(self) -> "FlowKey":
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return self
        return FlowKey(
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
            protocol=self.protocol
        )


@dataclass
class Flow:
    key: FlowKey
    start_time: float
    last_time: float
    packet_count: int = 0
    byte_count: int = 0
    state: TcpState = TcpState.NEW
    flags_seen: Dict[str, int] = field(default_factory=lambda: {
        "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0
    })

    def update(self, packet: ParsedPacket) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        self.last_time = packet.timestamp

        if packet.tcp:
            tcp = packet.tcp
            if tcp.syn: self.flags_seen["syn"] += 1
            if tcp.ack: self.flags_seen["ack"] += 1
            if tcp.fin: self.flags_seen["fin"] += 1
            if tcp.rst: self.flags_seen["rst"] += 1
            if tcp.psh: self.flags_seen["psh"] += 1
            if tcp.urg: self.flags_seen["urg"] += 1

            # State transition logic
            if tcp.rst:
                self.state = TcpState.RESET
            elif tcp.fin:
                self.state = TcpState.FIN_WAIT
            elif self.state == TcpState.NEW and tcp.syn and not tcp.ack:
                self.state = TcpState.SYN_SENT
            elif self.state == TcpState.SYN_SENT and tcp.syn and tcp.ack:
                self.state = TcpState.SYN_RECEIVED
            elif self.state in (TcpState.SYN_SENT, TcpState.SYN_RECEIVED) and tcp.ack:
                self.state = TcpState.ESTABLISHED

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)


class FlowTracker:
    def __init__(self, expiry_timeout: float = 300.0):
        self.flows: Dict[FlowKey, Flow] = {}
        self.expiry_timeout = expiry_timeout

    def process(self, packet: ParsedPacket) -> Optional[Flow]:
        if not packet.ip:
            return None

        src_port = 0
        dst_port = 0
        if packet.tcp:
            src_port = packet.tcp.src_port
            dst_port = packet.tcp.dst_port
        elif packet.udp:
            src_port = packet.udp.src_port
            dst_port = packet.udp.dst_port

        raw_key = FlowKey(
            src_ip=packet.ip.src_ip,
            src_port=src_port,
            dst_ip=packet.ip.dst_ip,
            dst_port=dst_port,
            protocol=packet.protocol_name
        )
        canonical_key = raw_key.canonical()

        flow = self.flows.get(canonical_key)
        if not flow:
            flow = Flow(key=canonical_key, start_time=packet.timestamp, last_time=packet.timestamp)
            self.flows[canonical_key] = flow

        flow.update(packet)
        return flow

    def cleanup(self, current_time: float) -> int:
        expired = [k for k, f in self.flows.items() if (current_time - f.last_time) > self.expiry_timeout]
        for k in expired:
            del self.flows[k]
        return len(expired)
