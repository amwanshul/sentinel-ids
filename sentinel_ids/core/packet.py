import struct
import socket
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


def mac_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def ip_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntoa(ip_bytes)


@dataclass
class EthernetHeader:
    dest_mac: str
    src_mac: str
    ethertype: int


@dataclass
class ArpPacket:
    hardware_type: int
    protocol_type: int
    hardware_size: int
    protocol_size: int
    opcode: int  # 1=Request, 2=Reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass
class Ipv4Header:
    version: int
    ihl: int
    dscp: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    checksum: int
    src_ip: str
    dst_ip: str


@dataclass
class TcpHeader:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags_raw: int
    window_size: int
    checksum: int
    urgent_ptr: int
    # Decoded flags
    fin: bool
    syn: bool
    rst: bool
    psh: bool
    ack: bool
    urg: bool
    payload: bytes = field(repr=False)


@dataclass
class UdpHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes = field(repr=False)


@dataclass
class IcmpHeader:
    type: int
    code: int
    checksum: int
    payload: bytes = field(repr=False)


@dataclass
class DnsQuery:
    name: str
    qtype: int
    qclass: int


@dataclass
class DnsPacket:
    transaction_id: int
    flags: int
    is_response: bool
    questions_count: int
    answers_count: int
    queries: List[DnsQuery] = field(default_factory=list)


@dataclass
class ParsedPacket:
    raw: bytes
    timestamp: float
    length: int
    ethernet: Optional[EthernetHeader] = None
    arp: Optional[ArpPacket] = None
    ip: Optional[Ipv4Header] = None
    tcp: Optional[TcpHeader] = None
    udp: Optional[UdpHeader] = None
    icmp: Optional[IcmpHeader] = None
    dns: Optional[DnsPacket] = None

    @property
    def protocol_name(self) -> str:
        if self.tcp:
            return "TCP"
        if self.udp:
            return "UDP"
        if self.icmp:
            return "ICMP"
        if self.arp:
            return "ARP"
        if self.ip:
            return f"IP({self.ip.protocol})"
        return "UNKNOWN"


class PacketDecoder:
    @staticmethod
    def decode_dns(data: bytes) -> Optional[DnsPacket]:
        if len(data) < 12:
            return None
        try:
            tx_id, flags, q_count, a_count, _, _ = struct.unpack("!HHHHHH", data[:12])
            is_response = bool(flags & 0x8000)
            offset = 12
            queries = []

            for _ in range(q_count):
                if offset >= len(data):
                    break
                labels = []
                while offset < len(data):
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    # DNS pointer compression check
                    if (length & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1
                    if offset + length > len(data):
                        break
                    labels.append(data[offset:offset+length].decode("ascii", errors="ignore"))
                    offset += length

                if offset + 4 <= len(data):
                    qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
                    offset += 4
                    queries.append(DnsQuery(name=".".join(labels), qtype=qtype, qclass=qclass))

            return DnsPacket(
                transaction_id=tx_id,
                flags=flags,
                is_response=is_response,
                questions_count=q_count,
                answers_count=a_count,
                queries=queries
            )
        except Exception:
            return None

    @classmethod
    def decode(cls, raw: bytes, timestamp: float = 0.0) -> ParsedPacket:
        packet = ParsedPacket(raw=raw, timestamp=timestamp, length=len(raw))
        if len(raw) < 14:
            return packet

        # 1. Parse Ethernet Header
        dst_mac = mac_to_str(raw[0:6])
        src_mac = mac_to_str(raw[6:12])
        ethertype = struct.unpack("!H", raw[12:14])[0]
        packet.ethernet = EthernetHeader(dest_mac=dst_mac, src_mac=src_mac, ethertype=ethertype)

        offset = 14

        # Handle 802.1Q VLAN Tagging if present
        if ethertype == 0x8100:
            if len(raw) < 18:
                return packet
            ethertype = struct.unpack("!H", raw[16:18])[0]
            offset = 18

        # 2. Handle ARP (0x0806)
        if ethertype == 0x0806:
            if len(raw) >= offset + 28:
                arp_raw = raw[offset:offset+28]
                hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", arp_raw[:8])
                s_mac = mac_to_str(arp_raw[8:14])
                s_ip = ip_to_str(arp_raw[14:18])
                t_mac = mac_to_str(arp_raw[18:24])
                t_ip = ip_to_str(arp_raw[24:28])
                packet.arp = ArpPacket(
                    hardware_type=hw_type,
                    protocol_type=proto_type,
                    hardware_size=hw_size,
                    protocol_size=proto_size,
                    opcode=opcode,
                    sender_mac=s_mac,
                    sender_ip=s_ip,
                    target_mac=t_mac,
                    target_ip=t_ip
                )
            return packet

        # 3. Handle IPv4 (0x0800)
        if ethertype == 0x0800:
            if len(raw) < offset + 20:
                return packet

            ip_header_raw = raw[offset:offset+20]
            v_ihl, dscp_ecn, total_len, ident, flags_frag, ttl, protocol, checksum, s_ip, d_ip = struct.unpack(
                "!BBHHHBBH4s4s", ip_header_raw
            )
            version = v_ihl >> 4
            ihl = (v_ihl & 0x0F) * 4

            if len(raw) < offset + ihl:
                return packet

            packet.ip = Ipv4Header(
                version=version,
                ihl=ihl,
                dscp=dscp_ecn,
                total_length=total_len,
                identification=ident,
                flags=(flags_frag >> 13),
                fragment_offset=(flags_frag & 0x1FFF),
                ttl=ttl,
                protocol=protocol,
                checksum=checksum,
                src_ip=ip_to_str(s_ip),
                dst_ip=ip_to_str(d_ip)
            )

            l4_offset = offset + ihl

            # 4. Handle TCP (Protocol 6)
            if protocol == 6:
                if len(raw) >= l4_offset + 20:
                    tcp_raw = raw[l4_offset:l4_offset+20]
                    src_port, dst_port, seq, ack, offset_reserved, flags, win, csum, urg = struct.unpack(
                        "!HHIIBBHHH", tcp_raw
                    )
                    data_offset = (offset_reserved >> 4) * 4
                    payload = raw[l4_offset + data_offset:] if len(raw) >= l4_offset + data_offset else b""
                    packet.tcp = TcpHeader(
                        src_port=src_port,
                        dst_port=dst_port,
                        seq_num=seq,
                        ack_num=ack,
                        data_offset=data_offset,
                        flags_raw=flags,
                        window_size=win,
                        checksum=csum,
                        urgent_ptr=urg,
                        fin=bool(flags & 0x01),
                        syn=bool(flags & 0x02),
                        rst=bool(flags & 0x04),
                        psh=bool(flags & 0x08),
                        ack=bool(flags & 0x10),
                        urg=bool(flags & 0x20),
                        payload=payload
                    )

            # 5. Handle UDP (Protocol 17)
            elif protocol == 17:
                if len(raw) >= l4_offset + 8:
                    udp_raw = raw[l4_offset:l4_offset+8]
                    src_port, dst_port, u_len, csum = struct.unpack("!HHHH", udp_raw)
                    payload = raw[l4_offset+8:]
                    packet.udp = UdpHeader(
                        src_port=src_port,
                        dst_port=dst_port,
                        length=u_len,
                        checksum=csum,
                        payload=payload
                    )

                    # Inspect DNS (port 53)
                    if src_port == 53 or dst_port == 53:
                        packet.dns = cls.decode_dns(payload)

            # 6. Handle ICMP (Protocol 1)
            elif protocol == 1:
                if len(raw) >= l4_offset + 4:
                    icmp_type, icmp_code, csum = struct.unpack("!BBH", raw[l4_offset:l4_offset+4])
                    packet.icmp = IcmpHeader(
                        type=icmp_type,
                        code=icmp_code,
                        checksum=csum,
                        payload=raw[l4_offset+4:]
                    )

        return packet
