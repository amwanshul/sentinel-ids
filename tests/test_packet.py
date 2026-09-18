import struct
import pytest
from sentinel_ids.core.packet import PacketDecoder


def make_ethernet(src_mac=b"\x00\x11\x22\x33\x44\x55", dst_mac=b"\xaa\xbb\xcc\xdd\xee\xff", ethertype=0x0800):
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def make_ipv4(src_ip=b"\xc0\xa8\x01\x01", dst_ip=b"\xc0\xa8\x01\x02", proto=6, payload=b""):
    v_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
    dscp = 0
    total_len = 20 + len(payload)
    ident = 1234
    flags_frag = 0x4000  # DF
    ttl = 64
    checksum = 0
    header = struct.pack("!BBHHHBBH4s4s", v_ihl, dscp, total_len, ident, flags_frag, ttl, proto, checksum, src_ip, dst_ip)
    return header + payload


def make_tcp(src_port=12345, dst_port=80, seq=1000, ack=0, flags=0x02, payload=b""):
    offset_reserved = 0x50  # 5 words = 20 bytes
    win = 65535
    csum = 0
    urg = 0
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_reserved, flags, win, csum, urg)
    return header + payload


def test_decode_tcp_packet():
    eth = make_ethernet(ethertype=0x0800)
    tcp = make_tcp(src_port=443, dst_port=54321, flags=0x02)  # SYN
    ip = make_ipv4(proto=6, payload=tcp)
    raw = eth + ip

    pkt = PacketDecoder.decode(raw, timestamp=1000.0)
    assert pkt.ethernet is not None
    assert pkt.ip is not None
    assert pkt.ip.src_ip == "192.168.1.1"
    assert pkt.ip.dst_ip == "192.168.1.2"
    assert pkt.tcp is not None
    assert pkt.tcp.src_port == 443
    assert pkt.tcp.dst_port == 54321
    assert pkt.tcp.syn is True
    assert pkt.tcp.ack is False


def test_decode_arp_packet():
    eth = make_ethernet(ethertype=0x0806)
    # hw_type=1, proto=0x0800, hw_sz=6, proto_sz=4, opcode=2 (reply)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    s_mac = b"\x00\xaa\xbb\xcc\xdd\xee"
    s_ip = b"\n\x00\x00\x01"  # 10.0.0.1
    t_mac = b"\x00\x11\x22\x33\x44\x55"
    t_ip = b"\n\x00\x00\x02"  # 10.0.0.2
    raw = eth + arp + s_mac + s_ip + t_mac + t_ip

    pkt = PacketDecoder.decode(raw)
    assert pkt.arp is not None
    assert pkt.arp.opcode == 2
    assert pkt.arp.sender_ip == "10.0.0.1"
    assert pkt.arp.target_ip == "10.0.0.2"
