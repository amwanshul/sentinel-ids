import pytest
from sentinel_ids.engine import SentinelEngine
from sentinel_ids.core.packet import PacketDecoder
from sentinel_ids.detectors.port_scan import PortScanDetector
from sentinel_ids.detectors.syn_flood import SynFloodDetector
from sentinel_ids.detectors.arp_spoof import ArpSpoofDetector
from sentinel_ids.detectors.dns_tunnel import DnsTunnelDetector, shannon_entropy
from tests.test_packet import make_ethernet, make_ipv4, make_tcp
import struct


def test_port_scan_detector():
    detector = PortScanDetector(threshold_ports=5, window_seconds=10.0)
    engine = SentinelEngine(detectors=[detector])

    # Simulate scanning 6 distinct ports from 192.168.1.100 to 192.168.1.200
    alerts = []
    eth = make_ethernet(ethertype=0x0800)
    for port in range(1, 8):
        tcp = make_tcp(src_port=50000, dst_port=port, flags=0x02)  # SYN
        ip = make_ipv4(src_ip=b"\xc0\xa8\x01\x64", dst_ip=b"\xc0\xa8\x01\xc8", proto=6, payload=tcp)
        raw = eth + ip
        a = engine.process_raw_packet(raw, timestamp=100.0)
        alerts.extend(a)

    assert len(alerts) >= 1
    assert alerts[0].detector == "PortScanDetector"
    assert "Vertical Port Scan" in alerts[0].title
    assert alerts[0].source_ip == "192.168.1.100"


def test_port_scan_below_threshold_does_not_alert():
    detector = PortScanDetector(threshold_ports=5, window_seconds=10.0)
    engine = SentinelEngine(detectors=[detector])

    eth = make_ethernet(ethertype=0x0800)
    alerts = []
    for port in range(1, 5):
        tcp = make_tcp(src_port=50000, dst_port=port, flags=0x02)
        ip = make_ipv4(src_ip=b"\xc0\xa8\x01\x64", dst_ip=b"\xc0\xa8\x01\xc8", proto=6, payload=tcp)
        alerts.extend(engine.process_raw_packet(eth + ip, timestamp=100.0 + port * 0.1))

    assert alerts == []


def test_syn_flood_detector():
    detector = SynFloodDetector(threshold_syn_rate=10, window_seconds=2.0)
    engine = SentinelEngine(detectors=[detector])

    alerts = []
    eth = make_ethernet(ethertype=0x0800)
    tcp = make_tcp(src_port=12345, dst_port=80, flags=0x02)  # pure SYN
    ip = make_ipv4(src_ip=b"\n\x00\x00\x05", dst_ip=b"\n\x00\x00\x01", proto=6, payload=tcp)
    raw = eth + ip

    for i in range(12):
        a = engine.process_raw_packet(raw, timestamp=10.0 + (i * 0.1))
        alerts.extend(a)

    assert len(alerts) >= 1
    assert alerts[0].detector == "SynFloodDetector"
    assert "SYN Flood" in alerts[0].title


def test_arp_spoof_detector():
    detector = ArpSpoofDetector()
    engine = SentinelEngine(detectors=[detector])

    eth = make_ethernet(ethertype=0x0806)
    arp_base = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    s_ip = b"\xc0\xa8\x01\x01"  # 192.168.1.1 Gateway
    t_ip = b"\xc0\xa8\x01\x32"  # 192.168.1.50 Victim

    # Normal ARP from legitimate router MAC
    mac1 = b"\x00\x11\x22\x33\x44\x55"
    raw1 = eth + arp_base + mac1 + s_ip + mac1 + t_ip
    a1 = engine.process_raw_packet(raw1, timestamp=1.0)
    assert len(a1) == 0

    # Attacker claiming same Gateway IP with different MAC
    mac2 = b"\xaa\xbb\xcc\xdd\xee\xff"
    raw2 = eth + arp_base + mac2 + s_ip + mac2 + t_ip
    a2 = engine.process_raw_packet(raw2, timestamp=2.0)
    assert len(a2) == 1
    assert a2[0].detector == "ArpSpoofDetector"
    assert "ARP Cache Poisoning" in a2[0].title


def test_dns_tunnel_entropy():
    # Regular domain
    e1 = shannon_entropy("google")
    assert e1 < 3.0

    # Base64-like encoded exfiltration label
    high_ent_label = "v8h3n92k4ms91lskw9103ksd"
    e2 = shannon_entropy(high_ent_label)
    assert e2 > 3.6
