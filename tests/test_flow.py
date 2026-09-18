from sentinel_ids.core.flow import FlowTracker, TcpState
from sentinel_ids.core.packet import PacketDecoder
from tests.test_packet import make_ethernet, make_ipv4, make_tcp


def test_tcp_handshake_flow():
    tracker = FlowTracker()
    eth = make_ethernet(ethertype=0x0800)

    # 1. Client SYN
    tcp1 = make_tcp(src_port=40000, dst_port=80, flags=0x02)
    ip1 = make_ipv4(src_ip=b"\x0a\x00\x00\x02", dst_ip=b"\x0a\x00\x00\x01", proto=6, payload=tcp1)
    pkt1 = PacketDecoder.decode(eth + ip1, timestamp=1.0)
    flow1 = tracker.process(pkt1)
    assert flow1.state == TcpState.SYN_SENT

    # 2. Server SYN-ACK
    tcp2 = make_tcp(src_port=80, dst_port=40000, flags=0x12)
    ip2 = make_ipv4(src_ip=b"\x0a\x00\x00\x01", dst_ip=b"\x0a\x00\x00\x02", proto=6, payload=tcp2)
    pkt2 = PacketDecoder.decode(eth + ip2, timestamp=1.1)
    flow2 = tracker.process(pkt2)
    assert flow2.state == TcpState.SYN_RECEIVED
    assert flow1 is flow2  # Canonical bi-directional key matching

    # 3. Client ACK
    tcp3 = make_tcp(src_port=40000, dst_port=80, flags=0x10)
    ip3 = make_ipv4(src_ip=b"\x0a\x00\x00\x02", dst_ip=b"\x0a\x00\x00\x01", proto=6, payload=tcp3)
    pkt3 = PacketDecoder.decode(eth + ip3, timestamp=1.2)
    flow3 = tracker.process(pkt3)
    assert flow3.state == TcpState.ESTABLISHED
    assert flow3.packet_count == 3
