import os
import tempfile
from sentinel_ids.core.pcap import PcapWriter, PcapReader
from sentinel_ids.engine import SentinelEngine
from tests.test_packet import make_ethernet, make_ipv4, make_tcp


def test_pcap_write_and_read():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    try:
        eth = make_ethernet(ethertype=0x0800)
        tcp = make_tcp(src_port=55555, dst_port=80, flags=0x02)
        ip = make_ipv4(src_ip=b"\x0a\x00\x00\x01", dst_ip=b"\x0a\x00\x00\x02", proto=6, payload=tcp)
        packet_bytes = eth + ip

        with PcapWriter(pcap_path) as writer:
            writer.write_packet(packet_bytes, timestamp=1700000000.0)

        reader = PcapReader(pcap_path)
        packets = list(reader)
        assert len(packets) == 1
        assert packets[0][0] == packet_bytes
        assert abs(packets[0][1] - 1700000000.0) < 0.001

        engine = SentinelEngine()
        engine.analyze_pcap(pcap_path)
        stats = engine.get_stats()
        assert stats["total_packets"] == 1
        assert stats["protocols"]["TCP"] == 1
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
