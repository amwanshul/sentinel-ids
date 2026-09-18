import struct
import time
from typing import Iterator, Tuple


PCAP_MAGIC_SAME_ENDIAN = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED_ENDIAN = 0xD4C3B2A1


class PcapReader:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def __iter__(self) -> Iterator[Tuple[bytes, float]]:
        with open(self.filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = struct.unpack("!I", global_header[:4])[0]
            if magic == PCAP_MAGIC_SAME_ENDIAN:
                endian = ">"
            elif struct.unpack("<I", global_header[:4])[0] == PCAP_MAGIC_SAME_ENDIAN:
                endian = "<"
            else:
                endian = "<"

            while True:
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", packet_header)
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break

                timestamp = float(ts_sec) + (float(ts_usec) / 1_000_000.0)
                yield packet_data, timestamp


class PcapWriter:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None

    def __enter__(self):
        self._file = open(self.filepath, "wb")
        # Global header: magic (4), v_major(2)=2, v_minor(2)=4, thiszone(4)=0, sigfigs(4)=0, snaplen(4)=65535, network(4)=1 (Ethernet)
        header = struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self._file.write(header)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()

    def write_packet(self, packet_bytes: bytes, timestamp: float = None):
        if timestamp is None:
            timestamp = time.time()
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        length = len(packet_bytes)
        pkt_header = struct.pack("=IIII", ts_sec, ts_usec, length, length)
        self._file.write(pkt_header)
        self._file.write(packet_bytes)
