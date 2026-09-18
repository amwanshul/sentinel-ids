# Sentinel IDS 🛡️

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Domain-Network_Security_%26_Forensics-red?style=flat-square" alt="Network Security">
  <img src="https://img.shields.io/badge/Core-Zero_Dependency_Binary_Parser-blue?style=flat-square" alt="Zero Dependency">
  <img src="https://img.shields.io/badge/Tests-8%2F8_Passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
</p>

A high-performance, modular **Network Packet Analyzer & Intrusion Detection System (IDS)** implemented in Python. 

Engineered from network protocol specifications (RFC 791, RFC 793, RFC 826) to decode raw binary packet streams, reconstruct stateful TCP bidirectional flows, and detect network anomalies in real time.

---

## 🏛️ Architecture Overview

```mermaid
flowchart TD
    A[Raw PCAP File / Live Socket Stream] --> B[PacketDecoder]

    subgraph Protocol Decoding [Layer 2 to 7 Dissection]
        B --> L2[Ethernet II / ARP]
        B --> L3[IPv4 / ICMP]
        B --> L4[TCP State / UDP]
        B --> L7[DNS Protocol & Queries]
    end

    Protocol Decoding --> C[FlowTracker Engine]
    C --> State[Bi-directional TCP State Machine
SYN_SENT → SYN_RECV → ESTABLISHED → FIN/RST]

    State --> D[Sentinel Detection Pipeline]

    subgraph Detection Modules [Heuristic & Signature Rules]
        D --> D1[PortScanDetector
Vertical & Horizontal Sweeps]
        D --> D2[SynFloodDetector
Half-Open Velocity & Volumetric Anomaly]
        D --> D3[ArpSpoofDetector
Dynamic IP-to-MAC Cache Poisoning]
        D --> D4[DnsTunnelDetector
Shannon Entropy & Covert Channel Analysis]
    end

    Detection Modules --> E[Alert Engine & SIEM JSON Sink]
```

---

## ⚡ Core Capabilities

### 1. Zero-Dependency Binary Protocol Dissection
Decodes raw network frames byte-by-byte using Python's native `struct` module:
- **Layer 2 (Data Link)**: Ethernet II framing, MAC resolution, 802.1Q VLAN tag stripping, ARP opcode mapping (Requests & Replies).
- **Layer 3 (Network)**: IPv4 header parsing (IHL, TTL, protocol demuxing, fragmentation flags, checksums), ICMP types & codes.
- **Layer 4 (Transport)**: TCP 6-flag bitwise decoding (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), sequence/acknowledgement numbers, window sizing; UDP datagram extraction.
- **Layer 7 (Application)**: DNS transaction parsing, compression pointer resolution, recursive query decomposition.

### 2. Stateful TCP Flow Reconstruction
- Maps bi-directional conversations into canonical `FlowKey(src_ip, src_port, dst_ip, dst_port, protocol)` 5-tuples.
- Tracks protocol state transitions (`SYN_SENT` $	o$ `SYN_RECEIVED` $	o$ `ESTABLISHED` $	o$ `FIN_WAIT` / `RESET`).
- Aggregates packet velocity, byte volume, and duration metrics.

### 3. Attack Detection Modules

| Attack Vector | Detection Mechanism | Severity |
|---|---|---|
| **Vertical Port Scan** | Sliding-window threshold tracking distinct ports probed on a single target ($N \ge 10$ in $10	ext{s}$) | `HIGH` |
| **Horizontal Sweep** | Detects one source scanning the same destination port across multiple hosts | `MEDIUM` |
| **TCP SYN Flood (DoS)** | Flags anomalous half-open connection velocity where SYN arrival vastly exceeds corresponding ACKs | `CRITICAL` |
| **ARP Cache Poisoning** | Detects conflicting MAC-to-IP bindings and gratuitous ARP spoofing attempts (MITM) | `CRITICAL` |
| **DNS Tunneling / Exfiltration** | Computes Shannon entropy on queried subdomain labels ($H(X) = -\sum p_i \log_2 p_i$) to detect encoded covert channels | `HIGH` |

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/amwanshul/sentinel-ids.git
cd sentinel-ids

python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

### 2. Analyze Network Captures (PCAP)

Run the CLI on any standard `.pcap` capture file:

```bash
python -m sentinel_ids.cli --pcap sample_traffic.pcap --output alerts.json
```

### 3. Programmatic Usage in Python

```python
from sentinel_ids.engine import SentinelEngine

engine = SentinelEngine()

# Analyze a PCAP capture
alerts = engine.analyze_pcap("capture.pcap")

# Inspect results
stats = engine.get_stats()
print(f"Total packets: {stats['total_packets']}")
print(f"Threats detected: {len(alerts)}")

for alert in alerts:
    print(f"[{alert.severity}] {alert.title} from {alert.source_ip}")
```

---

## 🧪 Testing & Verification

Sentinel IDS includes comprehensive unit tests verifying packet parsing, flow state transitions, and attack detectors:

```bash
PYTHONPATH=. pytest tests/ -v
```

All 8 tests run deterministically in $< 0.1$ seconds without requiring root privileges or external network interfaces.

---

## ⚠️ Educational & Defensive Use Only

This software is designed exclusively for educational, defensive, and network analysis purposes. Always ensure you have authorized permission prior to monitoring any network traffic.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
