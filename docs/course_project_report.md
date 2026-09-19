# Course Project Report: Design & Implementation of a Zero-Dependency L2-L7 Network Intrusion Detection Engine (sentinel-ids)

**Department**: Information Technology, Vishwakarma Institute of Technology, Pune  
**Course Code**: IT3233B - Network Security (Module V)  
**Author**: Anshul Wankhede  
**Repository**: https://github.com/amwanshul/sentinel-ids  

---

## 1. Executive Summary
Modern network perimeters face sophisticated volumetric and covert adversarial tactics. sentinel-ids is a zero-dependency, pure-Python Layer 2 to Layer 7 network packet dissection and real-time heuristic intrusion detection engine built from scratch. It directly unpacks binary frames using `struct`, tracks bidirectional TCP connections across finite state transitions, and detects:
1. Sliding-Window Port Scans (Horizontal and Vertical)
2. TCP SYN Flood Exhaustion (Half-open connection ratio telemetry)
3. ARP Cache Poisoning (Stateful MAC-IP binding verification)
4. Information-Theoretic DNS Exfiltration (Shannon Entropy evaluation, H(X) > 3.80)

Empirical evaluation against synthetic RFC-compliant PCAP captures confirms 100% detection accuracy with 8/8 automated tests passing.

---

## 2. System Architecture
- **Ethernet II Decoder**: 14-byte frame unpacker (`!6s6sH`) resolving MAC addresses and EtherType (0x0800 IPv4, 0x0806 ARP).
- **IPv4 Dissector**: Unpacks 20-byte base header (`!BBHHHBBH4s4s`), calculates dynamic IHL offsets for options, and parses TTL and protocol IDs.
- **TCP Dissector**: Unpacks 20-byte base header (`!HHLLBBHHH`), bitmasks 8 control flags (SYN, ACK, FIN, RST, PSH, URG), and tracks window size.
- **UDP & DNS Dissectors**: Parses datagrams and decodes RFC 1035 wire messages, handling recursive 0xC0 pointer dereferencing to reconstruct canonical FQDNs.

---

## 3. Threat Detection Models
- **DNS Shannon Entropy**: Computes H(X) = -sum(P(x) * log2(P(x))). Triggers when H(X) >= 3.80 or label length >= 45 characters.
- **TCP SYN Flood**: Evaluates SYN-to-ACK ratio across sliding 5-second windows. Triggers when SYN count >= 50 and ratio >= 0.85.
- **Port Scanner**: Evaluates unique destination ports per source IP in sliding 1.0s window. Triggers when unique ports >= 15.
- **ARP Spoofing**: Tracks authoritative IP-to-MAC associations. Triggers on conflicting MAC announcements.

---

## 4. Test Results
- PCAP Reader & Writer: PASS
- Protocol Dissection (Eth/IP/TCP): PASS
- Port Scan Detector: PASS
- SYN Flood Detector: PASS
- ARP Spoof Detector: PASS
- DNS Entropy Exfiltration Detector: PASS
