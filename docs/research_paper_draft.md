# Low-Overhead Stateful Intrusion Detection via Protocol-Independent Flow Dissection and Entropy-Based Exfiltration Profiling

**Author**: Anshul Wankhede  
**Affiliation**: Department of Information Technology, Vishwakarma Institute of Technology, Pune  
**Target Submission**: IEEE / Springer Conference (IT3235 Engineering Research and Innovation-V)  

---

### Abstract
Modern edge network infrastructures require responsive, low-footprint intrusion detection mechanisms capable of identifying link-layer manipulation, transport-layer state exhaustion, and covert application-layer exfiltration. While production-grade systems such as Snort, Suricata, and Zeek offer robust multi-threaded pattern matching, their reliance on native C/C++ libraries (libpcap, Hyperscan) and extensive memory footprints limits rapid deployment within constrained edge routers and rapid security research sandboxes. In this paper, we propose and evaluate **Sentinel-IDS**, a deterministic, zero-dependency network telemetry and intrusion detection architecture implemented entirely within memory-managed primitives. The engine features wire-format decoders for Layers 2 through 7, an asynchronous bidirectional TCP connection-state tracker, and four targeted heuristic detection algorithms. We benchmark Sentinel-IDS across synthetic attack corpora formatted under standard RFC specifications and demonstrate deterministic attack classification with zero packet drop in burst conditions.

**Keywords**: Network Security, Intrusion Detection Systems (IDS), Shannon Entropy, DNS Tunneling, SYN Flood, Flow Dissection, Zero-Dependency Systems.

---

### Sections Overview
- **Section I**: Introduction and motivation for zero-dependency packet analysis.
- **Section II**: Related work (Snort, Suricata, Zeek, Scapy bottlenecks).
- **Section III**: Wire-format framing methodology using binary packing primitives.
- **Section IV**: Heuristic detection formulations (Shannon Entropy, SYN ratio, Sliding window).
- **Section V**: Empirical evaluation against synthetic attack PCAP corpora.
- **Section VI**: Conclusion and roadmap toward eBPF/XDP integration.
