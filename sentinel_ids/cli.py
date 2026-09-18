import argparse
import json
import sys
from sentinel_ids.engine import SentinelEngine
from sentinel_ids.alerts import Alert


def print_alert(alert: Alert):
    color = "\033[91m" if alert.severity in ("HIGH", "CRITICAL") else "\033[93m"
    reset = "\033[0m"
    print(f"{color}[!] [{alert.severity}] {alert.title}{reset}")
    print(f"    Detector: {alert.detector} | Time: {alert.timestamp}")
    print(f"    Source: {alert.source_ip} -> Target: {alert.destination_ip}:{alert.destination_port or ''}")
    print(f"    Detail: {alert.description}\n")


def main():
    parser = argparse.ArgumentParser(description="Sentinel IDS - Network Packet Analysis & Intrusion Detection")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file for offline analysis")
    parser.add_argument("--output", type=str, help="Output JSON file path for recorded alerts")
    args = parser.parse_args()

    if not args.pcap:
        print("Please provide a PCAP file via --pcap.")
        sys.exit(1)

    print(f"[*] Initializing Sentinel IDS Engine...")
    engine = SentinelEngine()

    print(f"[*] Ingesting and analyzing '{args.pcap}'...")
    alerts = engine.analyze_pcap(args.pcap, alert_callback=print_alert)

    stats = engine.get_stats()
    print("-" * 50)
    print("ANALYSIS SUMMARY")
    print(f"Total Packets Processed: {stats['total_packets']}")
    print(f"Active Network Flows:    {stats['total_flows']}")
    print(f"Security Alerts Fired:   {stats['total_alerts']}")
    print("Protocol Breakdown:")
    for proto, count in stats['protocols'].items():
        print(f"  - {proto}: {count}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([a.to_dict() for a in alerts], f, indent=2)
        print(f"[*] Alerts saved to {args.output}")


if __name__ == "__main__":
    main()
