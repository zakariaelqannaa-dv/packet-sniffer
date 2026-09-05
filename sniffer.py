#!/usr/bin/env python3
"""Packet Sniffer - Captures and displays network packets using Scapy."""

import sys
import argparse
from datetime import datetime

from scapy.all import (
    sniff,
    conf,
    get_if_list,
    TCP,
    UDP,
    ICMP,
    IP,
    IPv6,
    ARP,
    DNS,
    Raw,
    wrpcap,
)


PROTO_MAP = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "arp": ARP}


def get_interfaces():
    return get_if_list()


def select_interface():
    interfaces = get_interfaces()
    print("\nAvailable network interfaces:\n")
    for i, iface in enumerate(interfaces, 1):
        default = " (default)" if iface == conf.iface else ""
        print(f"  [{i}] {iface}{default}")
    print()
    while True:
        try:
            choice = int(input("Select interface number (press Enter for default): ") or "0")
            if choice == 0:
                return conf.iface
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
        except (ValueError, EOFError):
            return conf.iface
        print("Invalid choice. Try again.")


def packet_callback(pkt, verbose, write_file):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    summary = []

    if IP in pkt:
        summary.append(f"{pkt[IP].src} -> {pkt[IP].dst}")
        summary.append(f"Proto: {pkt[IP].proto}")
    elif IPv6 in pkt:
        summary.append(f"{pkt[IPv6].src} -> {pkt[IPv6].dst}")
    elif ARP in pkt:
        summary.append(f"ARP: {pkt[ARP].psrc} -> {pkt[ARP].pdst}")

    if TCP in pkt:
        flags = pkt[TCP].flags
        summary.append(f"TCP {pkt[TCP].sport} -> {pkt[TCP].dport} [{flags}]")
    elif UDP in pkt:
        summary.append(f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}")
    elif ICMP in pkt:
        summary.append(f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}")

    if DNS in pkt:
        if pkt[DNS].qr == 0:
            summary.append(f"DNS Query: {pkt[DNS].qname.decode(errors='replace')}")
        else:
            summary.append(f"DNS Response")

    if Raw in pkt:
        payload = pkt[Raw].load
        summary.append(f"Payload: {len(payload)} bytes")

    print(f"[{timestamp}] {' | '.join(summary)}")

    if verbose:
        pkt.show()
        print()


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tcp", "udp", "icmp", "arp"],
        help="Filter by protocol",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full packet details")
    parser.add_argument("-o", "--output", help="Save captured packets to pcap file")
    args = parser.parse_args()

    iface = args.interface or select_interface()
    proto_filter = PROTO_MAP.get(args.protocol)

    print(f"\n[*] Sniffing on {iface} ...")
    if args.filter:
        print(f"[*] BPF filter: {args.filter}")
    if args.protocol:
        print(f"[*] Protocol filter: {args.protocol.upper()}")
    print("[*] Press Ctrl+C to stop.\n")

    captured = []

    def handler(pkt):
        if proto_filter and not pkt.haslayer(proto_filter):
            return
        captured.append(pkt)
        packet_callback(pkt, args.verbose, args.output)

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            prn=handler,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Run as Administrator/root.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        if args.output and captured:
            wrpcap(args.output, captured)
            print(f"\n[*] Saved {len(captured)} packets to {args.output}")
        print(f"\n[*] Done. Captured {len(captured)} packets.")


if __name__ == "__main__":
    main()
