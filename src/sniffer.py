"""
--------------------------
A basic educational packet analyzer built with Scapy for the
CodeAlpha Cybersecurity Internship (Task 1).

Captures live network traffic, identifies protocols (TCP/UDP/ICMP/ARP),
extracts structured packet information, safely previews payloads, and
reports capture statistics. Intended for use only on networks/systems
you own or are explicitly authorized to monitor.
"""

import argparse
import time
from typing import Optional

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

PAYLOAD_PREVIEW_LIMIT = 32  # bytes shown in terminal, to keep lines readable


# ---------------------------------------------------------------------------
# Protocol detection
# ---------------------------------------------------------------------------

def detect_protocol(packet) -> str:
    """
    Inspects a packet's layers and returns a human-readable protocol label.
    Order matters: ARP has no IP layer, so it must be checked first.
    TCP/UDP/ICMP only make sense once we know we're inside IP or IPv6.
    """
    if ARP in packet:
        return "ARP"
    if IP in packet or IPv6 in packet:
        if TCP in packet:
            return "TCP"
        if UDP in packet:
            return "UDP"
        if ICMP in packet:
            return "ICMP"
        return "IP (Other)"
    return "Other/Unknown"


# ---------------------------------------------------------------------------
# Payload extraction
# ---------------------------------------------------------------------------

def extract_payload_preview(packet) -> Optional[str]:
    """
    Safely extracts a short, printable preview of a packet's payload.
    Returns None if there is no payload at all.

    Payload bytes are never assumed to be valid text - encrypted (TLS)
    and binary payloads are the normal case, not an edge case, so we
    decode defensively rather than assuming UTF-8 will succeed.
    """
    if Raw not in packet:
        return None

    raw_bytes = bytes(packet[Raw].load)
    if not raw_bytes:
        return None

    truncated = raw_bytes[:PAYLOAD_PREVIEW_LIMIT]

    # errors="replace" swaps any non-decodable byte with a placeholder
    # character instead of raising UnicodeDecodeError - this is what
    # makes binary/encrypted payloads safe to print rather than crashing.
    preview = truncated.decode("utf-8", errors="replace")

    # Strip control characters (newlines, nulls, etc.) that would break
    # our single-line terminal formatting.
    preview = "".join(ch if ch.isprintable() else "." for ch in preview)

    suffix = "..." if len(raw_bytes) > PAYLOAD_PREVIEW_LIMIT else ""
    return f"{preview}{suffix} ({len(raw_bytes)} bytes)"


# ---------------------------------------------------------------------------
# Structured field extraction
# ---------------------------------------------------------------------------

def extract_packet_info(packet) -> dict:
    """
    Pulls structured fields out of a packet: protocol, IPs, ports, length,
    and a payload preview. Returns a dictionary so downstream code
    (display, filtering, statistics) works with clean data instead of
    re-parsing the packet each time.
    """
    info = {
        "protocol": detect_protocol(packet),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "payload": extract_payload_preview(packet),
    }

    # ARP has no IP layer at all - it carries its own address fields.
    if ARP in packet:
        info["src_ip"] = packet[ARP].psrc
        info["dst_ip"] = packet[ARP].pdst
        return info

    # IPv4 and IPv6 store addresses on different layer classes.
    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
    elif IPv6 in packet:
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst

    # Ports only exist for TCP/UDP - ICMP and "IP (Other)" have none.
    if TCP in packet:
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport

    return info


# ---------------------------------------------------------------------------
# Display formatting
# ---------------------------------------------------------------------------

def format_packet_line(packet_number: int, info: dict) -> str:
    """
    Turns an extracted-info dict into a single readable block for the
    terminal: one summary line, plus an optional indented payload line.
    """
    proto = info["protocol"]
    length = info["length"]

    src = info["src_ip"] or "N/A"
    dst = info["dst_ip"] or "N/A"

    if info["src_port"] is not None:
        src = f"{src}:{info['src_port']}"
    if info["dst_port"] is not None:
        dst = f"{dst}:{info['dst_port']}"

    line = f"[{packet_number}] {proto:<12} {src} -> {dst}  len={length}"

    if info["payload"]:
        line += f"\n      payload: {info['payload']}"

    return line


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def create_stats() -> dict:
    """
    Initializes the running statistics structure. A plain dict is used
    deliberately - no behavior is needed beyond storing counts, so a
    class would be unnecessary overhead for this scope.
    """
    return {
        "total": 0,
        "by_protocol": {},   # e.g. {"TCP": 12, "UDP": 3, "ARP": 1}
        "start_time": time.time(),
    }


def update_stats(stats: dict, protocol: str) -> None:
    stats["total"] += 1
    stats["by_protocol"][protocol] = stats["by_protocol"].get(protocol, 0) + 1


def print_summary(stats: dict) -> None:
    elapsed = time.time() - stats["start_time"]
    print("\n" + "=" * 40)
    print("Capture Summary")
    print("=" * 40)
    print(f"Total packets displayed : {stats['total']}")
    print(f"Duration                : {elapsed:.1f} seconds")
    if stats["by_protocol"]:
        print("Breakdown by protocol:")
        for proto, count in sorted(stats["by_protocol"].items(), key=lambda x: -x[1]):
            print(f"  {proto:<12} {count}")
    print("=" * 40)


# ---------------------------------------------------------------------------
# Per-packet callback
# ---------------------------------------------------------------------------

def handle_packet(packet, stats: dict, protocol_filter: Optional[str]) -> None:
    """
    Scapy calls this once per captured packet. Extracts info, applies
    the optional protocol filter, updates statistics, and prints the
    packet - in that order, so displayed packet numbers stay sequential
    and only count packets that actually passed the filter.
    """
    info = extract_packet_info(packet)

    if protocol_filter and info["protocol"].lower() != protocol_filter:
        return  # Silently skip - doesn't match the requested filter.

    update_stats(stats, info["protocol"])
    print(format_packet_line(stats["total"], info))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Defines and parses the command-line interface.
    Returns a Namespace with attributes: interface, protocol, count.
    """
    parser = argparse.ArgumentParser(
        description="CodeAlpha Network Sniffer - a basic educational packet analyzer."
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to capture on (default: Scapy's auto-selected interface).",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        choices=["tcp", "udp", "icmp", "arp"],
        default=None,
        help="Only display packets matching this protocol (default: show all).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture before stopping automatically (default: 0 = unlimited).",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_arguments()

    print("Starting capture... Press Ctrl+C to stop.")
    if args.interface:
        print(f"Interface: {args.interface}")
    if args.protocol:
        print(f"Filtering protocol: {args.protocol.upper()}")
    if args.count:
        print(f"Stopping after {args.count} packets.")

    stats = create_stats()

    try:
        sniff(
            iface=args.interface,
            count=args.count,
            prn=lambda pkt: handle_packet(pkt, stats, args.protocol),
        )
    except ValueError as e:
        # Raised by Scapy when the given --interface name doesn't exist.
        # We return here (skipping the summary below) because no actual
        # capture took place - printing a "0 packets" summary would be
        # misleading after a startup error rather than a real session.
        print(f"\nError: {e}")
        print("Tip: run Python, then:")
        print("     from scapy.all import show_interfaces; show_interfaces()")
        print("     to see valid interface names.")
        return
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")

    # Reached on normal completion (count limit hit) or after Ctrl+C -
    # NOT reached if the ValueError branch above already returned.
    print_summary(stats)


if __name__ == "__main__":
    main()