# Network Sniffer

A basic, educational command-line network packet analyzer built with Python and Scapy, created for **Basic Network Sniffer**.

The tool captures live traffic from a network interface, identifies the protocol of each packet (TCP, UDP, ICMP, ARP), extracts structured fields (source/destination IP, ports, length), safely previews payloads without assuming they are readable text, and reports summary statistics when capture ends.

This project is intentionally scoped as a learning tool, not a production security product. See [Limitations](#limitations) below for an honest account of what it can and cannot do.

---

## Features

- Live packet capture on a chosen (or auto-selected) network interface
- Protocol detection: TCP, UDP, ICMP, ARP, with graceful fallback for anything else (including IPv6 traffic)
- Structured field extraction: source/destination IP, source/destination port, protocol, packet length
- Safe payload preview — truncated, and decoded defensively so binary or encrypted data never crashes the program
- Command-line filtering by protocol (`--protocol tcp`)
- Optional packet count limit (`--count 20`)
- Optional interface selection (`--interface "Wi-Fi"`)
- Clean Ctrl+C shutdown with a capture summary (total packets, duration, per-protocol breakdown)
- Clear, non-crashing error handling for invalid interface names

---

## Technologies

- Python 3
- [Scapy](https://scapy.net/) — chosen over raw `socket` programming specifically to focus on protocol structure and traffic analysis rather than low-level byte parsing

---

## Architecture

```text
Network Interface (via Npcap on Windows)
            |
      sniff() [Scapy capture loop]
            |
   Per-packet callback (handle_packet)
            |
   Layer detection: IP? IPv6? TCP? UDP? ICMP? ARP?
            |
   Field extraction: IPs, ports, length, payload preview
            |
   Optional protocol filter
            |
   Formatted terminal output
            |
   Running statistics (per-protocol counts)
            |
   Ctrl+C or --count reached -> summary report
```

The project deliberately separates **capture** (Scapy's `sniff()`), **analysis** (`detect_protocol`, `extract_packet_info`, `extract_payload_preview`), and **display** (`format_packet_line`, `print_summary`) into distinct functions. This keeps each piece independently understandable and testable, and means filtering logic reuses the same protocol detection used for display, rather than duplicating it.

---

## Supported Protocols

| Protocol | Notes |
|---|---|
| **TCP** | Connection-oriented; source/destination ports extracted |
| **UDP** | Connectionless; source/destination ports extracted |
| **ICMP** | Diagnostic/control traffic (e.g. `ping`); no ports |
| **ARP** | Local network address resolution; no IP layer, no ports — uses its own address fields |
| **IP (Other)** | Any other IPv4/IPv6-based traffic not matching the above (e.g. ICMPv6 Neighbor Discovery — see Limitations) |
| **Other/Unknown** | Anything without an IP or ARP layer at all |

Both IPv4 and IPv6 are supported for address extraction.

---

## Installation (Windows / PowerShell)

This project was developed and tested on **Windows**, using **PowerShell** and a Python virtual environment.

### 1. Install Npcap

Scapy requires [Npcap](https://npcap.com/#download) to capture packets on Windows (not WinPcap, which is deprecated). During installation, check **"Install Npcap in WinPcap API-compatible Mode."**

### 2. Set up the project

```powershell
git clone https://github.com/talhahassanmalik57-collab/Basic_NetworkSniffer.git
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If activation is blocked by execution policy, run once (in an Administrator PowerShell):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Find your interface name (optional)

```powershell
python
```
```python
from scapy.all import show_interfaces
show_interfaces()
```

---

## Usage

**Live packet capture generally requires an Administrator PowerShell window** on Windows, since raw packet capture needs elevated privileges.

```powershell
# Capture indefinitely until Ctrl+C
python src\sniffer.py

# Capture exactly 20 packets, then stop automatically
python src\sniffer.py --count 20

# Only show TCP traffic
python src\sniffer.py --protocol tcp

# Capture on a specific interface
python src\sniffer.py --interface "Wi-Fi"

# Combine flags
python src\sniffer.py --interface "Wi-Fi" --protocol udp --count 15
```

---

## Example Output

*(Example output only — illustrative of format, not a guarantee of exact values on your machine.)*

```text
Starting capture... Press Ctrl+C to stop.
Filtering protocol: TCP
Stopping after 5 packets.
[1] TCP          192.168.1.5:51322 -> 142.251.150.119:80  len=54
[2] TCP          142.251.150.119:80 -> 192.168.1.5:51322  len=1458
      payload: HTTP/1.1 200 OK.... (1404 bytes)
[3] ARP          192.168.1.5 -> 192.168.1.1  len=42
[4] TCP          192.168.1.5:56123 -> 172.64.148.235:443  len=1234
      payload: ..I.\..#.......zL.......... (1180 bytes)
[5] TCP          172.64.148.235:443 -> 192.168.1.5:56123  len=54

========================================
Capture Summary
========================================
Total packets displayed : 5
Duration                : 0.4 seconds
Breakdown by protocol:
  TCP          4
  ARP          1
========================================
```

Note the port-443 payload above is garbled — this is **expected and correct**, not a bug. It's encrypted TLS traffic; see Limitations.

---

## How It Works

1. **Capture** — `scapy.sniff()` opens the chosen (or default) network interface via Npcap and invokes a callback function once per captured packet.
2. **Protocol detection** — each packet's layers are inspected (`ARP in packet`, `TCP in packet`, etc.) to classify it. ARP is checked first since it has no IP layer; TCP/UDP/ICMP are only checked once IP or IPv6 is confirmed present, since they always ride inside one of those.
3. **Field extraction** — source/destination IP and port, protocol, and total length are pulled into a plain dictionary per packet.
4. **Payload preview** — if a packet has leftover data after all known headers (Scapy's `Raw` layer), the first 32 bytes are decoded with `errors="replace"` so binary or encrypted data is displayed safely as placeholder characters instead of crashing the program.
5. **Filtering** — if `--protocol` was specified, non-matching packets are silently skipped before being counted or displayed.
6. **Statistics** — every displayed packet updates a running total and a per-protocol count.
7. **Shutdown** — Ctrl+C or reaching `--count` both lead to a printed summary; an invalid `--interface` name is caught and reported cleanly instead of crashing, and correctly skips printing a summary since no capture occurred.

---

## Testing

Traffic was generated and observed using only the developer's own machine and network, for example:
- Browsing websites (generates TCP/HTTPS traffic)
- `ping google.com` (generates ICMP/ICMPv6 traffic)
- Normal background OS/network activity (generates ARP and DNS-over-UDP/TCP traffic)

No traffic from other people's devices was targeted or analyzed.

---

## Security and Ethical Considerations

Packet capture should **only** be performed on networks and systems you own or are explicitly authorized to monitor. Capturing traffic on networks without authorization may be illegal depending on jurisdiction and network policy. This tool is provided strictly for personal learning and authorized security work.

---

## Limitations

Documented honestly, based on this project's actual scope and testing:

- **Encrypted traffic cannot be read as plaintext.** TLS/HTTPS payloads will always appear as garbled binary — this is encryption working correctly, not a flaw in this tool.
- **Port number does not guarantee content type.** During testing, plaintext-port (80) traffic was observed carrying binary (likely compressed) payloads, and port 443 traffic was observed over UDP (consistent with QUIC/HTTP3) rather than only classic TLS-over-TCP. This tool labels by protocol and port convention only — it does not reconstruct or verify actual application-layer content.
- **ICMPv6 is not separately classified.** IPv6 Neighbor Discovery messages (`ICMPv6ND_NS`/`ICMPv6ND_NA`, IPv6's equivalent of ARP) are currently reported as `IP (Other)` rather than a dedicated ICMPv6 label. This was a deliberate scope decision, not an oversight — see Future Improvements.
- **Visibility is limited by network topology.** On most modern switched networks, this tool will primarily see the host machine's own traffic plus broadcast/multicast traffic (like ARP) — not arbitrary other devices' traffic.
- **Windows capture requires Npcap and typically Administrator privileges.**
- **This is a basic educational sniffer, not a production intrusion detection system.**

---

## Future Improvements

- Dedicated ICMPv6 protocol classification
- Saving captured packet metadata to a file (CSV/JSON) or standard `.pcap` format
- TCP stream reassembly for more accurate application-layer content inspection
- A packet statistics dashboard beyond the terminal summary
- Rule-based anomaly detection as a foundation for **Network Intrusion Detection System**

---

## Project Structure

```text
CodeAlpha_NetworkSniffer/
|
├── src/
│   └── sniffer.py
|
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

---

## Cybersecurity Learning Connection

This project moves through the same conceptual pipeline that underlies real network security monitoring:

```text
Packet Capture -> Network Visibility -> Traffic Analysis ->
Protocol Understanding -> Security Monitoring -> Intrusion Detection
```

The protocol classification, structured field extraction, and statistical baseline built here are the same foundational building blocks a future **Network Intrusion Detection System** would consume and act on — this project stops at *observing and describing* traffic; an IDS would go further and *judge* it against expected baselines or known attack patterns.
