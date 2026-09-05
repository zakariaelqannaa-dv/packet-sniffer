# Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.7+-00C853?style=for-the-badge&logo=python&logoColor=white)
![Npcap](https://img.shields.io/badge/Npcap-Windows-FF6B6B?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00C853?style=for-the-badge)

A lightweight network packet sniffer built with Python and Scapy. Captures, analyzes, and displays network traffic in real-time with protocol filtering and pcap export support.

## Features

- **Real-time capture** - Live packet monitoring with timestamps
- **Protocol filtering** - Filter by TCP, UDP, ICMP, or ARP
- **BPF filters** - Use Berkeley Packet Filter syntax for advanced filtering
- **Verbose mode** - Full packet dissection and detailed view
- **Pcap export** - Save captures to `.pcap` files for Wireshark analysis
- **Auto interface detection** - Automatically selects your default network interface
- **Interactive selection** - Choose from available network interfaces

## Requirements

- **Windows** with [Npcap](https://npcap.com/#download) installed (WinPcap-compatible mode)
- **Linux/macOS** - Works out of the box
- Python 3.8+
- Administrator/root privileges (required for packet capture)

## Installation

```bash
# Clone the repository
git clone https://github.com/zakariaelqannaa-dv/packet-sniffer.git
cd packet-sniffer

# Create virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Quick Start

```bash
# Run with auto-selected interface
python sniffer.py

# Or double-click run.bat on Windows (auto-requests admin rights)
```

### Examples

```bash
# Capture 100 packets on default interface
python sniffer.py -c 100

# Capture only TCP traffic
python sniffer.py -p tcp

# Capture HTTP traffic on port 80
python sniffer.py -p tcp -f "tcp port 80"

# Verbose mode with full packet details
python sniffer.py -v -c 20

# Save captured packets to file
python sniffer.py -o capture.pcap -c 50

# Specify a network interface
python sniffer.py -i "\Device\NPF_{AF7BD7AB-CAAA-4E7D-A9CA-CA555868BE9E}"
```

### Command-Line Options

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Network interface to sniff on |
| `-f`, `--filter` | BPF filter expression (e.g. `tcp port 443`) |
| `-p`, `--protocol` | Filter by protocol: `tcp`, `udp`, `icmp`, `arp` |
| `-c`, `--count` | Number of packets to capture (0 = unlimited) |
| `-v`, `--verbose` | Show full packet dissection |
| `-o`, `--output` | Save captured packets to a `.pcap` file |

## Output Format

```
[14:08:09.085] 192.168.1.100 -> 93.184.216.34 | Proto: 6 | TCP 49245 -> 443 [A] | Payload: 32 bytes
[14:08:09.118] 93.184.216.34 -> 192.168.1.100 | Proto: 17 | UDP 443 -> 51234 | Payload: 275 bytes
[14:08:10.899] fe80::c6:16ff:fe89:16ca -> ff02::16
```

## Project Structure

```
packet-sniffer/
├── sniffer.py          # Main packet sniffer script
├── run.bat             # Windows launcher (auto-elevates to admin)
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## How It Works

1. **Interface Selection** - Lists all available network interfaces and lets you choose (or auto-selects the default)
2. **Packet Capture** - Uses Scapy's sniff engine to capture raw packets from the network
3. **Protocol Analysis** - Parses each packet and extracts relevant fields (IP, TCP/UDP ports, DNS queries, payload size)
4. **Display** - Prints a one-line summary per packet with timestamp, source/destination, protocol, and port info

## Legal Disclaimer

This tool is intended for **educational and authorized security testing purposes only**. Unauthorized interception of network traffic may be illegal in your jurisdiction. Always obtain proper authorization before capturing network packets.

## Author

**Zakaria El Qannaa** - [GitHub](https://github.com/zakariaelqannaa-dv)

## License

This project is open source and available under the [MIT License](LICENSE).
