# Network Packet Sniffer (GUI)

A lightweight, Windows-focused network packet sniffer with a clean Tkinter GUI. It captures IPv4 traffic using raw sockets and presents a color-coded, filterable view of packets with a details pane for deeper inspection.

This project emphasizes an approachable, GUI-first experience for inspecting ICMP, TCP, and UDP traffic on the local machine.

## Features

- GUI-based capture and inspection built with Tkinter (no terminal required)
- Start/Stop controls and one-click Clear
- Color-coded rows by protocol for quick scanning
- Summary table with columns: Time, Protocol, Source, Destination, Info
- Details pane with parsed headers and payload preview
- IPv4 parsing with protocol-specific decoding for ICMP, TCP, and UDP
- Safe error reporting (errors highlighted and shown in the details view)

## How it works

- Uses a raw socket to capture IPv4 packets on Windows and enables promiscuous mode via `SIO_RCVALL`
- Parses IPv4 headers and dispatches to protocol-specific decoders
- Displays packet summaries in a `ttk.Treeview` and full details in a `ScrolledText` widget
- Leverages a thread-safe queue to pass parsed packets from the capture thread to the GUI thread

Key modules and functions in `sniffer.py`:

- `PacketSnifferGUI`: Main application class (UI, capture control, event loop)
- `PacketSnifferGUI._process_packet()`: Parses incoming bytes and builds summary/detail views
- `ipv4_packet(data)`: Extracts version, header length, TTL, protocol, source, destination
- `icmp_packet(data)`, `tcp_segment(data)`, `udp_packet(data)`: Protocol decoders
- `format_multi_line(prefix, string, size=80)`: Pretty-prints payload bytes

## Requirements

- Windows 10/11
- Python 3.8+
- Tkinter (included with most standard Python builds for Windows)
- Administrator privileges to open raw sockets

## Installation

1. Ensure you have Python 3.8+ installed. Verify:
   ```powershell
   python --version
   ```
2. (Recommended) Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. No external dependencies are required beyond the Python standard library.

## Usage

1. Run the application as Administrator (required for raw sockets):
   - Open an elevated PowerShell (Run as Administrator)
   - Navigate to the project folder and execute:
     ```powershell
     python sniffer.py
     ```
2. In the GUI:
   - Click `Start` to begin capture
   - Select any row to view full details in the bottom pane
   - Click `Stop` to end capture
   - Click `Clear` to clear the current view

Notes:
- The app captures IPv4 packets using the primary local interface determined by `socket.gethostname()`/`gethostbyname()`.
- On Windows, promiscuous mode is toggled via `SIO_RCVALL` when starting/stopping capture.

## Screenshots and diagrams

You can include protocol reference images bundled in this repo in your documentation or issues:
- `ipv4Header.png`
- `ip header diagram.png`
- `IPv4-Header-1.webp`
- `Ethernet_Type_II_Frame_format.svg.png`

## Troubleshooting

- "Failed to start capture" or permission errors:
  - Ensure you launched the terminal as Administrator
  - Confirm your Python build includes Tkinter
- The UI opens but no packets appear:
  - Verify that the network interface has traffic
  - Some firewalls or VPNs may restrict raw socket capture
- Parse error rows appear in red:
  - Select the row to inspect the stack trace in the details pane

## Limitations

- Windows-only due to `SIO_RCVALL` usage in raw sockets
- Captures IPv4; IPv6 parsing is not implemented
- No persistence or pcap export in the current version

## Roadmap (Ideas)

- IPv6 support
- PCAP/PCAPNG export
- Basic filtering (port, protocol, address)
- Aggregated flows view and search
- Cross-platform capture support via libpcap/WinPcap/Npcap

## Project structure

```
Network-Packet-Sniffer/
├─ sniffer.py                      # Main application (GUI + packet parsing)
├─ ipv4Header.png                  # Reference image
├─ ip header diagram.png           # Reference image
├─ IPv4-Header-1.webp              # Reference image
├─ Ethernet_Type_II_Frame_format.svg.png # Reference image
└─ .gitattributes
```

## Development

- Code style: standard Python with type-agnostic functions
- Main entry point is at the bottom of `sniffer.py` via `main()`
- GUI built with `tkinter`, `ttk`, and `ScrolledText`
- Threading: one background capture thread; UI updated via Tk `.after()` polling

## Contributing

Contributions are welcome! If you'd like to propose features, fixes, or refactoring:

- Open an issue describing the change and rationale
- For PRs, keep changes focused and include before/after behavior where applicable

## License

Add a license of your choice (e.g., MIT, Apache-2.0) to clarify usage and redistribution terms.
