import socket
import struct
import textwrap
import sys
import threading
import queue
from datetime import datetime
import platform
import traceback
try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText
except Exception:
    tk = None
    ttk = None
    ScrolledText = None

#biggest buffer size: 65535
#65535 (0xFFFF) is the largest possible value that fits in an unsigned 16-bit integer.
BUFFER_SIZE = 65535

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

class PacketSnifferGUI:
    def __init__(self):
        if tk is None:
            raise RuntimeError("Tkinter is not available on this system. Install Tk support for Python.")
        self.root = tk.Tk()
        self.root.title("Network Packet Sniffer")
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.conn = None
        self.mode = "windows"
        self.details_by_iid = {}
        self._build_ui()

    def _build_ui(self):
        ctrl = ttk.Frame(self.root)
        ctrl.pack(fill="x", padx=8, pady=6)

        self.start_btn = ttk.Button(ctrl, text="Start", command=self.start_capture)
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop_capture, state="disabled")
        self.clear_btn = ttk.Button(ctrl, text="Clear", command=self.clear_view)
        self.start_btn.pack(side="left")
        self.stop_btn.pack(side="left", padx=(6, 0))
        self.clear_btn.pack(side="left", padx=(6, 0))

        columns = ("time", "proto", "source", "destination", "info")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=18)
        self.tree.heading("time", text="Time")
        self.tree.heading("proto", text="Proto")
        self.tree.heading("source", text="Source")
        self.tree.heading("destination", text="Destination")
        self.tree.heading("info", text="Info")
        self.tree.column("time", width=140, anchor="w")
        self.tree.column("proto", width=70, anchor="w")
        self.tree.column("source", width=180, anchor="w")
        self.tree.column("destination", width=180, anchor="w")
        self.tree.column("info", width=260, anchor="w")

        # Colorize rows by protocol using tags
        self.tree.tag_configure("TCP", background="#9BCDF3")   # light blue
        self.tree.tag_configure("UDP", background="#c5f3ca")   # light green
        self.tree.tag_configure("ICMP", background="#f5eeae")  # light yellow
        self.tree.tag_configure("ERR", background="#fbc0c9")   # light red for errors
        self.tree.tag_configure("OTHER", background="#dad7d8") # light gray

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 6))
        vsb.pack(side="left", fill="y", padx=(0, 8), pady=(0, 6))

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        lbl = ttk.Label(self.root, text="Details")
        lbl.pack(fill="x", padx=8)
        self.details = ScrolledText(self.root, height=12, wrap="word")
        self.details.pack(fill="both", expand=False, padx=8, pady=(0, 8))

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_queue()
        self.root.mainloop()

    def on_close(self):
        self.stop_capture()
        try:
            self.root.destroy()
        except Exception:
            pass

    def start_capture(self):
        if self.conn is not None:
            return
        try:
            host = socket.gethostbyname(socket.gethostname())
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((host, 0))
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.conn = conn
            self.mode = "windows"
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            t = threading.Thread(target=self._capture_loop, daemon=True)
            t.start()
        except Exception as e:
            self._append_detail(f"Failed to start capture: {e}\n{traceback.format_exc()}")

    def stop_capture(self):
        if self.conn is None:
            return
        try:
            try:
                self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            self.stop_event.set()
            try:
                self.conn.close()
            except Exception:
                pass
        finally:
            self.conn = None
            self.stop_event.clear()
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")

    def clear_view(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            self.details.delete("1.0", "end")
        except Exception:
            pass
        self.details_by_iid.clear()

    def _capture_loop(self):
        while self.conn is not None and not self.stop_event.is_set():
            try:
                raw_data, _ = self.conn.recvfrom(BUFFER_SIZE)
                summary, detail = self._process_packet(raw_data)
                if summary:
                    self.queue.put((summary, detail))
            except OSError:
                break
            except Exception as e:
                self.queue.put((("", "ERR", "", "", str(e)), f"Error: {e}\n{traceback.format_exc()}"))

    def _poll_queue(self):
        try:
            while True:
                summary, detail = self.queue.get_nowait()
                t, proto_name, src, dst, info = summary
                tags = (proto_name,) if proto_name in ("ICMP", "TCP", "UDP") else (("ERR",) if proto_name == "ERR" else ("OTHER",))
                iid = self.tree.insert("", "end", values=(t, proto_name, src, dst, info), tags=tags)
                self.details_by_iid[iid] = detail
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        detail = self.details_by_iid.get(iid, "")
        try:
            self.details.delete("1.0", "end")
            self.details.insert("end", detail)
        except Exception:
            pass

    def _process_packet(self, raw_data):
        try:
            data = raw_data
            version, header_length, ttl, proto, src, target, payload = ipv4_packet(data)
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

            lines = []
            lines.append("IPv4 Packet")
            lines.append(f"  Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            lines.append(f"  Protocol: {proto_name} ({proto}), Source: {src}, Target: {target}")

            info = ""
            if proto == 1:
                icmp_type, code, checksum, payload = icmp_packet(payload)
                lines.append("ICMP Packet")
                lines.append(f"  Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                if payload:
                    lines.append("  Data:")
                    lines.append(format_multi_line('    ', payload))
            elif proto == 6:
                src_port, des_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = tcp_segment(payload)
                lines.append("TCP Segment")
                lines.append(f"  SrcPort: {src_port}, DstPort: {des_port}, Seq: {sequence}, Ack: {acknowledgement}")
                lines.append(f"  Flags: URG={flag_urg} ACK={flag_ack} PSH={flag_psh} RST={flag_rst} SYN={flag_syn} FIN={flag_fin}")
                info = f"{src_port} -> {des_port}"
                if payload:
                    lines.append("  Data:")
                    lines.append(format_multi_line('    ', payload))
            elif proto == 17:
                src_port, dest_port, size, payload = udp_packet(payload)
                lines.append("UDP Packet")
                lines.append(f"  SrcPort: {src_port}, DstPort: {dest_port}, Size: {size}")
                info = f"{src_port} -> {dest_port}"
                if payload:
                    lines.append("  Data:")
                    lines.append(format_multi_line('    ', payload))

            detail = "\n".join(lines)
            summary = (ts, proto_name, src, target, info)
            return summary, detail
        except Exception as e:
            return ("", "ERR", "", "", "parse error"), f"Parse error: {e}\n{traceback.format_exc()}"

    def _append_detail(self, text):
        try:
            self.details.insert("end", text + "\n")
            self.details.see("end")
        except Exception:
            pass

def main():
    app = PacketSnifferGUI()
    app.run()

#unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return a formatted mac address (example: AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):    
    bytes_str = map('{:02x}'.format, bytes_addr)
    #joins the pieces made in map above, and then uppercases them
    return ':'.join(bytes_str).upper()

#Unpack IPv4 packet
def ipv4_packet(data):
    version_header_len = data[0]
    #shift 4 bits to the right to get version
    version = version_header_len >> 4
    header_length = (version_header_len & 15) * 4
    # ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    # slice from byte 2 to match our struct format
    total_length, identification, flags_fragment, ttl, proto, checksum, src, target = struct.unpack(
        '! H H H B B H 4s 4s', data[2:20]
    )

    return (
        version,
        header_length,
        ttl,
        proto,
        socket.inet_ntoa(src),
        socket.inet_ntoa(target),
        data[header_length:]
    )

#unpack ICMP
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpack TCP segment
def tcp_segment(data):
    (src_port, des_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, des_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpack UDP
def udp_packet(data):
    # Unpack first 8 bytes as UDP header
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    payload = data[8:]  # everything after the header is the UDP data
    return src_port, dest_port, length, payload

#formats the multiple line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()