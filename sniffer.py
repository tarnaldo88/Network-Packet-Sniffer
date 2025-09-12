import socket
import struct
import textwrap
import sys

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

#listening for packets Loop
def main():
    # try:
    #     # Try Linux-style AF_PACKET (raw Ethernet frames)
    #     conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #     mode = "linux"
    #     print("[*] Using AF_PACKET (Linux / raw Ethernet frames)")
    # except OSError:
    # Fallback: Windows / AF_INET (only IP packets)
    HOST = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((HOST, 0))
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    mode = "windows"
    print(f"[*] Using AF_INET (Windows / IP packets only) on host {HOST}")

    while True:
        raw_data, addr = conn.recvfrom(BUFFER_SIZE)

        if mode == "linux":
            # Parse Ethernet frame first (Linux only)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 + f'Dest: {dest_mac} src: {src_mac} proto: {eth_proto}')

            # EtherType 8 = IPv4
            if eth_proto != 8:
                continue  # skip non-IPv4 frames
        else:
            # On Windows, raw_data already starts at IP header
            data = raw_data

        # IPv4 parsing works on both Windows + Linux now
        version, header_length, ttl, proto, src, target, payload = ipv4_packet(data)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
        print(TAB_3 + f'Protocol: {proto}, Source: {src}, Target: {target}')

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, payload = icmp_packet(payload)
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, payload))

        # TCP
        elif proto == 6:
            src_port, des_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = tcp_segment(payload)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + f'Source: {src_port}, Destination: {des_port}, Seq: {sequence}, Ack: {acknowledgement}')
            print(TAB_2 + 'Flags:')
            print(TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, payload))

        # UDP
        elif proto == 17:
            src_port, dest_port, size, payload = udp_packet(payload)
            print(TAB_1 + 'UDP Packet:')
            print(TAB_2 + f'Source: {src_port}, Destination: {dest_port}, Size: {size}')
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, payload))


#unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]

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

#returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))

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
    flag_rst = (offset_reserved_flags & 2) >> 2
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