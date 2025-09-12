import socket
import struct
import textwrap

#biggest buffer size: 65535
#65535 (0xFFFF) is the largest possible value that fits in an unsigned 16-bit integer.

#listening for packets Loop
def main():
    #Does not work since windows does not allow.
    #conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    HOST = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    conn.bind((HOST, 0))
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    BUFFER_SIZE = 65535
    print('Testing\n')

    while True:
        raw_data, addr = conn.recvfrom(BUFFER_SIZE)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print('Dest: {} src: {} proto: {}'.format(dest_mac,src_mac,eth_proto))

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
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

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
    src_port, dest_port, size =  struct.unpack('! H H 2x H', data[8:])
    return src_port, dest_port, size, data[8:]

#formats the multiple line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()