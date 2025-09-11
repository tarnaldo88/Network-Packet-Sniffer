import socket
import struct
import textwrap

#biggest buffer size: 65535

#listening for packets Loop
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    BUFFER_SIZE = 65535

    while True:
        raw_data, addr = conn.recvfrom(BUFFER_SIZE)
        

#unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]

#return a formatted mac address
def get_mac_addr(bytes_addr):    
    bytes_str = map('{:02x}'.format, bytes_addr)
    #joins the pieces made in map above, and then uppercases them
    return ':'.join(bytes_addr).upper()


main()