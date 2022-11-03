import socket
import struct

from netstack.eth import ETH
from netstack.ip import IP
from netstack.tcp import TCP
from netstack.payload import Payload
from netstack.tls import HANDSHAKE, CLIENT_HELLO


def checksum(header: bytes) -> int:
    # odd length
    if len(header) % 2 == 1:
        header += b"\0"

    chk_sum = sum(
        struct.unpack('{}H'.format(divmod(len(header), 2)[0]), header)
    )
    while chk_sum >> 16:
        chk_sum = (chk_sum >> 16) + (chk_sum & 0xffff)

    chk_sum = ~chk_sum & 0xffff

    return chk_sum


class Packet:
    def __init__(self):
        self.__raw = None
        self.eth = None
        self.ip = None
        self.tcp = None
        self.payload = None

    def has_payload(self) -> bool:
        return self.payload is not None

    def is_tls_client_hello(self) -> bool:
        return self.tcp.has_flag('ack') \
               and self.tcp.has_flag('psh') \
               and self.has_payload() \
               and self.payload.len > 5 \
               and self.payload.get_bytes()[0] == HANDSHAKE \
               and self.payload.get_bytes()[5] == CLIENT_HELLO

    def parse_from(self, raw: bytes):
        self.__raw = raw
        self.eth = ETH(raw)
        self.ip = IP(raw)
        self.tcp = TCP(raw)
        self.payload = Payload(raw, 34 + self.tcp.get_hlen())

    def __repr__(self):
        return '<Packet size: {}, l2:{}, l3:{}, l4:{}, l5: {}>'.format(
            len(self.__raw),
            self.eth.__repr__(),
            self.ip.__repr__(),
            self.tcp.__repr__(),
            self.payload.__repr__()
        )


def make_rst(pkt: Packet) -> bytes:
    source_ip = pkt.ip.get_dst()
    dest_ip = pkt.ip.get_src()

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 0
    ip_frag_off = 0x4000
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr)

    # tcp header fields
    tcp_source = pkt.tcp.get_dst()  # source port
    tcp_dest = pkt.tcp.get_src()  # destination port
    tcp_seq = pkt.tcp.get_ack()  # random.randint(1000000000, 4294967294)
    tcp_ack_seq = 0
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    tcp_fin = 0
    tcp_syn = 0
    tcp_rst = 1
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = 0
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (
            tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq,
                             tcp_ack_seq, tcp_offset_res, tcp_flags,
                             tcp_window, tcp_check, tcp_urg_ptr)

    user_data = b''

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    pseudo_header = struct.pack('!4s4sBBH', source_address, dest_address,
                                placeholder, protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header + user_data

    tcp_check = checksum(pseudo_header)

    tcp_header = struct.pack(
        '!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
        tcp_flags, tcp_window
    ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

    return ip_header + tcp_header + user_data
