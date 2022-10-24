import socket
import struct

from netstack.eth import ETH
from netstack.ip import IP
from netstack.tcp import TCP, checksum
from netstack.payload import Payload


class Packet:
    def __init__(self):
        self.__raw = None
        self.eth = None
        self.ip = None
        self.tcp = None
        self.payload = None
        self.__is_http = None
        self.__session = None

    def has_payload(self):
        if self.payload is None:
            return False
        return self.payload.len

    def parse_from(self, raw):
        self.__raw = raw
        self.eth = ETH(raw)
        self.ip = IP(raw)
        self.tcp = TCP(raw)
        self.payload = Payload(raw, 34 + self.tcp.get_hlen())

    def get_session_name(self):
        if self.__session is None:
            self.__session = '{}:{}->{}:{}'.format(
                self.ip.get_src(), self.tcp.get_src(),
                self.ip.get_dst(), self.tcp.get_dst()
            )
        return self.__session

    def __repr__(self):
        return '<Packet size: {}, l2:{}, l3:{}, l4:{}, l5: {}>'.format(
            len(self.__raw),
            self.eth.__repr__(),
            self.ip.__repr__(),
            self.tcp.__repr__(),
            self.payload.__repr__()
        )


def make_response(pkt, reset=None, hsh=None):
    source_ip = pkt.ip.get_dst()
    dest_ip = pkt.ip.get_src()

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 0  # random.randint(1000, 9999)  # Id of this packet
    ip_frag_off = 0x4000
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr)

    # tcp header fields
    tcp_source = pkt.tcp.get_dst()  # source port
    tcp_dest = pkt.tcp.get_src()  # destination port
    tcp_seq = pkt.tcp.get_ack()  # random.randint(1000000000, 4294967294)
    tcp_ack_seq = 0 if reset else pkt.tcp.get_seq() + 1
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    tcp_fin = 0
    tcp_syn = 0
    tcp_rst = 1 if reset else 0
    tcp_psh = 0 if reset else 1
    tcp_ack = 0 if reset else 1
    tcp_urg = 0
    tcp_window = 0 if reset else socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                             tcp_window, tcp_check, tcp_urg_ptr)

    if reset:
        user_data = b''
    else:
        resp = [
            b'HTTP/1.1 307 Temporary Redirect',
            b'Location: http://blocked/?h=' + bytes(hsh, 'ascii'),
            b'',
            b'',
        ]
        user_data = b'\r\n'.join(resp)

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    pseudo_header = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    pseudo_header = pseudo_header + tcp_header + user_data

    tcp_check = checksum(pseudo_header)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = struct.pack(
        '!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window
    ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

    # final full packet - syn packets dont have any data

    # print(tcp_seq, tcp_check)

    return ip_header + tcp_header + user_data
