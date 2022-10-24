import struct


# checksum functions needed for calculation checksum
def checksum(pkt):
    # chk_sum = 0

    # odd lenght
    if len(pkt) % 2 == 1:
        pkt += b"\0"

    chk_sum = sum(struct.unpack('{}H'.format(divmod(len(pkt), 2)[0]), pkt))
    while chk_sum >> 16:
        chk_sum = (chk_sum >> 16) + (chk_sum & 0xffff)

    # complement and mask to 4 byte short
    chk_sum = ~chk_sum & 0xffff

    return chk_sum


class TCP:
    def __init__(self, raw):
        self.__raw = struct.unpack("!HHLLBB", raw[34:48])
        self.__tcp_flags_list = ['fin', 'syn', 'rst', 'psh', 'ack', 'urg']
        self.__hlen = None
        self.__flags = [''] * 6

    def get_src(self):
        return self.__raw[0]

    def get_dst(self):
        return self.__raw[1]

    def get_seq(self):
        return self.__raw[2]

    def get_ack(self):
        return self.__raw[3]

    def get_hlen(self):
        if self.__hlen is None:
            self.__hlen = (self.__raw[4] >> 4) * 4
        return self.__hlen

    def has_flag(self, flag):
        if flag in self.__flags:
            return True
        bit = self.__tcp_flags_list.index(flag)
        has = self.__raw[5] >> bit & 1
        if has:
            self.__flags[bit] = flag
            return True
        return False

    def get_flags(self):
        for flag in self.__tcp_flags_list:
            self.has_flag(flag)
        return self.__flags

    def __repr__(self):
        return '<TCP {} -> {}, s: {}, a: {}, f: [{}]>'.format(
            self.get_src(),
            self.get_dst(),
            self.get_seq(),
            self.get_ack(),
            ','.join(self.get_flags())
        )
