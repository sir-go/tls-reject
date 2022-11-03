import struct

_tcp_flags_list = ['fin', 'syn', 'rst', 'psh', 'ack', 'urg']


class TCP:
    def __init__(self, raw: bytes):
        self.__raw = struct.unpack("!HHLLBB", raw[34:48])
        self.__hlen = None
        self.__flags = [''] * 6

    def get_src(self) -> int:
        return self.__raw[0]

    def get_dst(self) -> int:
        return self.__raw[1]

    def get_seq(self) -> int:
        return self.__raw[2]

    def get_ack(self) -> int:
        return self.__raw[3]

    def get_hlen(self) -> int:
        if self.__hlen is None:
            self.__hlen = (self.__raw[4] >> 4) * 4
        return self.__hlen

    def has_flag(self, flag: str) -> bool:
        if flag in self.__flags:
            return True
        bit = _tcp_flags_list.index(flag)
        if self.__raw[5] >> bit & 1:
            self.__flags[bit] = flag
            return True
        return False

    def get_flags(self):
        for flag in _tcp_flags_list:
            self.has_flag(flag)
        return self.__flags

    def __repr__(self):
        return f'<TCP {self.get_src()} -> {self.get_dst()}, ' \
               f's: {self.get_seq()}, a: {self.get_ack()}, ' \
               f'f: [{",".join(self.get_flags())}]>'
