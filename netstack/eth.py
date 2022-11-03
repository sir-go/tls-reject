import struct


class ETH:
    def __init__(self, raw: bytes):
        self.__raw = struct.unpack("!6s6s", raw[0:12])
        self.__dst = None
        self.__src = None

    @staticmethod
    def __get_target(target: bytes, sep: str = ':') -> str:
        return sep.join('{:02x}'.format(x) for x in target)

    def get_dst(self, sep: str = ':') -> str:
        if self.__dst is None:
            self.__dst = self.__get_target(self.__raw[0], sep)
        return self.__dst

    def get_src(self, sep: str = ':') -> str:
        if self.__src is None:
            self.__src = self.__get_target(self.__raw[1], sep)
        return self.__src

    def __repr__(self) -> str:
        return f'<ETH {self.get_src()} -> {self.get_dst()}>'
