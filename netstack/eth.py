import struct


class ETH:
    def __init__(self, raw):
        self.__raw = struct.unpack("!6s6s", raw[0:12])
        self.__dst = None
        self.__src = None

    @staticmethod
    def __get_target(target, sep=None):
        return (sep if sep is not None else ':').join('{:02x}'.format(x) for x in target)

    def get_dst(self, sep=None):
        if self.__dst is None:
            self.__dst = self.__get_target(self.__raw[0], sep)
        return self.__dst

    def get_src(self, sep=None):
        if self.__src is None:
            self.__src = self.__get_target(self.__raw[1], sep)
        return self.__src

    def __repr__(self):
        return '<ETH {} -> {}>'.format(
            self.get_src(),
            self.get_dst()
        )
