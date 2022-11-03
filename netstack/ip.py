import socket
import struct


class IP:
    def __init__(self, raw: bytes):
        self.__raw = struct.unpack("!4s4s", raw[26:34])
        self.__src = None
        self.__dst = None

    @staticmethod
    def __get_target(target: bytes) -> str:
        return socket.inet_ntoa(target)

    def get_dst(self) -> str:
        if self.__dst is None:
            self.__dst = self.__get_target(self.__raw[1])
        return self.__dst

    def get_src(self) -> str:
        if self.__src is None:
            self.__src = self.__get_target(self.__raw[0])
        return self.__src

    def __repr__(self):
        return f'<IP {self.get_src()} -> {self.get_dst()}>'
