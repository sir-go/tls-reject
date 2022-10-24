import struct

CHANGE_CIPHER_SPEC = 0x14
ALERT = 0x15
HANDSHAKE = 0x16
APPLICATION_DATA = 0x17

HELLO_REQUEST = 0x00
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
CERTIFICATE = 0x0b
SERVER_KEY_EXCHANGE = 0x0c
CERTIFICATE_REQUEST = 0x0d
SERVER_DONE = 0x0e
CERTIFICATE_VERIFY = 0x0f
CLIENT_KEY_EXCHANGE = 0x10
FINISHED = 0x14


class ClientHello:
    def __init__(self, raw):
        self.__raw = raw
        self.__len = len(raw)
        self.__sni = None
        # try:
        self.__parse()
        # except (IndexError, struct.error) as e:
        #     pass

    def __parse(self):
        # try:
            # tls header
            tls_type = self.__raw[0]
            # tls_version = self.__raw[1:3]
            # tls_len = self.__raw[3:5]

            # handshake header
            handshake_type = self.__raw[5]

            if tls_type != HANDSHAKE or handshake_type != CLIENT_HELLO or self.__len < 44:
                return

            # client hello header

            # c_hello_len = struct.unpack('!I', b'\x00' + self.__raw[6:9])[0]
            # c_hello_tls_version = struct.unpack('!H', self.__raw[9:11])[0]
            # if c_hello_tls_version < 0x301:
            #     return

            # c_hello_random = self.__raw[11:43]

            pos = 43

            # -------------------------------------- session id
            session_id_len = self.__raw[pos]
            pos += 1
            # session_id = self.__raw[pos:pos + session_id_len]
            pos += session_id_len

            # -------------------------------------- cipher suites
            if pos + 2 > self.__len:
                return
            cipher_suites_len = struct.unpack('!H', self.__raw[pos: pos + 2])[0]
            pos += 2
            # cipher_suites = self.__raw[pos: pos + cipher_suites_len]
            pos += cipher_suites_len

            # -------------------------------------- compression methods
            if pos > self.__len:
                return
            compression_methods_len = self.__raw[pos]
            pos += 1
            # compression_methods = self.__raw[pos: pos + compression_methods_len]
            pos += compression_methods_len

            # -------------------------------------- extensions
            if pos + 2 > self.__len:
                return
            # extensions_len = struct.unpack('!H', self.__raw[pos: pos + 2])[0]
            pos += 2
            # extensions = self.__raw[pos: pos + extensions_len]
            # pos += extensions_len

            while (pos + 4) < self.__len:
                ext_header = self.__raw[pos: pos + 4]
                ext_type, ext_len = struct.unpack('!HH', ext_header)
                pos += 4

                if ext_type == 0 and pos + ext_len > 5:
                    # sni_list_len = self.__raw[pos: pos + 2]
                    pos += 2

                    # sni_type = self.__raw[pos]
                    pos += 1

                    if pos + 2 > self.__len:
                        return
                    sni_len = struct.unpack('!H', self.__raw[pos: pos + 2])[0]
                    pos += 2

                    if pos + sni_len > self.__len:
                        return

                    self.__sni = self.__raw[pos: pos + sni_len]
                    return

                pos += ext_len
        # except Exception as e:
        #     pass

    @property
    def server_name(self):
        return self.__sni

