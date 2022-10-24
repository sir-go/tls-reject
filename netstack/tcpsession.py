import re

http_re_begin = re.compile(rb"^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)\s+", re.I)
http_re_resource = re.compile(rb"(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)\s+.*\s+HTTP", re.I)
http_re_host = re.compile(rb"HOST(\s+)?:(\s+)?", re.I)
http_end_rnrn = b'\r\n\r\n'
http_end_nn = b'\n\n'


class HTTPSession:
    def __init__(self, name, ts):
        self.name = name
        self.ts = ts
        self.__packet_buffer = []
        self.has_begin = False
        self.has_end = False
        self.__sep = None
        self.__active_ack = None

    def add(self, p):
        self.__packet_buffer.append(p)

        payload = p.payload.get_bytes()

        if not self.has_begin and http_re_begin.match(payload):
            self.has_begin = True
            self.__active_ack = p.tcp.get_ack()

        if self.has_begin and self.__active_ack == p.tcp.get_ack():
            if payload.find(http_end_rnrn) != -1:
                self.__sep = b'\r\n'
                self.has_end = True
            elif payload.find(http_end_nn) != -1:
                    self.__sep = b'\n'
                    self.has_end = True

        if self.has_end:
            self.__packet_buffer = [pkt for pkt in self.__packet_buffer if pkt.tcp.get_ack() == self.__active_ack]

    def get_buffer(self):
        return self.__packet_buffer

    def get_payload(self):
        buff = sorted(self.__packet_buffer, key=lambda p: p.tcp.get_seq())
        return b''.join([p.payload.get_bytes() for p in buff]) if buff is not None else b''

    def get_headers(self):
        payload = self.get_payload()
        headers_part = payload.split(self.__sep + self.__sep)[0]
        return headers_part.split(self.__sep)

    def get_url(self):
        url = host = b''

        # split headers by newlines
        for header in self.get_headers():

            # get URL header
            if http_re_resource.match(header):
                url = header.split(b' ')[1]

            # get HOST header
            elif http_re_host.match(header):
                host = header.split(b':')[1]

            # found both headers - don't search more
            if host and url:
                break

        # header HOST not found
        if not host:

            # header GET contains 'http://' ?
            if url.startswith(b'http://'):
                return url

            else:
                # bad request - without HOST
                pass

        return b'http://' + host.strip(b' ') + url.strip(b' ')
