class Payload:
    def __init__(self, raw, offset):
        self.__raw = raw
        self.__offset = offset
        self.len = len(raw) - offset

    def get_bytes(self):
        return self.__raw[self.__offset:]

    def __repr__(self):
        l = len(self.get_bytes())
        return '<Payload len: {}, data: "{}">'.format(
            l,
            '{} ... {}'.format(self.get_bytes()[:4], self.get_bytes()[-4:]) if l > 8 else self.get_bytes()
        ) if l > 0 else '<Payload None>'
