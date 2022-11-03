import pytest

from netstack.tcp import TCP

raw = b'\0' * 34
raw += b"\x87\x5c" \
       b"\x01\xbb" \
       b"\x7d\xfc\x89\x40" \
       b"\xaf\x35\xd6\xe0" \
       b"\x80" \
       b"\x18\x80"


@pytest.fixture
def tcp():
    return TCP(raw)


def test_tcp(tcp):
    assert tcp.get_hlen() == 32
    assert str(tcp) == '<TCP 34652 -> 443, s: 2113702208, a: 2939541216, ' \
                       'f: [,,,psh,ack,]>'
