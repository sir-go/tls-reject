import pytest

from netstack.packet import Packet, make_rst, checksum
from netstack.payload import Payload


@pytest.fixture
def pkt() -> Packet:
    with open('netstack/tests/dumps/packet.dump', 'rb') as dumpFd:
        raw = dumpFd.read()
        p = Packet()
        p.parse_from(raw)
        return p


def test_packet(pkt):
    assert str(pkt) == '<Packet size: 589, ' \
                       'l2:<ETH 14:5a:fc:72:7c:95 -> c8:0c:c8:91:65:2d>, ' \
                       'l3:<IP 192.168.1.3 -> 188.127.241.203>, ' \
                       'l4:<TCP 34192 -> 443, ' \
                       's: 3766533566, ' \
                       'a: 2761766695, ' \
                       'f: [,,,psh,ack,]>, ' \
                       'l5: <Payload len: 523, ' \
                       'data: ' \
                       '"b\'\\x16\\x03\\x01\\x02\' ... ' \
                       'b\'z\\x00\\x01\\x00\'">>'


def test_checksum():
    header = b"\xbc\x7f\xf1\xcb\xc0\xa8\x01\x03\x00\x06\x00" \
             b"\x14\x01\xbb\x85\x90\xa4\x9d\x37\x27\x00\x00" \
             b"\x00\x00\x50\x04\x00\x00\x00\x00\x00\x00"
    assert checksum(header) == 55772
    assert checksum(header) != 55000


def test_has_payload(pkt):
    assert pkt.has_payload() is True

    pkt.payload = None
    assert pkt.has_payload() is False


def test_is_tls_client_hello(pkt):
    assert pkt.is_tls_client_hello() is True

    pkt.payload = Payload(b'\x00' * 16, 0)
    assert pkt.is_tls_client_hello() is False


def test_make_rst(pkt):
    rst_l3 = make_rst(pkt)
    with open('netstack/tests/dumps/rst.dump', 'br') as dfd:
        assert rst_l3 == dfd.read()
