import pytest

from netstack.ip import IP

raw = b'\0' * 26 + \
      b"\xC0\xA8\x1C\x40" \
      b"\xAC\x11\x00\x36"


@pytest.fixture
def ip():
    return IP(raw)


def test_ip(ip):
    assert str(ip) == '<IP 192.168.28.64 -> 172.17.0.54>'
