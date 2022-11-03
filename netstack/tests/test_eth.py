import pytest

from netstack.eth import ETH

raw = b"\x0a\x0b\x0c\x0d\x0e\x0f" \
      b"\x00\x01\x02\x03\x04\x05"


@pytest.fixture
def eth():
    return ETH(raw)


def test_eth(eth):
    assert str(eth) == '<ETH 00:01:02:03:04:05 -> 0a:0b:0c:0d:0e:0f>'
