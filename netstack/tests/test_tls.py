import pytest

from netstack.tls import ClientHello


@pytest.fixture
def tls() -> ClientHello:
    with open('netstack/tests/dumps/tls.dump', 'rb') as dumpFd:
        raw = dumpFd.read()
    return ClientHello(raw)


def test_tls(tls):
    assert tls.server_name == b'cdn.sstatic.net'
