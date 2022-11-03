import os.path

import pytest
from reject import proc_traffic
from socket import socket


@pytest.fixture(autouse=True)
def mock_socket(monkeypatch):
    monkeypatch.setattr('socket.socket.sendto', lambda *args, **kwargs: 0)


@pytest.mark.parametrize('dump,expected', [
    ('empty', False),
    ('invalid', False),
    ('non_tcp', False),
    ('non_tls_port', False),
    ('non_hello', False),
    ('non_denied', False),
    ('denied', True),
])
def test_proc_traffic(monkeypatch, dump: str, expected: bool):
    fs_in, fs_out = socket(), socket()
    d_list = {'host0', 'micro.org', 'host2'}

    test_bytes = b''

    with open(os.path.join('tests/dumps', dump + '.dump'), 'rb') as dfd:
        test_bytes = dfd.read()

    monkeypatch.setattr('socket.socket.recv', lambda bs, flags: test_bytes)
    assert proc_traffic(fs_in, fs_out, d_list) == expected
