from netstack.payload import Payload

raw0 = b'\0' * 20
raw1 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" \
       b"\x0a\x0b\x0c\x0d\x0e\x0f"


def test_payload():
    p = Payload(b'', 0)
    assert str(p) == '<Payload None>'

    p = Payload(b'', 10)
    assert str(p) == '<Payload None>'

    p = Payload(raw0 + raw1, 0)
    assert p.get_bytes() == raw0 + raw1

    p = Payload(raw0 + raw1, 24)
    assert p.get_bytes() == raw1[4:]
    assert str(p) == '<Payload len: 12, data: ' \
                     '"b\'\\x04\\x05\\x06\\x07\' ... b\'\\x0c\\r\\x0e\\x0f\'">'

    p = Payload(raw1, 10)
    assert p.get_bytes() == raw1[10:]
    assert str(p) == '<Payload len: 6, data: ' \
                     '"b\'\\n\\x0b\\x0c\\r\\x0e\\x0f\'">'
