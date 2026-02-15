import pytest
import server.src.framing as framing

def build_frame(payload: bytes, *, client_id=None, version: int = 1, code: int = 0x1234) -> bytes:
    if client_id is None:
        client_id = b"\x01" * 16
    assert len(client_id) == 16

    header = bytearray()
    header += client_id
    header += bytes([version & 0xFF])
    header += int(code & 0xFFFF).to_bytes(2, "little")
    header += len(payload).to_bytes(4, "little")
    assert len(header) == framing.HEADER_LEN
    return bytes(header) + payload

def test_framer_init():
    frame=framing.Framer()
    assert frame is not None

def test_feed_empty_returns_no_frames():
    frame = framing.Framer()
    assert frame.feed(b"") ==[]

def test_incomplete_header_returns_no_frames_and_buffers_data():
    f = framing.Framer()
    frame = build_frame(b"")
    part = frame[:framing.HEADER_LEN - 1]
    assert f.feed(part) == []
    out = f.feed(frame[framing.HEADER_LEN - 1:])
    assert out == [frame]

def test_single_complete_frame_in_one_feed():
    f = framing.Framer()
    payload = b"abc"
    frame = build_frame(payload)
    out = f.feed(frame)
    assert out == [frame]

def test_frame_split_across_two_feeds():
    f = framing.Framer()
    payload = b"hello world"
    frame = build_frame(payload)
    cut = 10
    out1 = f.feed(frame[:cut])
    assert out1 == []
    out2 = f.feed(frame[cut:])
    assert out2 == [frame]

def test_two_frames_in_one_feed():
    f = framing.Framer()
    a = build_frame(b"a")
    b = build_frame(b"bbbb")
    out = f.feed(a+b)
    assert out == [a,b]

def test_trailing_bytes_are_kept_for_next_feed():
    f = framing.Framer()
    first = build_frame(b"xyz")
    second = build_frame(b"")
    trailing = second[:3]
    out1 = f.feed(first+trailing)
    assert out1 == [first]
    out2 = f.feed(second[3:])
    assert out2 == [second]

def test_partial_payload_buffers_until_complete():
    f = framing.Framer()
    payload = b"0123456789"
    frame = build_frame(payload)
    split = framing.HEADER_LEN + 3
    out1 = f.feed(frame[:split])
    assert out1 == []
    out2 = f.feed(frame[split:])
    assert out2 == [frame]

def test_payload_size_is_read_little_endian():
    f = framing.Framer()
    header = bytearray(b"\x11" * framing.HEADER_LEN)
    header[framing.PAYLOAD_SIZE_OFFSET:framing.PAYLOAD_SIZE_OFFSET+4] = (1).to_bytes(4,"little")
    out1 = f.feed(bytes(header))
    assert out1 == []
    out2 = f.feed(b"\x99")
    assert len(out2) == 1
    assert out2[0] == bytes(header) + b"\x99"

def test_payload_size_above_limit_raises_and_clears_buffer():
    f = framing.Framer(max_payload_size=5)
    header = bytearray(b"\x11" * framing.HEADER_LEN)
    header[framing.PAYLOAD_SIZE_OFFSET:framing.PAYLOAD_SIZE_OFFSET + 4] = (6).to_bytes(4, "little")
    with pytest.raises(ValueError):
        f.feed(bytes(header))
    ok = build_frame(b"12345")
    assert f.feed(ok) == [ok]


