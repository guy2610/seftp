import pytest
import src.store as store
import src.answers as answers
import asyncio

class FakeLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def exception(self, *a, **k): pass

class FakeSession:
    def __init__(self, store):
        self.store = store
        self.log = FakeLogger()
        self.sent = []
        self.disconnect_reason = None

    async def send(self, data: bytes) -> None:
        self.sent.append(data)
def test_message_answer_builds_correct_frame():
    version = b"\x03"
    code = "826"
    payload = b"\x10" * 10
    payload_size = str(len(payload))
    fake = FakeSession(store.Store())

    msg = answers.message_answer(version, code, payload_size, payload, fake)
    assert len(msg) == 1 + 2 + 4 + 10
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == int(code)
    assert int.from_bytes(msg[3:7], "little") == len(payload)
    assert msg[7:] == payload
def test_message_answer_payload_size_mismatch():
    version = b"\x03"
    code = "826"
    payload = b"\x10" * 5
    payload_size = "10"
    fake = FakeSession(store.Store())
    with pytest.raises(ValueError):
        answers.message_answer(version, code, payload_size, payload, fake)
def test_message_answer_invalid_version_length():
    version = b"\x03\x04"
    code = "826"
    payload = b"\x10"
    payload_size = "1"
    fake = FakeSession(store.Store())
    with pytest.raises(ValueError):
        answers.message_answer(version, code, payload_size, payload, fake)

@pytest.mark.asyncio
async def test_answer_1600_correct_frame():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04"*16

    await answers.answer_1600(client_id,version,fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert len(msg) == 1+2+4+16
    assert msg[0:1] == version

    code = int.from_bytes(msg[1:3], "little")
    assert code == 1600

    payload_size = int.from_bytes(msg[3:7], "little")
    assert payload_size == 16
    assert msg[7:] == client_id
    assert client_id in fake.store.clients_recent_log

    last_entry = fake.store.clients_recent_log[client_id][-1]
    assert last_entry[0] == "answer_1600"

@pytest.mark.asyncio
async def test_answer_1601_correct_frame():
    fake = FakeSession(store.Store())
    version = b"\x03"

    await answers.answer_1601(version, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert len(msg) == 1 + 2 + 4
    assert msg[0:1] == version

    code = int.from_bytes(msg[1:3], "little")
    assert code == 1601

    payload_size = int.from_bytes(msg[3:7], "little")
    assert payload_size == 0
    assert msg[7:] == b""

@pytest.mark.asyncio
async def test_answer_1602_correct_frame():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    cipher = b"\xA1" * 30
    fake.store.clients_info["Alice"]=[client_id,b"\x99","last_seen","aes_b64"]
    before = fake.store.clients_info["Alice"][2]

    await answers.answer_1602(cipher,client_id,version,fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert len(msg) == 1+2+4+16+30
    assert msg[0:1] == version

    code = int.from_bytes(msg[1:3], "little")
    assert code == 1602

    payload_size = int.from_bytes(msg[3:7], "little")
    assert payload_size == len(cipher) + len(client_id)

    payload = msg[7:]
    assert payload[:len(cipher)] == cipher
    assert payload[len(cipher):] == client_id
    assert client_id in fake.store.clients_recent_log

    after = fake.store.clients_info["Alice"][2]
    assert after != before

    last_entry = fake.store.clients_recent_log[client_id][-1]
    assert last_entry[0] == "answer_1602"

@pytest.mark.asyncio
async def test_answer_1606_zero_client_id_logs_by_name_and_sends_frame():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x00" * 16
    name = "Alice"

    await answers.answer_1606(client_id, version, name, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1606
    assert int.from_bytes(msg[3:7], "little") == 16
    assert msg[7:] == client_id

    last = fake.store.clients_recent_log[name][-1]
    assert last[0] == "answer_1606"

@pytest.mark.asyncio
async def test_answer_1606_nonzero_client_id_updates_last_seen_and_logs_by_client_id():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    name = "Alice"
    fake.store.clients_info[name] = [client_id, b"\x99", "last_seen", "aes"]
    before = fake.store.clients_info[name][2]

    await answers.answer_1606(client_id, version, name, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1606
    assert int.from_bytes(msg[3:7], "little") == 16
    assert msg[7:] == client_id

    last = fake.store.clients_recent_log[client_id][-1]
    assert last[0] == "answer_1606"

    after = fake.store.clients_info[name][2]
    assert after != before

@pytest.mark.asyncio
async def test_answer_1605_correct_frame_and_side_effects():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    cipher = b"\xA1" * 30
    fake.store.clients_info["Alice"] = [client_id, b"\x99", "last_seen", "aes"]
    before = fake.store.clients_info["Alice"][2]

    await answers.answer_1605(cipher, client_id, version, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1605

    payload_size = int.from_bytes(msg[3:7], "little")
    assert payload_size == len(cipher) + len(client_id)

    payload = msg[7:]
    assert payload[:len(cipher)] == cipher
    assert payload[len(cipher):] == client_id
    assert fake.store.clients_info["Alice"][2] != before
    assert fake.store.clients_recent_log[client_id][-1][0] == "answer_1605"

@pytest.mark.asyncio
async def test_answer_1603_builds_payload_with_null_terminated_filename_and_crc():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    fake.store.clients_info["Alice"] = [client_id, b"\x99", "last_seen", "aes"]
    file_name = "a.txt"
    content_size = 123
    crc32_val = 0xAABBCCDD
    before = fake.store.clients_info["Alice"][2]

    await answers.answer_1603(client_id, version, file_name, content_size, crc32_val, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1603

    payload_size = int.from_bytes(msg[3:7], "little")
    payload = msg[7:]
    assert payload_size == len(payload)
    assert payload[:16] == client_id
    assert int.from_bytes(payload[16:20], "little") == content_size

    name_bytes = file_name.encode("utf-8") + b"\x00"
    assert payload[20:20 + len(name_bytes)] == name_bytes

    crc_off = 20 + len(name_bytes)
    assert int.from_bytes(payload[crc_off:crc_off + 4], "little") == crc32_val
    assert fake.store.clients_info["Alice"][2] != before
    assert fake.store.clients_recent_log[client_id][-1][0] == "answer_1603"

@pytest.mark.asyncio
async def test_answer_1604_correct_frame_and_side_effects():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    fake.store.clients_info["Alice"] = [client_id, b"\x99", "last_seen", "aes"]
    before = fake.store.clients_info["Alice"][2]

    await answers.answer_1604(client_id, version, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1604
    assert int.from_bytes(msg[3:7], "little") == 16
    assert msg[7:] == client_id
    assert fake.store.clients_info["Alice"][2] != before
    assert fake.store.clients_recent_log[client_id][-1][0] == "answer_1604"

@pytest.mark.asyncio
async def test_answer_1607_payload_is_client_id_plus_utf8_text_and_logs():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    text = "bad request"

    await answers.answer_1607(client_id, version, text, fake)
    assert len(fake.sent) == 1

    msg = fake.sent[0]
    assert msg[0:1] == version
    assert int.from_bytes(msg[1:3], "little") == 1607

    payload = msg[7:]
    assert payload[:16] == client_id
    assert payload[16:] == text.encode("utf-8")
    assert fake.store.clients_recent_log[client_id][-1][0] == "answer_1607"

@pytest.mark.asyncio
async def test_answer_1607_updates_last_seen_when_client_known_and_public_key_is_str():
    fake = FakeSession(store.Store())
    version = b"\x03"
    client_id = b"\x04" * 16
    text = "oops"
    fake.store.clients_info["Alice"] = [client_id, "public_key_str", "last_seen", "aes"]
    before = fake.store.clients_info["Alice"][2]
    
    await answers.answer_1607(client_id, version, text, fake)
    assert fake.store.clients_info["Alice"][2] != before
    assert fake.store.clients_recent_log[client_id][-1][0] == "answer_1607"