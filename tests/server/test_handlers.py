import pytest
import server.src.handlers as handlers
import server.src.config as config
import asyncio
from typing import Optional
from collections import defaultdict
from Crypto.PublicKey import RSA
import base64
from base64 import b64decode

class FakeLogger:
    def __init__(self):
        self.request_id = "-"
        self.info_calls = []
        self.warning_calls = []
        self.error_calls = []
        self.debug_calls = []

    def info(self, *args, **kwargs):
        self.info_calls.append((args, kwargs))

    def warning(self, *args, **kwargs):
        self.warning_calls.append((args, kwargs))

    def error(self, *args, **kwargs):
        self.error_calls.append((args, kwargs))

    def debug(self, *args, **kwargs):
        self.debug_calls.append((args, kwargs))

    def isEnabledFor(self, level):
        return True

class FakeStore:
    def __init__(self):
        self.clients_info={}
        self.clients_recent_log=defaultdict(list)

    def name_of_dict_from_id(self,client_id):
        for k, vals in self.clients_info.items():
            if vals[0] == client_id:
                return k
        return None
class FakeSession:
    def __init__(self,config):
        self.request_id = None
        self.log = FakeLogger()
        self.store = FakeStore()
        self.config = config
        self.upload_active = False
        self.transfer_iv = None
        self.expected_packet_num = None
        self.expected_total_packets = None
        self.expected_content_size = None
        self.expected_orig_file_size = None
        self.received_cipher_bytes = 0
        self.transfer_cipher = bytearray()
        self.upload_filename = None
        self.reset_calls=[]


    def on_frame_ok(self):
        self.on_frame_ok_calls += 1

    def on_frame_bad(self, reason: str):
        self.on_frame_bad_calls.append(reason)

    def reset_transfer_state(self, reason: str):
        self.reset_calls.append(reason)

@pytest.mark.asyncio
async def test_825_registration_succeed(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload = b'alice\0'
    version = b'\03'
    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append("1600")
    async def fake_1601(version, session):
        fake_session.reset_calls.append("1601")

    monkeypatch.setattr("server.src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("server.src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload,version,fake_session)
    name = payload[:-1].decode('utf-8')
    assert name in fake_session.store.clients_info
    client_id = fake_session.store.clients_info[name][0]
    assert len(client_id) == 16
    public_key = fake_session.store.clients_info[name][1]
    assert public_key == "public_key_none_for_now"
    aes_key = fake_session.store.clients_info[name][3]
    assert aes_key == "aes_key_none_for_now"
    assert "request_825" in fake_session.store.clients_recent_log[client_id][0]
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls [-1] == "1600"
    assert fake_session.reset_calls [-1] != "1601"

@pytest.mark.asyncio
async def test_825_name_exist_eror(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload = b'alice\0'
    version = b'\03'
    name = payload[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [b'\01'*16, "public_key_none_for_now","last_seen", "aes_key_none_for_now"]
    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append("1600")
    async def fake_1601(version, session):
        fake_session.reset_calls.append("1601")

    monkeypatch.setattr("server.src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("server.src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload,version,fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls [-1] != "1600"
    assert fake_session.reset_calls [-1] == "1601"

@pytest.mark.asyncio
async def test_825_registration_name_need_strip(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload = b'alice\x00\x00'
    version = b'\03'

    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append("1600")
    async def fake_1601(version, session):
        fake_session.reset_calls.append("1601")

    monkeypatch.setattr("server.src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("server.src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload, version, fake_session)
    name = payload[:-2].decode('utf-8')
    assert name in fake_session.store.clients_info
    client_id = fake_session.store.clients_info[name][0]
    assert len(client_id) == 16
    public_key = fake_session.store.clients_info[name][1]
    assert public_key == "public_key_none_for_now"
    aes_key = fake_session.store.clients_info[name][3]
    assert aes_key == "aes_key_none_for_now"
    assert "request_825" in fake_session.store.clients_recent_log[client_id][0]
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1] == "1600"
    assert fake_session.reset_calls[-1] != "1601"

@pytest.mark.asyncio
async def test_826_public_key_correct(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = payload_name + public_b64 +b'\00'
    version = b'\03'
    client_id = b'\01'*16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append("1607")

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id,payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1] == "1602"

    assert name in fake_session.store.clients_info
    assert fake_session.store.clients_info[name][0] == client_id
    assert fake_session.store.clients_info[name][1] == public_der
    aes_b64 = fake_session.store.clients_info[name][3]
    assert aes_b64 != "aes_key_none_for_now"
    assert len(base64.b64decode(aes_b64)) == 32
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_no_null_after_name(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = payload_name[:-1] + public_b64
    version = b'\03'
    client_id = b'\01'*16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id,payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "bad 826 payload: missing NUL after name"

    assert name in fake_session.store.clients_info
    assert fake_session.store.clients_info[name][0] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_name_not_utf8(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = payload_name[:-1] + b"\xff\x00" + public_b64 +b'\00'
    version = b'\03'
    client_id = b'\01'*16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id,payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "bad 826 payload: name is not valid UTF-8"

    assert name in fake_session.store.clients_info
    assert fake_session.store.clients_info[name][0] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_name_mismatch(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    fake_name = b'bob\x00'
    payload = fake_name + public_b64 +b'\00'
    version = b'\03'
    client_id = b'\01'*16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id,payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == f"name mismatch: got {fake_name[:-1].decode('utf-8')!r}, expected {name!r}"

    assert name in fake_session.store.clients_info
    assert fake_session.store.clients_info[name][0] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_not_ascii_base64(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen", "aes_key_none_for_now"]
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    bad_public_blob = b"AAAA" + b"\xff" + b"BBBB"
    payload = b"alice\x00" + bad_public_blob + b"\x00"

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(cid, ver, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "Public key is not ASCII base64"
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_invalid_base64(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen", "aes_key_none_for_now"]
    bad_b64 = b"@@@NOT_BASE64@@@"
    payload = b"alice\x00" + bad_b64 + b"\x00"

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append("1606")
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "Invalid RSA public key"
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_private_key_rejected(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen", "aes_key_none_for_now"]
    key = RSA.generate(2048)
    private_der = key.export_key(format="DER")
    private_b64 = base64.b64encode(private_der)
    payload = b"alice\x00" + private_b64 + b"\x00"

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_wrong_size(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen", "aes_key_none_for_now"]
    key = RSA.generate(1024)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = b"alice\x00" + public_b64 + b"\x00"

    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_826_public_key_bad_exponent(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen", "aes_key_none_for_now"]
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = b"alice\x00" + public_b64 + b"\x00"

    class FakeRsaKey:
        def has_private(self): return False
        def size_in_bits(self): return 2048
        @property
        def e(self): return 2
        def export_key(self):
            return b"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----"

    def fake_import_key(_der):
        return FakeRsaKey()
    async def fake_1602(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append("1602")
    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1607(client_id,version,text,session):
        fake_session.reset_calls.append(("1607",text))

    monkeypatch.setattr(handlers, "RSA", handlers.RSA)
    monkeypatch.setattr(handlers.RSA, "import_key", fake_import_key)
    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.store.clients_info[name][1] == "public_key_none_for_now"
    assert fake_session.store.clients_info[name][3] == "aes_key_none_for_now"
    assert "request_826" in fake_session.store.clients_recent_log[client_id][0]
