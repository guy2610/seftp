import pytest
import src.handlers as handlers
import src.config as config
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

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

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

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

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

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

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

@pytest.mark.asyncio
async def test_826_client_id_not_found_returns_without_answers(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    key = RSA.generate(2048)
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
    assert fake_session.reset_calls == []

@pytest.mark.asyncio
async def test_827_relogin_user_doesnt_exists(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    client_id = b"\x01" * 16
    version = b"\x03"
    payload = b"alice\x00"
    name="alice"

    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1605(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append(("1605",cipher_text_aes_encrypted,client_id,version,session))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == b"\x00" * 16
    assert "request_827" in fake_session.store.clients_recent_log[name][0]

@pytest.mark.asyncio
async def test_827_relogin_user_exists_public_key_valid(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    version = b'\03'
    client_id = b'\01' * 16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, public_der, "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1605(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append(("1605",cipher_text_aes_encrypted,client_id,version,session))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload_name, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1605"
    assert fake_session.reset_calls[-1][2] == client_id
    assert fake_session.store.clients_info[name][3] !=  "aes_key_none_for_now"
    assert "request_827" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_827_relogin_user_exists_public_key_not_valid(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    payload_name = b'alice\x00'
    key = RSA.generate(1024)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    version = b'\03'
    client_id = b'\01' * 16
    name = payload_name[:-1].decode('utf-8')
    fake_session.store.clients_info[name] = [client_id, public_der, "last_seen",
                                             "aes_key_none_for_now"]

    async def fake_1606(client_id,version,name,session):
        fake_session.reset_calls.append(("1606",client_id,name))
    async def fake_1605(cipher_text_aes_encrypted,client_id,version,session):
        fake_session.reset_calls.append(("1605",cipher_text_aes_encrypted,client_id,version,session))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload_name, version, fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.reset_calls[-1][2] == name
    assert fake_session.store.clients_info[name][3] ==  "aes_key_none_for_now"
    assert "request_827" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_900_crc_ok(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    version = b'\03'
    client_id = b'\01' * 16
    name = "alice"
    payload = b'file_name\x00\x00'
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]
    async def fake_1604(client_id,version,session):
        fake_session.reset_calls.append(("1604",client_id))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)

    await handlers.request_900(payload,version,client_id,fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1604"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.store.clients_info[name][2] != "last_seen"
    assert "request_900" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_901_crc_retry():
    fake_session = FakeSession(config.Config.load())
    version = b'\03'
    client_id = b'\01' * 16
    name = "alice"
    payload = b'file_name\x00\x00'
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]

    await handlers.request_901(payload,version,client_id,fake_session)
    assert fake_session.store.clients_info[name][2] != "last_seen"
    assert "request_901" in fake_session.store.clients_recent_log[client_id][0]

@pytest.mark.asyncio
async def test_902_crc_failed_after_max_retries(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    version = b'\03'
    client_id = b'\01' * 16
    name = "alice"
    payload = b'file_name\x00\x00'
    fake_session.store.clients_info[name] = [client_id, "public_key_none_for_now", "last_seen",
                                             "aes_key_none_for_now"]
    async def fake_1604(client_id,version,session):
        fake_session.reset_calls.append(("1604",client_id))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)

    await handlers.request_902(payload,version,client_id,fake_session)
    assert len(fake_session.reset_calls) == 1
    assert fake_session.reset_calls[-1][0] == "1604"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.store.clients_info[name][2] != "last_seen"
    assert "request_902" in fake_session.store.clients_recent_log[client_id][0]

# Helpers for 828 tests
def _le_u32(n: int) -> bytes:
    return int(n).to_bytes(4, "little", signed=False)

def _le_u16(n: int) -> bytes:
    return int(n).to_bytes(2, "little", signed=False)

def make_828_payload(content_size: int,orig_file_size: int,packet_num: int,total_packets: int,filename_bytes: bytes,cipher_chunk: bytes,add_null_after_filename: bool = True) -> bytes:
    hdr = _le_u32(content_size) + _le_u32(orig_file_size) + _le_u16(packet_num) + _le_u16(total_packets)
    if add_null_after_filename:
        return hdr + filename_bytes + b"\x00" + cipher_chunk
    else:
        return hdr + filename_bytes + cipher_chunk

def setup_client(fake_session, name: str = "alice", client_id: bytes = b"\x01" * 16) -> bytes:
    aes_raw = b"\x11" * 32
    aes_b64 = base64.b64encode(aes_raw).decode("ascii")
    fake_session.store.clients_info[name] = [client_id,b"public_der_dummy","last_seen",aes_b64]
    fake_session.mark_upload_progress = lambda: None
    return aes_raw

def patch_828_side_effects(monkeypatch, fake_session):
    calls = []

    async def fake_1603(client_id, version, file_name, content_size, crc32_val, session):
        calls.append(("1603", client_id, version, file_name, content_size, crc32_val))

    async def fake_1607(client_id, version, text, session):
        calls.append(("1607", client_id, version, text))

    monkeypatch.setattr(handlers, "_draw_progress", lambda *args, **kwargs: None)

    def fake_finalize_upload(file_path, cipher_bytes, iv, expected_size, aes_key):
        return (0x12345678, expected_size)

    async def fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(handlers.answers, "answer_1603", fake_1603)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)
    monkeypatch.setattr(handlers, "finalize_upload", fake_finalize_upload)
    monkeypatch.setattr(handlers.asyncio, "to_thread", fake_to_thread)
    return calls

@pytest.mark.asyncio
async def test_828_packet0_initializes_state(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(content_size=10,orig_file_size=5,packet_num=0,total_packets=2,filename_bytes=filename,cipher_chunk=iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert calls == []
    assert fake_session.transfer_iv == iv
    assert fake_session.expected_packet_num == 1
    assert fake_session.expected_total_packets == 2
    assert fake_session.expected_content_size == 10
    assert fake_session.expected_orig_file_size == 5
    assert fake_session.received_cipher_bytes == 0

@pytest.mark.asyncio
async def test_828_packet0_when_upload_active_or_iv_set(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.upload_active = True
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(10, 5, 0, 2, filename, iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828 payload: currently uploading with new upload"
    assert fake_session.reset_calls[-1] == "bad_828_iv"

@pytest.mark.asyncio
async def test_828_packet0_iv_too_short(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv_short = b"\xAA" * 15
    payload0 = make_828_payload(10, 5, 0, 2, filename, iv_short)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828 payload: name is not valid UTF-8"
    assert fake_session.reset_calls[-1] == "bad_828_iv"

@pytest.mark.asyncio
async def test_828_packet1_without_iv(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload1 = make_828_payload(10, 5, 1, 2, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: missing IV packet"
    assert fake_session.reset_calls[-1] == "bad_828_iv"

@pytest.mark.asyncio
async def test_828_expected_packet_num_none(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = None
    fake_session.expected_total_packets = 2
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload1 = make_828_payload(10, 5, 1, 2, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: expected packet num is not initialize"
    assert fake_session.reset_calls[-1] == "bad_828_expected_packet_num"

@pytest.mark.asyncio
async def test_828_total_packets_mismatch(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = 1
    fake_session.expected_total_packets = 2
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload1 = make_828_payload(10, 5, 1, 3, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828:total_packets != expected_total_packets"
    assert fake_session.reset_calls[-1] == "bad_828_expected_total_packet"

@pytest.mark.asyncio
async def test_828_sizes_mismatch(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = 1
    fake_session.expected_total_packets = 2
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload1 = make_828_payload(11, 5, 1, 2, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: content_size or orig_file_size not as expected"
    assert fake_session.reset_calls[-1] == "bad_828 content_size or orig_file_size"

@pytest.mark.asyncio
async def test_828_filename_missing_null(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload = make_828_payload(content_size=10,orig_file_size=5,packet_num=0,total_packets=2,filename_bytes=filename,cipher_chunk=chunk,add_null_after_filename=False)

    await handlers.request_828(payload, version, client_id, fake_session)
    assert calls == []
    assert fake_session.reset_calls[-1] == "bad_828_filename_missing_null"

@pytest.mark.asyncio
async def test_828_filename_not_utf8(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    bad_filename = b"\xff\xff"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(10, 5, 0, 2, bad_filename, iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828 payload: name is not valid UTF-8"
    assert fake_session.reset_calls[-1] == "bad_828_filename_utf8"

@pytest.mark.asyncio
async def test_828_unknown_client_id(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(10, 5, 0, 2, filename, iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert calls == []
    assert fake_session.reset_calls[-1] == "bad_828_client_or_name"

@pytest.mark.asyncio
async def test_828_validate_header_total_packets_zero(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(content_size=10,orig_file_size=5,packet_num=0,total_packets=0,filename_bytes=filename,cipher_chunk=iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: total_packets not valid"
    assert fake_session.reset_calls[-1] == "bad_828_range"

@pytest.mark.asyncio
async def test_828_chunk_too_large(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = 1
    fake_session.expected_total_packets = 2
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    version = b"\x03"
    filename = b"file.bin"
    big_chunk = b"\xBB" * (fake_session.config.max_chunk_size + 1)
    payload1 = make_828_payload(10, 5, 1, 2, filename, big_chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: cipher_chunk bigger than the max"
    assert fake_session.reset_calls[-1] == "bad_828 cipher_chunk bigger than the max"

@pytest.mark.asyncio
async def test_828_content_size_overflow(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = 1
    fake_session.expected_total_packets = 2
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    fake_session.received_cipher_bytes = 9
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 2
    payload1 = make_828_payload(10, 5, 1, 2, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: content_size will overflow"
    assert fake_session.reset_calls[-1] == "bad_828 content_size will overflow"

@pytest.mark.asyncio
async def test_828_out_of_order_packet(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.transfer_iv = b"\xAA" * 16
    fake_session.expected_packet_num = 2
    fake_session.expected_total_packets = 3
    fake_session.expected_content_size = 10
    fake_session.expected_orig_file_size = 5
    fake_session.received_cipher_bytes = 0
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 2
    payload3 = make_828_payload(10, 5, 3, 3, filename, chunk)

    await handlers.request_828(payload3, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: out of order"
    assert fake_session.reset_calls[-1] == "bad_828_out_of_order"

@pytest.mark.asyncio
async def test_828_full_upload_success(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    chunk1 = b"\xBB" * 4
    chunk2 = b"\xCC" * 6
    content_size = len(chunk1) + len(chunk2)
    orig_size = 5
    total_packets = 2
    payload0 = make_828_payload(content_size, orig_size, 0, total_packets, filename, iv)
    payload1 = make_828_payload(content_size, orig_size, 1, total_packets, filename, chunk1)
    payload2 = make_828_payload(content_size, orig_size, 2, total_packets, filename, chunk2)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)
    await handlers.request_828(payload2, version, client_id, fake_session)

    sent = [c for c in calls if c[0] == "1603"]
    assert len(sent) == 1
    assert sent[0][1] == client_id
    assert sent[0][2] == version
    assert sent[0][3] == "file.bin"
    assert sent[0][4] == content_size
    assert sent[0][5] == 0x12345678
    assert fake_session.reset_calls[-1] == "upload_complete"
    assert fake_session.store.clients_recent_log[client_id][0][0] == "request_828"

@pytest.mark.asyncio
async def test_828_last_packet_received_size_mismatch(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    declared_content_size = 10
    orig_size = 5
    total_packets = 1
    payload0 = make_828_payload(declared_content_size, orig_size, 0, total_packets, filename, iv)
    payload1 = make_828_payload(declared_content_size, orig_size, 1, total_packets, filename, b"\xBB" * 6)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)

    err = [c for c in calls if c[0] == "1607"]
    assert len(err) == 1
    assert err[0][3] == "bad 828: received_cipher_bytes != expected_content_size"
    assert fake_session.reset_calls[-1] == "bad_828 received_cipher_bytes  != expected_content_size"

@pytest.mark.asyncio
async def test_828_validate_header_packet_num_out_of_range(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(content_size=10,orig_file_size=5,packet_num=3,total_packets=2,filename_bytes=filename,cipher_chunk=iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert calls[0][3] == "bad 828: packet_num out of range"
    assert fake_session.reset_calls[-1] == "bad_828_range"

@pytest.mark.asyncio
async def test_828_validate_header_limits_total_packets_too_large(monkeypatch):
    fake_session = FakeSession(config.Config.load())
    calls = patch_828_side_effects(monkeypatch, fake_session)
    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    too_many = fake_session.config.max_packets + 1
    payload0 = make_828_payload(content_size=10,orig_file_size=5,packet_num=0,total_packets=too_many,filename_bytes=filename,cipher_chunk=iv)

    await handlers.request_828(payload0, version, client_id, fake_session)
    assert fake_session.reset_calls[-1] == "bad_828_limits"
    sent_1607 = [c for c in calls if c[0] == "1607"]
    assert len(sent_1607) == 1
    assert sent_1607[0][1] == client_id
    assert sent_1607[0][2] == version