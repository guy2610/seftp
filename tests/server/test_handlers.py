import pytest
import src.handlers as handlers
import src.config as config
import asyncio
from typing import Optional
from collections import defaultdict
from Crypto.PublicKey import RSA
import base64
from base64 import b64decode
import src.store as store

def make_sql_store(tmp_path):
    s = store.Store()
    db_path = tmp_path / "test.db"
    ok = s.initialize(str(db_path))
    assert ok
    return s


def seed_client(
    s,
    username="alice",
    client_id_hex=None,
    public_key_der=None,
    aes_key_b64="aes_b64",
):
    created_client_id_hex = s.create_client(username)

    if client_id_hex is not None and created_client_id_hex != client_id_hex:
        cur = s.sqliteConnection.cursor()
        cur.execute(
            "UPDATE Clients SET client_id_hex = ? WHERE username = ?",
            (client_id_hex, username),
        )
        s.sqliteConnection.commit()
        created_client_id_hex = client_id_hex

    if public_key_der is not None:
        assert s.set_client_public_key(created_client_id_hex, public_key_der)

    if aes_key_b64 is not None:
        assert s.set_client_aes_key(created_client_id_hex, aes_key_b64)

    return created_client_id_hex


class DummyUploadLimiter:
    async def try_acquire(self):
        return True

    async def release(self):
        return None

    async def current_active(self):
        return 0


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

    def exception(self, *args, **kwargs):
        self.error_calls.append((args, kwargs))

    def isEnabledFor(self, level):
        return True


class FakeBoundedExecutor:
    async def run(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    def shutdown(self):
        pass


class FakeSession:
    def __init__(self, cfg, store_obj):
        self.request_id = None
        self.log = FakeLogger()
        self.store = store_obj
        self.config = cfg

        self.upload_active = False
        self.transfer_iv = None
        self.expected_packet_num = None
        self.expected_total_packets = None
        self.expected_content_size = None
        self.expected_orig_file_size = None
        self.received_cipher_bytes = 0
        self.transfer_cipher = bytearray()

        self.upload_filename = None
        self.upload_id = None
        self.upload_path = None
        self.upload_crc = None

        self.upload_client_id_hex = None
        self.upload_username = None
        self.upload_aes_key = None

        self.reset_calls = []
        self.has_upload_slot = False
        self.upload_limiter = DummyUploadLimiter()
        self.bounded_executor = FakeBoundedExecutor()

        self.on_frame_ok_calls = 0
        self.on_frame_bad_calls = []

    def mark_upload_progress(self):
        pass

    def on_frame_ok(self):
        self.on_frame_ok_calls += 1

    def on_frame_bad(self, reason: str):
        self.on_frame_bad_calls.append(reason)

    def reset_transfer_state(self, reason: str):
        self.reset_calls.append(reason)
        self.upload_active = False
        self.transfer_iv = None
        self.expected_packet_num = None
        self.expected_total_packets = None
        self.expected_content_size = None
        self.expected_orig_file_size = None
        self.received_cipher_bytes = 0
        self.transfer_cipher = bytearray()

        self.upload_filename = None
        self.upload_id = None
        self.upload_path = None
        self.upload_crc = None

        self.upload_client_id_hex = None
        self.upload_username = None
        self.upload_aes_key = None

    async def release_upload_slot(self):
        if self.has_upload_slot:
            await self.upload_limiter.release()
            self.has_upload_slot = False


def _le_u32(n: int) -> bytes:
    return int(n).to_bytes(4, "little", signed=False)


def _le_u16(n: int) -> bytes:
    return int(n).to_bytes(2, "little", signed=False)


def make_828_payload(
    content_size: int,
    orig_file_size: int,
    packet_num: int,
    total_packets: int,
    filename_bytes: bytes,
    cipher_chunk: bytes,
    add_null_after_filename: bool = True,
) -> bytes:
    hdr = (
        _le_u32(content_size)
        + _le_u32(orig_file_size)
        + _le_u16(packet_num)
        + _le_u16(total_packets)
    )
    if add_null_after_filename:
        return hdr + filename_bytes + b"\x00" + cipher_chunk
    return hdr + filename_bytes + cipher_chunk


def setup_client(fake_session, name: str = "alice", client_id: bytes = b"\x01" * 16) -> bytes:
    aes_raw = b"\x11" * 32
    aes_b64 = base64.b64encode(aes_raw).decode("ascii")
    seed_client(
        fake_session.store,
        username=name,
        client_id_hex=client_id.hex(),
        public_key_der=b"public_der_dummy",
        aes_key_b64=aes_b64,
    )
    fake_session.mark_upload_progress = lambda: None
    return aes_raw


def patch_828_side_effects(monkeypatch):
    calls = []

    async def fake_1603(client_id, version, file_name, content_size, crc32_val, session):
        calls.append(("1603", client_id, version, file_name, content_size, crc32_val))

    async def fake_1607(client_id, version, text, session):
        calls.append(("1607", client_id, version, text))

    monkeypatch.setattr(handlers, "_draw_progress", lambda *args, **kwargs: None)

    def fake_finalize_upload(file_path, cipher_bytes, iv, expected_size, aes_key):
        return (0x12345678, expected_size)

    monkeypatch.setattr(handlers.answers, "answer_1603", fake_1603)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)
    monkeypatch.setattr(handlers, "finalize_upload", fake_finalize_upload)
    return calls


@pytest.mark.asyncio
async def test_825_registration_succeed(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    payload = b"alice\x00"
    version = b"\x03"

    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append("1600")

    async def fake_1601(version, session):
        fake_session.reset_calls.append("1601")

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload, version, fake_session)

    row = s.get_client_by_username("alice")
    assert row is not None
    client_id = bytes.fromhex(row[0])
    assert row[1] == "alice"
    assert row[2] is None
    assert row[3] is None
    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_825"
    assert fake_session.reset_calls[-1] == "1600"

@pytest.mark.asyncio
async def test_825_registration_name_need_strip(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    payload = b"  alice  \x00"
    version = b"\x03"

    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append(("1600", client_id))

    async def fake_1601(version, session):
        fake_session.reset_calls.append(("1601",))

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload, version, fake_session)

    row = s.get_client_by_username("alice")
    assert row is not None
    assert row[1] == "alice"
    assert fake_session.reset_calls[-1][0] == "1600"

@pytest.mark.asyncio
async def test_825_name_exist_error(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    seed_client(s, username="alice", client_id_hex=("01" * 16), public_key_der=None, aes_key_b64=None)
    fake_session = FakeSession(config.Config.load(), s)
    payload = b"alice\x00"
    version = b"\x03"

    async def fake_1600(client_id, version, session):
        fake_session.reset_calls.append("1600")

    async def fake_1601(version, session):
        fake_session.reset_calls.append("1601")

    monkeypatch.setattr("src.router.answers.answer_1600", fake_1600)
    monkeypatch.setattr("src.router.answers.answer_1601", fake_1601)

    await handlers.request_825(payload, version, fake_session)

    assert fake_session.reset_calls[-1] == "1601"


@pytest.mark.asyncio
async def test_826_public_key_correct(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    payload_name = b"alice\x00"
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = payload_name + public_b64 + b"\x00"
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append("1602")

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append("1606")

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == "1602"

    row = s.get_client_by_username(name)
    assert row[0] == client_id.hex()
    assert row[2] == public_der
    assert row[3] is not None
    assert len(base64.b64decode(row[3])) == 32
    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_826"


@pytest.mark.asyncio
async def test_826_public_key_no_null_after_name(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    payload_name = b"alice\x00"
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = payload_name[:-1] + public_b64
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append("1602")

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append("1606")

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "bad 826 payload: missing NUL after name"

    row = s.get_client_by_username(name)
    assert row[2] is None
    assert row[3] is None
    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_826"

@pytest.mark.asyncio
async def test_826_client_id_not_found_returns_error(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)

    client_id = b"\x01" * 16
    version = b"\x03"
    payload = b"alice\x00" + public_b64 + b"\x00"

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1602",))

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606",))

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == ("1607", "unknown client id")

@pytest.mark.asyncio
async def test_826_public_key_invalid_base64(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    payload = b"alice\x00" + b"%%%not-base64%%%" + b"\x00"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1602",))

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606",))

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == ("1607", "bad 826 payload: key is not valid Base64")

    row = s.get_client_by_username(name)
    assert row[2] is None
    assert row[3] is None

@pytest.mark.asyncio
async def test_826_private_key_rejected(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    private_key = RSA.generate(2048)
    private_der = private_key.export_key(format="DER")
    private_b64 = base64.b64encode(private_der)

    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    payload = b"alice\x00" + private_b64 + b"\x00"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1602",))

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == ("1606", client_id, name)

    row = s.get_client_by_username(name)
    assert row[2] is None
    assert row[3] is None

@pytest.mark.asyncio
async def test_826_public_key_wrong_size(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    key = RSA.generate(1024)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)

    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    payload = b"alice\x00" + public_b64 + b"\x00"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1602",))

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == ("1606", client_id, name)

@pytest.mark.asyncio
async def test_826_public_key_bad_exponent(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    payload = b"alice\x00" + base64.b64encode(b"dummy-der") + b"\x00"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    class FakeRSAKey:
        e = 2

        def has_private(self):
            return False

        def size_in_bits(self):
            return 2048

        def export_key(self):
            return b"fake"

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1602",))

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.RSA, "import_key", lambda der: FakeRSAKey())
    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1] == ("1606", client_id, name)

@pytest.mark.asyncio
async def test_826_public_key_name_not_utf8(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = b"\xff\x00" + public_b64 + b"\x00"
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append("1602")

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append("1606")

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "bad 826 payload: name is not valid UTF-8"


@pytest.mark.asyncio
async def test_826_public_key_name_mismatch(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    public_b64 = base64.b64encode(public_der)
    payload = b"bob\x00" + public_b64 + b"\x00"
    version = b"\x03"
    client_id = b"\x01" * 16
    expected_name = "alice"

    seed_client(s, username=expected_name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append("1602")

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append("1606")

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "name mismatch: got 'bob', expected 'alice'"


@pytest.mark.asyncio
async def test_826_public_key_not_ascii_base64(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    client_id = b"\x01" * 16
    version = b"\x03"
    name = "alice"
    bad_public_blob = b"AAAA" + b"\xff" + b"BBBB"
    payload = b"alice\x00" + bad_public_blob + b"\x00"

    seed_client(s, username=name, client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    async def fake_1602(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append("1602")

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append("1606")

    async def fake_1607(client_id, version, text, session):
        fake_session.reset_calls.append(("1607", text))

    monkeypatch.setattr(handlers.answers, "answer_1602", fake_1602)
    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_826(client_id, payload, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1][1] == "bad 826 payload: public key is not ASCII base64"


@pytest.mark.asyncio
async def test_827_relogin_user_not_exist(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    payload_name = b"alice\x00"
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1605(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1605", cipher_text_aes_encrypted, client_id))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload_name, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == b"\x00" * 16
    assert fake_session.reset_calls[-1][2] == name


@pytest.mark.asyncio
async def test_827_relogin_user_exists_public_key_valid(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    payload_name = b"alice\x00"
    key = RSA.generate(2048)
    public_der = key.publickey().export_key(format="DER")
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    seed_client(
        s,
        username=name,
        client_id_hex=client_id.hex(),
        public_key_der=public_der,
        aes_key_b64=None,
    )

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1605(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1605", cipher_text_aes_encrypted, client_id, version))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload_name, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1605"
    assert fake_session.reset_calls[-1][2] == client_id

    row = s.get_client_by_username(name)
    assert row[3] is not None
    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_827"


@pytest.mark.asyncio
async def test_827_relogin_user_exists_public_key_not_valid(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    payload_name = b"alice\x00"
    key = RSA.generate(1024)
    public_der = key.publickey().export_key(format="DER")
    version = b"\x03"
    client_id = b"\x01" * 16
    name = "alice"

    seed_client(
        s,
        username=name,
        client_id_hex=client_id.hex(),
        public_key_der=public_der,
        aes_key_b64=None,
    )

    async def fake_1606(client_id, version, name, session):
        fake_session.reset_calls.append(("1606", client_id, name))

    async def fake_1605(cipher_text_aes_encrypted, client_id, version, session):
        fake_session.reset_calls.append(("1605", cipher_text_aes_encrypted, client_id))

    monkeypatch.setattr(handlers.answers, "answer_1606", fake_1606)
    monkeypatch.setattr(handlers.answers, "answer_1605", fake_1605)

    await handlers.request_827(client_id, payload_name, version, fake_session)

    assert fake_session.reset_calls[-1][0] == "1606"
    assert fake_session.reset_calls[-1][1] == client_id
    assert fake_session.reset_calls[-1][2] == name

    row = s.get_client_by_username(name)
    assert row[3] is None
    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_827"


@pytest.mark.asyncio
async def test_900_success_completes_upload_and_cleans_session(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"file.bin\x00\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1604(client_id_arg, version_arg, session_arg):
        calls.append(("1604", client_id_arg, version_arg, session_arg))

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, version_arg, text_arg, session_arg))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_900(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1604"
    assert calls[0][1] == client_id

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "upload_complete"
    assert fake_session.upload_id is None
    assert fake_session.upload_filename is None
    assert fake_session.upload_path is None
    assert fake_session.upload_crc is None

    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_900"

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]

    assert upload[7] == "completed"
    assert upload[3] == "data/uploads/alice/file.bin"
    assert upload[6] == 0x12345678
    assert upload[8] is None
    assert upload[10] is not None


@pytest.mark.asyncio
async def test_900_db_failure_returns_1607_and_cleans_session(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"file.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1604(client_id_arg, version_arg, session_arg):
        calls.append(("1604", client_id_arg))

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)
    monkeypatch.setattr(fake_session.store, "complete_upload_record", lambda *args, **kwargs: False)

    await handlers.request_900(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert "complete upload record problem in db" in calls[0][2]

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 900: complete_upload_record problem in db"
    assert fake_session.upload_id is None
    assert fake_session.upload_filename is None
    assert fake_session.upload_path is None
    assert fake_session.upload_crc is None

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload[7] == "in_progress"
    assert upload[3] is None
    assert upload[6] is None

@pytest.mark.asyncio
async def test_900_invalid_session_attributes_returns_1607(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"file.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    fake_session.upload_id = None
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1604(client_id_arg, version_arg, session_arg):
        calls.append(("1604", client_id_arg))

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_900(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert "session upload attributes are invalid" in calls[0][2]

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 900: session upload attributes are invalid"
    assert fake_session.upload_id is None
    assert fake_session.upload_filename is None
    assert fake_session.upload_path is None
    assert fake_session.upload_crc is None

@pytest.mark.asyncio
async def test_901_marks_crc_mismatch_and_resets(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"file.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_901(payload, version, client_id, fake_session)

    assert calls == []
    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 901: CRC mismatch"
    assert fake_session.upload_id is None
    assert fake_session.upload_filename is None
    assert fake_session.upload_path is None
    assert fake_session.upload_crc is None

    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_901"

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload[7] == "crc_mismatch"
    assert upload[8] == "CRC mismatch"
    assert upload[10] is not None


@pytest.mark.asyncio
async def test_901_filename_mismatch_returns_1607(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"other.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_901(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert "session upload name is invalid" in calls[0][2]

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 901: session upload name is invalid"

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload[7] == "in_progress"
    assert upload[8] is None


@pytest.mark.asyncio
async def test_902_marks_failed_and_sends_1604(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"file.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1604(client_id_arg, version_arg, session_arg):
        calls.append(("1604", client_id_arg))

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_902(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1604"
    assert calls[0][1] == client_id

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 902: invalid CRC on the 4th time"
    assert fake_session.upload_id is None
    assert fake_session.upload_filename is None
    assert fake_session.upload_path is None
    assert fake_session.upload_crc is None

    assert fake_session.store.clients_recent_log[client_id][-1][0] == "request_902"

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload[7] == "failed"
    assert upload[8] == "invalid CRC on the 4th time"
    assert upload[10] is not None


@pytest.mark.asyncio
async def test_902_filename_mismatch_returns_1607(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)

    version = b"\x03"
    client_id = b"\x01" * 16
    payload = b"other.bin\x00"

    seed_client(s, username="alice", client_id_hex=client_id.hex(), public_key_der=None, aes_key_b64=None)

    upload_id = s.create_upload_record(client_id.hex(), "file.bin", 5, 10)
    assert upload_id is not None

    fake_session.upload_id = upload_id
    fake_session.upload_filename = "file.bin"
    fake_session.upload_path = "data/uploads/alice/file.bin"
    fake_session.upload_crc = 0x12345678
    fake_session.has_upload_slot = True
    fake_session.upload_active = True

    calls = []

    async def fake_1604(client_id_arg, version_arg, session_arg):
        calls.append(("1604", client_id_arg))

    async def fake_1607(client_id_arg, version_arg, text_arg, session_arg):
        calls.append(("1607", client_id_arg, text_arg))

    monkeypatch.setattr(handlers.answers, "answer_1604", fake_1604)
    monkeypatch.setattr(handlers.answers, "answer_1607", fake_1607)

    await handlers.request_902(payload, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1607"
    assert "session upload name is invalid" in calls[0][2]

    assert fake_session.has_upload_slot is False
    assert fake_session.reset_calls[-1] == "bad 902: session upload name is invalid"

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload[7] == "in_progress"
    assert upload[8] is None

@pytest.mark.asyncio
async def test_828_packet0_initializes_state(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=filename,
        cipher_chunk=iv,
    )

    await handlers.request_828(payload0, version, client_id, fake_session)

    assert calls == []
    assert fake_session.transfer_iv == iv
    assert fake_session.expected_packet_num == 1
    assert fake_session.expected_total_packets == 2
    assert fake_session.expected_content_size == 10
    assert fake_session.expected_orig_file_size == 5
    assert fake_session.received_cipher_bytes == 0


@pytest.mark.asyncio
async def test_828_unknown_client_id(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    payload0 = make_828_payload(10, 5, 0, 2, filename, iv)

    await handlers.request_828(payload0, version, client_id, fake_session)

    assert calls == []
    assert fake_session.reset_calls[-1] == "bad_828_client_or_name"

@pytest.mark.asyncio
async def test_828_filename_missing_null(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
        add_null_after_filename=False,
    )

    await handlers.request_828(payload, version, client_id, fake_session)

    assert calls == []
    assert fake_session.reset_calls[-1] == "bad_828_filename_missing_null"

@pytest.mark.asyncio
async def test_828_filename_not_utf8(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=b"\xff\xfe",
        cipher_chunk=b"\xAA" * 16,
    )

    await handlers.request_828(payload, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828 payload: name is not valid UTF-8"
    assert fake_session.reset_calls[-1] == "bad_828_filename_utf8"

@pytest.mark.asyncio
async def test_828_validate_header_total_packets_zero(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=0,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )

    await handlers.request_828(payload, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert "total_packets" in calls[-1][3]

@pytest.mark.asyncio
async def test_828_chunk_too_large(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    cfg = config.Config.load()
    cfg.max_chunk_size = 4
    fake_session = FakeSession(cfg, s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(10, 5, 0, 2, b"file.bin", b"\xAA" * 16)
    payload1 = make_828_payload(10, 5, 1, 2, b"file.bin", b"\xBB" * 5)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: cipher_chunk bigger than the max"

@pytest.mark.asyncio
async def test_828_content_size_overflow(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(4, 5, 0, 2, b"file.bin", b"\xAA" * 16)
    payload1 = make_828_payload(4, 5, 1, 2, b"file.bin", b"\xBB" * 5)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: content_size will overflow"

@pytest.mark.asyncio
async def test_828_iv_too_short(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(10, 5, 0, 2, b"file.bin", b"\xAA" * 8)

    await handlers.request_828(payload0, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert fake_session.reset_calls[-1] == "bad_828_iv"


@pytest.mark.asyncio
async def test_828_packet0_when_upload_active_or_iv_set(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    fake_session.upload_active = True

    version = b"\x03"
    payload0 = make_828_payload(10, 5, 0, 2, b"file.bin", b"\xAA" * 16)

    await handlers.request_828(payload0, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828 payload: currently uploading with new upload"
    assert fake_session.reset_calls[-1] == "bad_828_iv"

@pytest.mark.asyncio
async def test_828_validate_header_packet_num_out_of_range(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=3,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )

    await handlers.request_828(payload, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert "packet_num" in calls[-1][3]

@pytest.mark.asyncio
async def test_828_validate_header_limits_total_packets_too_large(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    cfg = config.Config.load()
    cfg.max_packets = 2
    fake_session = FakeSession(cfg, s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=3,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )

    await handlers.request_828(payload, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert "total_packets" in calls[-1][3]

@pytest.mark.asyncio
async def test_828_packet1_without_iv(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    chunk = b"\xBB" * 4
    payload1 = make_828_payload(10, 5, 1, 2, filename, chunk)

    await handlers.request_828(payload1, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: missing IV packet"
    assert fake_session.reset_calls[-1] == "bad_828_iv"

@pytest.mark.asyncio
async def test_828_expected_packet_num_none(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )
    await handlers.request_828(payload0, version, client_id, fake_session)

    fake_session.expected_packet_num = None

    payload1 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=1,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xBB" * 4,
    )

    await handlers.request_828(payload1, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: expected packet num is not initialize"
    assert fake_session.reset_calls[-1] == "bad_828_expected_packet_num"

@pytest.mark.asyncio
async def test_828_total_packets_mismatch(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )
    await handlers.request_828(payload0, version, client_id, fake_session)

    payload1 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=1,
        total_packets=3,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xBB" * 4,
    )

    await handlers.request_828(payload1, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828:total_packets != expected_total_packets"
    assert fake_session.reset_calls[-1] == "bad_828_expected_total_packet"

@pytest.mark.asyncio
async def test_828_last_packet_received_size_mismatch(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"

    payload0 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=0,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xAA" * 16,
    )
    payload1 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=1,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xBB" * 4,
    )
    payload2 = make_828_payload(
        content_size=10,
        orig_file_size=5,
        packet_num=2,
        total_packets=2,
        filename_bytes=b"file.bin",
        cipher_chunk=b"\xCC" * 5,
    )

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)
    await handlers.request_828(payload2, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: received_cipher_bytes != expected_content_size"
    assert fake_session.reset_calls[-1] == "bad_828 received_cipher_bytes != expected_content_size"

@pytest.mark.asyncio
async def test_828_full_upload_success_keeps_upload_in_progress(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    chunk1 = b"\xBB" * 4
    chunk2 = b"\xCC" * 6

    payload0 = make_828_payload(10, 5, 0, 2, filename, iv)
    payload1 = make_828_payload(10, 5, 1, 2, filename, chunk1)
    payload2 = make_828_payload(10, 5, 2, 2, filename, chunk2)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload1, version, client_id, fake_session)
    await handlers.request_828(payload2, version, client_id, fake_session)

    assert len(calls) == 1
    assert calls[0][0] == "1603"
    assert calls[0][1] == client_id
    assert calls[0][3] == "file.bin"
    assert calls[0][4] == 10
    assert calls[0][5] == 0x12345678

    assert fake_session.reset_calls == []
    assert fake_session.upload_id is not None
    assert fake_session.upload_filename == "file.bin"
    assert fake_session.upload_path is not None
    assert fake_session.upload_crc == 0x12345678
    assert fake_session.has_upload_slot is True

    uploads = s.get_client_uploads(client_id.hex())
    assert len(uploads) == 1
    upload = uploads[0]

    assert upload[1] == client_id.hex()
    assert upload[2] == "file.bin"
    assert upload[5] == 10
    assert upload[7] == "in_progress"
    assert upload[3] is None
    assert upload[6] is None
    assert upload[8] is None


@pytest.mark.asyncio
async def test_828_out_of_order_packet(monkeypatch, tmp_path):
    s = make_sql_store(tmp_path)
    fake_session = FakeSession(config.Config.load(), s)
    calls = patch_828_side_effects(monkeypatch)

    client_id = b"\x01" * 16
    setup_client(fake_session, "alice", client_id)
    version = b"\x03"
    filename = b"file.bin"
    iv = b"\xAA" * 16
    chunk = b"\xBB" * 4

    payload0 = make_828_payload(10, 5, 0, 2, filename, iv)
    payload2 = make_828_payload(10, 5, 2, 2, filename, chunk)

    await handlers.request_828(payload0, version, client_id, fake_session)
    await handlers.request_828(payload2, version, client_id, fake_session)

    assert calls[-1][0] == "1607"
    assert calls[-1][3] == "bad 828: out of order"
    assert fake_session.reset_calls[-1] == "bad_828_out_of_order"