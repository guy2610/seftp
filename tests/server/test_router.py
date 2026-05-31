import pytest
import src.router as router
import src.config as config
import src.store as store
import asyncio
import time
from typing import Optional

class FakeLogger:
    def __init__(self):
        self.request_id = "-"
        self.info_calls = []
        self.warning_calls = []
        self.exception_calls = []

    def info(self, *args, **kwargs):
        self.info_calls.append((args, kwargs))

    def warning(self, *args, **kwargs):
        self.warning_calls.append((args, kwargs))

    def exception(self, *args, **kwargs):
        self.exception_calls.append((args, kwargs))

class FakeSession:
    def __init__(self):
        self.request_id = None
        self.log = FakeLogger()
        self.upload_active = False
        self.disconnect_reason = None
        self.last_client_id = None
        self.last_version = None
        self.on_frame_ok_calls = 0
        self.on_frame_bad_calls = []
        self.reset_calls = []
        self.handshake_verified = True

    def on_frame_ok(self):
        self.on_frame_ok_calls += 1

    def on_frame_bad(self, reason: str):
        self.on_frame_bad_calls.append(reason)

    def reset_transfer_state(self, reason: str):
        self.reset_calls.append(reason)


@pytest.mark.asyncio
@pytest.mark.parametrize("n", range(0, 17))
async def test_handle_frame_len_lt_17_marks_bad_and_returns(n):
    s = FakeSession()
    frame = b"\x01" * n
    await router.handle_frame(frame, s)
    assert s.on_frame_bad_calls == ["short_frame_lt_17"]
    assert s.reset_calls == []

@pytest.mark.asyncio
@pytest.mark.parametrize("n", range(17, 23))
async def test_handle_frame_len_17_to_22_sends_1607_and_resets(monkeypatch, n):
    s = FakeSession()
    frame = b"\x01" * n
    calls = []
    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))
    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    await router.handle_frame(frame, s)
    assert s.on_frame_bad_calls == ["short_frame_missing_header"]
    assert s.reset_calls == ["protocol_error_1607"]
    assert len(calls) == 1
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_len_23_plus_payload_different_payload_size(monkeypatch):
    s = FakeSession()
    calls = []
    code_num = int(826).to_bytes(2,"little")
    payload_size = int(10).to_bytes(4,"little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01"
    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    await router.handle_frame(frame, s)
    assert s.on_frame_bad_calls == ["short_frame_payload_truncated"]
    assert s.reset_calls == ["protocol_error_1607"]
    assert len(calls) == 1
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_correct_code(monkeypatch):
    s = FakeSession()
    calls = []
    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))
    async def fake_825(payload_info, version,session):
        calls.append((payload_info, version,session))
    async def fake_827(client_id, payload_info, version, session):
        calls.append((client_id,payload_info, version,session))
    async def fake_826(client_id, payload_info, version,session):
        calls.append((client_id, payload_info, version,session))
    async def fake_828(payload_info,version,client_id,session):
        calls.append((payload_info,version,client_id,session))
    async def fake_900(payload_info, version, client_id,session):
        calls.append((payload_info, version, client_id,session))
    async def fake_901(payload_info, version, client_id,session):
        calls.append((payload_info, version, client_id,session))
    async def fake_902(payload_info, version, client_id,session):
        calls.append((payload_info, version, client_id,session))
    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_825", fake_825)
    monkeypatch.setattr("src.router.handlers.request_827", fake_827)
    monkeypatch.setattr("src.router.handlers.request_826", fake_826)
    monkeypatch.setattr("src.router.handlers.request_828", fake_828)
    monkeypatch.setattr("src.router.handlers.request_900", fake_900)
    monkeypatch.setattr("src.router.handlers.request_901", fake_901)
    monkeypatch.setattr("src.router.handlers.request_902", fake_902)

    codes=[825,826,827,828,900,901,902]
    for i in range(len(codes)):
        code_num = int(codes[i]).to_bytes(2,"little")
        payload_size = int(10).to_bytes(4,"little")
        frame = b"\x01" * 17 + code_num + payload_size + b"\x01"*10

        await router.handle_frame(frame, s)
        assert s.on_frame_bad_calls == []
        assert s.reset_calls == []
        assert len(calls) == i + 1
        assert s.request_id == "-"
        assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_825_passes_correct_parameters(monkeypatch):
    s = FakeSession()
    calls = []

    async def fake_825(payload_info, version, session):
        calls.append((payload_info, version, session))

    async def fake_1607(client_id, version, text, session):
        raise AssertionError("1607 should not be called")

    monkeypatch.setattr("src.router.handlers.request_825", fake_825)
    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)

    client_id = b"\xAA" * 16
    version = b"\x03"
    payload = b"\x99" * 10
    code_num = (825).to_bytes(2, "little")
    payload_size = len(payload).to_bytes(4, "little")
    frame = client_id + version + code_num + payload_size + payload

    await router.handle_frame(frame, s)
    assert len(calls) == 1
    passed_payload, passed_version, passed_session = calls[0]
    assert passed_payload == payload
    assert passed_version == version
    assert passed_session is s
    assert s.on_frame_ok_calls == 1
    assert s.on_frame_bad_calls == []
    assert s.last_client_id == client_id
    assert s.last_version == version
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_unknown_code_while_not_uploading(monkeypatch):
    s = FakeSession()
    calls = []
    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)

    code_num = int(800).to_bytes(2, "little")
    payload_size = int(10).to_bytes(4, "little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01" * 10

    await router.handle_frame(frame, s)
    assert s.on_frame_bad_calls == ["unknown_code"]
    assert s.reset_calls == []
    assert len(calls) == 1
    assert calls[0][0] == frame[:16]
    assert calls[0][1] == frame[16:17]
    assert "unknown" in calls[0][2].lower()
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_unknown_code_while_uploading(monkeypatch):
    s = FakeSession()
    calls = []
    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)

    code_num = int(800).to_bytes(2, "little")
    payload_size = int(10).to_bytes(4, "little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01" * 10
    s.upload_active=True

    await router.handle_frame(frame, s)
    assert s.on_frame_bad_calls == ["unknown_code"]
    assert s.reset_calls == ["protocol_error_1607"]
    assert len(calls) == 1
    assert calls[0][0] == frame[:16]
    assert calls[0][1] == frame[16:17]
    assert "unknown" in calls[0][2].lower()
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_correct_code_exception_not_upload_active(monkeypatch):
    s = FakeSession()
    calls = []

    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))
    async def fake_825(payload_info, version,session):
        raise Exception

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_825", fake_825)
    code_num = int(825).to_bytes(2, "little")
    payload_size = int(10).to_bytes(4, "little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01" * 10

    await router.handle_frame(frame, s)
    assert s.on_frame_ok_calls == 1
    assert s.on_frame_bad_calls == ["handle_frame_exception"]
    assert s.reset_calls == []
    assert len(calls) == 1
    assert calls[0][0] == frame[:16]
    assert calls[0][1] == frame[16:17]
    assert "error" in calls[0][2].lower() or "exception" in calls[0][2].lower()
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_handle_frame_correct_code_exception_upload_active(monkeypatch):
    s = FakeSession()
    calls = []

    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))
    async def fake_825(payload_info, version,session):
        raise Exception

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_825", fake_825)
    code_num = int(825).to_bytes(2, "little")
    payload_size = int(10).to_bytes(4, "little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01" * 10
    s.upload_active = True

    await router.handle_frame(frame, s)
    assert s.on_frame_ok_calls == 1
    assert s.on_frame_bad_calls == ["handle_frame_exception"]
    assert s.reset_calls == ["protocol_error_1607"]
    assert len(calls) == 1
    assert calls[0][0] == frame[:16]
    assert calls[0][1] == frame[16:17]
    assert "error" in calls[0][2].lower() or "exception" in calls[0][2].lower()
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_send_error_reraises(monkeypatch):
    s = FakeSession()
    calls = []

    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text))

    async def fake_825(payload_info, version, session):
        raise BrokenPipeError()

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_825", fake_825)

    code_num = int(825).to_bytes(2, "little")
    payload_size = int(10).to_bytes(4, "little")
    frame = b"\x01" * 17 + code_num + payload_size + b"\x01" * 10
    s.upload_active = True
    s.disconnect_reason = "send_error"

    with pytest.raises(BrokenPipeError):
        await router.handle_frame(frame, s)
    assert len(calls) == 0
    assert s.request_id == "-"
    assert s.log.request_id == "-"
    assert "handle_frame_exception" in s.on_frame_bad_calls

@pytest.mark.asyncio
async def test_handle_frame_updates_last_client_id_and_version(monkeypatch):
    s = FakeSession()
    calls = []

    async def fake_825(payload_info, version, session):
        calls.append((payload_info, version))

    monkeypatch.setattr("src.router.handlers.request_825", fake_825)

    client_id = b"\xAA" * 16
    version = b"\x03"
    code_num = int(825).to_bytes(2, "little")
    payload = b"\x01" * 10
    payload_size = len(payload).to_bytes(4, "little")
    frame = client_id + version + code_num + payload_size + payload

    await router.handle_frame(frame, s)
    assert s.last_client_id == client_id
    assert s.last_version == version
    assert len(calls) == 1
    assert s.request_id == "-"
    assert s.log.request_id == "-"

@pytest.mark.asyncio
async def test_router_rejects_application_request_before_stage7_handshake(monkeypatch):
    s = FakeSession()
    s.handshake_verified = False

    calls = []

    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text, session))

    async def fake_825(payload_info, version, session):
        raise AssertionError("825 handler should not be called before handshake")

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_825", fake_825)

    client_id = b"\x01" * 16
    version = b"\x03"
    payload = b"alice\x00"
    frame = (
        client_id
        + version
        + (825).to_bytes(2, "little")
        + len(payload).to_bytes(4, "little")
        + payload
    )

    await router.handle_frame(frame, s)

    assert len(calls) == 1
    assert calls[0][0] == client_id
    assert calls[0][1] == version
    assert "handshake required" in calls[0][2]


@pytest.mark.asyncio
async def test_router_allows_829_before_stage7_handshake(monkeypatch):
    s = FakeSession()
    s.handshake_verified = False

    calls = []

    async def fake_829(payload_info, version, client_id, session):
        calls.append((payload_info, version, client_id, session))

    async def fake_1607(client_id, version, text, session):
        raise AssertionError("1607 should not be called for 829 before handshake")

    monkeypatch.setattr("src.router.handlers.request_829", fake_829)
    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)

    client_id = b"\x00" * 16
    version = b"\x03"
    payload = b"\x01" + (b"\xAA" * 32) + b"\x00"
    frame = (
        client_id
        + version
        + (829).to_bytes(2, "little")
        + len(payload).to_bytes(4, "little")
        + payload
    )

    await router.handle_frame(frame, s)

    assert len(calls) == 1
    assert calls[0][0] == payload
    assert calls[0][1] == version
    assert calls[0][2] == client_id


@pytest.mark.asyncio
async def test_router_rejects_handshake_code_after_completion(monkeypatch):
    s = FakeSession()
    s.handshake_verified = True

    calls = []

    async def fake_1607(client_id, version, text, session):
        calls.append((client_id, version, text, session))

    async def fake_829(payload_info, version, client_id, session):
        raise AssertionError("829 should not be called after handshake completion")

    monkeypatch.setattr("src.router.answers.answer_1607", fake_1607)
    monkeypatch.setattr("src.router.handlers.request_829", fake_829)

    client_id = b"\x00" * 16
    version = b"\x03"
    payload = b"\x01" + (b"\xAA" * 32) + b"\x00"
    frame = (
        client_id
        + version
        + (829).to_bytes(2, "little")
        + len(payload).to_bytes(4, "little")
        + payload
    )

    await router.handle_frame(frame, s)

    assert len(calls) == 1
    assert "already completed" in calls[0][2]