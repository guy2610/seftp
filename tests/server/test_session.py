import pytest
import src.session as session
import src.config as config
import src.store as store
import asyncio
import time
from typing import Optional

class FakeLogger:
    def __init__(self):
        self.debug_calls = []
        self.info_calls = []
        self.warning_calls = []
        self.exception_calls = []

    def debug(self, msg, *args, **kwargs):
        self.debug_calls.append((msg, args, kwargs))

    def info(self, msg, *args, **kwargs):
        self.info_calls.append((msg, args, kwargs))

    def warning(self, msg, *args, **kwargs):
        self.warning_calls.append((msg, args, kwargs))

    def exception(self, msg, *args, **kwargs):
        self.exception_calls.append((msg, args, kwargs))

class FakeWriter:
    def __init__(self, *, fail_on_write: Optional[Exception] = None, fail_on_drain: Optional[Exception] = None):
        self.fail_on_write = fail_on_write
        self.fail_on_drain = fail_on_drain
        self.writes = []
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        if self.fail_on_write:
            raise self.fail_on_write
        self.writes.append(data)

    async def drain(self) -> None:
        self.drain_calls += 1
        if self.fail_on_drain:
            raise self.fail_on_drain
class FakeFramer:
    def __init__(self):
        self.called_with = None
    def feed(self, chunk):
        self.called_with = chunk
        return [b"frame"]
def test_session_counters_and_timestamp():
    client_session = session.ClientSession(None,None,None,config.Config.load())
    prev_bytes_in = client_session.bytes_in
    prev_last_activity=client_session.last_activity

    client_session.on_frame_received(5)
    assert client_session.bytes_in == prev_bytes_in + 5
    assert client_session.last_activity >= prev_last_activity

    prev_bytes_out = client_session.bytes_out
    prev_last_activity = client_session.last_activity

    client_session.on_frame_sent(6)
    assert client_session.bytes_out == prev_bytes_out + 6
    assert client_session.last_activity >= prev_last_activity

    prev_frames_ok = client_session.frames_ok
    client_session.on_frame_ok()
    assert client_session.frames_ok == prev_frames_ok + 1

    prev_frames_bad = client_session.frames_bad
    reason = "bad input"
    client_session.on_frame_bad(reason)
    assert client_session.frames_bad == prev_frames_bad + 1
    assert client_session.disconnect_reason == reason

def test_mark_upload_progress():
    client_session = session.ClientSession(None, None, None, config.Config.load())
    prev_last_upload_progress_ts = client_session.last_upload_progress_ts
    prev_last_activity = client_session.last_activity

    client_session.mark_upload_progress()
    assert client_session.last_upload_progress_ts is not None
    assert client_session.last_activity >= prev_last_activity
    assert client_session.last_activity >= client_session.last_upload_progress_ts

def test_reset_transfer_state_logs_reason(monkeypatch):
    fake_logger = FakeLogger()
    monkeypatch.setattr(
        "server.src.session.make_session_logger",
        lambda base_logger, connection_id: fake_logger
    )
    class DummyConfig:
        max_payload_size = 10_000_000

    dummy_config = DummyConfig()
    s = session.ClientSession(None, None, None, dummy_config)
    s.upload_active = True
    s.upload_filename = "file"
    s.received_cipher_bytes = 123

    s.reset_transfer_state("timeout")
    assert s.upload_active is False
    assert s.upload_filename is None
    assert s.received_cipher_bytes == 0
    assert len(fake_logger.info_calls) == 1
    assert fake_logger.info_calls[0][1][0] == "timeout"

@pytest.mark.asyncio
async def test_send_happy_path(monkeypatch):
    fake_logger = FakeLogger()
    fake_writer = FakeWriter()
    monkeypatch.setattr(
        "server.src.session.make_session_logger",
        lambda base_logger, connection_id: fake_logger
    )
    class DummyConfig:
        max_payload_size = 10_000_000

    dummy_config = DummyConfig()
    client_session = session.ClientSession(fake_writer, store.Store(), None, dummy_config)
    prev_last_activity = client_session.last_activity
    prev_bytes_out = client_session.bytes_out

    await client_session.send(b"abc")
    assert fake_writer.writes == [b"abc"]
    assert fake_writer.drain_calls == 1
    assert client_session.bytes_out == prev_bytes_out + 3
    assert client_session.last_activity >= prev_last_activity

@pytest.mark.asyncio
async def test_send_error_path_sets_disconnect_reason_and_raises(monkeypatch):
    fake_logger = FakeLogger()
    fake_writer = FakeWriter(fail_on_write=BrokenPipeError())
    monkeypatch.setattr(
        "server.src.session.make_session_logger",
        lambda base_logger, connection_id: fake_logger
    )
    class DummyConfig:
        max_payload_size = 10_000_000

    client_session = session.ClientSession(fake_writer, store.Store(), None, DummyConfig())
    with pytest.raises(BrokenPipeError):
        await client_session.send(b"abc")
    assert client_session.disconnect_reason == "send_error"
    assert fake_writer.writes == []

@pytest.mark.asyncio
async def test_send_fail_on_drain_sets_disconnect_reason_and_keeps_written_data(monkeypatch):
    fake_logger = FakeLogger()
    fake_writer = FakeWriter(fail_on_drain=ConnectionResetError())
    monkeypatch.setattr(
        "server.src.session.make_session_logger",
        lambda base_logger, connection_id: fake_logger
    )
    class DummyConfig:
        max_payload_size = 10_000_000
    client_session = session.ClientSession(fake_writer, store.Store(), None, DummyConfig())
    with pytest.raises(ConnectionResetError):
        await client_session.send(b"abc")
    assert fake_writer.writes == [b"abc"]
    assert fake_writer.drain_calls == 1
    assert client_session.disconnect_reason == "send_error"

def test_feed(monkeypatch):
    fake_logger = FakeLogger()
    fake_writer = FakeWriter(fail_on_drain=ConnectionResetError())
    monkeypatch.setattr(
        "server.src.session.make_session_logger",
        lambda base_logger, connection_id: fake_logger
    )

    class DummyConfig:
        max_payload_size = 10_000_000
    client_session = session.ClientSession(fake_writer,FakeFramer(), None, DummyConfig())
    client_session.framer = FakeFramer()
    out = client_session.feed(b"abc")
    assert out == [b"frame"]
    assert client_session.framer.called_with == b"abc"