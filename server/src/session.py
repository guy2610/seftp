import uuid
from src.framing import Framer
from src.logging_setup import make_session_logger
import asyncio
import time

class ClientSession:
    def __init__(self, writer,store ,base_logger):
        self.writer=writer
        self.store = store
        self.connection_id=uuid.uuid4().hex
        self.request_id =None
        self.log = make_session_logger(base_logger,self.connection_id)
        self.framer=Framer()
        self.transfer_iv=None
        self.transfer_cipher=bytearray()
        now = time.monotonic()
        self.connected_at = now
        self.last_activity = now
        self.bytes_in = 0
        self.bytes_out = 0
        self.frames_ok = 0
        self.frames_bad = 0
        self.disconnect_reason = "unknown"
        self.last_client_id = None
        self.last_version = None
        self.upload_active = False
        self.last_upload_progress_ts = None
        self.upload_filename = None

    async def send(self,data:bytes)->None:
        if not data:
            return
        if not self.writer:
            return
        try:
            self.writer.write(data)
            await self.writer.drain()
            self.on_frame_sent(len(data))
        except (ConnectionResetError, BrokenPipeError):
            self.disconnect_reason = "send_error"
            raise

    def feed(self, chunk: bytes) -> list[bytes]:
        return self.framer.feed(chunk)

    def mark_activity(self):
        self.last_activity = time.monotonic()

    def on_frame_received(self, nbytes: int):
        self.bytes_in += int(nbytes)
        self.mark_activity()

    def on_frame_sent(self, nbytes: int):
        self.bytes_out += int(nbytes)
        self.mark_activity()

    def on_frame_ok(self):
        self.frames_ok += 1

    def on_frame_bad(self, reason: str):
        self.frames_bad += 1
        if reason:
            self.disconnect_reason = reason
    def mark_upload_progress(self):
        self.last_upload_progress_ts=time.monotonic()
        self.mark_activity()
