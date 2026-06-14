import uuid
from src.framing import Framer
from src.logging_setup import make_session_logger
import asyncio
import time
from typing import Optional
from collections import deque
import os

class ClientSession:
    def __init__(self, writer, store, base_logger, config, upload_limiter, bounded_executor, server_identity_key=None):
        self.config=config
        self.writer=writer
        self.store = store
        self.connection_id=uuid.uuid4().hex
        self.request_id =None
        self.log = make_session_logger(base_logger,self.connection_id)
        self.framer=Framer(max_payload_size=config.max_payload_size)
        self.transfer_iv=None
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
        self.expected_packet_num = None
        self.expected_total_packets = None
        self.expected_content_size = None
        self.expected_orig_file_size = None
        self.received_cipher_bytes = 0
        self.upload_limiter = upload_limiter
        self.has_upload_slot = False
        self.bounded_executor = bounded_executor
        self.upload_client_id_hex = None
        self.upload_username = None
        self.upload_aes_key = None
        self.upload_id = None
        self.upload_path = None
        self.upload_crc = None
        self.upload_decrypt_cipher = None
        self.upload_tmp_path = None
        self.upload_tmp_file = None
        self.upload_plain_tail = bytearray()
        self.upload_plain_bytes_written = 0
        self.upload_crc32_state = 0
        self.handshake_verified = False
        self.client_nonce = None
        self.server_nonce = None
        self.security_version = None
        self.server_identity_key = server_identity_key
        self.request_timestamps = deque()

    async def release_upload_slot(self):
        if self.has_upload_slot:
            await self.upload_limiter.release()
            self.has_upload_slot = False
            active_now = await self.upload_limiter.current_active()
            self.log.info(
                "released upload slot active_uploads=%d max=%d",
                active_now,
                self.config.max_concurrent_uploads,
            )

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
    def reset_transfer_state(self,reason: Optional[str] = None):
        if self.upload_tmp_file is not None:
            try:
                self.upload_tmp_file.close()
            except Exception:
                pass

        if self.upload_tmp_path is not None:
            try:
                if os.path.exists(self.upload_tmp_path):
                    os.remove(self.upload_tmp_path)
            except Exception:
                pass
        self.transfer_iv=None
        self.upload_active=False
        self.last_upload_progress_ts=None
        self.upload_filename=None

        self.expected_packet_num = None
        self.expected_total_packets = None
        self.expected_content_size = None
        self.expected_orig_file_size = None
        self.received_cipher_bytes = 0
        self.upload_username = None
        self.upload_aes_key = None
        self.upload_client_id_hex = None
        self.upload_id = None
        self.upload_path = None
        self.upload_crc = None
        self.upload_decrypt_cipher = None
        self.upload_tmp_path = None
        self.upload_tmp_file = None
        self.upload_plain_tail = bytearray()
        self.upload_plain_bytes_written = 0
        self.upload_crc32_state = 0
        if reason:
            self.log.info("reset transfer state reason=%s",reason)

    def allow_request_now(self, now: float) -> bool:
        window_start = now - self.config.req_window_s

        while self.request_timestamps and self.request_timestamps[0] < window_start:
            self.request_timestamps.popleft()

        if len(self.request_timestamps) >= self.config.max_req_per_window:
            return False

        self.request_timestamps.append(now)
        return True


