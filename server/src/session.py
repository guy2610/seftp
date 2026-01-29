import uuid
from src.framing import Framer
from src.logging_setup import make_session_logger
import asyncio

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

    async def send(self,data:bytes)->None:
        if not data:
            return
        if not self.writer:
            return
        self.writer.write(data)
        await self.writer.drain()

    def feed(self, chunk: bytes) -> list[bytes]:
        return self.framer.feed(chunk)