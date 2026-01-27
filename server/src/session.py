import uuid
from src.framing import Framer
from src.logging_setup import make_session_logger

class ClientSession:
    def __init__(self, sock,store ,base_logger):
        self.sock=sock
        self.store = store
        self.connection_id=uuid.uuid4().hex
        self.request_id =None
        self.log = make_session_logger(base_logger,self.connection_id)
        self.framer=Framer()
        self.transfer_iv=None
        self.transfer_cipher=bytearray()

    def send(self,data:bytes)->None:
        if not data:
            return
        self.sock.sendall(data)

    def feed(self, chunk: bytes) -> list[bytes]:
        return self.framer.feed(chunk)