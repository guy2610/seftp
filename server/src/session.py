from src.framing import Framer
class ClientSession:
    def __init__(self, sock,store ,debug_mode: bool = False):
        self.sock=sock
        self.debug_mode=debug_mode
        self.framer=Framer()
        self.transfer_iv=None
        self.transfer_cipher=bytearray()
        self.store=store
    def send(self,data:bytes)->None:
        if not data:
            return
        if self.debug_mode:
            print(f'[SESSION] sending {len(data)} bytes')
        self.sock.sendall(data)

    def feed(self, chunk: bytes) -> list[bytes]:
        return self.framer.feed(chunk)