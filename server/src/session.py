class ClientSession:
    def __init__(self, sock, debug_mode: bool = False):
        self.sock=sock
        self.debug_mode=debug_mode
    def send(self,data:bytes)->None:
        if not data:
            return
        if self.debug_mode:
            print(f'[SESSION] sending {len(data)} bytes')
        self.sock.sendall(data)