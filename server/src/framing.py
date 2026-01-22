# Stream-to-frame extraction (binary framing) lives here.
CLIENT_ID_LEN = 16
VERSION_LEN = 1
CODE_LEN = 2
PAYLOAD_SIZE_LEN = 4
HEADER_LEN = 23  # 16 client_id + 1 version + 2 code + 4 payload_size
PAYLOAD_SIZE_OFFSET=19  # 16 client_id + 1 version + 2 code

class Framer:
    """
        Incrementally collects bytes from the socket and extracts complete protocol frames.

        Behavior:
        - Keeps leftover bytes between recv() calls
        - Extracts full frames when available
        - Does not parse payload, only uses payload_size from header
        """
    def __init__(self):
        self._buf = bytearray()
    def feed(self,chunks:bytes)->list[bytes]:
        if not chunks:
            return []
        self._buf.extend(chunks)
        frames:list[bytes]=[]
        while True:
            if len(self._buf)<HEADER_LEN:
                break
            payload_size=int.from_bytes(self._buf[PAYLOAD_SIZE_OFFSET:PAYLOAD_SIZE_OFFSET+4],"little")
            frame_len=HEADER_LEN+payload_size
            if len(self._buf)<frame_len:
                break
            frame=bytes(self._buf[:frame_len])
            del self._buf[:frame_len]
            frames.append(frame)
        return frames


