"""
Secure File Transfer Server

- Handles client registration & login using a persistent client_id (16-byte identifier) and RSA public key.
- Generates per-client AES-256 key and sends it encrypted with RSA-OAEP
- Receives encrypted file in chunks (code 828), decrypts with AES-CBC, verifies CRC, and writes to disk.
- Uses AES-256-CBC with a fresh random IV per file transfer. IV is provided by the client as part of request 828 metadata.
"""

import socket
from src.session import ClientSession
from src import router
from src.store import Store
from src.config import Config
from src.logging_setup import setup_logging

config=Config.load()
logger=setup_logging(config.log_level)

store=Store()
store.load_client_info(config.data_path)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((config.host, config.port))
    logger.info("socket binded to %d", config.port)
    s.listen(5)
    logger.info("socket is listening")
    c, addr = s.accept()
    session = ClientSession(c,store,logger)
    session.log.info("Got connection from %s", addr)
    with c:
        try:
            while True:
                chunk = c.recv(1024)
                if not chunk:
                    session.log.info("Client %s disconnected", addr)
                    break
                frames = session.feed(chunk)
                for frame in frames:
                    router.handle_frame(frame, session)
        except (ConnectionResetError, BrokenPipeError):
            session.log.warning("Client %s disconnected unexpectedly", addr)
        finally:
            c.close()
store.save_clients_info(config.data_path)
logger.debug("clients_recent_log=%r", dict(store.clients_recent_log))

