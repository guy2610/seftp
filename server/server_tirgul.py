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

HOST='127.0.0.1'
try:
    with open("port.info","r") as port_file:
        for line in port_file:
            PORT=int(line)
except:
    PORT=1256
DATA_PATH = "data/clients_info.json"
store=Store()
store.load_client_info(DATA_PATH)

ans=input("do you wish to see debug console promts? answer 'yes' or something else for no ")
debug_mode=True if ans.lower()=="yes" else False

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    print("socket binded to %s" % PORT)
    s.listen(5)
    print("socket is listening")
    c, addr = s.accept()
    session = ClientSession(c,store, debug_mode)
    with c:
        print('Got connection from', addr)
        try:
            while True:
                chunk = c.recv(1024)
                if not chunk:
                    print(f"Client {addr} disconnected.")
                    break
                frames = session.feed(chunk)
                for frame in frames:
                    router.handle_frame(frame, session)
        except (ConnectionResetError, BrokenPipeError):
            print(f"Client {addr} disconnected unexpectedly.")
        finally:
            c.close()
store.save_clients_info(DATA_PATH)
print(dict(store.clients_recent_log))
