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
import src.answers as answers
import src.handlers as handlers
from src.store import Store

HOST='127.0.0.1'
try:
    with open("port.info","r") as port_file:
        for line in port_file:
            PORT=int(line)
except:
    PORT=1256

# clients_info structure:
# {
#   "username": [
#       client_id (16-byte UUID as bytes),
#       public_key (RSA public key in DER format, as bytes),
#       last_seen (string timestamp),
#       aes_key_b64 (AES-256 key, Base64-encoded string)
#   ]
# }
store=Store()
store.load_client_info("clients.info")

def name_of_dict_from_id(client_id):
    """
        Given client_id (bytes), return the associated username from clients_info.
        Returns None if not found.
        """
    if debug_mode: print("inside name_of_dict_from_id")
    for k, vals in store.clients_info.items():
        if vals[0] == client_id:
            return k
    return



'''
####DEBUG ONLY###
def helper_for_now_for_sso():
    if debug_mode: print("inside helper_for_now_for_sso")
    global clients_info
    with open("your\\path\\to\\me.info",'r') as f:
        data=f.read()
    lines=[ln.strip() for ln in data.splitlines() if ln.strip()]
    if len(lines)<3:
        raise ValueError("me.info must have 3 line: name, client_id_hex, public_key")
    name=lines[0]
    client_id_hex = lines[1]
    if len(client_id_hex) != 32:
        raise ValueError(f"client_id hex with invalid len: {len(client_id_hex)} needs 32 ")
    client_id_bytes = bytes.fromhex(client_id_hex)
    public_key_blob = b64decode(lines[2], validate=True)
    pub = RSA.import_key(public_key_blob)
    print("public key bits:", pub.size_in_bits())

    last_seen="none for now"
    aes_key="will be generated"
    clients_info[name] = [client_id_bytes, public_key_blob, last_seen, aes_key]
    if debug_mode: print(f"name: {name}")
    if debug_mode: print(f"client_id (hex): {client_id_hex}")
'''

ans=input("do you wish to see debug console promts? answer 'yes' or something else for no ")
debug_mode=True if ans.lower()=="yes" else False

answers.clients_info = store.clients_info
answers.clients_recent_log = store.clients_recent_log
answers.name_of_dict_from_id = name_of_dict_from_id

handlers.clients_info = store.clients_info
handlers.clients_recent_log = store.clients_recent_log
handlers.name_of_dict_from_id = name_of_dict_from_id

handlers.answer_1600 = answers.answer_1600
handlers.answer_1601 = answers.answer_1601
handlers.answer_1602 = answers.answer_1602
handlers.answer_1603 = answers.answer_1603
handlers.answer_1604 = answers.answer_1604
handlers.answer_1605 = answers.answer_1605
handlers.answer_1606 = answers.answer_1606
handlers.answer_1607 = answers.answer_1607
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
print(dict(clients_recent_log))
