"""
Secure File Transfer Server

- Handles client registration & login using a persistent client_id (16-byte identifier) and RSA public key.
- Generates per-client AES-256 key and sends it encrypted with RSA-OAEP
- Receives encrypted file in chunks (code 828), decrypts with AES-CBC, verifies CRC, and writes to disk.
- Uses AES-256-CBC with a fresh random IV per file transfer. IV is provided by the client as part of request 828 metadata.
"""

import socket
import uuid
import datetime
from collections import defaultdict
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import zlib
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import base64
from src.session import ClientSession
from src import router
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
clients_info={}
clients_recent_log = defaultdict(list)
try:
    with open("clients.info","r") as file:
        i=0
        for line in file:
            if i%4==0:
                name = line[:len(line) - 1]
                clients_info[name]=["none"]*4
            elif i % 4 == 1:
                clients_info[name][0]=line[:len(line) - 1]
            elif i % 4 == 2:
                clients_info[name][1] = line[:len(line) - 1]
            elif i % 4 == 3:
                clients_info[name][2] = line[:len(line) - 1]
            else:
                clients_info[name][3] = line[:len(line) - 1]
            i+=1

except:
    print(f'file name clients.info not found')



def message_answer(version:bytes,code_num:str,payload_size:str,payload:bytes):
    """
    Build a binary response frame to send to the client.

    Frame format:
    - 1 byte: version
    - 2 bytes: code (little-endian)
    - 4 bytes: payload size (little-endian)
    - N bytes: payload
    """
    if debug_mode: print("making the message and sending it")
    message = (
            int(version).to_bytes(1, 'little') +
            int(code_num).to_bytes(2, 'little') +
            int(payload_size).to_bytes(4, 'little') +
            payload
    )
    if debug_mode: print(message)
    return message

def answer_1600(client_id,version,session:ClientSession):
    """
        Send response 1600: registration succeeded.

        Payload:
        - 16 bytes: client_id (client_id (persistent identifier) as bytes)

        Side effects:
        - Logs the event in clients_recent_log
        - Prints the client_id in Base64 for debugging
        """
    if debug_mode: print("inside answer 1600")
    clients_recent_log[client_id].append(["answer_1600",str(datetime.datetime.now())])
    message=message_answer(version,"1600","16",client_id)
    print(f"sign on succeed for {base64.b64encode(client_id).decode('utf-8')}")
    session.send(message)

def answer_1601(version,session:ClientSession):
    """
    Send response 1601: registration failed (username already exists or invalid).

    No payload.
    """
    if debug_mode: print("inside answer 1601")
    message = message_answer(version, "1601", "0", "")
    print(f"sign on failed")
    session.send(message)
    #send error in answer format

def request_825(payload_info,version,session:ClientSession):
    """
    Handle request 825: initial registration.

    Payload:
    - Null-terminated UTF-8 username

    Behavior:
    - If username does not exist: create a persistent client_id (used across sessions), store it in clients_info, reply with 1600.
    - If username exists: reply with 1601.
    """
    if debug_mode: print("inside request 825")
    global  clients_info,clients_recent_log
    payload_info=payload_info.rstrip(b'\x00').decode()
    if not payload_info in clients_info:
        client_id=uuid.uuid4().bytes
        name=payload_info.strip()
        public_key="public_key_none_for_now"
        last_seen=str(datetime.datetime.now())
        aes_key="aes_key_none_for_now"
        clients_info[name] = [client_id, public_key, last_seen, aes_key]
        tmp = [base64.b64encode(clients_info[name][0]).decode('utf-8'),clients_info[name][1], clients_info[name][2], clients_info[name][3]]
        print(f'{name} has created. this is his list: {tmp}')
        if name in clients_recent_log.keys():
            user_past_log=clients_recent_log.get(name)
            clients_recent_log[client_id].extend(user_past_log)
            clients_recent_log.pop(name)
        clients_recent_log[client_id].append(["request_825",str(datetime.datetime.now())])
        answer_1600(client_id, version,session)
    else:
        print(f'{payload_info} is in the clients info')
        answer_1601(version,session)

def answer_1602(cipher_text_aes_encrypted,client_id,version,session:ClientSession):
    """
    Send response 1602: AES key encrypted with client's RSA public key.

    Payload:
    - RSA-encrypted AES key (ciphertext)
    - 16 bytes client_id

    Also updates last_seen and logs the event.
    """
    if debug_mode: print("inside answer 1602")
    payload = cipher_text_aes_encrypted + client_id
    message = message_answer(version, "1602", str(len(payload)), payload)
    print(f"got the {name_of_dict_from_id(client_id)}'s public key, sending the encrypted AES key")
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["answer_1602",str(datetime.datetime.now())])
    session.send(message)

def answer_1606(client_id,version,name,session:ClientSession):
    """
    Send response 1606: re-login / sign-on rejected.

    Reasons:
    - Client is not registered (unknown client_id (persistent identifier))
    - Stored public key is invalid (e.g., wrong size or format)
    """
    if debug_mode: print("inside answer 1606")
    message = message_answer(version, "1606", "16", client_id)
    print(f'request for sign on for {base64.b64encode(client_id).decode('utf-8')} rejected (client is not register or the public key is invalid. need to re-register)')
    if client_id==b'\x00'*16:
        clients_recent_log[name].append(["answer_1606", str(datetime.datetime.now())])
    else:
        clients_recent_log[client_id].append(["answer_1606", str(datetime.datetime.now())])
        clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    session.send(message)

def answer_1605(cipher_text_aes_encrypted,client_id,version,session:ClientSession):
    """
    Send response 1605: re-login approved.

    Payload:
    - RSA-encrypted AES key
    - 16 bytes client_id
    """
    if debug_mode: print("inside answer 1605")
    message = message_answer(version, "1605", str(len(cipher_text_aes_encrypted+client_id)), cipher_text_aes_encrypted+client_id)
    print(f'request for sign on for {base64.b64encode(client_id).decode('utf-8')} succeed, sending the encrypted AES key')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["answer_1605",str(datetime.datetime.now())])
    session.send(message)

def name_of_dict_from_id(client_id):
    """
        Given client_id (bytes), return the associated username from clients_info.
        Returns None if not found.
        """
    if debug_mode: print("inside name_of_dict_from_id")
    global clients_info
    for k, vals in clients_info.items():
        if vals[0] == client_id:
            return k
    return

def request_826(client_id, payload_info: bytes, version,session:ClientSession):
    """
    Handle request 826: send/update RSA public key + receive AES key.

    Payload:
    - username (UTF-8, null-terminated)
    - RSA public key in Base64 (DER)

    Behavior:
    - Validates that the username matches the client_id (persistent identifier) in clients_info.
    - Decodes and imports the RSA public key.
    - Generates a random AES-256 key, stores it, encrypts it with RSA-OAEP.
    - Responds with 1602 containing the encrypted AES key.
    """
    if debug_mode: print("inside request 826")
    global clients_info
    name_in_dict = name_of_dict_from_id(client_id)
    clients_info[name_in_dict][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_826",str(datetime.datetime.now())])
    if not name_in_dict:
        if debug_mode: print(clients_info)
        print(f'uuid not in client_info; client_id={client_id!r}')
        return

    sep = payload_info.find(b'\x00')
    if sep == -1:
        print("bad 826 payload: missing NUL after name")
        answer_1607(client_id,version,"bad 826 payload: missing NUL after name",session)
        return

    try:
        name = payload_info[:sep].decode('utf-8')
    except UnicodeDecodeError:
        print("bad 826 payload: name is not valid UTF-8")
        answer_1607(client_id, version, "bad 826 payload: name is not valid UTF-8",session)
        return

    if name != name_in_dict:
        print(f'name mismatch: got {name!r}, expected {name_in_dict!r}')
        answer_1607(client_id, version, f'name mismatch: got {name!r}, expected {name_in_dict!r}',session)
        return
    print(f"{name} logged successfully")

    public_blob = payload_info[sep + 1:].rstrip(b'\x00').strip()  #text in Base64
    try:
        public_str = public_blob.decode('ascii')
    except UnicodeDecodeError:
        answer_1607(client_id, version, "Public key is not ASCII base64",session)
        return
    if debug_mode: print("public_blob len:", len(public_str))  #need to be approx 392

    try:
        der = b64decode(public_str, validate=True)
        key_rsa = RSA.import_key(der)
        print(f"{name} has this RSA key: {key_rsa.export_key().decode()} with the size: {key_rsa.size_in_bits()}")  # size need to be 2048
        if key_rsa.has_private():
            answer_1606(clients_info[name][0], version, name,session)
            return
        if key_rsa.size_in_bits()!=2048:
            answer_1606(clients_info[name][0], version, name,session)
            return
        e = int(key_rsa.e)
        if e < 3 or e % 2 == 0:
            answer_1606(clients_info[name][0], version, name,session)
            return
    except Exception as e:
        print(f"RSA validation/import failed for 826: {e}")
        answer_1607(client_id, version, "Invalid RSA public key",session)
        return

    clients_info[name_in_dict][1] = der  #keep DER, not Base64

    # generate AES key
    key = get_random_bytes(32)
    clients_info[name][3] = base64.b64encode(key).decode('ascii')
    if debug_mode: print(f'the name: {name} has this list {clients_info[name]}')

    # encrypt AES key with RSA public
    cipher = PKCS1_OAEP.new(key_rsa)
    ciphertext = cipher.encrypt(key)
    tmp=[base64.b64encode(clients_info[name][0]).decode('utf-8'),base64.b64encode(clients_info[name][1]).decode('utf-8'),clients_info[name][2],clients_info[name][3]]
    print(f'the user: {name} has this list {tmp}.\nand this is the aes key encrypted by the public key: {base64.b64encode(ciphertext).decode('utf-8')}')

    # send 1602 aes key
    answer_1602(ciphertext, clients_info[name][0], version,session)

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

def request_827(client_id,payload_info:bytes,version,session:ClientSession):
    """
        Handle request 827: "single sign-on" / re-login.

        Payload:
        - username (UTF-8, null-terminated)

        Behavior:
        - If username not in clients_info: send 1606 with zero client_id.
        - If public key is invalid: send 1606 with actual client_id.
        - Otherwise: generate new AES key, encrypt with stored public key, reply with 1605.
        """
    if debug_mode: print("inside request 827")
    global clients_info
    payload_info = payload_info.decode()
    name=payload_info[:-1]
    if not name in clients_info:
        #the user doesnt exist
        print(f'the user {name} not in the clients dictionary')
        #clients_info[name][2] = str(datetime.datetime.now())
        clients_recent_log[name].append(["request_827",str(datetime.datetime.now())])
        answer_1606(b'\x00'*16, version,name,session)
    else:
        clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
        clients_recent_log[client_id].append(["request_827",str(datetime.datetime.now())])
        pub = RSA.import_key(clients_info[name][1])
        if pub.size_in_bits()!=2048:
            print(f"the public key: [{clients_info[name][1]}] in request 827 is not valid the len needs to be 2048 and is {str(len(clients_info[name][1]))}")
            answer_1606(clients_info[name][0],version,name,session)
        else:
            # generate aes key
            key = get_random_bytes(32)
            clients_info[name][3] = base64.b64encode(key).decode('ascii')
            if debug_mode: print(f'the person with the name: {name} has this list {clients_info[name]}')
            # encrypt aes key
            key_rsa = RSA.importKey(clients_info[name][1])
            cipher = PKCS1_OAEP.new(key_rsa)
            ciphertext = cipher.encrypt(key)
            print("request to sign on succeed")
            print(f'the name: {name} has this list {clients_info[name]}.\nand this is the aes key encrypted by the public key [{ciphertext}]')
            answer_1605(ciphertext, clients_info[name][0], version,session)
def crc(fileName):
    prev = 0
    with open(fileName, "rb") as f:
        data = f.read()
    return zlib.crc32(data) & 0xFFFFFFFF

def answer_1603(client_id,version,file_name,content_size,decrypted_total,session:ClientSession):
    """
       Send response 1603: CRC verification result.

       The server:
       - Computes CRC32 over decrypted plaintext.
       - Builds payload:
           client_id (16 bytes)
           content_size (4 bytes, little-endian)
           file_name (UTF-8 bytes)
           checksum (4 bytes, little-endian)
       - Logs success and sends the message to the client.
       """
    if debug_mode: print("inside answer 1603")
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["answer_1603",str(datetime.datetime.now())])
    #checksum = crc(file_name)  # int
    # Compute CRC32 over the decrypted plaintext
    checksum=zlib.crc32(decrypted_total) & 0xFFFFFFFF
    checksum_bytes = checksum.to_bytes(4, "little")
    content_size_bytes = content_size.to_bytes(4, "little")
    file_name_bytes = file_name.encode("utf-8")

    # Build binary payload:
    #   client_id (16 bytes)
    #   content_size (4 bytes)
    #   file_name (UTF-8)
    #   checksum (4 bytes, CRC32)
    payload = client_id + content_size_bytes + file_name_bytes + checksum_bytes
    if(debug_mode):print(f"server CRC dec={checksum}, hex=0x{checksum:08X}")

    # Send 1603 response with CRC to client
    message = message_answer(version, 1603, len(payload), payload)
    print(f'received {file_name} with valid CRC ')
    session.send(message)

def request_828(payload_info,version,client_id,session:ClientSession):
    """
        Handle request 828: receive encrypted file in chunks.

        Payload:
        - 4 bytes: total ciphertext size
        - 4 bytes: original (plaintext) file size
        - 2 bytes: packet number (1-based)
        - 2 bytes: total packets
        - filename (UTF-8, null-terminated)
        - ciphertext chunk

        Behavior:
        - Accumulates ciphertext in a static buffer (session.transfer_cipher).
        - On the last packet:
            * Decrypts using AES-256-CBC with a per-file random IV provided by the client in packet 0. IV is never static or reused across files.
            * Unpads (PKCS#7), trims to orig_file_size.
            * Writes plaintext to disk.
            * Calls answer_1603 to send CRC result back.
        """
    if debug_mode: print("inside request 828")
    global clients_info
    # Parse header fields from payload
    content_size=int.from_bytes(payload_info[:4], byteorder="little")
    orig_file_size=int.from_bytes(payload_info[4:8], byteorder="little")
    packet_num=int.from_bytes(payload_info[8:10], byteorder="little")
    total_packets = int.from_bytes(payload_info[10:12], byteorder="little")
    # Find filename (null-terminated) starting from byte 12
    sep = payload_info[12:].find(b'\x00')
    if sep == -1:
        print("bad 828 payload: cant find the name of the file")
        return
    try:
        sep += 12  # convert to absolute index inside payload_info
        file_name = payload_info[12:sep].decode('utf-8')
    except UnicodeDecodeError:
        print("bad 828 payload: name is not valid UTF-8")
        answer_1607(client_id, version, "bad 828 payload: name is not valid UTF-8",session)
        return
    if debug_mode: print(sep)
    if debug_mode: print(file_name)
    # The rest of the payload is the ciphertext chunk
    cipher_chunk = payload_info[sep + 1:]
    # Resolve username from client_id
    name_in_dict = name_of_dict_from_id(client_id)
    if not name_in_dict:
        print(clients_info)
        print(f'uuid not in client_info; client_id={client_id!r}')
        return
    # Decode AES key (Base64) for this client
    raw_key = base64.b64decode(clients_info[name_in_dict][3])
    aes_key = raw_key

    if packet_num==0:
        if len(cipher_chunk) < 16:
            print("bad 828: IV too short")
            answer_1607(client_id, version, "bad 828 payload: name is not valid UTF-8",session)
            return
        session.transfer_iv = bytes(cipher_chunk[:16])
        print("IV(hex)=", session.transfer_iv.hex())
        return
    else:
        if packet_num==1:
            print(f"write the file {file_name} ")
            session.transfer_cipher = bytearray()
            clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
            clients_recent_log[client_id].append(["request_828", str(datetime.datetime.now())])
        # Append chunk to the accumulated ciphertext
        print(f"\rgot packet with chunk size={len(cipher_chunk)}, {packet_num / total_packets * 100:.2f}% complete", end="")
        session.transfer_cipher.extend(cipher_chunk)
        if debug_mode: print(f"[SERVER] accumulated cipher size={len(session.transfer_cipher)}")
        if debug_mode: print(f'packet number: {packet_num} of {total_packets}')
        # Once we have the last packet, decrypt and write file
        if packet_num == total_packets:
            clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
            cipher_total=bytes(session.transfer_cipher)
            print(f"\nfinal cipher text total size={len(cipher_total)}, expected content size={content_size}")
            # AES-256-CBC with zero IV (same as client)
            decrypt_cipher = AES.new(aes_key, AES.MODE_CBC, iv=session.transfer_iv)
            decrypted_all = decrypt_cipher.decrypt(cipher_total)
            # Try to remove PKCS#7 padding
            try:
                plaintext = unpad(decrypted_all, AES.block_size)
            except ValueError:
                # In case padding is wrong, keep raw decrypted data
                plaintext = decrypted_all
            # Trim plaintext to the original size specified by client
            plaintext = plaintext[:orig_file_size]
            if debug_mode:print(f"[SERVER] after trim: len(plaintext)={len(plaintext)}, orig_file_size={orig_file_size}")
            # Write plaintext to disk
            with open(file_name, "wb") as f:
                f.write(plaintext)
            print(f"length of the plaintext= {len(plaintext)}, original file size={orig_file_size}")
            if debug_mode:
                print("==== SERVER DEBUG ====")
                print(f"File name: {file_name}")
                print(f"orig_file_size (from header)={orig_file_size}")
                print(f"len(plaintext after decrypt)={len(plaintext)}")
                print(f"CRC of plaintext (dec)={zlib.crc32(plaintext) & 0xFFFFFFFF}, "
                  f"hex=0x{zlib.crc32(plaintext) & 0xFFFFFFFF:08X}")
                print("======================")
            # Respond with 1603 including server-side CRC
            answer_1603(client_id, version, file_name, content_size, plaintext,session)
        if packet_num > total_packets:
            print(f'the packet number: {packet_num} is greater than the total: {total_packets}')

def answer_1604(client_id,version,session:ClientSession):
    """
    Send response 1604: file transfer finished (client already knows if CRC was valid).

    Also prints the most recent state of the client in clients_info.
    """
    if debug_mode: print("inside answer 1604")
    message = message_answer(version, "1604", "16", client_id)
    print("file transferring success if the the CRC is valid. Otherwise failed.")
    client_name=name_of_dict_from_id(client_id)
    tmp = [base64.b64encode(clients_info[client_name][0]).decode('utf-8'), base64.b64encode(clients_info[client_name][1]).decode('utf-8'), clients_info[client_name][2],clients_info[client_name][3]]
    print(f'this is the recent client information on {client_name}:  {tmp}')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["answer_1604",str(datetime.datetime.now())])
    session.send(message)

def request_900(payload_info,version,client_id,session:ClientSession):
    """
    Handle request 900: client confirms valid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log success and send 1604.
    """
    if debug_mode: print("inside request 900")
    file_name=payload_info.decode()
    file_name = file_name.rstrip('\x00')
    print(f'file name: {file_name} came with valid CRC, sending confirmation ')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_900",str(datetime.datetime.now())])
    answer_1604(client_id,version,session)

def request_901(payload_info,version,client_id,session:ClientSession):
    """
    Handle request 900: client confirms valid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log success and send 1604.
    """
    if debug_mode: print("inside request 901")
    file_name = payload_info.decode()
    print(f'file name: {file_name} came with invalid CRC from client id: {client_id},version:{version}')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_901",str(datetime.datetime.now())])
    if debug_mode: print('waiting for request 828')

def request_902(payload_info,version,client_id,session:ClientSession):
    """
    Handle request 902: client reports invalid CRC after max retries.

    Payload:
    - filename (UTF-8)

    Behavior:
    - Logs failure and sends 1604 (transfer finished with error).
    """
    if debug_mode: print("inside request 902")
    file_name=payload_info.decode()
    print(f'file name: {file_name} came with invalid CRC on the 4th time')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_902",str(datetime.datetime.now())])
    answer_1604(client_id,version,session)
def answer_1607(client_id,version,text,session:ClientSession):
    """
    Send response 1607: protocol-level error.
    Client must abort the current flow and must not continue with subsequent requests.

    Also prints the most recent state of the client in clients_info.
    """
    if debug_mode: print("inside answer 1607")
    payload = client_id + text.encode("utf-8")
    message = message_answer(version, "1607", str(len(payload)), payload)
    print(f"error occurred: {text}")
    client_name=name_of_dict_from_id(client_id)
    if client_name !=None:
        if isinstance(clients_info[client_name][1],str) :
            public_key_tmp=clients_info[client_name][1]
        else:
            public_key_tmp=base64.b64encode(clients_info[client_name][1]).decode('utf-8')

        tmp = [base64.b64encode(clients_info[client_name][0]).decode('utf-8'), public_key_tmp, clients_info[client_name][2],clients_info[client_name][3]]
        print(f'this is the recent client information on {client_name}:  {tmp}')
        clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["answer_1607",str(datetime.datetime.now())])
    session.send(message)

ans=input("do you wish to see debug console promts? answer 'yes' or something else for no ")
debug_mode=True if ans.lower()=="yes" else False
router.answer_1607 = answer_1607
router.request_825 = request_825
router.request_826 = request_826
router.request_827 = request_827
router.request_828 = request_828
router.request_900 = request_900
router.request_901 = request_901
router.request_902 = request_902
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    print("socket binded to %s" % PORT)
    s.listen(5)
    print("socket is listening")
    c, addr = s.accept()
    session = ClientSession(c, debug_mode)
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
