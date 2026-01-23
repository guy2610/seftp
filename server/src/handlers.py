import uuid
import datetime
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import zlib
from Crypto.Util.Padding import unpad
import base64
def request_825(payload_info,version,session):
    """
    Handle request 825: initial registration.

    Payload:
    - Null-terminated UTF-8 username

    Behavior:
    - If username does not exist: create a persistent client_id (used across sessions), store it in clients_info, reply with 1600.
    - If username exists: reply with 1601.
    """
    if session.debug_mode: print("inside request 825")
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
def request_826(client_id, payload_info: bytes, version,session):
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
    if session.debug_mode: print("inside request 826")
    global clients_info
    name_in_dict = name_of_dict_from_id(client_id)
    clients_info[name_in_dict][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_826",str(datetime.datetime.now())])
    if not name_in_dict:
        if session.debug_mode: print(clients_info)
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
    if session.debug_mode: print("public_blob len:", len(public_str))  #need to be approx 392

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
    if session.debug_mode: print(f'the name: {name} has this list {clients_info[name]}')

    # encrypt AES key with RSA public
    cipher = PKCS1_OAEP.new(key_rsa)
    ciphertext = cipher.encrypt(key)
    tmp=[base64.b64encode(clients_info[name][0]).decode('utf-8'),base64.b64encode(clients_info[name][1]).decode('utf-8'),clients_info[name][2],clients_info[name][3]]
    print(f'the user: {name} has this list {tmp}.\nand this is the aes key encrypted by the public key: {base64.b64encode(ciphertext).decode('utf-8')}')

    # send 1602 aes key
    answer_1602(ciphertext, clients_info[name][0], version,session)
def request_827(client_id,payload_info:bytes,version,session):
    """
        Handle request 827: "single sign-on" / re-login.

        Payload:
        - username (UTF-8, null-terminated)

        Behavior:
        - If username not in clients_info: send 1606 with zero client_id.
        - If public key is invalid: send 1606 with actual client_id.
        - Otherwise: generate new AES key, encrypt with stored public key, reply with 1605.
        """
    if session.debug_mode: print("inside request 827")
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
            if session.debug_mode: print(f'the person with the name: {name} has this list {clients_info[name]}')
            # encrypt aes key
            key_rsa = RSA.importKey(clients_info[name][1])
            cipher = PKCS1_OAEP.new(key_rsa)
            ciphertext = cipher.encrypt(key)
            print("request to sign on succeed")
            print(f'the name: {name} has this list {clients_info[name]}.\nand this is the aes key encrypted by the public key [{ciphertext}]')
            answer_1605(ciphertext, clients_info[name][0], version,session)



def request_828(payload_info,version,client_id,session):
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
    if session.debug_mode: print("inside request 828")
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
    if session.debug_mode: print(sep)
    if session.debug_mode: print(file_name)
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
        if session.debug_mode: print(f"[SERVER] accumulated cipher size={len(session.transfer_cipher)}")
        if session.debug_mode: print(f'packet number: {packet_num} of {total_packets}')
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
            if session.debug_mode:print(f"[SERVER] after trim: len(plaintext)={len(plaintext)}, orig_file_size={orig_file_size}")
            # Write plaintext to disk
            with open(file_name, "wb") as f:
                f.write(plaintext)
            print(f"length of the plaintext= {len(plaintext)}, original file size={orig_file_size}")
            if session.debug_mode:
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

def request_900(payload_info,version,client_id,session):
    """
    Handle request 900: client confirms valid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log success and send 1604.
    """
    if session.debug_mode: print("inside request 900")
    file_name=payload_info.decode()
    file_name = file_name.rstrip('\x00')
    print(f'file name: {file_name} came with valid CRC, sending confirmation ')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_900",str(datetime.datetime.now())])
    answer_1604(client_id,version,session)

def request_901(payload_info,version,client_id,session):
    """
    Handle request 900: client confirms valid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log success and send 1604.
    """
    if session.debug_mode: print("inside request 901")
    file_name = payload_info.decode()
    print(f'file name: {file_name} came with invalid CRC from client id: {client_id},version:{version}')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_901",str(datetime.datetime.now())])
    if session.debug_mode: print('waiting for request 828')

def request_902(payload_info,version,client_id,session):
    """
    Handle request 902: client reports invalid CRC after max retries.

    Payload:
    - filename (UTF-8)

    Behavior:
    - Logs failure and sends 1604 (transfer finished with error).
    """
    if session.debug_mode: print("inside request 902")
    file_name=payload_info.decode()
    print(f'file name: {file_name} came with invalid CRC on the 4th time')
    clients_info[name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    clients_recent_log[client_id].append(["request_902",str(datetime.datetime.now())])
    answer_1604(client_id,version,session)