import datetime
import base64
import zlib
def message_answer(version:bytes,code_num:str,payload_size:str,payload:bytes,session):
    """
    Build a binary response frame to send to the client.

    Frame format:
    - 1 byte: version
    - 2 bytes: code (little-endian)
    - 4 bytes: payload size (little-endian)
    - N bytes: payload
    """
    if session.debug_mode: print("making the message and sending it")
    message = (
            int(version).to_bytes(1, 'little') +
            int(code_num).to_bytes(2, 'little') +
            int(payload_size).to_bytes(4, 'little') +
            payload
    )
    if session.debug_mode: print(message)
    return message

def answer_1600(client_id,version,session):
    """
        Send response 1600: registration succeeded.

        Payload:
        - 16 bytes: client_id (client_id (persistent identifier) as bytes)

        Side effects:
        - Logs the event in clients_recent_log
        - Prints the client_id in Base64 for debugging
        """
    if session.debug_mode: print("inside answer 1600")
    store = session.store
    store.clients_recent_log[client_id].append(["answer_1600",str(datetime.datetime.now())])
    message=message_answer(version,"1600","16",client_id,session)
    print(f"sign on succeed for {base64.b64encode(client_id).decode('utf-8')}")
    session.send(message)

def answer_1601(version,session):
    """
    Send response 1601: registration failed (username already exists or invalid).

    No payload.
    """
    if session.debug_mode: print("inside answer 1601")
    message = message_answer(version, "1601", "0",b"",session)
    print(f"sign on failed")
    session.send(message)
    #send error in answer format
def answer_1602(cipher_text_aes_encrypted,client_id,version,session):
    """
    Send response 1602: AES key encrypted with client's RSA public key.

    Payload:
    - RSA-encrypted AES key (ciphertext)
    - 16 bytes client_id

    Also updates last_seen and logs the event.
    """
    if session.debug_mode: print("inside answer 1602")
    store = session.store
    payload = cipher_text_aes_encrypted + client_id
    message = message_answer(version, "1602", str(len(payload)), payload,session)
    print(f"got the {store.name_of_dict_from_id(client_id)}'s public key, sending the encrypted AES key")
    store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    store.clients_recent_log[client_id].append(["answer_1602",str(datetime.datetime.now())])
    session.send(message)

def answer_1606(client_id,version,name,session):
    """
    Send response 1606: re-login / sign-on rejected.

    Reasons:
    - Client is not registered (unknown client_id (persistent identifier))
    - Stored public key is invalid (e.g., wrong size or format)
    """
    if session.debug_mode: print("inside answer 1606")
    store = session.store
    message = message_answer(version, "1606", "16", client_id,session)
    print(f'request for sign on for {base64.b64encode(client_id).decode('utf-8')} rejected (client is not register or the public key is invalid. need to re-register)')
    if client_id==b'\x00'*16:
        store.clients_recent_log[name].append(["answer_1606", str(datetime.datetime.now())])
    else:
        store.clients_recent_log[client_id].append(["answer_1606", str(datetime.datetime.now())])
        store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    session.send(message)

def answer_1605(cipher_text_aes_encrypted,client_id,version,session):
    """
    Send response 1605: re-login approved.

    Payload:
    - RSA-encrypted AES key
    - 16 bytes client_id
    """
    if session.debug_mode: print("inside answer 1605")
    store = session.store
    message = message_answer(version, "1605", str(len(cipher_text_aes_encrypted+client_id)), cipher_text_aes_encrypted+client_id,session)
    print(f'request for sign on for {base64.b64encode(client_id).decode('utf-8')} succeed, sending the encrypted AES key')
    store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    store.clients_recent_log[client_id].append(["answer_1605",str(datetime.datetime.now())])
    session.send(message)
def answer_1603(client_id,version,file_name,content_size,decrypted_total,session):
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
    if session.debug_mode: print("inside answer 1603")
    store = session.store
    store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    store.clients_recent_log[client_id].append(["answer_1603",str(datetime.datetime.now())])
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
    if(session.debug_mode):print(f"server CRC dec={checksum}, hex=0x{checksum:08X}")

    # Send 1603 response with CRC to client
    message = message_answer(version, 1603, len(payload), payload,session)
    print(f'received {file_name} with valid CRC ')
    session.send(message)
def answer_1604(client_id,version,session):
    """
    Send response 1604: file transfer finished (client already knows if CRC was valid).

    Also prints the most recent state of the client in clients_info.
    """
    if session.debug_mode: print("inside answer 1604")
    store = session.store
    message = message_answer(version, "1604", "16", client_id,session)
    print("file transferring success if the the CRC is valid. Otherwise failed.")
    client_name=store.name_of_dict_from_id(client_id)
    tmp = [base64.b64encode(store.clients_info[client_name][0]).decode('utf-8'), base64.b64encode(store.clients_info[client_name][1]).decode('utf-8'), store.clients_info[client_name][2],store.clients_info[client_name][3]]
    print(f'this is the recent client information on {client_name}:  {tmp}')
    store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    store.clients_recent_log[client_id].append(["answer_1604",str(datetime.datetime.now())])
    session.send(message)
def answer_1607(client_id,version,text,session):
    """
    Send response 1607: protocol-level error.
    Client must abort the current flow and must not continue with subsequent requests.

    Also prints the most recent state of the client in clients_info.
    """
    if session.debug_mode: print("inside answer 1607")
    store = session.store
    payload = client_id + text.encode("utf-8")
    message = message_answer(version, "1607", str(len(payload)), payload,session)
    print(f"error occurred: {text}")
    client_name=store.name_of_dict_from_id(client_id)
    if client_name !=None:
        if isinstance(store.clients_info[client_name][1],str) :
            public_key_tmp=store.clients_info[client_name][1]
        else:
            public_key_tmp=base64.b64encode(store.clients_info[client_name][1]).decode('utf-8')

        tmp = [base64.b64encode(store.clients_info[client_name][0]).decode('utf-8'), public_key_tmp, store.clients_info[client_name][2],store.clients_info[client_name][3]]
        print(f'this is the recent client information on {client_name}:  {tmp}')
        store.clients_info[store.name_of_dict_from_id(client_id)][2] = str(datetime.datetime.now())
    store.clients_recent_log[client_id].append(["answer_1607",str(datetime.datetime.now())])
    session.send(message)