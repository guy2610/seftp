import datetime
import base64
from src.server_identity import sign_aes_key_binding
import zlib

def _build_bound_aes_key_payload(cipher_text_aes_encrypted: bytes, client_id: bytes, response_code: int, session) -> bytes:
    if not session.handshake_verified:
        raise RuntimeError("cannot send AES key before Stage 7 handshake completion")

    if session.security_version is None or session.client_nonce is None or session.server_nonce is None:
        raise RuntimeError("missing Stage 7 handshake state for AES key binding")

    signature = sign_aes_key_binding(
        session.server_identity_key,
        session.security_version,
        session.client_nonce,
        session.server_nonce,
        client_id,
        response_code,
        cipher_text_aes_encrypted,
    )

    if len(cipher_text_aes_encrypted) > 65535:
        raise ValueError("encrypted AES key too large")

    if len(signature) > 65535:
        raise ValueError("AES key binding signature too large")

    return (
        client_id +
        len(cipher_text_aes_encrypted).to_bytes(2, "little") +
        cipher_text_aes_encrypted +
        len(signature).to_bytes(2, "little") +
        signature
    )

def message_answer(version:bytes,code_num:str,payload_size:str,payload:bytes,session):
    """
    Build a binary response frame to send to the client.

    Frame format:
    - 1 byte: version
    - 2 bytes: code (little-endian)
    - 4 bytes: payload size (little-endian)
    - N bytes: payload
    """
    if not isinstance(version, (bytes, bytearray)) or len(version) != 1:
        raise ValueError("version must be exactly 1 byte")
    if int(payload_size) != len(payload):
        raise ValueError("payload_size mismatch")
    session.log.debug("making the message and sending it")
    message = (
            version + # int(version).to_bytes(1, 'little')
            int(code_num).to_bytes(2, 'little') +
            int(payload_size).to_bytes(4, 'little') +
            payload
    )
    session.log.debug(message)
    return message

async def answer_1600(client_id,version,session):
    """
        Send response 1600: registration succeeded.

        Payload:
        - 16 bytes: client_id (client_id (persistent identifier) as bytes)

        Side effects:
        - Logs the event in clients_recent_log
        - Prints the client_id in Base64 for debugging
        """
    session.log.debug("inside answer 1600")
    store = session.store
    store.clients_recent_log[client_id].append(["answer_1600",str(datetime.datetime.now())])
    message=message_answer(version,"1600","16",client_id,session)
    session.log.info(f"sign on succeed for {base64.b64encode(client_id).decode('utf-8')}")
    await session.send(message)

async def answer_1601(version,session):
    """
    Send response 1601: registration failed (username already exists or invalid).

    No payload.
    """
    session.log.debug("inside answer 1601")
    message = message_answer(version, "1601", "0",b"",session)
    session.log.info("sign on failed")
    await session.send(message)
    #send error in answer format
async def answer_1602(cipher_text_aes_encrypted,client_id,version,session):
    """
    Send response 1602: AES key encrypted with client's RSA public key.

    Payload:
    - RSA-encrypted AES key (ciphertext)
    - 16 bytes client_id

    Also updates last_seen and logs the event.
    """
    session.log.debug("inside answer 1602")
    store = session.store
    payload = _build_bound_aes_key_payload(cipher_text_aes_encrypted, client_id, 1602, session)
    message = message_answer(version, "1602", str(len(payload)), payload, session)
    client_record = store.get_client_by_id(client_id.hex())
    client_name = client_record.username if client_record is not None else "<unknown>"
    session.log.info("sending encrypted AES key to %s", client_name)

    store.touch_client_last_seen(client_id.hex())
    store.clients_recent_log[client_id].append(["answer_1602", str(datetime.datetime.now())])
    await session.send(message)

async def answer_1606(client_id,version,name,session):
    """
    Send response 1606: re-login / sign-on rejected.

    Reasons:
    - Client is not registered (unknown client_id (persistent identifier))
    - Stored public key is invalid (e.g., wrong size or format)
    """
    session.log.debug("inside answer 1606")
    store = session.store
    message = message_answer(version, "1606", "16", client_id,session)
    name_or_id = name if name else base64.b64encode(client_id).decode("utf-8")
    session.log.info(f"relogin rejected for {name_or_id}")
    if client_id==b'\x00'*16:
        store.clients_recent_log[name].append(["answer_1606", str(datetime.datetime.now())])
    else:
        store.clients_recent_log[client_id].append(["answer_1606", str(datetime.datetime.now())])
        store.touch_client_last_seen(client_id.hex())
    await session.send(message)

async def answer_1605(cipher_text_aes_encrypted,client_id,version,session):
    """
    Send response 1605: re-login approved.

    Payload:
    - RSA-encrypted AES key
    - 16 bytes client_id
    """
    session.log.debug("inside answer 1605")
    store = session.store
    payload = _build_bound_aes_key_payload(cipher_text_aes_encrypted, client_id, 1605, session)
    message = message_answer(version, "1605", str(len(payload)), payload, session)
    session.log.info(f"relogin approved for {base64.b64encode(client_id).decode('utf-8')}; sending encrypted AES key")
    store.touch_client_last_seen(client_id.hex())
    store.clients_recent_log[client_id].append(["answer_1605",str(datetime.datetime.now())])
    await session.send(message)

async def answer_1603(client_id,version,file_name,content_size,crc32_val,session):
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
    session.log.debug("inside answer 1603")
    store = session.store
    store.touch_client_last_seen(client_id.hex())
    store.clients_recent_log[client_id].append(["answer_1603",str(datetime.datetime.now())])
    # Compute CRC32 over the decrypted plaintext
    checksum=crc32_val
    checksum_bytes = checksum.to_bytes(4, "little")
    content_size_bytes = content_size.to_bytes(4, "little")
    file_name_bytes = file_name.encode("utf-8")+ b"\x00"

    # Build binary payload:
    #   client_id (16 bytes)
    #   content_size (4 bytes)
    #   file_name (UTF-8)
    #   checksum (4 bytes, CRC32)
    payload = client_id + content_size_bytes + file_name_bytes + checksum_bytes
    session.log.debug(f"server CRC dec={checksum}, hex=0x{checksum:08X}")

    # Send 1603 response with CRC to client
    message = message_answer(version, "1603", str(len(payload)), payload,session)
    session.log.info(f'received {file_name} with valid CRC ')
    await session.send(message)
async def answer_1604(client_id,version,session):
    """
    Send response 1604: file transfer finished (client already knows if CRC was valid).

    Also prints the most recent state of the client in clients_info.
    """
    session.log.debug("inside answer 1604")
    store = session.store
    message = message_answer(version, "1604", "16", client_id,session)
    session.log.info("file transferring success if the the CRC is valid. Otherwise failed.")
    client_record = store.get_client_by_id(client_id.hex())
    if client_record is not None:
        client_name = client_record.username
        public_key_tmp = (
            base64.b64encode(client_record.public_key_der).decode('utf-8')
            if client_record.public_key_der is not None
            else None
        )
        tmp = [
            client_record.client_id_hex,
            public_key_tmp,
            client_record.last_seen,
            client_record.aes_key_b64,
        ]
        session.log.info(f'this is the recent client information on {client_name}: {tmp}')
        store.touch_client_last_seen(client_record.client_id_hex)

    store.clients_recent_log[client_id].append(["answer_1604", str(datetime.datetime.now())])
    await session.send(message)

async def answer_1607(client_id,version,text,session):
    """
    Send response 1607: protocol-level error.
    Client must abort the current flow and must not continue with subsequent requests.

    Also prints the most recent state of the client in clients_info.
    """
    session.log.debug("inside answer 1607")
    if getattr(session, "runtime_metrics", None) is not None:
        await session.runtime_metrics.inc_responses_1607()
    store = session.store
    payload = client_id + text.encode("utf-8")
    message = message_answer(version, "1607", str(len(payload)), payload,session)
    session.log.info(f"error occurred: {text}")

    client_record = store.get_client_by_id(client_id.hex())
    if client_record is not None:
        client_name = client_record.username
        if client_record.public_key_der is None:
            public_key_tmp = None
        elif isinstance(client_record.public_key_der, str):
            public_key_tmp = client_record.public_key_der
        else:
            public_key_tmp = base64.b64encode(client_record.public_key_der).decode('utf-8')

        tmp = [
            client_record.client_id_hex,
            public_key_tmp,
            client_record.last_seen,
            client_record.aes_key_b64,
        ]
        session.log.info(f'this is the recent client information on {client_name}:  {tmp}')
        store.touch_client_last_seen(client_record.client_id_hex)
    store.clients_recent_log[client_id].append(["answer_1607",str(datetime.datetime.now())])
    await session.send(message)

async def answer_1608(version, security_version, server_nonce, server_public_key_der, signature, session):
    session.log.debug("inside answer 1608")

    if len(server_nonce) != 32:
        raise ValueError("server_nonce must be exactly 32 bytes")

    if not (0 <= int(security_version) <= 255):
        raise ValueError("security_version must fit in one byte")

    if len(server_public_key_der) > 65535:
        raise ValueError("server_public_key_der too large")

    if len(signature) > 65535:
        raise ValueError("signature too large")

    payload = (
        int(security_version).to_bytes(1, "little") +
        server_nonce +
        len(server_public_key_der).to_bytes(2, "little") +
        server_public_key_der +
        len(signature).to_bytes(2, "little") +
        signature
    )

    message = message_answer(version, "1608", str(len(payload)), payload, session)
    session.log.info("sending stage7 SERVER_HELLO")
    await session.send(message)
