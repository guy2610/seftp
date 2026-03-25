import os.path
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
import sys
import  logging
from src import answers
import asyncio

async def request_825(payload_info,version,session):
    """
    Handle request 825: initial registration.

    Payload:
    - Null-terminated UTF-8 username

    Behavior:
    - If username does not exist: create a persistent client_id (used across sessions), store it in clients_info, reply with 1600.
    - If username exists: reply with 1601.
    """
    session.log.debug("inside request 825")
    store = session.store
    payload_info=payload_info.rstrip(b'\x00').decode()
    name = payload_info.strip()
    if not store.client_exists_by_username(name):
        client_id_hex = store.create_client(name)
        session.log.info(f'{name} has created.')
        client_id = bytes.fromhex(client_id_hex)
        if name in store.clients_recent_log.keys():
            user_past_log=store.clients_recent_log.get(name)
            store.clients_recent_log[client_id].extend(user_past_log)
            store.clients_recent_log.pop(name)
        store.clients_recent_log[client_id].append(["request_825",str(datetime.datetime.now())])
        await answers.answer_1600(client_id, version,session)
    else:
        session.log.info(f'{payload_info} is in the clients info')
        await answers.answer_1601(version,session)
async def request_826(client_id, payload_info: bytes, version,session):
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
    session.log.debug("inside request 826")
    store=session.store
    client_id_hex = client_id.hex()

    client_row = store.get_client_by_id(client_id_hex)
    if client_row is None:
        session.log.info(f'uuid not in clients db; client_id={client_id!r}')
        await answers.answer_1607(client_id, version, "unknown client id", session)
        return

    name_in_db = client_row[1]
    store.touch_client_last_seen(client_id_hex)
    store.clients_recent_log[client_id].append(["request_826",str(datetime.datetime.now())])

    sep = payload_info.find(b'\x00')
    if sep <= 0:
        session.log.warning("bad 826 payload: missing NUL after name")
        await answers.answer_1607(client_id,version,"bad 826 payload: missing NUL after name",session)
        return

    raw_name = payload_info[:sep]
    public_key_raw = payload_info[sep + 1:]

    try:
        name = raw_name.decode('utf-8').strip()
    except UnicodeDecodeError:
        session.log.error("bad 826 payload: name is not valid UTF-8")
        await answers.answer_1607(client_id, version, "bad 826 payload: name is not valid UTF-8",session)
        return
    if name != name_in_db:
        session.log.warning(f'name mismatch: got {name!r}, expected {name_in_db!r}')
        await answers.answer_1607(client_id, version, f'name mismatch: got {name!r}, expected {name_in_db!r}',session)
        return

    session.log.info(f"{name} logged successfully")

    public_blob = public_key_raw.rstrip(b'\x00').strip()  #text in Base64
    try:
        public_str = public_blob.decode('ascii')
    except UnicodeDecodeError:
        session.log.error("bad 826 payload: public key is not ASCII base64")
        await answers.answer_1607(client_id, version, "bad 826 payload: public key is not ASCII base64",session)
        return
    session.log.debug("public_blob len:", len(public_str))  #need to be approx 392

    try:
        der = b64decode(public_str, validate=True)
    except Exception:
        session.log.error("bad 826 payload: key is not valid Base64")
        await answers.answer_1607(client_id, version, "bad 826 payload: key is not valid Base64", session)
        return
    try:
        key_rsa = RSA.import_key(der)
        if session.log.isEnabledFor(logging.DEBUG):
            session.log.debug(f"{name} has this RSA key: {key_rsa.export_key().decode()} with the size: {key_rsa.size_in_bits()}")  # size need to be 2048
        if key_rsa.has_private():
            await answers.answer_1606(client_id, version, name,session)
            return
        if key_rsa.size_in_bits()!=2048:
            await answers.answer_1606(client_id, version, name,session)
            return
        e = int(key_rsa.e)
        if e < 3 or e % 2 == 0:
            await answers.answer_1606(client_id, version, name,session)
            return
    except Exception as e:
        session.log.error(f"RSA validation/import failed for 826: {e}")
        await answers.answer_1607(client_id, version, "Invalid RSA public key",session)
        return

    store.set_client_public_key(client_id_hex, der) #keep DER, not Base64

    # generate AES key
    key = get_random_bytes(32)
    aes_key_b64 = base64.b64encode(key).decode('ascii')
    store.set_client_aes_key(client_id_hex, aes_key_b64)

    # encrypt AES key with RSA public
    cipher = PKCS1_OAEP.new(key_rsa)
    ciphertext = cipher.encrypt(key)

    if session.log.isEnabledFor(logging.DEBUG):
        session.log.debug(
            f"the user: {name} has client_id={client_id_hex} and this is the aes key encrypted by the public key: "
            f"{base64.b64encode(ciphertext).decode('utf-8')}"
        )
    # send 1602 aes key
    await answers.answer_1602(ciphertext, client_id, version,session)

async def request_827(client_id,payload_info:bytes,version,session):
    """
        Handle request 827: "single sign-on" / re-login.

        Payload:
        - username (UTF-8, null-terminated)

        Behavior:
        - If username not in clients_info: send 1606 with zero client_id.
        - If public key is invalid: send 1606 with actual client_id.
        - Otherwise: generate new AES key, encrypt with stored public key, reply with 1605.
        """
    session.log.debug("inside request 827")
    store=session.store
    try:
        name = payload_info.rstrip(b'\x00').decode().strip()
    except UnicodeDecodeError:
        session.log.info("bad 827 payload: name is not valid UTF-8")
        await answers.answer_1606(b'\x00' * 16, version, "", session)
        return
    client_row = store.get_client_by_username(name)
    if client_row is None:
        #the user doesnt exist
        session.log.info(f'the user {name} not in the clients db')
        store.clients_recent_log[name].append(["request_827",str(datetime.datetime.now())])
        await answers.answer_1606(b'\x00'*16, version,name,session)
        return
    stored_client_id_hex = client_row[0]
    store_pub_key = client_row[2]

    if stored_client_id_hex != client_id.hex():
        session.log.info(f'the user {name} has another id')
        store.clients_recent_log[name].append(["request_827", str(datetime.datetime.now())])
        await answers.answer_1606(b'\x00' * 16, version, name, session)
        return
    if not store_pub_key:
        session.log.info(f'the user {name} has no stored public key')
        await answers.answer_1606(client_id, version, name, session)
        return

    store.touch_client_last_seen(client_id.hex())
    store.clients_recent_log[client_id].append(["request_827",str(datetime.datetime.now())])
    try:
        pub = RSA.import_key(store_pub_key)
    except Exception as e:
        session.log.info(f"stored public key for {name} is invalid: {e}")
        await answers.answer_1606(client_id, version, name, session)
        return
    if pub.size_in_bits()!=2048:
        session.log.info(f"the public key: [{store_pub_key}] in request 827 is not valid the len needs to be 2048 and is {str(len(store_pub_key))}")
        await answers.answer_1606(client_id,version,name,session)
        return

    # generate aes key
    key = get_random_bytes(32)
    aes_key_b64 = base64.b64encode(key).decode('ascii')
    store.set_client_aes_key(client_id.hex(), aes_key_b64)

    cipher = PKCS1_OAEP.new(pub)
    ciphertext = cipher.encrypt(key)
    session.log.info("request to sign on succeed")
    if session.log.isEnabledFor(logging.DEBUG):
        session.log.debug(f'the name: {name} has this list {client_row}.\nand this is the aes key encrypted by the public key [{ciphertext}]')
    await answers.answer_1605(ciphertext, client_id, version,session)

def _draw_progress(packet_num, total_packets, chunk_size):
    percent = packet_num / total_packets * 100
    sys.stderr.write(f"\rgot packet with chunk size={chunk_size}, {percent:.2f}% complete")
    sys.stderr.flush()

    if packet_num == total_packets:
        sys.stderr.write("\n")
        sys.stderr.flush()
def finalize_upload(file_path, cipher_bytes, iv, expected_size,aes_key):
    # AES-256-CBC with random IV
    decrypt_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_all = decrypt_cipher.decrypt(cipher_bytes)
    # Try to remove PKCS#7 padding
    try:
        plaintext = unpad(decrypted_all, AES.block_size)
    except ValueError:
        # In case padding is wrong, keep raw decrypted data
        plaintext = decrypted_all
    # Trim plaintext to the original size specified by client
    plaintext = plaintext[:expected_size]
    # Write plaintext to disk
    with open(file_path, "wb") as f:
        f.write(plaintext)
    # Compute CRC32 over the decrypted plaintext
    return  zlib.crc32(plaintext) & 0xFFFFFFFF , len(plaintext)

def validate_header(session, packet_num, total_packets, content_size, orig_file_size):
    if total_packets <= 0:
        return ("bad_828_range", "bad 828: total_packets not valid")
    if packet_num < 0 or packet_num > total_packets:
        return ("bad_828_range", "bad 828: packet_num out of range")
    if content_size <= 0:
        return ("bad_828_range", "bad 828: content_size not valid")
    if orig_file_size <= 0:
        return ("bad_828_range", "bad 828: orig_file_size not valid")
    if total_packets > session.config.max_packets:
        return ("bad_828_limits", "bad 828: total_packets too large")
    if orig_file_size > session.config.max_file_size:
        return ("bad_828_limits", "bad 828: orig_file_size too large")
    if content_size > session.config.max_file_size:
        return ("bad_828_limits", "bad 828: content_size too large")
    return None

async def request_828(payload_info,version,client_id,session):
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
    session.log.debug("inside request 828")
    store=session.store
    # Parse header fields from payload
    content_size=int.from_bytes(payload_info[:4], byteorder="little")
    orig_file_size=int.from_bytes(payload_info[4:8], byteorder="little")
    packet_num=int.from_bytes(payload_info[8:10], byteorder="little")
    total_packets = int.from_bytes(payload_info[10:12], byteorder="little")
    # Find filename (null-terminated) starting from byte 12
    sep = payload_info[12:].find(b'\x00')
    if sep == -1:
        session.log.info("bad 828 payload: cant find the name of the file")
        await session.release_upload_slot()
        session.reset_transfer_state("bad_828_filename_missing_null")
        return
    try:
        sep += 12  # convert to absolute index inside payload_info
        file_name = payload_info[12:sep].decode('utf-8')
        file_name = os.path.basename(file_name) #absolute path
    except UnicodeDecodeError:
        session.log.error("bad 828 payload: name is not valid UTF-8")
        await answers.answer_1607(client_id, version, "bad 828 payload: name is not valid UTF-8",session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad_828_filename_utf8")
        return
    session.log.debug(sep)
    session.log.debug(file_name)
    # The rest of the payload is the ciphertext chunk
    cipher_chunk = payload_info[sep + 1:]
    client_id_hex = client_id.hex()
    if session.upload_client_id_hex is None:
        client_row = store.get_client_by_id(client_id_hex)
        if client_row is None:
            session.log.info(f'uuid not in clients db; client_id={client_id!r}')
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_client_or_name")
            return
        username = client_row[1]
        aes_key_b64 = client_row[3]
        if not aes_key_b64:
            session.log.info(f'client has no AES key; client_id={client_id!r}')
            await answers.answer_1607(client_id, version, "bad 828: missing AES key", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_missing_aes")
            return
        try:
            session.upload_aes_key = base64.b64decode(aes_key_b64)
        except Exception:
            session.log.info(f'client AES key is invalid base64; client_id={client_id!r}')
            await answers.answer_1607(client_id, version, "bad 828: invalid AES key", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_invalid_aes")
            return
        session.upload_username = username
        session.upload_client_id_hex = client_id_hex
    if session.upload_client_id_hex != client_id_hex:
        session.log.info("bad 828: client id changed during upload")
        await answers.answer_1607(client_id, version, "bad 828: client mismatch during upload", session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad_828_client_mismatch")
        return
    aes_key = session.upload_aes_key
    username = session.upload_username
    err = validate_header(session, packet_num, total_packets, content_size, orig_file_size)
    if err:
        reason, msg = err
        session.log.info(msg)
        try:
            await answers.answer_1607(client_id, version, msg, session)
        except Exception:
            pass
        await session.release_upload_slot()
        session.reset_transfer_state(reason)
        return
    if packet_num==0:
        if session.upload_active or session.transfer_iv:
            session.log.info("bad 828: upload_active or transfer_iv")
            await answers.answer_1607(client_id, version, "bad 828 payload: currently uploading with new upload", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_iv")
            return
        if len(cipher_chunk) < 16:
            session.log.info("bad 828: IV too short")
            await answers.answer_1607(client_id, version, "bad 828 payload: name is not valid UTF-8",session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_iv")
            return
        session.transfer_iv = bytes(cipher_chunk[:16])
        session.expected_packet_num = 1
        session.expected_total_packets = total_packets
        session.expected_content_size=content_size
        session.expected_orig_file_size = orig_file_size
        session.received_cipher_bytes = 0
        if session.log.isEnabledFor(logging.DEBUG):
            session.log.debug(f"IV(hex)={session.transfer_iv.hex()}")
        return
    else:
        if not session.transfer_iv:
            session.log.info("bad 828: missing IV packet")
            if session.upload_id and not store.fail_upload_record(session.upload_id,"missing IV packet", "failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: missing IV packet", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_iv")
            return
        if not session.expected_packet_num:
            session.log.info("bad 828: expected_packet_num is None")
            if session.upload_id and not store.fail_upload_record(session.upload_id,"expected_packet_num is None", "failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: expected packet num is not initialize", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_expected_packet_num")
            return
        if total_packets!=session.expected_total_packets:
            session.log.info("bad 828:total_packets != expected_total_packets")
            if session.upload_id and not store.fail_upload_record(session.upload_id,"total_packets != expected_total_packets" ,"failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828:total_packets != expected_total_packets", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_expected_total_packet")
            return
        if content_size != session.expected_content_size or orig_file_size != session.expected_orig_file_size:
            session.log.info("bad 828: content_size or orig_file_size not as expected")
            if session.upload_id and not store.fail_upload_record(session.upload_id,"content_size or orig_file_size not as expected" , "failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: content_size or orig_file_size not as expected", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828 content_size or orig_file_size")
            return
        if len(cipher_chunk) > session.config.max_chunk_size:
            session.log.info("bad 828: cipher_chunk bigger than the max")
            if session.upload_id and not store.fail_upload_record(session.upload_id,"cipher_chunk bigger than the max" ,"failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: cipher_chunk bigger than the max",session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828 cipher_chunk bigger than the max")
            return
        if packet_num==1:
            if not session.has_upload_slot:
                acquired = await session.upload_limiter.try_acquire()
                if not acquired:
                    session.log.info("upload rejected: max concurrent uploads reached")
                    await answers.answer_1607(client_id, version, "server busy: too many concurrent uploads", session)
                    session.reset_transfer_state("upload_rejected_backpressure")
                    return
                session.has_upload_slot = True
                active_now = await session.upload_limiter.current_active()
                session.log.info(
                    "upload slot acquired file=%s active_uploads=%d max=%d",
                    file_name,
                    active_now,
                    session.config.max_concurrent_uploads,
                )
            session.upload_active = True
            session.upload_filename = file_name
            session.mark_upload_progress()
            sys.stderr.write("\n")
            sys.stderr.flush()
            session.log.info(f"writing the file {file_name} ")
            session.transfer_cipher = bytearray()
            store.touch_client_last_seen(client_id_hex)
            session.upload_id = store.create_upload_record(client_id_hex, file_name, orig_file_size, session.expected_content_size)
            if session.upload_id == None:
                session.log.info("bad 828: upload id is None in db")
                await answers.answer_1607(client_id, version, "bad 828: upload id is None in db", session)
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828 upload id is None in db")
                return
            store.clients_recent_log[client_id].append(["request_828", str(datetime.datetime.now())])
        # Append chunk to the accumulated ciphertext
        _draw_progress(packet_num, total_packets, len(cipher_chunk))
        if session.received_cipher_bytes + len(cipher_chunk) > session.expected_content_size:
            session.log.info("bad 828: content_size will overflow")
            if not store.fail_upload_record(session.upload_id,"content_size will overflow","failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: content_size will overflow",session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828 content_size will overflow")
            return
        if packet_num != session.expected_packet_num:
            session.log.info("bad 828: out of order packet_num=%d expected=%d", packet_num, session.expected_packet_num)
            if not store.fail_upload_record(session.upload_id,"out of order packet_num" ,"failed", str(datetime.datetime.now())):
                session.log.info("bad 828: fail_upload_record problem in db")
                await session.release_upload_slot()
                session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                return
            await answers.answer_1607(client_id, version, "bad 828: out of order", session)
            await session.release_upload_slot()
            session.reset_transfer_state("bad_828_out_of_order")
            return
        session.mark_upload_progress()
        session.transfer_cipher.extend(cipher_chunk)
        session.expected_packet_num += 1
        session.received_cipher_bytes+=len(cipher_chunk)
        session.log.debug(f"[SERVER] accumulated cipher size={len(session.transfer_cipher)}")
        session.log.debug(f'packet number: {packet_num} of {total_packets}')
        # Once we have the last packet, decrypt and write file
        if packet_num == total_packets:
            if session.received_cipher_bytes != session.expected_content_size:
                session.log.info("bad 828: received_cipher_bytes != expected_content_size")
                if not store.fail_upload_record(session.upload_id,"received_cipher_bytes  != expected_content_size" ,"failed", str(datetime.datetime.now())):
                    session.log.info("bad 828: fail_upload_record problem in db")
                    await session.release_upload_slot()
                    session.reset_transfer_state("bad 828: fail_upload_record problem in db")
                    return
                await answers.answer_1607(client_id, version, "bad 828: received_cipher_bytes != expected_content_size",session)
                await session.release_upload_slot()
                session.reset_transfer_state("bad_828 received_cipher_bytes  != expected_content_size")
                return
            store.touch_client_last_seen(client_id_hex)
            cipher_total=bytes(session.transfer_cipher)
            session.log.info(f"final cipher text total size={len(cipher_total)}, expected content size={content_size}")
            # making directory if not exist for user
            base_dir = "data/uploads"
            user_dir = os.path.join(base_dir, username)
            os.makedirs(user_dir, exist_ok=True)
            out_path = os.path.join(user_dir, file_name)
            out_path = os.path.normpath(out_path)
            crc32_val, pt_len = await session.bounded_executor.run(finalize_upload,out_path,cipher_total,session.transfer_iv,orig_file_size,aes_key)
            session.log.info("writing file to %s", out_path)
            session.log.info(f"length of the plaintext= {pt_len}, original file size={orig_file_size}")

            session.upload_path = out_path
            session.upload_crc = crc32_val

            if session.log.isEnabledFor(logging.DEBUG):
                session.log.debug("==== SERVER DEBUG ====")
                session.log.debug(f"File name: {file_name}")
                session.log.debug(f"orig_file_size (from header)={orig_file_size}")
                session.log.debug(f"len(plaintext after decrypt)={pt_len}")
                session.log.debug(f"CRC of plaintext (dec)={crc32_val}, "f"hex=0x{crc32_val:08X}")
                session.log.debug("======================")

            # Respond with 1603 including server-side CRC
            await answers.answer_1603(client_id, version, file_name, content_size, crc32_val,session)

async def request_900(payload_info,version,client_id,session):
    """
    Handle request 900: client confirms valid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log success and send 1604.
    """
    session.log.debug("inside request 900")
    store=session.store
    file_name=payload_info.decode()
    file_name = file_name.rstrip('\x00')
    session.log.info(f'file name: {file_name} came with valid CRC, sending confirmation ')
    store.touch_client_last_seen(client_id.hex())
    store.clients_recent_log[client_id].append(["request_900",str(datetime.datetime.now())])
    if session.upload_id == None or session.upload_path == None or session.upload_crc == None or session.upload_filename == None or file_name != session.upload_filename:
        session.log.info("bad 900: session upload attributes are invalid")
        await answers.answer_1607(client_id, version, "bad 900: session upload attributes are invalid",
                                  session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 900: session upload attributes are invalid")
        return
    if not store.complete_upload_record(session.upload_id, session.upload_path, session.upload_crc, str(datetime.datetime.now())):
        session.log.info("bad 900: complete_upload_record problem in db")
        await answers.answer_1607(client_id, version, "bad 900: complete upload record problem in db",
                                  session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 900: complete_upload_record problem in db")
        return
    await answers.answer_1604(client_id,version,session)
    await session.release_upload_slot()
    session.reset_transfer_state("upload_complete")

async def request_901(payload_info,version,client_id,session):
    """
    Handle request 901: client reports invalid CRC.

    Payload:
    - filename (UTF-8, may include trailing nulls)

    Behavior:
    - Log failure.
    """
    session.log.debug("inside request 901")
    store = session.store
    file_name = payload_info.decode()
    session.log.info(f'file name: {file_name} came with invalid CRC from client id: {client_id},version:{version}')
    store.touch_client_last_seen(client_id.hex())
    now = str(datetime.datetime.now())
    if session.upload_filename == None or file_name != session.upload_filename:
        session.log.info("bad 901: session upload name is invalid")
        await answers.answer_1607(client_id, version, "bad 901: session upload name is invalid",
                                  session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 901: session upload name is invalid")
        return
    if not store.fail_upload_record(session.upload_id,"CRC mismatch", "crc_mismatch",now):
        session.log.info("bad 901: fail_upload_record problem in db")
        await answers.answer_1607(client_id, version, "bad 901: fail_upload_record problem in db",
                                  session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 901: fail_upload_record problem in db")
        return
    await session.release_upload_slot()
    session.reset_transfer_state("bad 901: CRC mismatch")
    store.clients_recent_log[client_id].append(["request_901",now])
    session.log.debug('waiting for request 828')

async def request_902(payload_info,version,client_id,session):
    """
    Handle request 902: client reports invalid CRC after max retries.

    Payload:
    - filename (UTF-8)

    Behavior:
    - Log failure and sends 1604 (transfer finished with error).
    """
    session.log.debug("inside request 902")
    store = session.store
    file_name=payload_info.decode()
    session.log.info(f'file name: {file_name} came with invalid CRC on the 4th time')
    store.touch_client_last_seen(client_id.hex())
    now = str(datetime.datetime.now())
    if session.upload_filename == None or file_name != session.upload_filename:
        session.log.info("bad 902: session upload name is invalid")
        await answers.answer_1607(client_id, version, "bad 901: session upload name is invalid",
                                  session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 902: session upload name is invalid")
        return
    if not store.fail_upload_record(session.upload_id,"invalid CRC on the 4th time", "failed", now):
        session.log.info("bad 902: fail_upload_record problem in db")
        await answers.answer_1607(client_id, version, "bad 902: fail_upload_record problem in db",session)
        await session.release_upload_slot()
        session.reset_transfer_state("bad 902: complete_upload_record problem in db")
        return
    store.clients_recent_log[client_id].append(["request_902",now])
    await answers.answer_1604(client_id,version,session)
    await session.release_upload_slot()
    session.reset_transfer_state("bad 902: invalid CRC on the 4th time")