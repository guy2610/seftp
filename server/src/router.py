import uuid
from src import answers
from src import handlers
async def handle_frame(frame:bytes,session):
    """
     Parse a full frame from the client and dispatch to the correct handler.

     Frame format:
     - 16 bytes: client_id
     - 1 byte: version
     - 2 bytes: code (little-endian)
     - 4 bytes: payload_size (little-endian)
     - N bytes: payload

     Supported codes:
     - 825: registration
     - 826: submit/update public key
     - 827: re-login (SSO)
     - 828: encrypted file chunk
     - 900/901/902: CRC result / retry control
     """

    session.request_id = uuid.uuid4().hex
    session.log.request_id = session.request_id

    if len(frame)<17:
        session.on_frame_bad("short_frame_lt_17")
        session.log.warning(f"short frame (<17), request_id={session.log.request_id}")
        return
    client_id = frame[:16]
    version = frame[16:17]
    session.last_client_id =client_id
    session.last_version=version
    try:
        if len(frame)<23:
            session.on_frame_bad("short_frame_missing_header")
            await answers.answer_1607(client_id, version, "protocol error: missing request header",session)
            session.reset_transfer_state("protocol_error_1607")
            return
        code_num = str(int.from_bytes(frame[17:19], 'little'))
        payload_size = int.from_bytes(frame[19:23], 'little')

        session.log.info(f"frame received code={code_num} payload_size={payload_size}")

        if len(frame)<23+payload_size:
            session.on_frame_bad("short_frame_payload_truncated")
            await answers.answer_1607(client_id, version, "protocol error: truncated payload",session)
            session.reset_transfer_state("protocol_error_1607")
            return

        session.on_frame_ok()
        payload_info = frame[23:23 + payload_size]
        handshake_codes = {"829", "830"}
        if not session.handshake_verified and code_num not in handshake_codes:
            await answers.answer_1607(client_id, version, "stage7 handshake required", session)
            return
        elif session.handshake_verified and code_num in handshake_codes:
            await answers.answer_1607(client_id, version, "stage7 handshake already completed", session)
            return
        elif code_num=="825":
            await handlers.request_825(payload_info, version,session)
        elif code_num=="827":
            await handlers.request_827(client_id,payload_info, version,session)
        elif code_num == "826":
            await handlers.request_826(client_id, payload_info, version,session)
        elif code_num == "828":
            await handlers.request_828(payload_info,version,client_id,session)
        elif code_num == "829":
            await handlers.request_829(payload_info,version,client_id,session)
        elif code_num == "830":
            await handlers.request_830(payload_info, version, client_id, session)
        elif code_num == "900":
            await handlers.request_900(payload_info, version, client_id,session)
        elif code_num == "901":
            await handlers.request_901(payload_info, version, client_id,session)
        elif code_num == "902":
            await handlers.request_902(payload_info, version, client_id,session)
        else:
            session.on_frame_bad("unknown_code")
            await answers.answer_1607(client_id, version, "protocol error: unknown code",session)
            if session.upload_active:
                session.reset_transfer_state("protocol_error_1607")
    except Exception:
        session.on_frame_bad("handle_frame_exception")
        session.log.exception(f"unhandled exception in handle_frame")
        if session.disconnect_reason == "send_error":
            raise
        try:
            await answers.answer_1607(client_id,version,"server error: internal handler failure",session)
        except Exception:
            pass
        finally:
            if session.upload_active:
                session.reset_transfer_state("protocol_error_1607")
    finally:
        session.request_id = "-"
        try:
            session.log.request_id = "-"
        except Exception:
            pass