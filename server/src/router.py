import uuid
from src import answers
from src import handlers
def handle_frame(frame:bytes,session):
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

    session.log.request_id = uuid.uuid4().hex
    if len(frame)<17:
        session.log.warning(f"short frame (<17), request_id={session.log.request_id}")
        return
    client_id = frame[:16]
    version = frame[16]
    try:
        if len(frame)<23:
            answers.answer_1607(client_id, version, "request length too short, missing code number/payload size",session)
            return
        code_num = str(int.from_bytes(frame[17:19], 'little'))
        payload_size = int.from_bytes(frame[19:23], 'little')

        session.log.info(f"frame received code={code_num} payload_size={payload_size}")

        if len(frame)<23+payload_size:
            answers.answer_1607(client_id, version, "request length too short from the actual payload size",session)
            return

        payload_info = frame[23:23 + payload_size]
        if code_num=="825":
            handlers.request_825(payload_info, version,session)
        elif code_num=="827":
            handlers.request_827(client_id,payload_info, version,session)
        elif code_num == "826":
            handlers.request_826(client_id, payload_info, version,session)
        elif code_num == "828":
            handlers.request_828(payload_info,version,client_id,session)
        elif code_num == "900":
            handlers.request_900(payload_info, version, client_id,session)
        elif code_num == "901":
            handlers.request_901(payload_info, version, client_id,session)
        elif code_num == "902":
            handlers.request_902(payload_info, version, client_id,session)
        else:
            answers.answer_1607(client_id, version, "unknown code",session)
    except Exception:
        session.log.exception(f"unhandled exception in handle_frame")
        try:
            answers.answer_1607(client_id,version,"generic error in server, please try again later",session)
        except Exception:
            pass
    finally:
        session.request_id=None
        session.log.request_id = "-"