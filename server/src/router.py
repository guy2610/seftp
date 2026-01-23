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
    if session.debug_mode: print("inside the frame handler")
    if len(frame)<17:
        return
    client_id = frame[:16]
    version = frame[16]
    try:
        if len(frame)<23:
            answer_1607(client_id, version, "request length too short, missing code number/payload size",session)
            return
        code_num = str(int.from_bytes(frame[17:19], 'little'))
        payload_size = int.from_bytes(frame[19:23], 'little')
        if len(frame)<23+payload_size:
            answer_1607(client_id, version, "request length too short from the actual payload size",session)
            return
        if session.debug_mode: print(f'this is the code num: {str(code_num)}')
        if session.debug_mode: print(f'this is the size of the payload: {payload_size}')
        payload_info = frame[23:23 + payload_size]
        if session.debug_mode: print(f'this is the payload: {payload_info}')
        if code_num=="825":
            request_825(payload_info, version,session)
        elif code_num=="827":
            request_827(client_id,payload_info, version,session)
        elif code_num == "826":
            request_826(client_id, payload_info, version,session)
        elif code_num == "828":
            request_828(payload_info,version,client_id,session)
        elif code_num == "900":
            request_900(payload_info, version, client_id,session)
        elif code_num == "901":
            request_901(payload_info, version, client_id,session)
        elif code_num == "902":
            request_902(payload_info, version, client_id,session)
        else:
            answer_1607(client_id, version, "unknown code",session)
    except Exception as e:
        print(e)
        answer_1607(client_id,version,"generic error in server, please try again later",session)