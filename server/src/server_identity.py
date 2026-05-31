import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

TRANSCRIPT_CONTEXT = b"SEFTP_STAGE7_SERVER_HELLO"

def load_or_create_server_identity(path: str):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return RSA.import_key(f.read())

    private_key = RSA.generate(2048)

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    with open(path, "wb") as f:
        f.write(private_key.export_key(format="PEM"))

    return private_key



def get_public_key_der(private_key) -> bytes:
    return private_key.publickey().export_key(format="DER")

def sign_server_hello(private_key, security_version, client_nonce, server_nonce, server_public_key_der):
    transcript = (
            TRANSCRIPT_CONTEXT +
            int(security_version).to_bytes(1, "little") +
            client_nonce +
            server_nonce +
            server_public_key_der
    )

    digest = SHA256.new(transcript)

    return pkcs1_15.new(private_key).sign(digest)
