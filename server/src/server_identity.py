import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

TRANSCRIPT_CONTEXT = b"SEFTP_STAGE7_SERVER_HELLO"
PRIVATE_KEY_MODE = 0o600
AES_KEY_BINDING_CONTEXT = b"SEFTP_STAGE7_AES_KEY_BINDING"

def _set_owner_only_permissions(path: str):
    os.chmod(path, PRIVATE_KEY_MODE)

def load_or_create_server_identity(path: str):
    if os.path.exists(path):
        _set_owner_only_permissions(path)
        with open(path, "rb") as f:
            key_data = f.read()
        try:
            return RSA.import_key(key_data)
        except (ValueError, TypeError,IndexError) as exc:
            raise RuntimeError(f"server identity key exists but is invalid: {path}") from exc

    private_key = RSA.generate(2048)

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    with open(path, "wb") as f:
        f.write(private_key.export_key(format="PEM"))

    _set_owner_only_permissions(path)

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

def test_server_identity_truncated_existing_file_fails_startup(tmp_path):
    key_path = tmp_path / "server_identity.pem"

    key = load_or_create_server_identity(str(key_path))
    assert key is not None

    data = key_path.read_bytes()
    assert len(data) > 40

    key_path.write_bytes(data[:40])

    with pytest.raises(RuntimeError, match="server identity key exists but is invalid"):
        load_or_create_server_identity(str(key_path))

    assert key_path.read_bytes() == data[:40]

def sign_aes_key_binding(private_key,security_version: int,client_nonce: bytes,server_nonce: bytes,
    client_id: bytes,response_code: int,encrypted_key: bytes) -> bytes:
    transcript = (
        AES_KEY_BINDING_CONTEXT +
        int(security_version).to_bytes(1, "little") +
        client_nonce +
        server_nonce +
        client_id +
        int(response_code).to_bytes(2, "little") +
        encrypted_key
    )

    digest = SHA256.new(transcript)
    return pkcs1_15.new(private_key).sign(digest)