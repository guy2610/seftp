import os
import stat

from src.server_identity import load_or_create_server_identity


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_server_identity_created_with_owner_only_permissions(tmp_path):
    key_path = tmp_path / "server_identity.pem"

    key = load_or_create_server_identity(str(key_path))

    assert key is not None
    assert key_path.exists()
    assert _mode(key_path) == 0o600


def test_server_identity_existing_file_permissions_are_hardened(tmp_path):
    key_path = tmp_path / "server_identity.pem"

    key = load_or_create_server_identity(str(key_path))
    assert key is not None

    os.chmod(key_path, 0o644)
    assert _mode(key_path) == 0o644

    key2 = load_or_create_server_identity(str(key_path))

    assert key2 is not None
    assert _mode(key_path) == 0o600