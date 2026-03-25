import pytest
import src.store as store
import base64
import json
from pathlib import Path

def make_sql_store(tmp_path):
    s = store.Store()
    db_path = tmp_path / "test.db"
    ok = s.initialize(str(db_path))
    assert ok
    return s


def seed_client(
    s,
    username="alice",
    client_id_hex=None,
    public_key_der=None,
    aes_key_b64="aes_b64",
):
    created_client_id_hex = s.create_client(username)

    if client_id_hex is not None and created_client_id_hex != client_id_hex:
        cur = s.sqliteConnection.cursor()
        cur.execute(
            "UPDATE Clients SET client_id_hex = ? WHERE username = ?",
            (client_id_hex, username),
        )
        s.sqliteConnection.commit()
        created_client_id_hex = client_id_hex

    if public_key_der is not None:
        assert s.set_client_public_key(created_client_id_hex, public_key_der)

    if aes_key_b64 is not None:
        assert s.set_client_aes_key(created_client_id_hex, aes_key_b64)

    return created_client_id_hex


def test_initialize_and_create_client(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = s.create_client("alice")

    assert client_id_hex is not None
    row = s.get_client_by_username("alice")
    assert row is not None
    assert row[0] == client_id_hex
    assert row[1] == "alice"
    assert row[2] is None
    assert row[3] is None


def test_get_client_by_id(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(s, username="alice")

    row = s.get_client_by_id(client_id_hex)
    assert row is not None
    assert row[0] == client_id_hex
    assert row[1] == "alice"


def test_client_exists_helpers(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(s, username="alice")

    assert s.client_exists_by_username("alice") is True
    assert s.client_exists_by_username("bob") is False
    assert s.client_exists_by_id(client_id_hex) is True
    assert s.client_exists_by_id("ff" * 16) is False


def test_set_public_key_and_aes_key(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(
        s,
        username="alice",
        public_key_der=None,
        aes_key_b64=None,
    )

    assert s.set_client_public_key(client_id_hex, b"\x01\x02\x03")
    assert s.set_client_aes_key(client_id_hex, "YWJj")

    row = s.get_client_by_id(client_id_hex)
    assert row[2] == b"\x01\x02\x03"
    assert row[3] == "YWJj"


def test_touch_client_last_seen(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(s, username="alice")
    before = s.get_client_by_id(client_id_hex)[5]

    assert s.touch_client_last_seen(client_id_hex) is True

    after = s.get_client_by_id(client_id_hex)[5]
    assert after >= before


def test_create_and_complete_upload_record(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(s, username="alice")
    upload_id = s.create_upload_record(client_id_hex, "file.bin", 100, 128)

    assert upload_id is not None
    assert s.complete_upload_record(
        upload_id,
        "data/uploads/alice/file.bin",
        123456,
        "2026-03-24T12:00:00",
    )

    uploads = s.get_client_uploads(client_id_hex)
    assert len(uploads) == 1
    assert uploads[0][7] == "completed"
    assert uploads[0][6] == 123456
    assert uploads[0][3] == "data/uploads/alice/file.bin"


def test_fail_upload_record(tmp_path):
    s = make_sql_store(tmp_path)

    client_id_hex = seed_client(s, username="alice")
    upload_id = s.create_upload_record(client_id_hex, "file.bin", 100, 128)

    assert upload_id is not None
    assert s.fail_upload_record(
        upload_id,
        "crc mismatch",
        "crc_mismatch",
        "2026-03-24T12:00:00",
    )

    uploads = s.get_client_uploads(client_id_hex)
    assert len(uploads) == 1
    assert uploads[0][7] == "crc_mismatch"
    assert uploads[0][8] == "crc mismatch"

def test_aes_key_roundtrip_is_valid_base64(tmp_path):
    s = make_sql_store(tmp_path)

    aes_key_b64 = base64.b64encode(b"\x11" * 32).decode("ascii")
    client_id_hex = seed_client(
        s,
        username="alice",
        public_key_der=None,
        aes_key_b64=aes_key_b64,
    )

    row = s.get_client_by_id(client_id_hex)
    assert row[3] == aes_key_b64
    assert base64.b64decode(row[3]) == b"\x11" * 32