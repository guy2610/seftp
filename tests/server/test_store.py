import pytest
import src.store as store
import base64
import json
from pathlib import Path

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "data" / "clients_info.json"
    s = store.Store()
    s.clients_info["alice"] = [b"\x01"*16,b"\x02\x03\x04","2026-02-15","aes_b64_here"]
    s.clients_info["bob"] = [b"\xAA" * 16, None, None, None]
    s.save_clients_info(str(p))
    assert p.exists()

    s2 = store.Store()
    s2.load_client_info(str(p))
    assert set(s2.clients_info.keys()) == {"alice","bob"}

    a = s2.clients_info["alice"]
    assert a[0] == b"\x01" * 16
    assert a[1] == b"\x02\x03\x04"
    assert a[2] == "2026-02-15"
    assert a[3] == "aes_b64_here"

    b = s2.clients_info["bob"]
    assert b[0] == b"\xAA" * 16
    assert b[1] is None
    assert b[2] is None
    assert b[3] is None

def test_save_creates_parent_dir(tmp_path):
    p = tmp_path / "nested" / "dir" / "clients_info.json"
    s = store.Store()
    s.clients_info["u"] = [b"\x10" * 16, b"\x20", "ts", "aes"]
    s.save_clients_info(str(p))
    assert p.exists()
    assert p.parent.exists()

def test_load_missing_file_prints_warning_and_keeps_empty(tmp_path, capsys):
    p = tmp_path / "nope.json"
    s = store.Store()
    s.load_client_info(str(p))
    out = capsys.readouterr().out
    assert "Warning" in out
    assert s.clients_info == {}

def test_load_invalid_json_prints_error_and_keeps_empty(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    s = store.Store()
    s.load_client_info(str(p))
    out = capsys.readouterr().out
    assert "not a valid JSON" in out
    assert s.clients_info == {}

def test_load_bad_client_id_length_skips_user(tmp_path, capsys):
    p = tmp_path / "clients_info.json"
    bad_id = b"\x01" * 15  # invalid length
    data = {
        "baduser": {
            "client_id_b64": b64(bad_id),
            "public_key_b64": b64(b"\x99"),
            "last_seen": "ts",
            "aes_key_b64": "aes",
        },
        "gooduser": {
            "client_id_b64": b64(b"\x02" * 16),
            "public_key_b64": None,
            "last_seen": None,
            "aes_key_b64": None,
        },
    }
    p.write_text(json.dumps(data), encoding="utf-8")
    s = store.Store()
    s.load_client_info(str(p))
    out = capsys.readouterr().out
    assert "Error decoding data for user baduser" in out
    assert "baduser" not in s.clients_info
    assert "gooduser" in s.clients_info
    assert s.clients_info["gooduser"][0] == b"\x02" * 16


def test_name_of_dict_from_id():
    s = store.Store()
    cid1 = b"\x01" * 16
    cid2 = b"\x02" * 16
    s.clients_info["a"] = [cid1, None, None, None]
    s.clients_info["b"] = [cid2, None, None, None]
    assert s.name_of_dict_from_id(cid1) == "a"
    assert s.name_of_dict_from_id(cid2) == "b"
    assert s.name_of_dict_from_id(b"\x03" * 16) is None