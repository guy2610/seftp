import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last_error = e
            time.sleep(0.1)
    raise RuntimeError(f"server did not open port in time: {last_error}")


def _start_server(
    tmp_path: Path,
    max_connections: int,
    max_connections_per_ip: int,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.Popen, int, Path]:
    repo_root = Path(__file__).resolve().parents[2]
    server_dir = repo_root / "server"
    server_script = server_dir / "server_async.py"

    port = _get_free_port()
    (tmp_path / "port.info").write_text(str(port), encoding="ascii")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(server_dir)
    env["SEFTP_MAX_CONNECTIONS"] = str(max_connections)
    env["SEFTP_MAX_CONNECTIONS_PER_IP"] = str(max_connections_per_ip)
    if extra_env:
        env.update(extra_env)

    log_path = tmp_path / "server.log"
    log_file = open(log_path, "w", encoding="utf-8")

    proc = subprocess.Popen(
        [sys.executable, "-u", str(server_script)],
        cwd=str(tmp_path),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    try:
        _wait_for_port("127.0.0.1", port, timeout=10.0)
        time.sleep(0.5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        raise

    return proc, port, log_path


def _stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


def _open_client(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
    s.settimeout(0.5)
    return s


def _assert_socket_stays_open(sock: socket.socket) -> None:
    time.sleep(0.3)
    try:
        data = sock.recv(1)
        if data == b"":
            raise AssertionError("socket was closed unexpectedly")
        raise AssertionError(f"unexpected data received: {data!r}")
    except socket.timeout:
        return


def _assert_socket_closed_soon(sock: socket.socket) -> None:
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            data = sock.recv(1)
            if data == b"":
                return
            raise AssertionError(f"unexpected data received from rejected socket: {data!r}")
        except socket.timeout:
            time.sleep(0.1)
        except ConnectionResetError:
            return
        except OSError:
            return
    raise AssertionError("socket did not close in time")


def test_total_connection_limit_enforced_and_recovery_works(tmp_path: Path):
    proc, port, log_path = _start_server(
        tmp_path=tmp_path,
        max_connections=2,
        max_connections_per_ip=2,
    )

    s1 = s2 = s3 = s4 = None
    try:
        s1 = _open_client(port)
        s2 = _open_client(port)

        _assert_socket_stays_open(s1)
        _assert_socket_stays_open(s2)

        s3 = _open_client(port)
        _assert_socket_closed_soon(s3)

        s1.close()
        s1 = None
        time.sleep(0.5)

        s4 = _open_client(port)
        _assert_socket_stays_open(s4)

    finally:
        for s in (s1, s2, s3, s4):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        _stop_server(proc)

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    assert "connection rejected" in log_text


def test_per_ip_connection_limit_enforced(tmp_path: Path):
    proc, port, log_path = _start_server(
        tmp_path=tmp_path,
        max_connections=5,
        max_connections_per_ip=2,
    )

    s1 = s2 = s3 = None
    try:
        s1 = _open_client(port)
        s2 = _open_client(port)

        _assert_socket_stays_open(s1)
        _assert_socket_stays_open(s2)

        s3 = _open_client(port)
        _assert_socket_closed_soon(s3)

    finally:
        for s in (s1, s2, s3):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        _stop_server(proc)

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    assert "connection rejected" in log_text
def test_handshake_timeout_closes_idle_pre_handshake_connection(tmp_path: Path):
    proc, port, log_path = _start_server(
        tmp_path=tmp_path,
        max_connections=2,
        max_connections_per_ip=2,
        extra_env={
            "SEFTP_HANDSHAKE_TIMEOUT_S": "0.5",
            "SEFTP_READ_TIMEOUT_S": "0.1",
            "SEFTP_IDLE_TIMEOUT_S": "30",
        },
    )

    s = None
    try:
        s = _open_client(port)
        _assert_socket_closed_soon(s)
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass
        _stop_server(proc)

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    assert "handshake timeout" in log_text