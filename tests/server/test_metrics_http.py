import json

import pytest

from src.metrics_http import handle_metrics_http
from src.runtime_metrics import RuntimeMetrics


class FakeReader:
    def __init__(self, line: bytes):
        self._line = line

    async def readline(self):
        return self._line


class FakeWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data: bytes):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_metrics_http_returns_json_snapshot():
    metrics = RuntimeMetrics()
    await metrics.set_active_connections(2)
    await metrics.inc_responses_1607()

    reader = FakeReader(b"GET /metrics HTTP/1.1\r\n")
    writer = FakeWriter()

    await handle_metrics_http(reader, writer, metrics)

    assert writer.data.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: application/json\r\n" in writer.data

    _headers, body = writer.data.split(b"\r\n\r\n", 1)
    decoded = json.loads(body.decode("utf-8"))

    assert decoded["runtime_metrics"]["active_connections"] == 2
    assert decoded["runtime_metrics"]["responses_1607"] == 1
    assert writer.closed is True


@pytest.mark.asyncio
async def test_metrics_http_rejects_unknown_path():
    metrics = RuntimeMetrics()
    reader = FakeReader(b"GET /unknown HTTP/1.1\r\n")
    writer = FakeWriter()

    await handle_metrics_http(reader, writer, metrics)

    assert writer.data.startswith(b"HTTP/1.1 404 Not Found\r\n")
    assert writer.closed is True


@pytest.mark.asyncio
async def test_metrics_http_rejects_malformed_request():
    metrics = RuntimeMetrics()
    reader = FakeReader(b"\r\n")
    writer = FakeWriter()

    await handle_metrics_http(reader, writer, metrics)

    assert writer.data.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert writer.closed is True
