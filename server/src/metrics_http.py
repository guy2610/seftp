from .metrics_export import runtime_metrics_json
from .runtime_metrics import RuntimeMetrics


_HTTP_OK_TEMPLATE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: {length}\r\n"
    "Connection: close\r\n"
    "\r\n"
)

_HTTP_NOT_FOUND = (
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 9\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Not Found"
).encode("utf-8")

_HTTP_BAD_REQUEST = (
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 11\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Bad Request"
).encode("utf-8")


async def handle_metrics_http(reader, writer, metrics: RuntimeMetrics) -> None:
    try:
        request_line = await reader.readline()
        parts = request_line.decode("ascii", errors="replace").strip().split()

        if len(parts) < 2:
            writer.write(_HTTP_BAD_REQUEST)
            await writer.drain()
            return

        method, path = parts[0], parts[1]

        if method != "GET" or path != "/metrics":
            writer.write(_HTTP_NOT_FOUND)
            await writer.drain()
            return

        body = (await runtime_metrics_json(metrics)).encode("utf-8")
        header = _HTTP_OK_TEMPLATE.format(length=len(body)).encode("ascii")
        writer.write(header + body)
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
