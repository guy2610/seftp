import asyncio
from src.session import ClientSession
from src import router
from src.store import Store
from src.config import Config
from src.logging_setup import setup_logging
import time

async def main():
    config = Config.load()
    logger = setup_logging(config.log_level)

    store = Store()
    store.load_client_info(config.data_path)

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        session = ClientSession(writer, store, logger)
        session.peer = addr
        session.log.info("Got connection from %s", addr)
        reason = "unknown"
        idle_timeouts = 0
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=10)
                except asyncio.TimeoutError:
                    idle_timeouts += 1
                    session.log.debug("read timeout (%d), keeping connection alive", idle_timeouts)
                    if idle_timeouts>=6: #60 sec timeout
                        session.disconnect_reason="timeout"
                        break
                    continue
                if not chunk:
                    reason = "eof"
                    session.disconnect_reason = reason
                    session.log.info("Client %s disconnected", addr)
                    break
                idle_timeouts = 0
                session.on_frame_received(len(chunk))
                frames = session.feed(chunk)
                for frame in frames:
                    await router.handle_frame(frame, session)
        except (ConnectionResetError, BrokenPipeError):
            reason = "reset"
            session.disconnect_reason = reason
            session.log.warning("Client %s disconnected unexpectedly", addr)
        except asyncio.CancelledError:
            reason = "cancelled"
            session.disconnect_reason = reason
            raise
        except Exception:
            reason = "server_exception"
            session.disconnect_reason = reason
            session.log.exception("unhandled exception in handle_client")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            duration_ms = int((time.monotonic() - session.connected_at) * 1000)
            session.log.info(
                "disconnect summary peer=%s reason=%s duration_ms=%d bytes_in=%d bytes_out=%d frames_ok=%d frames_bad=%d",
                addr,
                session.disconnect_reason,
                duration_ms,
                session.bytes_in,
                session.bytes_out,
                session.frames_ok,
                session.frames_bad,
            )

    server = await asyncio.start_server(handle_client, config.host, config.port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logger.info("async server listening on %s", addrs)
    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            store.save_clients_info(config.data_path)
            logger.debug("clients_recent_log=%r", dict(store.clients_recent_log))
            logger.info("shutting down")


if __name__ == "__main__":
    asyncio.run(main())