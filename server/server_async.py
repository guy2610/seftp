import asyncio
from src.session import ClientSession
from src import router
from src.store import Store
from src.config import Config
from src.logging_setup import setup_logging
import time
from src import answers
async def main():
    config = Config.load()
    logger = setup_logging(config.log_level)

    store = Store()
    store.load_client_info(config.data_path)

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        session = ClientSession(writer, store, logger,config)
        session.peer = addr
        session.log.info("Got connection from %s", addr)
        reason = "unknown"
        idle_timeouts = 0
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=10)
                except asyncio.TimeoutError:
                    now=time.monotonic()
                    if session.upload_active:
                        last=session.last_upload_progress_ts or session.connected_at
                        if (now - last) >= config.upload_inactivity_timeout_s:
                            session.disconnect_reason = "upload_timeout"
                            if session.last_client_id is not None and session.last_version is not None:
                                try:
                                    await answers.answer_1607(session.last_client_id, session.last_version,
                                                              "upload inactivity timeout", session)
                                except Exception:
                                    pass
                            session.reset_transfer_state("upload_timeout")
                            break
                    else:
                        if (now - session.last_activity) >= config.idle_timeout_s:
                            session.disconnect_reason = "idle_timeout"
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
            if session.upload_active:
                session.reset_transfer_state(f"disconnect_{session.disconnect_reason}")
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