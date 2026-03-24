import asyncio
from src.session import ClientSession
from src import router
from src.store import Store
from src.config import Config
from src.logging_setup import setup_logging
import time
from src import answers
import signal
from src.upload_limiter import UploadLimiter
from src.connection_limiter import ConnectionLimiter
from src.bounded_executor import BoundedExecutor

async def main():
    config = Config.load()
    logger = setup_logging(config.log_level)

    store = Store()
    ok = store.initialize(config.data_path)
    if ok:
        logger.info("SQLite storage initialized")
    else:
        logger.error("Failed to initialize SQLite storage")
        raise RuntimeError("Failed to initialize SQLite storage")

    upload_limiter = UploadLimiter(config.max_concurrent_uploads)
    connection_limiter = ConnectionLimiter(config.max_connections, config.max_connections_per_ip)
    bounded_executor = BoundedExecutor(config.cpu_worker_threads, config.cpu_max_in_flight)

    logger.info(
        "server config host=%s port=%s data_path=%s log_level=%s idle_timeout_s=%s "
        "upload_inactivity_timeout_s=%s max_file_size=%s max_packets=%s max_chunk_size=%s max_payload_size=%s read_timeout_s=%s",
        config.host,
        config.port,
        config.data_path,
        config.log_level,
        config.idle_timeout_s,
        config.upload_inactivity_timeout_s,
        config.max_file_size,
        config.max_packets,
        config.max_chunk_size,
        config.max_payload_size,
        config.read_timeout_s,
    )

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        peer_ip = addr[0] if isinstance(addr, tuple) and len(addr) >= 1 else str(addr)
        session = ClientSession(writer, store, logger,config,upload_limiter, bounded_executor)
        session.peer = addr
        connection_acquired = False
        try:
            allowed, connection_reason = await connection_limiter.try_acquire(peer_ip)
            if not allowed:
                session.disconnect_reason = "connection_rejected"
                session.log.info("connection rejected peer=%s reason=%s", addr, connection_reason)
                return
            connection_acquired = True
            session.log.info("Got connection from %s", addr)
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=config.read_timeout_s)
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
                    session.disconnect_reason = "eof"
                    session.log.info("Client %s disconnected", addr)
                    break
                session.on_frame_received(len(chunk))
                frames = session.feed(chunk)
                for frame in frames:
                    await router.handle_frame(frame, session)
        except (ConnectionResetError, BrokenPipeError):
            session.disconnect_reason = "reset"
            session.log.warning("Client %s disconnected unexpectedly", addr)
        except asyncio.CancelledError:
            session.disconnect_reason = "cancelled"
            raise
        except Exception:
            session.disconnect_reason = "server_exception"
            session.log.exception("unhandled exception in handle_client")
        finally:
            if session.upload_active:
                session.reset_transfer_state(f"disconnect_{session.disconnect_reason}")
            duration_ms = int((time.monotonic() - session.connected_at) * 1000)

            if session.has_upload_slot:
                await session.release_upload_slot()
                session.log.info("released upload slot during disconnect cleanup")

            if connection_acquired:
                await connection_limiter.release(peer_ip)
                session.log.info("released connection slot peer=%s", peer_ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

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
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    def _stop():
        stop_event.set()
    # register signals
    try:
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)
    except (NotImplementedError, RuntimeError):
        # Windows
        pass
    async with server:
        try:
            await stop_event.wait()
        finally:
            logger.info("shutdown initiated")
            server.close()
            await server.wait_closed()
            bounded_executor.shutdown()
            try:
                store.close()
                logger.info("SQLite storage closed")
            except Exception:
                logger.exception("failed closing SQLite storage on shutdown")

            logger.info("shutting down complete")
            logger.debug("clients_recent_log=%r", dict(store.clients_recent_log))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise