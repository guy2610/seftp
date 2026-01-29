import asyncio
from src.session import ClientSession
from src import router
from src.store import Store
from src.config import Config
from src.logging_setup import setup_logging

async def main():
    config = Config.load()
    logger = setup_logging(config.log_level)

    store = Store()
    store.load_client_info(config.data_path)

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        session = ClientSession(None, store, logger)
        session.log.info("Got connection from %s", addr)
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=10)
                except asyncio.TimeoutError:
                    session.log.debug("read timeout, keeping connection alive")
                    continue
                if not chunk:
                    session.log.info("Client %s disconnected", addr)
                    break
                frames = session.feed(chunk)
                for frame in frames:
                    router.handle_frame(frame, session)
        except (ConnectionResetError, BrokenPipeError):
            session.log.warning("Client %s disconnected unexpectedly", addr)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_client, config.host, config.port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logger.info("async server listening on %s", addrs)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())