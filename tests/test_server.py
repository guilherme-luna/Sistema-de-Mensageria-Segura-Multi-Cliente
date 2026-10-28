import asyncio
from pathlib import Path

from common.config import ServerConfig
from common.framing import encode_error
from common.protocol import ErrorCode
from server.server import RelayServer


def make_config(max_clients: int) -> ServerConfig:
    return ServerConfig(
        bind_host="127.0.0.1", port=0, max_clients=max_clients, handshake_timeout=10,
        key_path=Path("unused.key"), cert_path=Path("unused.crt"), log_level="INFO",
    )


async def test_refuses_with_error_when_full():
    relay = RelayServer(make_config(max_clients=1))
    server = await asyncio.start_server(relay.handle_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        _, first = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)  # garante que a primeira conexão foi registrada

        second_reader, second = await asyncio.open_connection("127.0.0.1", port)
        received = await asyncio.wait_for(second_reader.read(), timeout=2)
        assert received == encode_error(ErrorCode.SERVER_FULL)

        for writer in (first, second):
            writer.close()
            await writer.wait_closed()
