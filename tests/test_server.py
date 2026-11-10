import asyncio

import pytest
from helpers import make_config, running_server

from common.crypto import CryptoError
from common.framing import encode_error
from common.protocol import ErrorCode
from server.server import RelayServer


async def test_refuses_with_error_when_full(identity):
    async with running_server(identity, max_clients=1) as (_, port):
        _, first = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)  # garante que a primeira conexão foi registrada

        second_reader, second = await asyncio.open_connection("127.0.0.1", port)
        received = await asyncio.wait_for(second_reader.read(), timeout=2)
        assert received == encode_error(ErrorCode.SERVER_FULL)

        for writer in (first, second):
            writer.close()
            await writer.wait_closed()


def test_refuses_key_that_does_not_match_certificate(identity, other_identity):
    key, _ = identity
    _, other_cert = other_identity
    with pytest.raises(CryptoError):
        RelayServer(make_config(), key, other_cert)
