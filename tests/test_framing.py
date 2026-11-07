import asyncio
import random
import struct

import pytest

from common.framing import Frame, FrameError, encode_frame, read_frame
from common.protocol import MAX_FRAME_LEN, MsgType


def stream(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=2 * MAX_FRAME_LEN)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def test_round_trip():
    reader = stream(encode_frame(MsgType.E2E, b"abc") + encode_frame(MsgType.PEER_LEAVE))
    assert await read_frame(reader) == Frame(MsgType.E2E, b"abc")
    assert await read_frame(reader) == Frame(MsgType.PEER_LEAVE, b"")
    assert await read_frame(reader) is None


async def test_reassembles_frame_split_across_tcp_segments():
    data = encode_frame(MsgType.E2E, b"mensagem")
    reader = asyncio.StreamReader()
    task = asyncio.create_task(read_frame(reader))
    for i in range(len(data)):
        reader.feed_data(data[i:i + 1])
        await asyncio.sleep(0)
    assert await task == Frame(MsgType.E2E, b"mensagem")


async def test_accepts_largest_frame():
    body = b"x" * (MAX_FRAME_LEN - 1)
    assert await read_frame(stream(encode_frame(MsgType.E2E, body))) == Frame(MsgType.E2E, body)


@pytest.mark.parametrize("data", [
    pytest.param(b"\x00\x00", id="prefixo-incompleto"),
    pytest.param(struct.pack(">I", 0), id="tamanho-zero"),
    pytest.param(struct.pack(">I", MAX_FRAME_LEN + 1), id="tamanho-acima-do-limite"),
    pytest.param(struct.pack(">I", 0xFFFFFFFF), id="tamanho-maximo-forjado"),
    pytest.param(struct.pack(">I", 10) + b"\x10abc", id="corpo-incompleto"),
    pytest.param(struct.pack(">IB", 1, 0xAB), id="tipo-desconhecido"),
])
async def test_rejects_invalid_frames(data):
    with pytest.raises(FrameError):
        await read_frame(stream(data))


async def test_forged_length_does_not_wait_for_body():
    # Sem EOF: um tamanho inválido precisa ser recusado sem esperar mais bytes
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", MAX_FRAME_LEN + 1))
    with pytest.raises(FrameError):
        await asyncio.wait_for(read_frame(reader), timeout=1)


async def test_random_bytes_never_raise_anything_but_frame_error():
    rng = random.Random(1234)
    for _ in range(500):
        reader = stream(rng.randbytes(rng.randrange(1, 64)))
        try:
            while await read_frame(reader) is not None:
                pass
        except FrameError:
            pass
