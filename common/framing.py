"""Framing TCP: | tamanho (4B, big-endian) | tipo (1B) | corpo |

O tamanho conta o byte de tipo + o corpo.
"""

import asyncio
import struct
from typing import NamedTuple, Optional

from common.protocol import LENGTH_PREFIX_LEN, MAX_FRAME_LEN, ErrorCode, MsgType

_HEADER = struct.Struct(">IB")
_LENGTH = struct.Struct(">I")


class FrameError(ValueError):
    pass


class Frame(NamedTuple):
    msg_type: MsgType
    body: bytes


def encode_frame(msg_type: MsgType, body: bytes = b"") -> bytes:
    length = 1 + len(body)
    if length > MAX_FRAME_LEN:
        raise FrameError(f"frame de {length} bytes excede o limite de {MAX_FRAME_LEN}")
    return _HEADER.pack(length, msg_type) + body


def encode_error(code: ErrorCode) -> bytes:
    return encode_frame(MsgType.ERROR, bytes([code]))


async def read_frame(reader: asyncio.StreamReader, max_len: int = MAX_FRAME_LEN) -> Optional[Frame]:
    """Lê um frame do stream. Retorna None se a conexão fechou entre dois frames.

    Levanta FrameError para qualquer frame inválido; quem chama deve encerrar a
    conexão. O tamanho é validado antes da leitura, para que um prefixo forjado
    não faça o processo reservar memória. Não aplica timeout: quem chama deve
    usar asyncio.wait_for onde um peer lento for um problema. max_len (tipo + corpo)
    permite um limite menor que MAX_FRAME_LEN, como antes do handshake.
    """
    try:
        prefix = await reader.readexactly(LENGTH_PREFIX_LEN)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None
        raise FrameError("conexão encerrada no meio do prefixo de tamanho") from None

    (length,) = _LENGTH.unpack(prefix)
    if not 1 <= length <= min(max_len, MAX_FRAME_LEN):
        raise FrameError(f"tamanho de frame inválido: {length}")

    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise FrameError("conexão encerrada no meio do frame") from None

    try:
        msg_type = MsgType(payload[0])
    except ValueError:
        raise FrameError(f"tipo de mensagem desconhecido: {payload[0]:#04x}") from None
    return Frame(msg_type, payload[1:])
