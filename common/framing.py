"""Framing TCP: | tamanho (4B, big-endian) | tipo (1B) | corpo |

O tamanho conta o byte de tipo + o corpo.
"""

import struct

from common.protocol import MAX_FRAME_LEN, ErrorCode, MsgType

_HEADER = struct.Struct(">IB")


class FrameError(ValueError):
    pass


def encode_frame(msg_type: MsgType, body: bytes = b"") -> bytes:
    length = 1 + len(body)
    if length > MAX_FRAME_LEN:
        raise FrameError(f"frame de {length} bytes excede o limite de {MAX_FRAME_LEN}")
    return _HEADER.pack(length, msg_type) + body


def encode_error(code: ErrorCode) -> bytes:
    return encode_frame(MsgType.ERROR, bytes([code]))
