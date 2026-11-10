import struct

import pytest

from common.framing import FrameError, encode_error, encode_frame
from common.protocol import MAX_FRAME_LEN, MAX_NAME_LEN, ErrorCode, MsgType, is_valid_name


@pytest.mark.parametrize("name", ["alice", "Bob_2", "carol-x", "a" * MAX_NAME_LEN])
def test_valid_names(name):
    assert is_valid_name(name)


@pytest.mark.parametrize("name", ["", "a" * (MAX_NAME_LEN + 1), "com espaço", "joão", "x\n", "a/b"])
def test_invalid_names(name):
    assert not is_valid_name(name)


def test_frame_layout():
    frame = encode_frame(MsgType.E2E, b"abc")
    length, msg_type = struct.unpack(">IB", frame[:5])
    assert length == 1 + 3
    assert msg_type == MsgType.E2E
    assert frame[5:] == b"abc"


def test_frame_too_large():
    encode_frame(MsgType.E2E, b"x" * (MAX_FRAME_LEN - 1))
    with pytest.raises(FrameError):
        encode_frame(MsgType.E2E, b"x" * MAX_FRAME_LEN)


def test_error_frame():
    assert encode_error(ErrorCode.SERVER_FULL) == struct.pack(">IBB", 2, MsgType.ERROR, ErrorCode.SERVER_FULL)
