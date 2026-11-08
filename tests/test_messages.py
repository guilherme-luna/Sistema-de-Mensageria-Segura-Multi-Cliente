import random
import uuid

import pytest

from common.messages import (
    HELLO_MAX_LEN,
    Hello,
    HelloResp,
    InvalidNameError,
    MessageError,
    PeerJoin,
    PeerLeave,
    Role,
)
from common.protocol import MAX_NAME_LEN, MsgType

ALICE = uuid.uuid4().bytes
BOB = uuid.uuid4().bytes
PK = bytes(range(32))
SALT = bytes(range(16))
SESSION_SALT = bytes(range(16, 32))
SIG = b"\xaa" * 256


def peer_join(**overrides):
    fields = dict(peer_id=BOB, pk_peer=PK, salt_ab=SALT, seq_send=7, role=Role.A, name="bob", signature=SIG)
    return PeerJoin(**{**fields, **overrides})


# --- Ida e volta ---


def test_hello_round_trip():
    hello = Hello(ALICE, PK, "alice")
    assert Hello.parse(hello.encode()) == hello


def test_largest_hello_fits_limit():
    hello = Hello(ALICE, PK, "a" * MAX_NAME_LEN)
    assert len(hello.encode()) == HELLO_MAX_LEN
    assert Hello.parse(hello.encode()) == hello


def test_hello_resp_round_trip():
    resp = HelloResp(b"\x30" * 800, SALT, SIG)
    assert HelloResp.parse(resp.encode()) == resp


@pytest.mark.parametrize("role", list(Role))
def test_peer_join_round_trip(role):
    msg = peer_join(role=role)
    assert PeerJoin.parse(msg.encode()) == msg


def test_peer_leave_round_trip():
    msg = PeerLeave(BOB, 2**64 - 1, SIG)
    assert PeerLeave.parse(msg.encode()) == msg


# --- Material assinado ---


def test_signed_material_binds_type_recipient_and_session():
    msg = peer_join()
    material = msg.signed_material(ALICE, SESSION_SALT)
    assert material == bytes([MsgType.PEER_JOIN]) + ALICE + SESSION_SALT + msg.fields()
    assert material != msg.signed_material(BOB, SESSION_SALT)
    assert material != msg.signed_material(ALICE, SALT)


def test_signed_material_covers_every_field():
    base = peer_join().signed_material(ALICE, SESSION_SALT)
    variants = [
        peer_join(peer_id=ALICE), peer_join(pk_peer=bytes(32)), peer_join(salt_ab=bytes(16)),
        peer_join(seq_send=8), peer_join(role=Role.B), peer_join(name="bobb"),
    ]
    for variant in variants:
        assert variant.signed_material(ALICE, SESSION_SALT) != base


def test_join_and_leave_material_differ_in_type_byte():
    join = peer_join().signed_material(ALICE, SESSION_SALT)
    leave = PeerLeave(BOB, 7).signed_material(ALICE, SESSION_SALT)
    assert join[0] == MsgType.PEER_JOIN and leave[0] == MsgType.PEER_LEAVE


def test_signature_is_not_part_of_material():
    assert peer_join(signature=b"x").signed_material(ALICE, SESSION_SALT) == \
        peer_join(signature=b"y").signed_material(ALICE, SESSION_SALT)


# --- Rejeições ---


@pytest.mark.parametrize("body", [
    pytest.param(ALICE + PK, id="sem-nome"),
    pytest.param(ALICE + PK + b"a" * (MAX_NAME_LEN + 1), id="nome-longo"),
    pytest.param(ALICE + PK[:10], id="truncado"),
])
def test_hello_rejects_bad_size(body):
    with pytest.raises(MessageError):
        Hello.parse(body)


@pytest.mark.parametrize("name", [b"com espaco", "joão".encode(), b"\xff\xfe", b"a/b"])
def test_hello_rejects_invalid_name(name):
    with pytest.raises(InvalidNameError):
        Hello.parse(ALICE + PK + name)


@pytest.mark.parametrize("body", [
    pytest.param(b"", id="vazio"),
    pytest.param(b"\x00", id="prefixo-incompleto"),
    pytest.param(b"\x00\x00" + SALT + SIG, id="certificado-vazio"),
    pytest.param(b"\x00\x05abcde" + SALT, id="sem-assinatura"),
    pytest.param(b"\x03\x20abc", id="certificado-truncado"),
])
def test_hello_resp_rejects_malformed(body):
    with pytest.raises(MessageError):
        HelloResp.parse(body)


def test_peer_join_rejects_unknown_role():
    body = bytearray(peer_join().encode())
    body[16 + 32 + 16 + 8] = 0x09
    with pytest.raises(MessageError):
        PeerJoin.parse(bytes(body))


def test_peer_join_rejects_missing_signature():
    with pytest.raises(MessageError):
        PeerJoin.parse(peer_join(signature=b"").encode())


def test_peer_join_rejects_invalid_name():
    with pytest.raises(MessageError):
        PeerJoin.parse(peer_join(signature=b"").fields()[:-3] + b"a b" + SIG)


def test_peer_leave_rejects_missing_signature():
    with pytest.raises(MessageError):
        PeerLeave.parse(PeerLeave(BOB, 1).encode())


@pytest.mark.parametrize("parse", [Hello.parse, HelloResp.parse, PeerJoin.parse, PeerLeave.parse])
def test_random_bytes_only_raise_message_error(parse):
    rng = random.Random(4321)
    for _ in range(500):
        try:
            parse(rng.randbytes(rng.randrange(0, 400)))
        except MessageError:
            pass
