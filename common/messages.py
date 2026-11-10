"""Corpos das mensagens de controle (HELLO, HELLO_RESP, PEER_JOIN, PEER_LEAVE).

Cada mensagem tem encode() e parse(). parse() só confere o formato; a assinatura
é verificada por quem recebe, com a chave do certificado pinado.

Material assinado das mensagens de controle (decisão 2):

    tipo (1B) || recipient_id || session_salt || campos da mensagem

- o tipo impede reaproveitar a assinatura de um PEER_LEAVE como outra mensagem;
- o recipient_id impede encaminhar a um cliente um anúncio feito para outro;
- o session_salt (o salt do HELLO_RESP desta conexão) impede repetir um anúncio
  de uma conexão anterior do mesmo client_id, cujo seq_send recomeçou do zero.

O material do handshake começa com pk_S em DER (byte 0x30), e o das mensagens de
controle começa com o byte de tipo (0x03 ou 0x04), então nenhuma assinatura de um
serve para o outro.
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

from common.protocol import (
    CLIENT_ID_LEN,
    MAX_NAME_LEN,
    SALT_LEN,
    SEQ_NO_LEN,
    X25519_PUBKEY_LEN,
    MsgType,
    is_valid_name,
)

_CERT_LEN = struct.Struct(">H")
_SEQ = struct.Struct(">Q")

HELLO_MAX_LEN = CLIENT_ID_LEN + X25519_PUBKEY_LEN + MAX_NAME_LEN


class MessageError(ValueError):
    pass


class InvalidNameError(MessageError):
    pass


class Role(IntEnum):
    """Papel do DESTINATÁRIO do PEER_JOIN no par (decisão 3): define quem usa Key_A2B para enviar."""

    A = 0x01  # já estava conectado: o peer anunciado é o recém-chegado
    B = 0x02  # é o recém-chegado: o peer anunciado já estava conectado


def _decode_name(raw: bytes) -> str:
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError:
        raise InvalidNameError("nome não é ASCII") from None
    if not is_valid_name(name):
        raise InvalidNameError("nome inválido")
    return name


def _require_min(body: bytes, minimum: int, what: str) -> None:
    if len(body) < minimum:
        raise MessageError(f"{what} curto demais: {len(body)} bytes")


@dataclass(frozen=True)
class Hello:
    client_id: bytes
    pk_client: bytes
    name: str

    def encode(self) -> bytes:
        return self.client_id + self.pk_client + self.name.encode("ascii")

    @classmethod
    def parse(cls, body: bytes) -> "Hello":
        fixed = CLIENT_ID_LEN + X25519_PUBKEY_LEN
        if not fixed < len(body) <= HELLO_MAX_LEN:
            raise MessageError(f"HELLO com tamanho inválido: {len(body)} bytes")
        return cls(body[:CLIENT_ID_LEN], body[CLIENT_ID_LEN:fixed], _decode_name(body[fixed:]))


@dataclass(frozen=True)
class HelloResp:
    certificate: bytes  # DER
    salt: bytes
    signature: bytes

    def encode(self) -> bytes:
        return _CERT_LEN.pack(len(self.certificate)) + self.certificate + self.salt + self.signature

    @classmethod
    def parse(cls, body: bytes) -> "HelloResp":
        _require_min(body, _CERT_LEN.size, "HELLO_RESP")
        (cert_len,) = _CERT_LEN.unpack_from(body)
        salt_start = _CERT_LEN.size + cert_len
        sig_start = salt_start + SALT_LEN
        if cert_len == 0 or len(body) <= sig_start:
            raise MessageError("HELLO_RESP com tamanho inválido")
        return cls(body[_CERT_LEN.size:salt_start], body[salt_start:sig_start], body[sig_start:])


def _control_material(msg_type: MsgType, recipient_id: bytes, session_salt: bytes, fields: bytes) -> bytes:
    if len(recipient_id) != CLIENT_ID_LEN or len(session_salt) != SALT_LEN:
        raise MessageError("recipient_id ou session_salt com tamanho inválido")
    return bytes([msg_type]) + recipient_id + session_salt + fields


@dataclass(frozen=True)
class PeerJoin:
    peer_id: bytes
    pk_peer: bytes
    salt_ab: bytes
    seq_send: int
    role: Role
    name: str
    signature: bytes = b""

    def fields(self) -> bytes:
        name = self.name.encode("ascii")
        return (
            self.peer_id + self.pk_peer + self.salt_ab + _SEQ.pack(self.seq_send)
            + bytes([self.role, len(name)]) + name
        )

    def signed_material(self, recipient_id: bytes, session_salt: bytes) -> bytes:
        return _control_material(MsgType.PEER_JOIN, recipient_id, session_salt, self.fields())

    def encode(self) -> bytes:
        return self.fields() + self.signature

    @classmethod
    def parse(cls, body: bytes) -> "PeerJoin":
        pk_start = CLIENT_ID_LEN
        salt_start = pk_start + X25519_PUBKEY_LEN
        seq_start = salt_start + SALT_LEN
        role_pos = seq_start + SEQ_NO_LEN
        name_start = role_pos + 2
        _require_min(body, name_start, "PEER_JOIN")
        try:
            role = Role(body[role_pos])
        except ValueError:
            raise MessageError("papel inválido no PEER_JOIN") from None
        sig_start = name_start + body[role_pos + 1]
        if len(body) <= sig_start:
            raise MessageError("PEER_JOIN sem assinatura")
        return cls(
            peer_id=body[:pk_start],
            pk_peer=body[pk_start:salt_start],
            salt_ab=body[salt_start:seq_start],
            seq_send=_SEQ.unpack_from(body, seq_start)[0],
            role=role,
            name=_decode_name(body[name_start:sig_start]),
            signature=body[sig_start:],
        )


@dataclass(frozen=True)
class PeerLeave:
    peer_id: bytes
    seq_send: int
    signature: bytes = b""

    def fields(self) -> bytes:
        return self.peer_id + _SEQ.pack(self.seq_send)

    def signed_material(self, recipient_id: bytes, session_salt: bytes) -> bytes:
        return _control_material(MsgType.PEER_LEAVE, recipient_id, session_salt, self.fields())

    def encode(self) -> bytes:
        return self.fields() + self.signature

    @classmethod
    def parse(cls, body: bytes) -> "PeerLeave":
        sig_start = CLIENT_ID_LEN + SEQ_NO_LEN
        if len(body) <= sig_start:
            raise MessageError("PEER_LEAVE curto demais")
        return cls(body[:CLIENT_ID_LEN], _SEQ.unpack_from(body, CLIENT_ID_LEN)[0], body[sig_start:])
