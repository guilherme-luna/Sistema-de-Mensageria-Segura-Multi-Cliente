"""Constantes do protocolo definidas no enunciado e nas decisões do grupo.

Estes valores precisam ser iguais no cliente e no servidor, por isso não são
configuráveis por variável de ambiente.
"""

import re
from enum import IntEnum

CLIENT_ID_LEN = 16       # UUID v4 binário
X25519_PUBKEY_LEN = 32   # chave pública raw
SALT_LEN = 16
NONCE_LEN = 12           # IV_base (4B) || seq_no (8B)
IV_BASE_LEN = 4
SEQ_NO_LEN = 8           # big-endian
GCM_TAG_LEN = 16
AES_KEY_LEN = 16         # AES-128
RSA_KEY_BITS = 2048

LENGTH_PREFIX_LEN = 4    # prefixo de tamanho de cada frame TCP (big-endian)
MSG_TYPE_LEN = 1         # byte de tipo logo após o prefixo de tamanho
MAX_PLAINTEXT_LEN = 4096

# Cabeçalho do frame E2E: nonce | sender_id | recipient_id | seq_no
E2E_HEADER_LEN = NONCE_LEN + 2 * CLIENT_ID_LEN + SEQ_NO_LEN
MAX_E2E_FRAME_LEN = E2E_HEADER_LEN + MAX_PLAINTEXT_LEN + GCM_TAG_LEN

# Limite absoluto aceito pelo framing (tipo + corpo). Frames maiores são erro
# de protocolo. Folga para mensagens de controle (ex.: handshake com certificado).
MAX_FRAME_LEN = 16 * 1024


class MsgType(IntEnum):
    HELLO = 0x01       # cliente -> servidor: client_id + pk_client + nome
    HELLO_RESP = 0x02  # servidor -> cliente: certificado + salt + assinatura
    PEER_JOIN = 0x03   # servidor -> cliente: peer + pk + salt_AB + seq + assinatura
    PEER_LEAVE = 0x04  # servidor -> cliente: peer + seq + assinatura
    E2E = 0x10         # cliente <-> cliente via relay: frame E2E do enunciado
    ERROR = 0x7F       # servidor -> cliente: código de erro


class ErrorCode(IntEnum):
    SERVER_FULL = 0x01
    BAD_FRAME = 0x02
    HANDSHAKE_TIMEOUT = 0x03
    NAME_TAKEN = 0x04
    INVALID_NAME = 0x05
    UNKNOWN_RECIPIENT = 0x06


# Nome exibido do cliente: ASCII simples, sem espaços, para funcionar em "/msg <nome> <texto>"
MAX_NAME_LEN = 32
_NAME_RE = re.compile(rf"[A-Za-z0-9_-]{{1,{MAX_NAME_LEN}}}")


def is_valid_name(name: str) -> bool:
    return _NAME_RE.fullmatch(name) is not None
