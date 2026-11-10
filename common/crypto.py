"""Primitivas criptográficas do protocolo: X25519, HKDF-SHA256, AES-128-GCM e RSA-PSS.

Toda falha vira CryptoError, sem incluir material sensível na mensagem, para que
possa ser logada com segurança. AuthenticationError indica dado adulterado ou
forjado (tag GCM ou assinatura inválida).
"""

import datetime
import hmac
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from common.protocol import (
    AES_KEY_LEN,
    CLIENT_ID_LEN,
    IV_BASE_LEN,
    MAX_PLAINTEXT_LEN,
    NONCE_LEN,
    RSA_KEY_BITS,
    SALT_LEN,
    SEQ_NO_LEN,
    X25519_PUBKEY_LEN,
    E2EFrame,
)

_MAX_SEQ_NO = 2 ** (8 * SEQ_NO_LEN) - 1
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

LABEL_A2B = b"A2B"
LABEL_B2A = b"B2A"


class CryptoError(Exception):
    pass


class AuthenticationError(CryptoError):
    pass


def _require_len(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise CryptoError(f"{name} deve ter {expected} bytes, recebido {len(value)}")


def random_salt() -> bytes:
    return os.urandom(SALT_LEN)


def random_iv_base() -> bytes:
    return os.urandom(IV_BASE_LEN)


# --- X25519 ---


def generate_x25519_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    """Gera um par efêmero. Retorna (sk, pk raw de 32 bytes)."""
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk


def x25519_shared_secret(sk: x25519.X25519PrivateKey, peer_pk: bytes) -> bytes:
    _require_len("chave pública X25519", peer_pk, X25519_PUBKEY_LEN)
    try:
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pk))
    except ValueError:
        # A biblioteca recusa chaves de ordem baixa, que gerariam um segredo todo zerado
        raise CryptoError("chave pública X25519 inválida") from None


# --- HKDF-SHA256 (RFC 5869) ---


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.digest(salt, ikm, "sha256")


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def derive_e2e_keys(shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Deriva (Key_A2B, Key_B2A) de um par de clientes a partir de Z_AB e do salt do par."""
    _require_len("segredo ECDH", shared_secret, X25519_PUBKEY_LEN)
    _require_len("salt", salt, SALT_LEN)
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, LABEL_A2B, AES_KEY_LEN), hkdf_expand(prk, LABEL_B2A, AES_KEY_LEN)


# --- AES-128-GCM ---


def build_nonce(iv_base: bytes, seq_no: int) -> bytes:
    _require_len("IV_base", iv_base, IV_BASE_LEN)
    return iv_base + _encode_seq_no(seq_no)


def build_aad(sender_id: bytes, recipient_id: bytes, seq_no: int) -> bytes:
    _require_len("sender_id", sender_id, CLIENT_ID_LEN)
    _require_len("recipient_id", recipient_id, CLIENT_ID_LEN)
    return sender_id + recipient_id + _encode_seq_no(seq_no)


def _encode_seq_no(seq_no: int) -> bytes:
    if not 0 <= seq_no <= _MAX_SEQ_NO:
        raise CryptoError("seq_no fora do intervalo de 64 bits")
    return seq_no.to_bytes(SEQ_NO_LEN, "big")


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Retorna ciphertext || tag (16 bytes)."""
    _require_len("chave AES", key, AES_KEY_LEN)
    _require_len("nonce", nonce, NONCE_LEN)
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    _require_len("chave AES", key, AES_KEY_LEN)
    _require_len("nonce", nonce, NONCE_LEN)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationError("tag GCM inválida") from None


def seal_e2e(
    key: bytes, iv_base: bytes, sender_id: bytes, recipient_id: bytes, seq_no: int, plaintext: bytes
) -> E2EFrame:
    """Cifra uma mensagem. Quem chama garante que (key, iv_base, seq_no) nunca se repete."""
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        raise CryptoError(f"mensagem excede o limite de {MAX_PLAINTEXT_LEN} bytes")
    nonce = build_nonce(iv_base, seq_no)
    aad = build_aad(sender_id, recipient_id, seq_no)
    ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)
    return E2EFrame(nonce, sender_id, recipient_id, seq_no, ciphertext)


def open_e2e(key: bytes, frame: E2EFrame) -> bytes:
    """Decifra um frame E2E. Não verifica replay: quem chama compara seq_no com o último aceito."""
    if frame.nonce[IV_BASE_LEN:] != _encode_seq_no(frame.seq_no):
        raise AuthenticationError("nonce não corresponde ao seq_no")
    aad = build_aad(frame.sender_id, frame.recipient_id, frame.seq_no)
    return aes_gcm_decrypt(key, frame.nonce, frame.ciphertext, aad)


# --- RSA-PSS e certificado ---


def _require_strong_rsa(key: object) -> None:
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise CryptoError("a chave do servidor deve ser RSA")
    if key.key_size < RSA_KEY_BITS:
        raise CryptoError(f"a chave RSA deve ter ao menos {RSA_KEY_BITS} bits")


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        raise CryptoError(f"não foi possível carregar a chave privada de {path}") from None
    _require_strong_rsa(key)
    return key


def load_certificate(path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        raise CryptoError(f"não foi possível carregar o certificado de {path}") from None


def certificate_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def public_key_der(key: rsa.RSAPublicKey) -> bytes:
    """Formato de pk_S no material assinado: DER (SubjectPublicKeyInfo)."""
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_pinned_certificate(
    pinned: x509.Certificate, received_der: bytes, now: Optional[datetime.datetime] = None
) -> rsa.RSAPublicKey:
    """Confere o certificado recebido contra o pinado e retorna a chave pública confiável.

    A chave vem sempre do certificado pinado, nunca dos bytes recebidos.
    """
    if received_der != certificate_der(pinned):
        raise AuthenticationError("o certificado recebido não é o certificado pinado")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not pinned.not_valid_before_utc <= now <= pinned.not_valid_after_utc:
        raise AuthenticationError("o certificado pinado está fora da validade")
    key = pinned.public_key()
    _require_strong_rsa(key)
    return key


def handshake_material(pk_server: bytes, pk_client: bytes, client_id: bytes, salt: bytes) -> bytes:
    """Material do handshake: pk_S || pk_C || client_id || salt."""
    _require_len("pk_client", pk_client, X25519_PUBKEY_LEN)
    _require_len("client_id", client_id, CLIENT_ID_LEN)
    _require_len("salt", salt, SALT_LEN)
    return pk_server + pk_client + client_id + salt


def sign_pss(key: rsa.RSAPrivateKey, material: bytes) -> bytes:
    """Assina com RSA-PSS. O SHA-256 do material é o H do enunciado: a biblioteca calcula H e assina H."""
    return key.sign(material, _PSS, hashes.SHA256())


def verify_pss(key: rsa.RSAPublicKey, signature: bytes, material: bytes) -> None:
    try:
        key.verify(signature, material, _PSS, hashes.SHA256())
    except InvalidSignature:
        raise AuthenticationError("assinatura RSA-PSS inválida") from None
