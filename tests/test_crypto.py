import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
from cryptography.x509.oid import NameOID

from common import crypto
from common.crypto import AuthenticationError, CryptoError
from common.protocol import (
    E2E_HEADER_LEN,
    GCM_TAG_LEN,
    MAX_PLAINTEXT_LEN,
    SEQ_NO_LEN,
    E2EFrame,
    E2EFrameError,
)

NOW = datetime.datetime(2026, 10, 30, tzinfo=datetime.timezone.utc)
ALICE = uuid.uuid4().bytes
BOB = uuid.uuid4().bytes
KEY = bytes(range(16))
IV_BASE = b"\x01\x02\x03\x04"


def make_cert(key, not_before=NOW - datetime.timedelta(days=1), not_after=NOW + datetime.timedelta(days=1)):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "teste")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# --- Vetores oficiais ---


def test_x25519_rfc7748_vector():
    alice = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert crypto.x25519_shared_secret(alice, bob_pk).hex() == expected


@pytest.mark.parametrize("salt, info, length, prk, okm", [
    pytest.param(
        "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        id="rfc5869-caso1",
    ),
    pytest.param(
        "", "", 42,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        id="rfc5869-caso3",
    ),
])
def test_hkdf_rfc5869_vectors(salt, info, length, prk, okm):
    extracted = crypto.hkdf_extract(bytes.fromhex(salt), b"\x0b" * 22)
    assert extracted.hex() == prk
    assert crypto.hkdf_expand(extracted, bytes.fromhex(info), length).hex() == okm


def test_aes_gcm_nist_vector():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    expected = (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        "5bc94fbc3221a5db94fae95ae7121a47"
    )
    assert crypto.aes_gcm_encrypt(key, nonce, plaintext, aad).hex() == expected
    assert crypto.aes_gcm_decrypt(key, nonce, bytes.fromhex(expected), aad) == plaintext


# --- X25519 e derivação ---


def test_both_peers_derive_the_same_keys():
    sk_a, pk_a = crypto.generate_x25519_keypair()
    sk_b, pk_b = crypto.generate_x25519_keypair()
    salt = crypto.random_salt()
    keys_a = crypto.derive_e2e_keys(crypto.x25519_shared_secret(sk_a, pk_b), salt)
    keys_b = crypto.derive_e2e_keys(crypto.x25519_shared_secret(sk_b, pk_a), salt)
    assert keys_a == keys_b
    assert keys_a[0] != keys_a[1]
    assert len(keys_a[0]) == 16


def test_different_salts_derive_different_keys():
    # Por isso o salt é por par (decisão 1): com salts diferentes, A e B não se entendem
    z = bytes(range(32))
    assert crypto.derive_e2e_keys(z, b"a" * 16) != crypto.derive_e2e_keys(z, b"b" * 16)


@pytest.mark.parametrize("peer_pk", [
    pytest.param(b"\x00" * 31, id="tamanho-errado"),
    pytest.param(b"\x00" * 32, id="ordem-baixa"),
])
def test_rejects_invalid_peer_key(peer_pk):
    sk, _ = crypto.generate_x25519_keypair()
    with pytest.raises(CryptoError):
        crypto.x25519_shared_secret(sk, peer_pk)


@pytest.mark.parametrize("z, salt", [(b"z" * 31, b"s" * 16), (b"z" * 32, b"s" * 15)])
def test_derive_rejects_wrong_lengths(z, salt):
    with pytest.raises(CryptoError):
        crypto.derive_e2e_keys(z, salt)


# --- Frame E2E ---


def seal(seq_no=7, plaintext=b"oi bob"):
    return crypto.seal_e2e(KEY, IV_BASE, ALICE, BOB, seq_no, plaintext)


def test_frame_layout_matches_the_spec():
    body = seal().encode()
    assert body[:4] == IV_BASE
    assert body[4:12] == (7).to_bytes(8, "big")
    assert body[12:28] == ALICE
    assert body[28:44] == BOB
    assert body[44:52] == (7).to_bytes(8, "big")
    assert len(body) == E2E_HEADER_LEN + len(b"oi bob") + GCM_TAG_LEN


def test_aad_and_nonce_layout_match_the_spec():
    seq = (7).to_bytes(8, "big")
    assert crypto.build_aad(ALICE, BOB, 7) == ALICE + BOB + seq
    assert crypto.build_nonce(IV_BASE, 7) == IV_BASE + seq


def test_seal_authenticates_the_spec_aad():
    # Decifra sem passar por open_e2e: a tag só confere com o AAD exato do enunciado
    frame = seal()
    aad = ALICE + BOB + (7).to_bytes(8, "big")
    assert crypto.aes_gcm_decrypt(KEY, frame.nonce, frame.ciphertext, aad) == b"oi bob"


def test_nonce_disagreeing_with_seq_no_is_rejected():
    # Tag válida, feita por quem tem a chave, mas com nonce de outro seq_no: permitiria reutilizar nonce
    nonce = crypto.build_nonce(IV_BASE, 9)
    ciphertext = crypto.aes_gcm_encrypt(KEY, nonce, b"oi bob", crypto.build_aad(ALICE, BOB, 7))
    with pytest.raises(AuthenticationError):
        crypto.open_e2e(KEY, E2EFrame(nonce, ALICE, BOB, 7, ciphertext))


def test_round_trip_through_bytes():
    assert crypto.open_e2e(KEY, E2EFrame.parse(seal().encode())) == b"oi bob"


def test_ciphertext_does_not_contain_plaintext():
    assert b"oi bob" not in seal().encode()


def test_flipping_any_bit_is_rejected():
    body = seal().encode()
    for i in range(len(body)):
        tampered = bytearray(body)
        tampered[i] ^= 0x01
        with pytest.raises(AuthenticationError):
            crypto.open_e2e(KEY, E2EFrame.parse(bytes(tampered)))


def test_rewriting_seq_no_and_nonce_together_is_rejected():
    # O atacante mantém nonce e seq_no coerentes, mas não consegue recalcular a tag
    frame = seal(seq_no=7)
    forged = E2EFrame(crypto.build_nonce(IV_BASE, 8), frame.sender_id, frame.recipient_id, 8, frame.ciphertext)
    with pytest.raises(AuthenticationError):
        crypto.open_e2e(KEY, forged)


def test_wrong_key_is_rejected():
    with pytest.raises(AuthenticationError):
        crypto.open_e2e(bytes(16), seal())


def test_swapping_sender_and_recipient_is_rejected():
    frame = seal()
    swapped = E2EFrame(frame.nonce, frame.recipient_id, frame.sender_id, frame.seq_no, frame.ciphertext)
    with pytest.raises(AuthenticationError):
        crypto.open_e2e(KEY, swapped)


def test_plaintext_limit():
    assert crypto.open_e2e(KEY, seal(plaintext=b"x" * MAX_PLAINTEXT_LEN)) == b"x" * MAX_PLAINTEXT_LEN
    with pytest.raises(CryptoError):
        seal(plaintext=b"x" * (MAX_PLAINTEXT_LEN + 1))


@pytest.mark.parametrize("seq_no", [-1, 2 ** (8 * SEQ_NO_LEN)])
def test_seq_no_out_of_range(seq_no):
    with pytest.raises(CryptoError):
        seal(seq_no=seq_no)


def test_largest_seq_no():
    largest = 2 ** (8 * SEQ_NO_LEN) - 1
    assert crypto.open_e2e(KEY, E2EFrame.parse(seal(seq_no=largest).encode())) == b"oi bob"


@pytest.mark.parametrize("size", [0, E2E_HEADER_LEN + GCM_TAG_LEN - 1, E2E_HEADER_LEN + MAX_PLAINTEXT_LEN + 17])
def test_parse_rejects_invalid_size(size):
    with pytest.raises(E2EFrameError):
        E2EFrame.parse(b"\x00" * size)


@pytest.mark.parametrize("key, nonce", [(b"k" * 15, b"n" * 12), (b"k" * 32, b"n" * 12), (b"k" * 16, b"n" * 11)])
def test_gcm_rejects_wrong_lengths(key, nonce):
    with pytest.raises(CryptoError):
        crypto.aes_gcm_encrypt(key, nonce, b"", b"")


# --- RSA-PSS e certificado ---


def test_signature_round_trip(rsa_key):
    material = b"material"
    crypto.verify_pss(rsa_key.public_key(), crypto.sign_pss(rsa_key, material), material)


def test_handshake_signature_detects_any_changed_field(rsa_key):
    pk_s = crypto.public_key_der(rsa_key.public_key())
    fields = {"pk_server": pk_s, "pk_client": b"c" * 32, "client_id": ALICE, "salt": b"s" * 16}
    signature = crypto.sign_pss(rsa_key, crypto.handshake_material(**fields))
    for name, value in fields.items():
        changed = {**fields, name: bytes([value[0] ^ 1]) + value[1:]}
        with pytest.raises(AuthenticationError):
            crypto.verify_pss(rsa_key.public_key(), signature, crypto.handshake_material(**changed))


def test_signature_from_another_key_is_rejected(rsa_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthenticationError):
        crypto.verify_pss(rsa_key.public_key(), crypto.sign_pss(other, b"material"), b"material")


def test_pinned_certificate_returns_trusted_key(rsa_key):
    cert = make_cert(rsa_key)
    key = crypto.verify_pinned_certificate(cert, crypto.certificate_der(cert), now=NOW)
    assert crypto.public_key_der(key) == crypto.public_key_der(rsa_key.public_key())


def test_rejects_certificate_other_than_pinned(rsa_key):
    # Um atacante apresenta um certificado válido, mas que não é o pinado
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    received = crypto.certificate_der(make_cert(attacker))
    with pytest.raises(AuthenticationError):
        crypto.verify_pinned_certificate(make_cert(rsa_key), received, now=NOW)


@pytest.mark.parametrize("delta", [datetime.timedelta(days=-2), datetime.timedelta(days=2)])
def test_rejects_certificate_outside_validity(rsa_key, delta):
    cert = make_cert(rsa_key)
    with pytest.raises(AuthenticationError):
        crypto.verify_pinned_certificate(cert, crypto.certificate_der(cert), now=NOW + delta)


def test_rejects_non_rsa_certificate():
    cert = make_cert(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(CryptoError):
        crypto.verify_pinned_certificate(cert, crypto.certificate_der(cert), now=NOW)


def write_pem_key(path, key):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))


def test_loads_key_and_certificate_from_disk(tmp_path, rsa_key):
    write_pem_key(tmp_path / "server.key", rsa_key)
    cert = make_cert(rsa_key)
    (tmp_path / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    assert crypto.load_private_key(tmp_path / "server.key").key_size == 2048
    assert crypto.load_certificate(tmp_path / "server.crt") == cert


def test_rejects_weak_rsa_key(tmp_path):
    write_pem_key(tmp_path / "weak.key", rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(CryptoError):
        crypto.load_private_key(tmp_path / "weak.key")


def test_load_errors_do_not_leak_file_contents(tmp_path):
    secret = b"conteudo-secreto"
    (tmp_path / "bad.key").write_bytes(secret)
    with pytest.raises(CryptoError) as excinfo:
        crypto.load_private_key(tmp_path / "bad.key")
    assert "conteudo-secreto" not in str(excinfo.value)
    with pytest.raises(CryptoError):
        crypto.load_certificate(tmp_path / "ausente.crt")
