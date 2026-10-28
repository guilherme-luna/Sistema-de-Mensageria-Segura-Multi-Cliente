"""Gera a chave RSA do servidor e um certificado autoassinado.

Uso: python scripts/gen_cert.py [--force]
"""

import argparse
import datetime
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from common.config import ConfigError, load_server_config  # noqa: E402
from common.log import fingerprint, force_utf8_output  # noqa: E402
from common.protocol import RSA_KEY_BITS  # noqa: E402

VALIDITY_DAYS = 365


def main() -> None:
    force_utf8_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="sobrescreve chave e certificado existentes")
    args = parser.parse_args()

    try:
        config = load_server_config()
    except ConfigError as e:
        raise SystemExit(f"erro de configuração: {e}") from None
    key_path, cert_path = config.key_path, config.cert_path

    for path in (key_path, cert_path):
        if path.exists() and not path.is_file():
            raise SystemExit(f"{path} existe mas não é um arquivo (é uma pasta?); remova-o antes")
    if (key_path.is_file() or cert_path.is_file()) and not args.force:
        raise SystemExit(f"{key_path} ou {cert_path} já existe (use --force para sobrescrever)")

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mensageria-segura-server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Chave privada legível só pelo dono
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_bytes)
    # O modo do os.open só vale para arquivo novo; com --force o arquivo antigo mantinha a permissão anterior
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"chave privada: {key_path}")
    print(f"certificado:   {cert_path}")
    print(f"fingerprint da chave pública: {fingerprint(spki)}")


if __name__ == "__main__":
    main()
