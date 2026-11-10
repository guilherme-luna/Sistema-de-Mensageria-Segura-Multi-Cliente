"""Logging do projeto.

Regra: nunca logar chaves privadas, segredos ECDH, salts, nonces ou texto de
mensagens. Para identificar uma chave pública em logs, use fingerprint().
"""

import hashlib
import logging
import sys


def force_utf8_output() -> None:
    """Garante UTF-8 mesmo em terminais/redirecionamentos do Windows que usam cp1252.

    Chamar no início do main, antes de qualquer mensagem de erro.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def fingerprint(public_key: bytes) -> str:
    """SHA-256 truncado (8 bytes em hex) de uma chave PÚBLICA, para debug."""
    return hashlib.sha256(public_key).hexdigest()[:16]
