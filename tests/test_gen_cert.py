import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from helpers import connect, running_server

from common import crypto

ROOT = Path(__file__).resolve().parents[1]


def gen_cert(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(
        os.environ,
        SERVER_KEY_PATH=str(tmp_path / "server.key"),
        SERVER_CERT_PATH=str(tmp_path / "public" / "server.crt"),
    )
    return subprocess.run(
        [sys.executable, "scripts/gen_cert.py", *args], cwd=ROOT, env=env, capture_output=True, text=True,
        encoding="utf-8",
    )


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("certs")
    result = gen_cert(tmp_path)
    assert result.returncode == 0, result.stderr
    return tmp_path, result


def test_certificate_is_not_a_ca_and_only_signs(generated):
    tmp_path, _ = generated
    cert = crypto.load_certificate(tmp_path / "public" / "server.crt")
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical
    assert usage.value.digital_signature
    assert not (usage.value.key_cert_sign or usage.value.key_encipherment or usage.value.key_agreement)


def test_output_shows_fingerprint_but_not_the_key(generated):
    tmp_path, result = generated
    key_lines = (tmp_path / "server.key").read_text().splitlines()
    assert "fingerprint" in result.stdout
    assert all(line not in result.stdout for line in key_lines[1:-1])


async def test_generated_identity_completes_a_handshake(generated):
    tmp_path, _ = generated
    key = crypto.load_private_key(tmp_path / "server.key")
    cert = crypto.load_certificate(tmp_path / "public" / "server.crt")
    async with running_server((key, cert)) as (_, port):
        conn = await connect(port, cert, "alice")
        assert conn.client.server_key is not None
        await conn.close()


def test_refuses_to_overwrite_without_force(generated):
    tmp_path, _ = generated
    before = (tmp_path / "server.key").read_bytes()
    result = gen_cert(tmp_path)
    assert result.returncode != 0
    assert (tmp_path / "server.key").read_bytes() == before
