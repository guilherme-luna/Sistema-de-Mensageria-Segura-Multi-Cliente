import pytest
from helpers import make_identity


@pytest.fixture(scope="session")
def identity():
    """(chave RSA, certificado) do servidor de teste; gerado uma vez por execução."""
    return make_identity()


@pytest.fixture(scope="session")
def other_identity():
    """Outro par, para simular um servidor impostor."""
    return make_identity()
