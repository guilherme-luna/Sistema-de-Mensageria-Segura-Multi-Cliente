import pytest

from common.config import ROOT_DIR, ConfigError, load_client_config, load_server_config

ENV_VARS = (
    "SERVER_BIND_HOST", "SERVER_HOST", "SERVER_PORT", "MAX_CLIENTS", "HANDSHAKE_TIMEOUT",
    "SERVER_KEY_PATH", "SERVER_CERT_PATH", "PINNED_CERT_PATH", "LOG_LEVEL",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Isola os testes do .env local e do ambiente do desenvolvedor
    monkeypatch.setattr("common.config.load_dotenv", lambda *a, **k: None)
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_server_defaults():
    config = load_server_config()
    assert config.bind_host == "127.0.0.1"
    assert config.port == 9000
    assert config.max_clients == 64
    assert config.key_path == ROOT_DIR / "certs/server.key"


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("SERVER_PORT", "9100")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    config = load_client_config()
    assert config.port == 9100
    assert config.log_level == "DEBUG"


def test_bind_host_and_client_host_are_independent(monkeypatch):
    monkeypatch.setenv("SERVER_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("SERVER_HOST", "192.168.0.10")
    assert load_server_config().bind_host == "0.0.0.0"
    assert load_client_config().host == "192.168.0.10"


@pytest.mark.parametrize("var", ["SERVER_BIND_HOST", "SERVER_PORT", "LOG_LEVEL", "SERVER_KEY_PATH"])
def test_empty_value_uses_default(monkeypatch, var):
    # Uma linha "VAR=" no .env não pode virar string vazia (ex.: bind em todas as interfaces)
    monkeypatch.setenv(var, "   ")
    config = load_server_config()
    assert config.bind_host == "127.0.0.1"
    assert config.port == 9000
    assert config.log_level == "INFO"
    assert config.key_path == ROOT_DIR / "certs/server.key"


def test_relative_paths_resolve_from_project_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PINNED_CERT_PATH", "outra/pasta/server.crt")
    assert load_client_config().pinned_cert_path == ROOT_DIR / "outra/pasta/server.crt"


@pytest.mark.parametrize("var, value", [
    ("SERVER_PORT", "abc"),
    ("SERVER_PORT", "70000"),
    ("MAX_CLIENTS", "0"),
    ("LOG_LEVEL", "VERBOSE"),
])
def test_invalid_values(monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    with pytest.raises(ConfigError):
        load_server_config()
