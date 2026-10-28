"""Configuração carregada de variáveis de ambiente (e do arquivo .env, se existir).

Prioridade: argumento de linha de comando > variável de ambiente > .env > padrão.
Variáveis definidas mas vazias (ex.: SERVER_PORT=) usam o valor padrão.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(ValueError):
    pass


def _get_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _get_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _get_str(name, "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} deve ser um inteiro, recebido {raw!r}") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} deve estar entre {minimum} e {maximum}, recebido {value}")
    return value


def _get_path(name: str, default: str) -> Path:
    # Caminhos relativos são resolvidos a partir da raiz do projeto, não do
    # diretório atual, para funcionar igual em qualquer máquina.
    path = Path(_get_str(name, default)).expanduser()
    return path if path.is_absolute() else ROOT_DIR / path


def _get_log_level() -> str:
    level = _get_str("LOG_LEVEL", "INFO").upper()
    if level not in LOG_LEVELS:
        raise ConfigError(f"LOG_LEVEL deve ser um de {LOG_LEVELS}, recebido {level!r}")
    return level


@dataclass(frozen=True)
class ServerConfig:
    bind_host: str
    port: int
    max_clients: int
    handshake_timeout: int
    key_path: Path
    cert_path: Path
    log_level: str


@dataclass(frozen=True)
class ClientConfig:
    host: str
    port: int
    pinned_cert_path: Path
    log_level: str


def load_server_config() -> ServerConfig:
    load_dotenv(ROOT_DIR / ".env")
    return ServerConfig(
        bind_host=_get_str("SERVER_BIND_HOST", "127.0.0.1"),
        port=_get_int("SERVER_PORT", 9000, 1, 65535),
        max_clients=_get_int("MAX_CLIENTS", 64, 1, 10_000),
        handshake_timeout=_get_int("HANDSHAKE_TIMEOUT", 10, 1, 300),
        key_path=_get_path("SERVER_KEY_PATH", "certs/server.key"),
        cert_path=_get_path("SERVER_CERT_PATH", "certs/public/server.crt"),
        log_level=_get_log_level(),
    )


def load_client_config() -> ClientConfig:
    load_dotenv(ROOT_DIR / ".env")
    return ClientConfig(
        host=_get_str("SERVER_HOST", "127.0.0.1"),
        port=_get_int("SERVER_PORT", 9000, 1, 65535),
        pinned_cert_path=_get_path("PINNED_CERT_PATH", "certs/public/server.crt"),
        log_level=_get_log_level(),
    )
