"""Cliente CLI da mensageria segura.

Esqueleto de infraestrutura. Handshake, tabela de peers e cifra E2E vêm nas
próximas fases.
"""

import argparse
import asyncio
import logging
import uuid
from dataclasses import replace

from common.config import ClientConfig, ConfigError, load_client_config
from common.log import force_utf8_output, setup_logging
from common.protocol import MAX_NAME_LEN, is_valid_name

log = logging.getLogger("client")


async def run(config: ClientConfig, name: str, client_id: uuid.UUID) -> None:
    try:
        reader, writer = await asyncio.open_connection(config.host, config.port)
    except OSError as e:
        raise SystemExit(f"não foi possível conectar em {config.host}:{config.port}: {e}") from None

    log.info("%s (%s) conectado a %s:%d", name, client_id, config.host, config.port)
    try:
        # TODO(fase 3): validar certificado pinado, handshake, peers e CLI
        await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()
        log.info("desconectado")


def _name(value: str) -> str:
    if not is_valid_name(value):
        raise argparse.ArgumentTypeError(
            f"nome inválido {value!r}: use de 1 a {MAX_NAME_LEN} caracteres entre letras, números, _ e -"
        )
    return value


def _client_id(value: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"client_id inválido {value!r}: esperado um UUID") from None
    if parsed.version != 4:
        raise argparse.ArgumentTypeError(f"client_id {value!r} não é um UUID v4")
    return parsed


def parse_args(config: ClientConfig) -> tuple[ClientConfig, str, uuid.UUID]:
    parser = argparse.ArgumentParser(description="Cliente da mensageria segura")
    parser.add_argument("--host", default=config.host)
    parser.add_argument("--port", type=int, default=config.port)
    parser.add_argument("--name", type=_name, required=True, help="nome exibido para os outros clientes")
    parser.add_argument(
        "--id", type=_client_id, default=None, dest="client_id",
        help="client_id (UUID v4) a reutilizar; por padrão um novo é gerado a cada execução",
    )
    args = parser.parse_args()
    client_id = args.client_id or uuid.uuid4()
    return replace(config, host=args.host, port=args.port), args.name, client_id


def main() -> None:
    force_utf8_output()
    try:
        config, name, client_id = parse_args(load_client_config())
    except ConfigError as e:
        raise SystemExit(f"erro de configuração: {e}") from None
    setup_logging(config.log_level)

    if not config.pinned_cert_path.is_file():
        raise SystemExit(
            f"certificado pinado não encontrado em {config.pinned_cert_path} "
            "(copie o server.crt gerado na máquina do servidor)"
        )

    try:
        asyncio.run(run(config, name, client_id))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
