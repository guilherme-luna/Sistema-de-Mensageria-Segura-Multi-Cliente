"""Cliente CLI da mensageria segura.

Esqueleto de infraestrutura. Handshake, tabela de peers e cifra E2E vêm nas
próximas fases.
"""

import argparse
import asyncio
import logging
from dataclasses import replace

from common.config import ClientConfig, ConfigError, load_client_config
from common.log import force_utf8_output, setup_logging

log = logging.getLogger("client")


async def run(config: ClientConfig, name: str) -> None:
    try:
        reader, writer = await asyncio.open_connection(config.host, config.port)
    except OSError as e:
        raise SystemExit(f"não foi possível conectar em {config.host}:{config.port}: {e}") from None

    log.info("%s conectado a %s:%d", name, config.host, config.port)
    try:
        # TODO(fase 3): validar certificado pinado, handshake, peers e CLI
        await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()
        log.info("desconectado")


def parse_args(config: ClientConfig) -> tuple[ClientConfig, str]:
    parser = argparse.ArgumentParser(description="Cliente da mensageria segura")
    parser.add_argument("--host", default=config.host)
    parser.add_argument("--port", type=int, default=config.port)
    parser.add_argument("--name", required=True, help="nome exibido para os outros clientes")
    args = parser.parse_args()
    return replace(config, host=args.host, port=args.port), args.name


def main() -> None:
    force_utf8_output()
    try:
        config, name = parse_args(load_client_config())
    except ConfigError as e:
        raise SystemExit(f"erro de configuração: {e}") from None
    setup_logging(config.log_level)

    if not config.pinned_cert_path.is_file():
        raise SystemExit(
            f"certificado pinado não encontrado em {config.pinned_cert_path} "
            "(copie o server.crt gerado na máquina do servidor)"
        )

    try:
        asyncio.run(run(config, name))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
