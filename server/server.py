"""Servidor relay: aceita conexões TCP simultâneas e encaminha frames E2E.

Esqueleto de infraestrutura. Handshake, tabela de sessões e relay vêm nas
próximas fases.
"""

import argparse
import asyncio
import logging
from dataclasses import replace

from common.config import ConfigError, ServerConfig, load_server_config
from common.framing import encode_error
from common.log import force_utf8_output, setup_logging
from common.protocol import ErrorCode

log = logging.getLogger("server")


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


class RelayServer:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.connections: set[asyncio.StreamWriter] = set()

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")

        if len(self.connections) >= self.config.max_clients:
            log.warning("limite de %d clientes atingido, recusando %s", self.config.max_clients, peer)
            writer.write(encode_error(ErrorCode.SERVER_FULL))
            await _close(writer)
            return

        self.connections.add(writer)
        log.info("conexão de %s (%d ativas)", peer, len(self.connections))
        try:
            # TODO(fase 2): handshake com timeout, registro em sessions e relay
            while await reader.read(4096):
                pass
        except ConnectionError:
            pass
        finally:
            self.connections.discard(writer)
            await _close(writer)
            log.info("desconexão de %s (%d ativas)", peer, len(self.connections))

    async def serve(self) -> None:
        host, port = self.config.bind_host, self.config.port
        try:
            server = await asyncio.start_server(self.handle_connection, host, port)
        except OSError as e:
            raise SystemExit(
                f"não foi possível escutar em {host}:{port} ({e.strerror or e}). "
                "A porta pode estar em uso ou o endereço não pertence a esta máquina; "
                "ajuste SERVER_PORT / SERVER_BIND_HOST."
            ) from None
        log.info("escutando em %s:%d", host, port)
        async with server:
            await server.serve_forever()


def parse_args(config: ServerConfig) -> ServerConfig:
    parser = argparse.ArgumentParser(description="Servidor relay da mensageria segura")
    parser.add_argument("--host", default=config.bind_host, help="interface de escuta (SERVER_BIND_HOST)")
    parser.add_argument("--port", type=int, default=config.port)
    args = parser.parse_args()
    return replace(config, bind_host=args.host, port=args.port)


def main() -> None:
    force_utf8_output()
    try:
        config = parse_args(load_server_config())
    except ConfigError as e:
        raise SystemExit(f"erro de configuração: {e}") from None
    setup_logging(config.log_level)

    if not config.key_path.is_file() or not config.cert_path.is_file():
        raise SystemExit("certificado não encontrado, rode: python scripts/gen_cert.py")

    try:
        asyncio.run(RelayServer(config).serve())
    except KeyboardInterrupt:
        log.info("servidor encerrado")


if __name__ == "__main__":
    main()
