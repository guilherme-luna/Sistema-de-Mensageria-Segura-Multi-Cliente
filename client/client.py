"""Cliente CLI da mensageria segura.

O cliente gera um par X25519 efêmero a cada conexão e só confia no servidor se o
certificado recebido for idêntico ao pinado e a assinatura do handshake conferir.
"""

import argparse
import asyncio
import logging
import uuid
from dataclasses import replace
from typing import Optional

from cryptography import x509

from common import crypto
from common.config import ClientConfig, ConfigError, load_client_config
from common.framing import Frame, FrameError, encode_frame, read_frame
from common.log import fingerprint, force_utf8_output, setup_logging
from common.messages import Hello, HelloResp, MessageError
from common.protocol import MAX_NAME_LEN, ErrorCode, MsgType, is_valid_name

log = logging.getLogger("client")

HANDSHAKE_TIMEOUT = 10


class HandshakeError(Exception):
    pass


def describe_error(frame: Frame) -> str:
    try:
        return ErrorCode(frame.body[0]).name if len(frame.body) == 1 else "frame de erro malformado"
    except ValueError:
        return f"código desconhecido {frame.body[0]:#04x}"


class ChatClient:
    def __init__(self, pinned_cert: x509.Certificate, name: str, client_id: bytes):
        self.pinned_cert = pinned_cert
        self.name = name
        self.client_id = client_id
        # Par efêmero: existe só em memória e só nesta conexão (forward secrecy)
        self._sk, self.pk = crypto.generate_x25519_keypair()
        self.session_salt: Optional[bytes] = None
        self.server_key = None

    async def handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Envia HELLO e autentica o servidor pelo HELLO_RESP. Levanta HandshakeError ou CryptoError."""
        writer.write(encode_frame(MsgType.HELLO, Hello(self.client_id, self.pk, self.name).encode()))
        await writer.drain()

        try:
            frame = await asyncio.wait_for(read_frame(reader), HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            raise HandshakeError("o servidor não respondeu ao HELLO") from None
        except FrameError as e:
            raise HandshakeError(f"resposta inválida do servidor: {e}") from None
        if frame is None:
            raise HandshakeError("o servidor encerrou a conexão")
        if frame.msg_type == MsgType.ERROR:
            raise HandshakeError(f"o servidor recusou o handshake: {describe_error(frame)}")
        if frame.msg_type != MsgType.HELLO_RESP:
            raise HandshakeError(f"esperado HELLO_RESP, recebido {frame.msg_type.name}")
        try:
            resp = HelloResp.parse(frame.body)
        except MessageError as e:
            raise HandshakeError(f"HELLO_RESP malformado: {e}") from None

        # A chave de verificação vem do certificado pinado, nunca dos bytes recebidos
        key = crypto.verify_pinned_certificate(self.pinned_cert, resp.certificate)
        material = crypto.handshake_material(crypto.public_key_der(key), self.pk, self.client_id, resp.salt)
        crypto.verify_pss(key, resp.signature, material)
        self.server_key = key
        self.session_salt = resp.salt


async def run(config: ClientConfig, name: str, client_id: uuid.UUID) -> None:
    try:
        pinned = crypto.load_certificate(config.pinned_cert_path)
    except crypto.CryptoError as e:
        raise SystemExit(str(e)) from None
    client = ChatClient(pinned, name, client_id.bytes)

    try:
        reader, writer = await asyncio.open_connection(config.host, config.port)
    except OSError as e:
        raise SystemExit(f"não foi possível conectar em {config.host}:{config.port}: {e}") from None

    log.info("%s (%s) conectado a %s:%d", name, client_id, config.host, config.port)
    try:
        try:
            await client.handshake(reader, writer)
        except crypto.AuthenticationError as e:
            raise SystemExit(f"servidor NÃO autenticado, conexão abortada: {e}") from None
        except (HandshakeError, crypto.CryptoError) as e:
            raise SystemExit(f"falha no handshake: {e}") from None
        log.info("servidor autenticado; chave efêmera %s", fingerprint(client.pk))
        # TODO(fase 2): tabela de peers a partir dos PEER_JOIN/PEER_LEAVE assinados
        await reader.read()
    except ConnectionError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass
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
