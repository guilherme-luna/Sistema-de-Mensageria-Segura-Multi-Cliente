"""Servidor relay: autentica o handshake, anuncia os peers e encaminha frames E2E.

O servidor nunca recebe nem deriva chaves E2E: ele só conhece as chaves públicas
X25519 dos clientes, assina o que anuncia com a chave RSA do certificado e
encaminha os frames E2E sem conseguir decifrá-los.
"""

import argparse
import asyncio
import logging
import uuid
from dataclasses import dataclass, replace
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from common import crypto
from common.config import ConfigError, ServerConfig, load_server_config
from common.framing import FrameError, encode_error, encode_frame, read_frame
from common.log import fingerprint, force_utf8_output, setup_logging
from common.messages import (
    HELLO_MAX_LEN,
    Hello,
    HelloResp,
    InvalidNameError,
    MessageError,
    PeerJoin,
    PeerLeave,
    Role,
)
from common.protocol import MSG_TYPE_LEN, E2EFrame, E2EFrameError, ErrorCode, MsgType

log = logging.getLogger("server")


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


class Refused(Exception):
    """Handshake recusado: o código é enviado ao cliente antes de fechar a conexão."""

    def __init__(self, code: ErrorCode, reason: str):
        super().__init__(reason)
        self.code = code


@dataclass(eq=False)
class Session:
    client_id: bytes
    name: str
    pk: bytes
    # Salt do HELLO_RESP desta conexão: entra no material assinado das mensagens
    # de controle para que não possam ser repetidas em outra conexão.
    salt: bytes
    writer: asyncio.StreamWriter
    seq_send: int = 0

    @property
    def label(self) -> str:
        return f"{self.name} ({uuid.UUID(bytes=self.client_id)})"


class RelayServer:
    def __init__(self, config: ServerConfig, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate):
        self.config = config
        self._key = private_key
        self._cert_der = crypto.certificate_der(certificate)
        self.pk_server = crypto.public_key_der(certificate.public_key())
        if self.pk_server != crypto.public_key_der(private_key.public_key()):
            raise crypto.CryptoError("a chave privada não corresponde ao certificado")
        self.connections: set[asyncio.StreamWriter] = set()
        self.sessions: dict[bytes, Session] = {}

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")

        if len(self.connections) >= self.config.max_clients:
            log.warning("limite de %d clientes atingido, recusando %s", self.config.max_clients, peer)
            writer.write(encode_error(ErrorCode.SERVER_FULL))
            await _close(writer)
            return

        self.connections.add(writer)
        log.info("conexão de %s (%d ativas)", peer, len(self.connections))
        session: Optional[Session] = None
        try:
            session = await self._handshake(reader, writer, peer)
            if session is not None:
                await self._serve_session(reader, session)
        except Refused as e:
            log.warning("handshake de %s recusado: %s", peer, e)
            writer.write(encode_error(e.code))
        except FrameError as e:
            log.warning("frame inválido de %s: %s", session.label if session else peer, e)
            writer.write(encode_error(ErrorCode.BAD_FRAME))
        except ConnectionError:
            pass
        finally:
            self.connections.discard(writer)
            if session is not None:
                self._unregister(session)
            await _close(writer)
            log.info("desconexão de %s (%d ativas)", peer, len(self.connections))

    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer) -> Optional[Session]:
        try:
            # Antes do handshake só cabe um HELLO, e o cliente tem tempo limitado para enviá-lo
            frame = await asyncio.wait_for(
                read_frame(reader, max_len=MSG_TYPE_LEN + HELLO_MAX_LEN), self.config.handshake_timeout
            )
        except asyncio.TimeoutError:
            raise Refused(ErrorCode.HANDSHAKE_TIMEOUT, "tempo de handshake esgotado") from None
        except FrameError as e:
            raise Refused(ErrorCode.BAD_FRAME, f"frame inválido no handshake: {e}") from None
        if frame is None:
            return None
        if frame.msg_type != MsgType.HELLO:
            raise Refused(ErrorCode.BAD_FRAME, f"esperado HELLO, recebido {frame.msg_type.name}")
        try:
            hello = Hello.parse(frame.body)
        except InvalidNameError:
            raise Refused(ErrorCode.INVALID_NAME, "nome inválido") from None
        except MessageError as e:
            raise Refused(ErrorCode.BAD_FRAME, str(e)) from None

        # Daqui até o registro não há await: a checagem de nome e id e a inserção
        # na tabela são atômicas em relação às outras conexões.
        if hello.client_id in self.sessions:
            raise Refused(ErrorCode.ID_TAKEN, "client_id já conectado")
        if any(s.name == hello.name for s in self.sessions.values()):
            raise Refused(ErrorCode.NAME_TAKEN, f"nome {hello.name!r} já em uso")

        salt = crypto.random_salt()
        material = crypto.handshake_material(self.pk_server, hello.pk_client, hello.client_id, salt)
        signature = crypto.sign_pss(self._key, material)
        session = Session(hello.client_id, hello.name, hello.pk_client, salt, writer)
        self.sessions[session.client_id] = session
        writer.write(encode_frame(MsgType.HELLO_RESP, HelloResp(self._cert_der, salt, signature).encode()))
        log.info("handshake de %s concluído, chave %s", session.label, fingerprint(session.pk))
        self._announce_join(session)
        return session

    # --- Rendezvous ---

    def _send_control(self, recipient: Session, msg: PeerJoin | PeerLeave) -> None:
        """Numera com o seq_send do destinatário, assina e envia uma mensagem de controle."""
        recipient.seq_send += 1
        msg = replace(msg, seq_send=recipient.seq_send)
        signature = crypto.sign_pss(self._key, msg.signed_material(recipient.client_id, recipient.salt))
        msg_type = MsgType.PEER_JOIN if isinstance(msg, PeerJoin) else MsgType.PEER_LEAVE
        recipient.writer.write(encode_frame(msg_type, replace(msg, signature=signature).encode()))

    def _announce_join(self, newcomer: Session) -> None:
        """Apresenta o recém-chegado a cada cliente já conectado, com um salt_AB novo por par."""
        for other in list(self.sessions.values()):
            if other is newcomer:
                continue
            salt_ab = crypto.random_salt()
            # Quem já estava conectado é A; o recém-chegado é B (decisão 3)
            self._send_control(other, PeerJoin(newcomer.client_id, newcomer.pk, salt_ab, 0, Role.A, newcomer.name))
            self._send_control(newcomer, PeerJoin(other.client_id, other.pk, salt_ab, 0, Role.B, other.name))
        log.info("%s anunciado a %d peer(s)", newcomer.label, len(self.sessions) - 1)

    def _unregister(self, session: Session) -> None:
        if self.sessions.get(session.client_id) is not session:
            return
        del self.sessions[session.client_id]
        for other in self.sessions.values():
            self._send_control(other, PeerLeave(session.client_id, 0))

    # --- Relay ---

    async def _serve_session(self, reader: asyncio.StreamReader, session: Session) -> None:
        while (frame := await read_frame(reader)) is not None:
            if frame.msg_type != MsgType.E2E:
                raise FrameError(f"tipo {frame.msg_type.name} não é aceito após o handshake")
            self._relay(session, frame.body)

    def _relay(self, sender: Session, body: bytes) -> None:
        try:
            e2e = E2EFrame.parse(body)
        except E2EFrameError as e:
            raise FrameError(str(e)) from None
        if e2e.sender_id != sender.client_id:
            # O AAD já impede o destinatário de aceitar um remetente falso; aqui o
            # servidor só recusa encaminhar algo que o próprio cliente não poderia ter feito.
            raise FrameError("sender_id não corresponde à sessão")
        recipient = self.sessions.get(e2e.recipient_id)
        if recipient is None or recipient is sender:
            log.info("frame de %s para destinatário desconhecido descartado", sender.label)
            sender.writer.write(encode_error(ErrorCode.UNKNOWN_RECIPIENT))
            return
        # Os bytes são repassados sem alteração: o servidor não tem a chave para lê-los
        recipient.writer.write(encode_frame(MsgType.E2E, body))
        log.debug("relay %s -> %s, %d bytes", sender.label, recipient.label, len(body))

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
        relay = RelayServer(config, crypto.load_private_key(config.key_path), crypto.load_certificate(config.cert_path))
    except crypto.CryptoError as e:
        raise SystemExit(f"erro no certificado do servidor: {e}") from None
    log.info("certificado carregado, chave %s", fingerprint(relay.pk_server))

    try:
        asyncio.run(relay.serve())
    except KeyboardInterrupt:
        log.info("servidor encerrado")


if __name__ == "__main__":
    main()
