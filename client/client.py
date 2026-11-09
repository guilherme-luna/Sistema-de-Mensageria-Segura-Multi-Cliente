"""Cliente CLI da mensageria segura.

O cliente gera um par X25519 efêmero a cada conexão e só confia no servidor se o
certificado recebido for idêntico ao pinado e a assinatura do handshake conferir.
Depois disso, só aceita anúncios de peers (PEER_JOIN/PEER_LEAVE) assinados pelo
servidor para esta conexão, e deriva as chaves E2E de cada par localmente.

O texto das mensagens nunca vai para o log: só é devolvido a quem chamou, para exibir.
"""

import argparse
import asyncio
import builtins
import logging
import uuid
from dataclasses import dataclass, field, replace
from functools import partial
from queue import Empty, Queue
from threading import Event, Thread
from typing import Optional

from cryptography import x509

from common import crypto
from common.config import ClientConfig, ConfigError, load_client_config
from common.framing import Frame, FrameError, encode_frame, read_frame
from common.log import fingerprint, force_utf8_output, setup_logging
from common.messages import Hello, HelloResp, MessageError, PeerJoin, PeerLeave, Role
from common.protocol import MAX_NAME_LEN, MAX_PLAINTEXT_LEN, E2EFrame, E2EFrameError, ErrorCode, MsgType, is_valid_name

log = logging.getLogger("client")


class HandshakeError(Exception):
    pass


class ProtocolError(Exception):
    """O servidor mandou algo fora do protocolo; a conexão deve ser encerrada."""


class MessageRejected(Exception):
    """Frame E2E descartado (adulterado, repetido ou de remetente desconhecido); a conexão continua."""


class SendError(ValueError):
    """Mensagem que não pode ser enviada (peer desconhecido, texto vazio ou longo demais)."""


@dataclass(frozen=True)
class ChatMessage:
    sender: str
    text: str


@dataclass
class Peer:
    client_id: bytes
    name: str
    role: Role  # papel DESTE cliente no par
    pk: bytes = field(repr=False)
    # Chaves E2E do par: nunca aparecem em repr nem em logs
    send_key: bytes = field(repr=False)
    recv_key: bytes = field(repr=False)
    # IV_base deste lado para este par. O do peer não é guardado: vem em cada nonce (decisão 5)
    iv_base: bytes = field(default_factory=crypto.random_iv_base, repr=False)
    send_seq: int = 0  # último seq_no enviado; incrementado ANTES de cifrar, o primeiro é 1
    recv_seq: int = 0  # último seq_no aceito; só aceita seq_no maior (anti-replay)

    @property
    def label(self) -> str:
        return f"{self.name} ({uuid.UUID(bytes=self.client_id)})"


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
        self.peers: dict[bytes, Peer] = {}
        self._last_control_seq = 0

    async def handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, timeout: float = 10,
    ) -> None:
        """Envia HELLO e autentica o servidor pelo HELLO_RESP. Levanta HandshakeError ou CryptoError."""
        writer.write(encode_frame(MsgType.HELLO, Hello(self.client_id, self.pk, self.name).encode()))
        await writer.drain()

        try:
            frame = await asyncio.wait_for(read_frame(reader), timeout)
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

    # --- Mensagens depois do handshake ---

    def handle_frame(self, frame: Frame) -> Optional[ChatMessage]:
        """Processa um frame do servidor e devolve a mensagem recebida, se houver.

        Levanta ProtocolError ou AuthenticationError quando a conexão deve ser encerrada.
        Um frame E2E inválido é só descartado (com aviso no log), sem derrubar a conexão.
        """
        try:
            if frame.msg_type == MsgType.PEER_JOIN:
                self._on_peer_join(PeerJoin.parse(frame.body))
            elif frame.msg_type == MsgType.PEER_LEAVE:
                self._on_peer_leave(PeerLeave.parse(frame.body))
            elif frame.msg_type == MsgType.E2E:
                try:
                    return self.decrypt(frame.body)
                except MessageRejected as e:
                    log.warning("frame E2E rejeitado: %s", e)
            elif frame.msg_type == MsgType.ERROR:
                log.warning("erro do servidor: %s", describe_error(frame))
            else:
                raise ProtocolError(f"tipo {frame.msg_type.name} inesperado após o handshake")
        except MessageError as e:
            raise ProtocolError(f"{frame.msg_type.name} malformado: {e}") from None

    def _verify_control(self, msg: PeerJoin | PeerLeave) -> None:
        if self.server_key is None or self.session_salt is None:
            raise ProtocolError("mensagem de controle antes do handshake")
        crypto.verify_pss(self.server_key, msg.signature, msg.signed_material(self.client_id, self.session_salt))
        # A assinatura só vale para esta conexão; dentro dela, seq_send impede repetição
        if msg.seq_send <= self._last_control_seq:
            raise crypto.AuthenticationError("seq_send repetido ou fora de ordem (replay)")
        self._last_control_seq = msg.seq_send

    def _on_peer_join(self, msg: PeerJoin) -> None:
        self._verify_control(msg)
        if msg.peer_id == self.client_id:
            raise ProtocolError("o servidor anunciou este próprio cliente como peer")
        shared = crypto.x25519_shared_secret(self._sk, msg.pk_peer)
        key_a2b, key_b2a = crypto.derive_e2e_keys(shared, msg.salt_ab)
        send_key, recv_key = (key_a2b, key_b2a) if msg.role == Role.A else (key_b2a, key_a2b)
        peer = Peer(msg.peer_id, msg.name, msg.role, msg.pk_peer, send_key, recv_key)
        self.peers[peer.client_id] = peer
        log.info("peer %s entrou, chave %s, papel %s", peer.label, fingerprint(peer.pk), peer.role.name)

    def _on_peer_leave(self, msg: PeerLeave) -> None:
        self._verify_control(msg)
        peer = self.peers.pop(msg.peer_id, None)
        if peer is not None:
            log.info("peer %s saiu", peer.label)

    # --- Mensagens E2E ---

    def peer_by_name(self, name: str) -> Optional[Peer]:
        return next((p for p in self.peers.values() if p.name == name), None)

    def encrypt(self, peer_name: str, text: str) -> bytes:
        """Cifra text para o peer e devolve o frame TCP pronto para enviar ao servidor."""
        peer = self.peer_by_name(peer_name)
        if peer is None:
            raise SendError(f"peer {peer_name!r} não está conectado")
        plaintext = text.encode("utf-8")
        if not plaintext:
            raise SendError("mensagem vazia")
        if len(plaintext) > MAX_PLAINTEXT_LEN:
            raise SendError(f"mensagem com {len(plaintext)} bytes excede o limite de {MAX_PLAINTEXT_LEN}")
        # Incrementa antes de cifrar: um erro depois daqui nunca leva a reusar o mesmo nonce
        peer.send_seq += 1
        e2e = crypto.seal_e2e(peer.send_key, peer.iv_base, self.client_id, peer.client_id, peer.send_seq, plaintext)
        return encode_frame(MsgType.E2E, e2e.encode())

    def decrypt(self, body: bytes) -> ChatMessage:
        """Valida e decifra um frame E2E. Levanta MessageRejected sem alterar o estado do peer."""
        try:
            e2e = E2EFrame.parse(body)
        except E2EFrameError as e:
            raise MessageRejected(str(e)) from None
        if e2e.recipient_id != self.client_id:
            raise MessageRejected("frame destinado a outro cliente")
        peer = self.peers.get(e2e.sender_id)
        if peer is None:
            raise MessageRejected("remetente desconhecido")
        try:
            plaintext = crypto.open_e2e(peer.recv_key, e2e)
        except crypto.AuthenticationError as e:
            raise MessageRejected(f"de {peer.label}: {e} (frame adulterado)") from None
        # O seq_no está no AAD, então só é confiável depois de a tag conferir
        if e2e.seq_no <= peer.recv_seq:
            raise MessageRejected(f"de {peer.label}: seq_no {e2e.seq_no} já visto (replay)")
        peer.recv_seq = e2e.seq_no
        return ChatMessage(peer.name, plaintext.decode("utf-8", errors="replace"))


HELP = "Comandos: /peers | /msg <nome> <texto> | /quit"


def parse_command(line: str) -> tuple[str, str, str]:
    """Devolve (comando, destinatário, texto); entrada inválida vira ajuda."""
    parts = line.strip().split(maxsplit=2)
    if parts in (["/peers"], ["/quit"]):
        return parts[0], "", ""
    if len(parts) == 3 and parts[0] == "/msg":
        return "/msg", parts[1], parts[2]
    return "/help", "", ""


def _terminal_input(stopped: Event) -> str:
    """Adapta input() para permitir encerrar mesmo com o teclado bloqueado.

    Cancelar to_thread não interrompe input(). Só a thread daemon abaixo pode
    ficar esperando Enter; ela não impede a saída do processo. O executor do
    asyncio recebe EOF em até 50 ms e pode encerrar normalmente, inclusive no Windows.
    """
    lines: Queue[Optional[str]] = Queue()

    def read() -> None:
        try:
            lines.put(builtins.input())
        except (EOFError, OSError):
            lines.put(None)

    if stopped.is_set():
        raise EOFError
    Thread(target=read, daemon=True, name="chat-input").start()
    while not stopped.is_set():
        try:
            line = lines.get(timeout=0.05)
        except Empty:
            continue
        if line is None:
            raise EOFError
        return line
    raise EOFError


async def receive_messages(client: ChatClient, reader: asyncio.StreamReader) -> None:
    while (frame := await read_frame(reader)) is not None:
        message = client.handle_frame(frame)
        if message is not None:
            print(f"[{message.sender}] {message.text}", flush=True)
    log.info("o servidor encerrou a conexão")


async def read_commands(client: ChatClient, writer: asyncio.StreamWriter, stopped: Event) -> None:
    # O adaptador mantém o input bloqueante fora do event loop e permite cancelamento.
    input = partial(_terminal_input, stopped)
    print(HELP, flush=True)
    while True:
        try:
            line = await asyncio.to_thread(input)
        except EOFError:
            return
        command, recipient, text = parse_command(line)
        if command == "/quit":
            return
        if command == "/peers":
            peers = "\n".join(peer.label for peer in client.peers.values())
            print(peers or "Nenhum participante conectado.", flush=True)
        elif command == "/msg":
            try:
                writer.write(client.encrypt(recipient, text))
                await writer.drain()
            except SendError as e:
                print(f"Não foi possível enviar: {e}", flush=True)
        else:
            print(HELP, flush=True)


async def chat(client: ChatClient, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Recebe e envia simultaneamente; a primeira tarefa a terminar encerra a outra."""
    stopped = Event()
    tasks = [
        asyncio.create_task(receive_messages(client, reader)),
        asyncio.create_task(read_commands(client, writer, stopped)),
    ]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            if task in done:
                task.result()  # Propaga erros para o tratamento já existente em run().
    finally:
        stopped.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


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
            await client.handshake(reader, writer, timeout=config.handshake_timeout)
        except crypto.AuthenticationError as e:
            raise SystemExit(f"servidor NÃO autenticado, conexão abortada: {e}") from None
        except (HandshakeError, crypto.CryptoError) as e:
            raise SystemExit(f"falha no handshake: {e}") from None
        log.info("servidor autenticado; chave efêmera %s", fingerprint(client.pk))
        await chat(client, reader, writer)
    except crypto.AuthenticationError as e:
        log.error("mensagem do servidor NÃO autenticada, conexão abortada: %s", e)
    except (FrameError, ProtocolError, crypto.CryptoError) as e:
        log.error("erro de protocolo, conexão abortada: %s", e)
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
