"""Proxy MITM para a demonstração: fica entre UM cliente e o servidor e ataca o tráfego ao vivo.

Uso (o cliente atacado conecta na porta do proxy; os outros, direto no servidor):

    python -m tools.mitm_proxy --listen 9001 --upstream 127.0.0.1:9000
    python -m client.client --name alice --port 9001
    python -m client.client --name bob

Comandos no terminal do proxy:

    b   inverte um bit na próxima mensagem E2E enviada pelo cliente (o destinatário rejeita pela tag GCM)
    r   reenvia agora a última mensagem E2E do cliente (o destinatário rejeita pelo seq_no: replay)
    k   troca a chave pública no próximo PEER_JOIN recebido pelo cliente (ele rejeita pela assinatura RSA-PSS)
    h   ajuda
    q   sai

Para cada frame E2E o proxy mostra só o que um atacante na rede vê: quem fala com
quem, o seq_no, o tamanho e o começo do ciphertext. O texto nunca aparece, porque
o proxy não tem a chave.
"""

import argparse
import asyncio
import contextlib
import os
import sys
import threading
import uuid
from typing import Callable, Optional

from common import crypto
from common.framing import Frame, FrameError, encode_frame, read_frame
from common.log import force_utf8_output
from common.messages import Hello, MessageError, PeerJoin
from common.protocol import CLIENT_ID_LEN, E2E_HEADER_LEN, X25519_PUBKEY_LEN, E2EFrame, E2EFrameError, MsgType

HELP = (
    "comandos: b = bitflip na próxima mensagem | r = replay da última mensagem | "
    "k = troca a chave do próximo PEER_JOIN | h = ajuda | q = sair"
)
CIPHERTEXT_PREVIEW = 16  # bytes do ciphertext mostrados em hex


class MitmProxy:
    """Repassa frames entre cliente e servidor, mostrando e (sob comando) atacando o tráfego.

    Pensado para um cliente por vez: os comandos valem para a conexão mais recente.
    """

    def __init__(self, upstream_host: str, upstream_port: int, show: Callable[[str], None] = print):
        self.upstream = (upstream_host, upstream_port)
        self.show = show
        self._bitflip_armed = False
        self._swap_key_armed = False
        self._last_e2e: Optional[bytes] = None
        self._server_writer: Optional[asyncio.StreamWriter] = None
        self._names: dict[bytes, str] = {}
        self._writers: set[asyncio.StreamWriter] = set()

    # --- Comandos ---

    def arm_bitflip(self) -> None:
        self._bitflip_armed = True
        self.show("[ataque] bitflip armado: a próxima mensagem E2E do cliente sai com 1 bit invertido")

    def arm_swap_key(self) -> None:
        self._swap_key_armed = True
        self.show("[ataque] troca de chave armada: o próximo PEER_JOIN chega ao cliente com outra chave pública")

    async def replay_last(self) -> None:
        if self._last_e2e is None or self._server_writer is None or self._server_writer.is_closing():
            self.show("[ataque] nada para reenviar: o cliente ainda não mandou mensagem")
            return
        self.show("[ataque] replay: reenviando a última mensagem E2E do cliente, byte a byte igual")
        self._server_writer.write(self._last_e2e)
        await self._server_writer.drain()

    # --- Interceptação (sobrescrevível nos testes) ---

    def client_to_server(self, frame: Frame) -> Optional[bytes]:
        """Bytes a repassar ao servidor (None descarta o frame)."""
        if frame.msg_type == MsgType.HELLO:
            with contextlib.suppress(MessageError):
                hello = Hello.parse(frame.body)
                self._names[hello.client_id] = hello.name
        data = encode_frame(frame.msg_type, frame.body)
        if frame.msg_type != MsgType.E2E:
            return data
        self._last_e2e = data  # guarda o original, para o replay ser idêntico ao que já foi aceito
        self._describe(frame.body, "cliente -> servidor")
        if self._bitflip_armed and len(frame.body) > E2E_HEADER_LEN:
            self._bitflip_armed = False
            body = bytearray(frame.body)
            body[E2E_HEADER_LEN] ^= 0x01  # primeiro byte do ciphertext
            self.show("[ataque] bit invertido no ciphertext desta mensagem")
            return encode_frame(MsgType.E2E, bytes(body))
        return data

    def server_to_client(self, frame: Frame) -> Optional[bytes]:
        """Bytes a entregar ao cliente (None descarta o frame)."""
        if frame.msg_type == MsgType.PEER_JOIN:
            with contextlib.suppress(MessageError):
                join = PeerJoin.parse(frame.body)
                self._names[join.peer_id] = join.name
            if self._swap_key_armed:
                self._swap_key_armed = False
                body = bytearray(frame.body)
                key_start = CLIENT_ID_LEN
                body[key_start:key_start + X25519_PUBKEY_LEN] = crypto.generate_x25519_keypair()[1]
                self.show("[ataque] chave pública do peer trocada pela do atacante neste PEER_JOIN")
                return encode_frame(MsgType.PEER_JOIN, bytes(body))
        elif frame.msg_type == MsgType.E2E:
            self._describe(frame.body, "servidor -> cliente")
        return encode_frame(frame.msg_type, frame.body)

    def _name(self, client_id: bytes) -> str:
        return self._names.get(client_id) or str(uuid.UUID(bytes=client_id))[:8]

    def _describe(self, body: bytes, direction: str) -> None:
        try:
            e2e = E2EFrame.parse(body)
        except E2EFrameError:
            self.show(f"[{direction}] E2E malformado, {len(body)} B")
            return
        preview = e2e.ciphertext[:CIPHERTEXT_PREVIEW].hex(" ")
        self.show(
            f"[{direction}] E2E {self._name(e2e.sender_id)} -> {self._name(e2e.recipient_id)} "
            f"seq_no={e2e.seq_no} {len(e2e.ciphertext)} B | ciphertext: {preview} ..."
        )

    # --- Rede ---

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            server_reader, server_writer = await asyncio.open_connection(*self.upstream)
        except OSError as e:
            self.show(f"[proxy] não foi possível conectar ao servidor {self.upstream}: {e}")
            client_writer.close()
            return
        self._server_writer = server_writer
        self._writers.update((client_writer, server_writer))
        self.show("[proxy] cliente conectado; repassando para o servidor")
        tasks = [
            asyncio.create_task(self._pump(client_reader, server_writer, self.client_to_server)),
            asyncio.create_task(self._pump(server_reader, client_writer, self.server_to_client)),
        ]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()
        for writer in (client_writer, server_writer):
            writer.close()
            self._writers.discard(writer)
        self.show("[proxy] conexão encerrada")

    async def _pump(self, reader, writer, intercept: Callable[[Frame], Optional[bytes]]) -> None:
        with contextlib.suppress(FrameError, ConnectionError):
            while (frame := await read_frame(reader)) is not None:
                data = intercept(frame)
                if data is not None:
                    writer.write(data)
                    await writer.drain()

    @contextlib.asynccontextmanager
    async def serving(self, host: str = "127.0.0.1", port: int = 0):
        """Escuta em host:port e entrega a porta efetiva; fecha tudo ao sair."""
        server = await asyncio.start_server(self.handle, host, port)
        try:
            yield server.sockets[0].getsockname()[1]
        finally:
            server.close()
            for writer in list(self._writers):
                writer.close()
            await asyncio.wait_for(server.wait_closed(), timeout=5)


async def read_commands(proxy: MitmProxy) -> None:
    loop = asyncio.get_running_loop()
    lines: asyncio.Queue[Optional[str]] = asyncio.Queue()

    def read_stdin() -> None:
        for line in sys.stdin:
            loop.call_soon_threadsafe(lines.put_nowait, line)
        loop.call_soon_threadsafe(lines.put_nowait, None)

    # Thread daemon: o input() bloqueante não pode rodar no laço do asyncio
    threading.Thread(target=read_stdin, daemon=True, name="proxy-input").start()
    proxy.show(HELP)
    while (line := await lines.get()) is not None:
        command = line.strip().lower()
        if command == "b":
            proxy.arm_bitflip()
        elif command == "r":
            await proxy.replay_last()
        elif command == "k":
            proxy.arm_swap_key()
        elif command == "q":
            return
        elif command:
            proxy.show(HELP)


async def run(listen_port: int, upstream_host: str, upstream_port: int) -> None:
    proxy = MitmProxy(upstream_host, upstream_port)
    async with proxy.serving("127.0.0.1", listen_port):
        proxy.show(f"[proxy] escutando em 127.0.0.1:{listen_port}, repassando para {upstream_host}:{upstream_port}")
        await read_commands(proxy)


def _upstream(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        raise argparse.ArgumentTypeError(f"esperado host:porta, recebido {value!r}")
    return host, int(port)


def main() -> None:
    force_utf8_output()
    parser = argparse.ArgumentParser(description="Proxy MITM para demonstrar bitflip, replay e troca de chave")
    parser.add_argument("--listen", type=int, default=9001, help="porta onde o cliente atacado conecta")
    parser.add_argument("--upstream", type=_upstream, default=("127.0.0.1", 9000), help="servidor real (host:porta)")
    args = parser.parse_args()
    code = 0
    try:
        asyncio.run(run(args.listen, *args.upstream))
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"erro: {e}", file=sys.stderr)
        code = 1
    # A thread que lê o teclado pode estar bloqueada; sair sem esperar por ela
    # (no Python 3.10 a finalização normal aborta disputando o lock do stdin).
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
