"""Utilitários dos testes de rede: servidor em porta livre, cliente conectado e proxy MITM."""

import asyncio
import contextlib
import datetime
import uuid
from pathlib import Path
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from client.client import ChatClient
from common.config import ServerConfig
from common.framing import Frame, encode_frame, read_frame
from server.server import RelayServer
from tools.mitm_proxy import MitmProxy


def make_identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "teste")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_config(max_clients: int = 64, handshake_timeout: int = 10) -> ServerConfig:
    return ServerConfig(
        bind_host="127.0.0.1", port=0, max_clients=max_clients, handshake_timeout=handshake_timeout,
        key_path=Path("unused.key"), cert_path=Path("unused.crt"), log_level="INFO",
    )


@contextlib.asynccontextmanager
async def running_server(identity, **config):
    """Sobe o RelayServer numa porta livre e entrega (relay, porta)."""
    relay = RelayServer(make_config(**config), *identity)
    server = await asyncio.start_server(relay.handle_connection, "127.0.0.1", 0)
    try:
        yield relay, server.sockets[0].getsockname()[1]
    finally:
        # Fecha as conexões que um teste com falha deixou abertas; sem isso o
        # wait_closed() do Python 3.12+ espera por elas e o teste trava.
        server.close()
        for writer in list(relay.connections):
            writer.close()
        await asyncio.wait_for(server.wait_closed(), timeout=5)


class _FunctionProxy(MitmProxy):
    """O proxy da demo com server_to_client trocado por uma função do teste."""

    def __init__(self, upstream_port: int, to_client: Callable[[Frame], Optional[bytes]]):
        super().__init__("127.0.0.1", upstream_port, show=lambda _: None)
        self._to_client = to_client

    def server_to_client(self, frame: Frame) -> Optional[bytes]:
        return self._to_client(frame)


@contextlib.asynccontextmanager
async def tampering_proxy(upstream_port: int, to_client: Callable[[Frame], Optional[bytes]]):
    """Proxy MITM (tools/mitm_proxy.py) que aplica to_client a cada frame do servidor para o cliente.

    to_client devolve os bytes a entregar ao cliente (ou None para descartar o frame).
    """
    async with _FunctionProxy(upstream_port, to_client).serving() as port:
        yield port


def frame_bytes(frame: Frame) -> bytes:
    return encode_frame(frame.msg_type, frame.body)


class Connected:
    """Cliente conectado e autenticado, para os testes."""

    def __init__(self, client: ChatClient, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.client, self.reader, self.writer = client, reader, writer

    async def close(self):
        self.writer.close()
        with contextlib.suppress(ConnectionError):
            await self.writer.wait_closed()


async def connect(port: int, cert: x509.Certificate, name: str, client_id: Optional[bytes] = None) -> Connected:
    client = ChatClient(cert, name, client_id or uuid.uuid4().bytes)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await client.handshake(reader, writer)
    except BaseException:
        writer.close()
        raise
    return Connected(client, reader, writer)


async def next_frame(conn: Connected, timeout: float = 2) -> Frame:
    frame = await asyncio.wait_for(read_frame(conn.reader), timeout)
    assert frame is not None, "o servidor encerrou a conexão"
    return frame


async def process(conn: Connected, count: int) -> list[Frame]:
    """Lê count frames e os entrega ao cliente, como o laço principal faria."""
    frames = []
    for _ in range(count):
        frame = await next_frame(conn)
        conn.client.handle_frame(frame)
        frames.append(frame)
    return frames
