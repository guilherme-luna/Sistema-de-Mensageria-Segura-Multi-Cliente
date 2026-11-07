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


@contextlib.asynccontextmanager
async def tampering_proxy(upstream_port: int, to_client: Callable[[Frame], Optional[bytes]]):
    """Proxy MITM: repassa cliente -> servidor intacto e aplica to_client a cada frame do servidor.

    to_client devolve os bytes a entregar ao cliente (ou None para descartar o frame).
    """
    async def pump_up(reader, writer):
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()

    async def pump_down(reader, writer):
        while (frame := await read_frame(reader)) is not None:
            out = to_client(frame)
            if out is not None:
                writer.write(out)
                await writer.drain()

    open_writers = set()

    async def handle(client_reader, client_writer):
        open_writers.add(client_writer)
        server_reader, server_writer = await asyncio.open_connection("127.0.0.1", upstream_port)
        tasks = [
            asyncio.create_task(pump_up(client_reader, server_writer)),
            asyncio.create_task(pump_down(server_reader, client_writer)),
        ]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()
        for writer in (client_writer, server_writer):
            writer.close()

    proxy = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield proxy.sockets[0].getsockname()[1]
    finally:
        proxy.close()
        for writer in open_writers:
            writer.close()
        await asyncio.wait_for(proxy.wait_closed(), timeout=5)


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
