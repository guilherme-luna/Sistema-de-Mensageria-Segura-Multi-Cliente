import asyncio
import logging
import struct
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from helpers import connect, frame_bytes, running_server, tampering_proxy

from client.client import ChatClient, HandshakeError
from common import crypto
from common.config import ClientConfig
from common.framing import Frame, encode_error, encode_frame
from common.messages import HELLO_MAX_LEN, Hello, HelloResp
from common.protocol import ErrorCode, MsgType


def hello_frame(name="alice", client_id=None, pk=b"\x09" * 32) -> bytes:
    return encode_frame(MsgType.HELLO, Hello(client_id or uuid.uuid4().bytes, pk, name).encode())


async def send_raw(port: int, data: bytes) -> bytes:
    """Envia bytes crus e devolve tudo que o servidor mandar até fechar a conexão."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    writer.write_eof()
    await writer.drain()
    try:
        return await asyncio.wait_for(reader.read(), timeout=3)
    finally:
        writer.close()


# --- Caminho feliz ---


async def test_client_authenticates_server_and_is_registered(identity):
    async with running_server(identity) as (relay, port):
        conn = await connect(port, identity[1], "alice")
        session = relay.sessions[conn.client.client_id]
        assert session.name == "alice"
        assert session.pk == conn.client.pk
        assert conn.client.session_salt == session.salt
        await conn.close()


async def test_each_connection_gets_fresh_salt_and_ephemeral_key(identity):
    async with running_server(identity) as (_, port):
        first = await connect(port, identity[1], "alice")
        second = await connect(port, identity[1], "bob")
        assert first.client.session_salt != second.client.session_salt
        assert first.client.pk != second.client.pk
        for conn in (first, second):
            await conn.close()


async def test_session_removed_on_disconnect(identity):
    async with running_server(identity) as (relay, port):
        conn = await connect(port, identity[1], "alice")
        await conn.close()
        for _ in range(50):
            if not relay.sessions:
                break
            await asyncio.sleep(0.02)
        assert relay.sessions == {}


async def test_same_id_and_name_can_reconnect_after_leaving(identity):
    async with running_server(identity) as (relay, port):
        client_id = uuid.uuid4().bytes
        first = await connect(port, identity[1], "alice", client_id)
        await first.close()
        for _ in range(50):
            if not relay.sessions:
                break
            await asyncio.sleep(0.02)
        second = await connect(port, identity[1], "alice", client_id)
        assert second.client.session_salt != first.client.session_salt
        await second.close()


# --- Autenticação do servidor (MITM) ---


async def test_rejects_server_with_other_certificate(identity, other_identity):
    async with running_server(other_identity) as (_, port):
        with pytest.raises(crypto.AuthenticationError):
            await connect(port, identity[1], "alice")


def flip_in_hello_resp(field: str):
    def transform(frame: Frame) -> bytes:
        if frame.msg_type != MsgType.HELLO_RESP:
            return frame_bytes(frame)
        resp = HelloResp.parse(frame.body)
        value = bytearray(getattr(resp, field))
        value[len(value) // 2] ^= 0x01
        tampered = HelloResp(**{**resp.__dict__, field: bytes(value)})
        return encode_frame(MsgType.HELLO_RESP, tampered.encode())
    return transform


@pytest.mark.parametrize("field", ["certificate", "salt", "signature"])
async def test_rejects_tampered_hello_resp(identity, field):
    async with running_server(identity) as (_, port):
        async with tampering_proxy(port, flip_in_hello_resp(field)) as proxy_port:
            with pytest.raises(crypto.AuthenticationError):
                await connect(proxy_port, identity[1], "alice")


async def test_rejects_signature_made_for_another_client(identity):
    """Um MITM repassa ao cliente um HELLO_RESP legítimo emitido para OUTRA chave efêmera."""
    async with running_server(identity) as (_, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = ChatClient(identity[1], "alice", uuid.uuid4().bytes)
        # O MITM troca a chave pública do HELLO pela dele; a resposta assina a chave do MITM
        _, mitm_pk = crypto.generate_x25519_keypair()
        writer.write(hello_frame("alice", client.client_id, mitm_pk))
        await writer.drain()
        stolen = await reader.read(4096)

        fake_reader = asyncio.StreamReader()
        fake_reader.feed_data(stolen)
        fake_writer = _NullWriter()
        with pytest.raises(crypto.AuthenticationError):
            await client.handshake(fake_reader, fake_writer)
        writer.close()


class _NullWriter:
    def write(self, data):
        pass

    async def drain(self):
        pass


async def test_client_uses_handshake_deadline(identity):
    client = ChatClient(identity[1], "alice", uuid.uuid4().bytes)
    # Nenhuma resposta nem EOF: só o timeout pode encerrar essa leitura.
    reader = asyncio.StreamReader()
    with pytest.raises(HandshakeError, match="não respondeu"):
        await asyncio.wait_for(client.handshake(reader, _NullWriter(), timeout=0.01), timeout=1)


async def test_run_passes_configured_timeout(identity, monkeypatch):
    from client import client as cli

    writer = Mock(wait_closed=AsyncMock())
    reader = Mock()
    handshake = AsyncMock(side_effect=HandshakeError("teste de timeout"))
    monkeypatch.setattr(cli.crypto, "load_certificate", Mock(return_value=identity[1]))
    monkeypatch.setattr(cli.ChatClient, "handshake", handshake)
    monkeypatch.setattr(cli.asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    config = ClientConfig("127.0.0.1", 9000, Path("unused.crt"), "INFO", handshake_timeout=27)
    with pytest.raises(SystemExit, match="teste de timeout"):
        await cli.run(config, "alice", uuid.uuid4())
    handshake.assert_awaited_once_with(reader, writer, timeout=27)
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


async def test_client_reports_server_refusal(identity):
    async with running_server(identity) as (_, port):
        first = await connect(port, identity[1], "alice")
        with pytest.raises(HandshakeError, match="NAME_TAKEN"):
            await connect(port, identity[1], "alice")
        await first.close()


# --- Recusas do servidor ---


async def test_refuses_duplicate_name(identity):
    async with running_server(identity) as (_, port):
        first = await connect(port, identity[1], "alice")
        assert await send_raw(port, hello_frame("alice")) == encode_error(ErrorCode.NAME_TAKEN)
        await first.close()


async def test_refuses_duplicate_client_id_online(identity):
    async with running_server(identity) as (relay, port):
        first = await connect(port, identity[1], "alice")
        received = await send_raw(port, hello_frame("mallory", first.client.client_id))
        assert received == encode_error(ErrorCode.ID_TAKEN)
        # A sessão legítima continua a mesma
        assert relay.sessions[first.client.client_id].name == "alice"
        await first.close()


@pytest.mark.parametrize("data, code", [
    pytest.param(encode_frame(MsgType.HELLO, b"\x00" * 48 + b"a b"), ErrorCode.INVALID_NAME, id="nome-invalido"),
    pytest.param(encode_frame(MsgType.HELLO, b"\x00" * 20), ErrorCode.BAD_FRAME, id="hello-curto"),
    pytest.param(encode_frame(MsgType.E2E, b"\x00" * 80), ErrorCode.BAD_FRAME, id="nao-e-hello"),
    pytest.param(struct.pack(">IB", 1, 0xEE), ErrorCode.BAD_FRAME, id="tipo-desconhecido"),
])
async def test_refuses_invalid_first_frame(identity, data, code):
    async with running_server(identity) as (relay, port):
        assert await send_raw(port, data) == encode_error(code)
        assert relay.sessions == {}


async def test_frame_larger_than_hello_refused_before_reading_body(identity):
    """Antes do handshake só cabe um HELLO: um tamanho maior é recusado sem esperar o corpo."""
    async with running_server(identity) as (relay, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(struct.pack(">I", 2 + HELLO_MAX_LEN))  # sem EOF e sem corpo
        received = await asyncio.wait_for(reader.read(), timeout=2)
        assert received == encode_error(ErrorCode.BAD_FRAME)
        assert relay.sessions == {}
        writer.close()


async def test_handshake_timeout(identity):
    async with running_server(identity, handshake_timeout=1) as (relay, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(hello_frame()[:10])  # meio frame e silêncio
        received = await asyncio.wait_for(reader.read(), timeout=3)
        assert received == encode_error(ErrorCode.HANDSHAKE_TIMEOUT)
        assert relay.sessions == {}
        writer.close()


async def test_silent_disconnect_before_hello_is_not_an_error(identity):
    async with running_server(identity) as (relay, port):
        assert await send_raw(port, b"") == b""
        assert relay.sessions == {}


# --- Política de logs ---


async def test_logs_never_contain_secrets(identity, caplog):
    caplog.set_level(logging.DEBUG)
    async with running_server(identity) as (relay, port):
        conn = await connect(port, identity[1], "alice")
        session = relay.sessions[conn.client.client_id]
        await conn.close()
        await asyncio.sleep(0.05)
    text = caplog.text.lower()
    for secret in (session.salt, session.pk, conn.client.pk):
        assert secret.hex() not in text
