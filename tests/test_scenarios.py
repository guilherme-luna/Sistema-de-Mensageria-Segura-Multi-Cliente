"""Cenários ponta a ponta obrigatórios: reconexão e framing inválido, com relay e conexões TCP reais."""

import asyncio
import struct

import pytest
from helpers import connect, frame_bytes, next_frame, process, running_server

from client.client import ChatMessage
from common.framing import encode_error, read_frame
from common.protocol import MAX_FRAME_LEN, ErrorCode, MsgType


async def exchange(sender, recipient, text):
    """Envia pelo relay e verifica o texto decifrado no destinatário."""
    frame = sender.client.encrypt(recipient.client.name, text)
    sender.writer.write(frame)
    await sender.writer.drain()
    received = recipient.client.handle_frame(await next_frame(recipient))
    assert received == ChatMessage(sender.client.name, text)
    return frame


async def test_reconnection_exchanges_messages_with_fresh_keys(identity, caplog):
    async with running_server(identity) as (relay, port):
        connections = []
        try:
            alice = await connect(port, identity[1], "alice")
            connections.append(alice)
            bob = await connect(port, identity[1], "bob")
            connections.append(bob)
            await process(alice, 1)
            await process(bob, 1)

            # Usa os contadores antes da saída: o novo par deve começar do zero.
            for _ in range(2):
                await exchange(alice, bob, "antes da reconexão")
                old_frame = await exchange(bob, alice, "resposta antiga")
            bob_id = bob.client.client_id
            old_pk = bob.client.pk
            old_salt = bob.client.session_salt
            old_peer = alice.client.peers[bob_id]
            old_keys = (old_peer.send_key, old_peer.recv_key)
            assert (old_peer.send_seq, old_peer.recv_seq) == (2, 2)

            await bob.close()
            assert (await process(alice, 1))[0].msg_type == MsgType.PEER_LEAVE
            assert bob_id not in relay.sessions
            assert bob_id not in alice.client.peers

            # Equivale ao --id: mantém UUID e nome, mas cria um novo ChatClient.
            bob = await connect(port, identity[1], "bob", bob_id)
            connections.append(bob)
            await process(alice, 1)
            await process(bob, 1)
            a_peer = alice.client.peers[bob_id]
            b_peer = bob.client.peers[alice.client.client_id]
            assert bob.client.client_id == bob_id
            assert bob.client.pk != old_pk
            assert bob.client.session_salt != old_salt
            assert a_peer.send_key != old_keys[0]
            assert a_peer.recv_key != old_keys[1]
            assert a_peer.send_key == b_peer.recv_key
            assert a_peer.recv_key == b_peer.send_key
            assert (a_peer.send_seq, a_peer.recv_seq, b_peer.send_seq, b_peer.recv_seq) == (0, 0, 0, 0)

            # Mesmo remetente/UUID: o ciphertext da conexão antiga não vale no par novo.
            bob.writer.write(old_frame)
            await bob.writer.drain()
            assert alice.client.handle_frame(await next_frame(alice)) is None
            assert "adulterado" in caplog.text
            assert a_peer.recv_seq == 0

            await exchange(alice, bob, "depois da reconexão")
            await exchange(bob, alice, "resposta com chave nova")
            assert (a_peer.send_seq, a_peer.recv_seq, b_peer.send_seq, b_peer.recv_seq) == (1, 1, 1, 1)
        finally:
            for conn in connections:
                await conn.close()


@pytest.mark.parametrize(("data", "eof"), [
    pytest.param(struct.pack(">I", 0), False, id="tamanho-zero"),
    pytest.param(struct.pack(">I", MAX_FRAME_LEN + 1), False, id="tamanho-acima-do-limite"),
    pytest.param(struct.pack(">I", 0xFFFFFFFF), False, id="tamanho-forjado"),
    pytest.param(struct.pack(">IB", 1, 0xEE), False, id="tipo-desconhecido"),
    pytest.param(b"\x00\x00", True, id="prefixo-incompleto"),
    pytest.param(struct.pack(">I", 10) + b"\x10abc", True, id="corpo-incompleto"),
])
async def test_invalid_framing_disconnects_only_offender(identity, data, eof):
    async with running_server(identity) as (relay, port):
        connections = []
        try:
            for name in ("alice", "bob", "invalido"):
                connections.append(await connect(port, identity[1], name))
            alice, bob, invalid = connections
            for conn in connections:
                await process(conn, 2)
            await exchange(alice, bob, "mensagem antes do erro")
            await exchange(bob, alice, "resposta antes do erro")

            invalid.writer.write(data)
            await invalid.writer.drain()
            if eof:
                # Encerra só o envio: ainda pode receber o erro do servidor.
                invalid.writer.write_eof()
            assert frame_bytes(await next_frame(invalid)) == encode_error(ErrorCode.BAD_FRAME)
            assert await asyncio.wait_for(read_frame(invalid.reader), timeout=2) is None
            assert set(relay.sessions) == {alice.client.client_id, bob.client.client_id}

            for conn in (alice, bob):
                assert (await process(conn, 1))[0].msg_type == MsgType.PEER_LEAVE
                assert invalid.client.client_id not in conn.client.peers
            await exchange(alice, bob, "continua depois do erro")
            await exchange(bob, alice, "a resposta também continua")
        finally:
            for conn in connections:
                await conn.close()
