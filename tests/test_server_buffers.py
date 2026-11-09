import asyncio
import socket
import uuid

import pytest
from helpers import connect, make_config, next_frame, process, running_server

from client.client import ChatMessage
from common import crypto
from common.framing import encode_frame
from common.messages import PeerJoin, PeerLeave, Role
from common.protocol import MAX_PLAINTEXT_LEN, MsgType
from server.server import MAX_WRITE_BUFFER, RelayServer, Session


class NonReadingWriter:
    """Transporte determinístico: acumula a fila e nunca escoa os bytes."""

    def __init__(self, queued=0):
        self.transport = self
        self.pending = bytearray(queued)
        self.writes = []
        self.closed = False

    def is_closing(self):
        return self.closed

    def get_write_buffer_size(self):
        return len(self.pending)

    def write(self, data):
        self.pending.extend(data)
        self.writes.append(data)

    def abort(self):
        self.closed = True
        self.pending.clear()


def session(name, queued=0):
    return Session(uuid.uuid4().bytes, name, b"\x09" * 32, crypto.random_salt(), NonReadingWriter(queued))


def relay_pair(identity):
    relay = RelayServer(make_config(), *identity)
    alice, bob = session("alice"), session("bob")
    relay.sessions = {s.client_id: s for s in (alice, bob)}
    body = crypto.seal_e2e(b"k" * 16, b"i" * 4, alice.client_id, bob.client_id, 1, b"teste").encode()
    return relay, alice, bob, body


@pytest.mark.parametrize("offset, disconnect", [(-1, False), (0, False), (1, True)])
def test_relay_buffer_boundary(identity, offset, disconnect):
    relay, alice, bob, body = relay_pair(identity)
    frame = encode_frame(MsgType.E2E, body)
    bob.writer.pending = bytearray(MAX_WRITE_BUFFER - len(frame) + offset)
    relay._relay(alice, body)
    assert bob.writer.closed is disconnect
    assert bob.writer.writes == ([] if disconnect else [frame])
    assert bob.writer.get_write_buffer_size() <= MAX_WRITE_BUFFER
    assert not alice.writer.closed


@pytest.mark.parametrize("kind", ["join", "leave"])
def test_control_also_disconnects_non_reader(identity, kind):
    relay, alice, bob, _ = relay_pair(identity)
    bob.writer.pending = bytearray(MAX_WRITE_BUFFER)
    msg = PeerLeave(alice.client_id, 0)
    if kind == "join":
        msg = PeerJoin(alice.client_id, alice.pk, crypto.random_salt(), 0, Role.B, alice.name)
    relay._send_control(bob, msg)
    assert bob.writer.closed
    assert bob.writer.writes == []
    assert not alice.writer.closed


def test_does_not_write_again_after_abort(identity):
    relay, alice, bob, body = relay_pair(identity)
    bob.writer.pending = bytearray(MAX_WRITE_BUFFER)
    relay._relay(alice, body)
    # abort esvaziou a fila, mas a conexão já está encerrando.
    relay._relay(alice, body)
    relay._send_control(bob, PeerLeave(alice.client_id, 0))
    assert bob.writer.closed
    assert bob.writer.writes == []


async def test_real_non_reader_disconnects_without_stopping_other_clients(identity, caplog):
    async with running_server(identity) as (relay, port):
        alice = await connect(port, identity[1], "alice")
        carol = await connect(port, identity[1], "carol")
        slow = None
        try:
            await process(alice, 1)
            await process(carol, 1)
            slow = await connect(port, identity[1], "lento")
            # Depois do handshake, este cliente não lê mais nenhum frame.
            slow.writer.transport.pause_reading()
            slow.writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow_session = relay.sessions[slow.client.client_id]
            slow_session.writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            await process(alice, 1)
            await process(carol, 1)

            async def flood():
                for _ in range(128):  # Até 16 MiB; os buffers dos sockets acima são pequenos.
                    if slow.client.client_id not in relay.sessions:
                        return
                    for _ in range(32):
                        alice.writer.write(alice.client.encrypt("lento", "x" * MAX_PLAINTEXT_LEN))
                    await alice.writer.drain()
                    await asyncio.sleep(0.001)
                pytest.fail("o destinatário que não lê não foi desconectado")

            await asyncio.wait_for(flood(), timeout=10)
            assert slow.client.client_id not in relay.sessions
            assert alice.client.client_id in relay.sessions
            assert carol.client.client_id in relay.sessions
            assert "limite de buffer de envio" in caplog.text

            async def receive_message(conn):
                # Processa também PEER_LEAVE e eventuais UNKNOWN_RECIPIENT após a queda.
                while True:
                    message = conn.client.handle_frame(await next_frame(conn))
                    if message is not None:
                        return message

            alice.writer.write(alice.client.encrypt("carol", "continua"))
            await alice.writer.drain()
            assert await asyncio.wait_for(receive_message(carol), 2) == ChatMessage("alice", "continua")
            carol.writer.write(carol.client.encrypt("alice", "resposta"))
            await carol.writer.drain()
            assert await asyncio.wait_for(receive_message(alice), 2) == ChatMessage("carol", "resposta")
        finally:
            for conn in (slow, alice, carol):
                if conn is not None:
                    await conn.close()
