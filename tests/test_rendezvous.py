import asyncio
import uuid

import pytest
from helpers import connect, frame_bytes, next_frame, process, running_server, tampering_proxy

from client.client import ProtocolError
from common import crypto
from common.framing import Frame, encode_error, encode_frame, read_frame
from common.messages import PeerJoin, Role
from common.protocol import E2EFrame, ErrorCode, MsgType


async def pair(port, cert):
    """alice conecta primeiro (A), bob depois (B); ambos processam o PEER_JOIN."""
    alice = await connect(port, cert, "alice")
    bob = await connect(port, cert, "bob")
    await process(alice, 1)
    await process(bob, 1)
    return alice, bob


# --- Distribuição de chaves ---


async def test_two_clients_derive_matching_directional_keys(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        a_view = alice.client.peers[bob.client.client_id]
        b_view = bob.client.peers[alice.client.client_id]

        assert (a_view.name, a_view.role, a_view.pk) == ("bob", Role.A, bob.client.pk)
        assert (b_view.name, b_view.role, b_view.pk) == ("alice", Role.B, alice.client.pk)
        # O que alice cifra, bob decifra, e vice-versa; cada direção tem sua chave
        assert a_view.send_key == b_view.recv_key
        assert b_view.send_key == a_view.recv_key
        assert a_view.send_key != a_view.recv_key
        for conn in (alice, bob):
            await conn.close()


async def test_three_clients_each_pair_gets_its_own_keys(identity):
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        bob = await connect(port, identity[1], "bob")
        carol = await connect(port, identity[1], "carol")
        await process(alice, 2)
        await process(bob, 2)
        await process(carol, 2)

        conns = (alice, bob, carol)
        keys = set()
        for me in conns:
            others = {c.client.client_id for c in conns if c is not me}
            assert set(me.client.peers) == others
            for peer in me.client.peers.values():
                keys.add(peer.send_key)
        assert len(keys) == 6  # 3 pares x 2 direções, todas diferentes
        assert carol.client.peers[alice.client.client_id].role == Role.B
        assert alice.client.peers[carol.client.client_id].role == Role.A
        for conn in conns:
            await conn.close()


async def test_peer_leave_removes_peer(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        await bob.close()
        frames = await process(alice, 1)
        assert frames[0].msg_type == MsgType.PEER_LEAVE
        assert alice.client.peers == {}
        await alice.close()


async def test_reconnection_gets_fresh_keys(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        old_key = alice.client.peers[bob.client.client_id].send_key
        bob_id = bob.client.client_id
        await bob.close()
        await process(alice, 1)

        bob = await connect(port, identity[1], "bob", bob_id)
        await process(alice, 1)
        assert alice.client.peers[bob_id].send_key != old_key
        for conn in (alice, bob):
            await conn.close()


# --- Ataques às mensagens de controle ---


def swap_peer_key(frame: Frame) -> bytes:
    """MITM troca a chave pública anunciada pela dele, mantendo a assinatura original."""
    if frame.msg_type != MsgType.PEER_JOIN:
        return frame_bytes(frame)
    body = bytearray(frame.body)
    body[16:48] = crypto.generate_x25519_keypair()[1]
    return encode_frame(MsgType.PEER_JOIN, bytes(body))


async def test_rejects_peer_join_with_swapped_key(identity):
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        async with tampering_proxy(port, swap_peer_key) as proxy_port:
            bob = await connect(proxy_port, identity[1], "bob")
            with pytest.raises(crypto.AuthenticationError):
                await process(bob, 1)
            assert bob.client.peers == {}
            await bob.close()
        await alice.close()


async def test_rejects_replayed_peer_join(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        carol = await connect(port, identity[1], "carol")
        join = await next_frame(alice)
        alice.client.handle_frame(join)
        with pytest.raises(crypto.AuthenticationError, match="replay"):
            alice.client.handle_frame(join)
        for conn in (alice, bob, carol):
            await conn.close()


async def test_rejects_peer_join_addressed_to_another_client(identity):
    """Um anúncio assinado para bob não é aceito por alice."""
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        bob = await connect(port, identity[1], "bob")
        carol = await connect(port, identity[1], "carol")
        await process(alice, 2)
        bob_frames = [await next_frame(bob) for _ in range(2)]
        carol_join_for_bob = bob_frames[1]
        with pytest.raises(crypto.AuthenticationError, match="assinatura"):
            alice.client.handle_frame(carol_join_for_bob)
        for conn in (alice, bob, carol):
            await conn.close()


async def test_rejects_peer_join_from_previous_connection(identity):
    """Mesmo client_id, conexão nova: o anúncio da conexão antiga (seq_send 1) não vale mais."""
    async with running_server(identity) as (relay, port):
        alice_id = uuid.uuid4().bytes
        alice = await connect(port, identity[1], "alice", alice_id)
        bob = await connect(port, identity[1], "bob")
        old_join = await next_frame(alice)
        await alice.close()
        while alice_id in relay.sessions:
            await asyncio.sleep(0.01)

        alice = await connect(port, identity[1], "alice", alice_id)
        assert PeerJoin.parse(old_join.body).seq_send == 1  # passaria só pelo contador
        with pytest.raises(crypto.AuthenticationError, match="assinatura"):
            alice.client.handle_frame(old_join)
        for conn in (alice, bob):
            await conn.close()


async def test_rejects_announcement_of_itself(identity):
    async with running_server(identity) as (relay, port):
        alice = await connect(port, identity[1], "alice")
        session = relay.sessions[alice.client.client_id]
        relay._send_control(session, PeerJoin(session.client_id, session.pk, crypto.random_salt(), 0, Role.A, "x"))
        with pytest.raises(ProtocolError):
            await process(alice, 1)
        await alice.close()


async def test_rejects_low_order_peer_key(identity):
    async with running_server(identity) as (relay, port):
        alice = await connect(port, identity[1], "alice")
        session = relay.sessions[alice.client.client_id]
        bad = PeerJoin(uuid.uuid4().bytes, bytes(32), crypto.random_salt(), 0, Role.A, "evil")
        relay._send_control(session, bad)
        with pytest.raises(crypto.CryptoError):
            await process(alice, 1)
        await alice.close()


# --- Relay ---


def seal(sender, recipient, seq_no: int, text: bytes) -> bytes:
    key = sender.client.peers[recipient.client.client_id].send_key
    frame = crypto.seal_e2e(key, crypto.random_iv_base(), sender.client.client_id,
                            recipient.client.client_id, seq_no, text)
    return frame.encode()


async def test_relay_delivers_e2e_frame_unchanged(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        body = seal(alice, bob, 1, b"oi bob")
        alice.writer.write(encode_frame(MsgType.E2E, body))

        frame = await next_frame(bob)
        assert frame == Frame(MsgType.E2E, body)
        recv_key = bob.client.peers[alice.client.client_id].recv_key
        assert crypto.open_e2e(recv_key, E2EFrame.parse(frame.body)) == b"oi bob"
        for conn in (alice, bob):
            await conn.close()


async def test_unknown_recipient_gets_error_and_connection_stays(identity):
    async with running_server(identity) as (relay, port):
        alice, bob = await pair(port, identity[1])
        body = bytearray(seal(alice, bob, 1, b"x"))
        body[28:44] = uuid.uuid4().bytes  # recipient_id que não existe
        alice.writer.write(encode_frame(MsgType.E2E, bytes(body)))
        assert frame_bytes(await next_frame(alice)) == encode_error(ErrorCode.UNKNOWN_RECIPIENT)
        assert alice.client.client_id in relay.sessions
        for conn in (alice, bob):
            await conn.close()


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda body: body[:12] + uuid.uuid4().bytes + body[28:], id="sender-falso"),
    pytest.param(lambda body: body[:40], id="e2e-curto"),
])
async def test_server_disconnects_on_invalid_e2e(identity, mutate):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        alice.writer.write(encode_frame(MsgType.E2E, mutate(seal(alice, bob, 1, b"x"))))
        assert frame_bytes(await next_frame(alice)) == encode_error(ErrorCode.BAD_FRAME)
        assert await asyncio.wait_for(read_frame(alice.reader), 2) is None
        # bob não recebeu nada além do aviso de saída de alice
        assert (await next_frame(bob)).msg_type == MsgType.PEER_LEAVE
        for conn in (alice, bob):
            await conn.close()


async def test_server_disconnects_on_control_frame_after_handshake(identity):
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        alice.writer.write(encode_frame(MsgType.HELLO, b"\x00" * 60))
        assert frame_bytes(await next_frame(alice)) == encode_error(ErrorCode.BAD_FRAME)
        await alice.close()


async def test_each_pair_gets_fresh_salt_shared_by_both_sides(identity):
    async with running_server(identity) as (_, port):
        conns = [await connect(port, identity[1], name) for name in ("alice", "bob", "carol")]
        salts = {}
        for conn in conns:
            for frame in await process(conn, 2):
                join = PeerJoin.parse(frame.body)
                pair_ids = frozenset((conn.client.client_id, join.peer_id))
                salts.setdefault(pair_ids, set()).add(join.salt_ab)
        # Os dois lados de cada par recebem o mesmo salt_AB, e cada par tem o seu
        assert all(len(s) == 1 for s in salts.values())
        assert len({next(iter(s)) for s in salts.values()}) == 3
        for conn in conns:
            await conn.close()


async def test_frame_addressed_to_sender_is_not_echoed(identity):
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        me = alice.client.client_id
        body = crypto.seal_e2e(bytes(16), crypto.random_iv_base(), me, me, 1, b"x").encode()
        alice.writer.write(encode_frame(MsgType.E2E, body))
        assert frame_bytes(await next_frame(alice)) == encode_error(ErrorCode.UNKNOWN_RECIPIENT)
        await alice.close()
