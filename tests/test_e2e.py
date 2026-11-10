import logging
import uuid

import pytest
from helpers import connect, next_frame, process, running_server

from client.client import ChatMessage, MessageRejected, SendError
from common.framing import encode_frame
from common.protocol import E2E_HEADER_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, E2EFrame, MsgType


async def pair(port, cert):
    alice = await connect(port, cert, "alice")
    bob = await connect(port, cert, "bob")
    await process(alice, 1)
    await process(bob, 1)
    return alice, bob


async def send(sender, recipient_name: str, text: str) -> bytes:
    frame = sender.client.encrypt(recipient_name, text)
    sender.writer.write(frame)
    await sender.writer.drain()
    return frame


async def receive(conn):
    return conn.client.handle_frame(await next_frame(conn))


@pytest.fixture
async def alice_bob(identity):
    async with running_server(identity) as (_, port):
        alice, bob = await pair(port, identity[1])
        yield alice, bob
        for conn in (alice, bob):
            await conn.close()


# --- Troca de mensagens ---


async def test_messages_flow_both_ways(alice_bob):
    alice, bob = alice_bob
    await send(alice, "bob", "oi bob")
    assert await receive(bob) == ChatMessage("alice", "oi bob")
    await send(bob, "alice", "olá alice ✓")
    assert await receive(alice) == ChatMessage("bob", "olá alice ✓")


async def test_three_clients_exchange_messages(identity):
    async with running_server(identity) as (_, port):
        conns = [await connect(port, identity[1], n) for n in ("alice", "bob", "carol")]
        for conn in conns:
            await process(conn, 2)
        alice, bob, carol = conns
        await send(alice, "carol", "para carol")
        await send(bob, "carol", "de bob")
        assert await receive(carol) == ChatMessage("alice", "para carol")
        assert await receive(carol) == ChatMessage("bob", "de bob")
        for conn in conns:
            await conn.close()


async def test_seq_starts_at_one_and_nonce_never_repeats(alice_bob):
    alice, _ = alice_bob
    frames = [E2EFrame.parse(alice.client.encrypt("bob", f"m{i}")[5:]) for i in range(5)]
    assert [f.seq_no for f in frames] == [1, 2, 3, 4, 5]
    assert len({f.nonce for f in frames}) == 5
    assert all(f.nonce[4:] == f.seq_no.to_bytes(8, "big") for f in frames)


async def test_ciphertext_does_not_contain_plaintext(alice_bob):
    alice, _ = alice_bob
    assert b"segredo" not in alice.client.encrypt("bob", "segredo")


# --- Adulteração e replay ---


@pytest.mark.parametrize("position", [
    pytest.param(0, id="nonce"),
    pytest.param(NONCE_LEN + 3, id="sender_id"),
    pytest.param(E2E_HEADER_LEN - 1, id="seq_no"),
    pytest.param(E2E_HEADER_LEN, id="ciphertext"),
    pytest.param(-1, id="tag"),
])
async def test_bitflip_is_rejected_and_connection_survives(alice_bob, position):
    alice, bob = alice_bob
    body = bytearray(alice.client.encrypt("bob", "original")[5:])
    body[position] ^= 0x01
    with pytest.raises(MessageRejected):
        bob.client.decrypt(bytes(body))
    # O frame inválido não muda o estado: a próxima mensagem legítima passa
    await send(alice, "bob", "depois")
    assert await receive(bob) == ChatMessage("alice", "depois")


async def test_bitflip_through_relay_is_discarded(alice_bob, caplog):
    alice, bob = alice_bob
    frame = bytearray(alice.client.encrypt("bob", "original"))
    frame[-1] ^= 0x01
    alice.writer.write(bytes(frame))
    assert await receive(bob) is None
    assert "adulterado" in caplog.text


async def test_replay_is_rejected(alice_bob):
    alice, bob = alice_bob
    frame = await send(alice, "bob", "uma vez")
    assert await receive(bob) == ChatMessage("alice", "uma vez")
    alice.writer.write(frame)  # o mesmo frame de novo
    with pytest.raises(MessageRejected, match="replay"):
        bob.client.decrypt((await next_frame(bob)).body)


async def test_old_frame_after_newer_one_is_rejected(alice_bob):
    alice, bob = alice_bob
    old = alice.client.encrypt("bob", "primeira")[5:]
    new = alice.client.encrypt("bob", "segunda")[5:]
    assert bob.client.decrypt(new).text == "segunda"
    with pytest.raises(MessageRejected, match="replay"):
        bob.client.decrypt(old)


async def test_rejects_frame_for_another_recipient(identity):
    async with running_server(identity) as (_, port):
        conns = [await connect(port, identity[1], n) for n in ("alice", "bob", "carol")]
        for conn in conns:
            await process(conn, 2)
        alice, _, carol = conns
        for_bob = alice.client.encrypt("bob", "só para bob")[5:]
        with pytest.raises(MessageRejected, match="outro cliente"):
            carol.client.decrypt(for_bob)
        for conn in conns:
            await conn.close()


async def test_rejects_unknown_sender(alice_bob):
    alice, bob = alice_bob
    body = bytearray(alice.client.encrypt("bob", "x")[5:])
    body[NONCE_LEN:NONCE_LEN + 16] = uuid.uuid4().bytes
    with pytest.raises(MessageRejected, match="desconhecido"):
        bob.client.decrypt(bytes(body))


async def test_rejects_malformed_e2e_body(alice_bob):
    _, bob = alice_bob
    with pytest.raises(MessageRejected):
        bob.client.decrypt(b"\x00" * 10)


# --- Envio ---


@pytest.mark.parametrize("name, text", [
    pytest.param("carol", "oi", id="peer-desconhecido"),
    pytest.param("bob", "", id="vazia"),
    pytest.param("bob", "x" * (MAX_PLAINTEXT_LEN + 1), id="longa-demais"),
])
async def test_send_errors(alice_bob, name, text):
    alice, _ = alice_bob
    with pytest.raises(SendError):
        alice.client.encrypt(name, text)
    assert alice.client.peer_by_name("bob").send_seq == 0


async def test_largest_message_fits_in_a_frame(alice_bob):
    alice, bob = alice_bob
    text = "x" * MAX_PLAINTEXT_LEN
    await send(alice, "bob", text)
    assert (await receive(bob)).text == text


async def test_message_text_never_logged(alice_bob, caplog):
    caplog.set_level(logging.DEBUG)
    alice, bob = alice_bob
    await send(alice, "bob", "texto-secreto-123")
    await receive(bob)
    assert "texto-secreto-123" not in caplog.text


def test_frame_layout_prefix():
    # Os testes acima cortam os 5 bytes do prefixo (tamanho + tipo) para obter o corpo E2E
    assert encode_frame(MsgType.E2E, b"abc")[5:] == b"abc"
