"""Testes da ferramenta de demonstração tools/mitm_proxy.py: os mesmos ataques mostrados ao vivo."""

import argparse
import io
import logging

import pytest
from helpers import connect, next_frame, process, running_server

from client.client import ChatMessage
from common import crypto
from tools import mitm_proxy
from tools.mitm_proxy import MitmProxy


class Demo:
    """alice conecta pelo proxy; bob conecta direto no servidor (o arranjo da apresentação)."""

    def __init__(self, proxy, alice, bob, server_port):
        self.proxy, self.alice, self.bob, self.server_port = proxy, alice, bob, server_port


@pytest.fixture
async def demo(identity):
    shown: list[str] = []
    async with running_server(identity) as (_, server_port):
        proxy = MitmProxy("127.0.0.1", server_port, show=shown.append)
        async with proxy.serving() as proxy_port:
            alice = await connect(proxy_port, identity[1], "alice")
            bob = await connect(server_port, identity[1], "bob")
            await process(alice, 1)
            await process(bob, 1)
            proxy.shown = shown
            yield Demo(proxy, alice, bob, server_port)
            for conn in (alice, bob):
                await conn.close()


async def send(conn, to: str, text: str) -> None:
    conn.writer.write(conn.client.encrypt(to, text))
    await conn.writer.drain()


async def receive(conn):
    return conn.client.handle_frame(await next_frame(conn))


# --- Repasse normal ---


async def test_relays_messages_both_ways(demo):
    await send(demo.alice, "bob", "oi bob")
    assert await receive(demo.bob) == ChatMessage("alice", "oi bob")
    await send(demo.bob, "alice", "oi alice")
    assert await receive(demo.alice) == ChatMessage("bob", "oi alice")


async def test_shows_only_what_an_attacker_sees(demo):
    await send(demo.alice, "bob", "texto-secreto")
    await receive(demo.bob)
    line = next(s for s in demo.proxy.shown if "E2E" in s)
    # Nomes aprendidos do HELLO e do PEER_JOIN, seq_no e ciphertext em hex
    assert "alice -> bob" in line and "seq_no=1" in line and "ciphertext:" in line
    assert all("texto-secreto" not in s for s in demo.proxy.shown)


# --- Ataques ---


async def test_bitflip_is_rejected_by_recipient(demo, caplog):
    demo.proxy.arm_bitflip()
    await send(demo.alice, "bob", "original")
    assert await receive(demo.bob) is None
    assert "adulterado" in caplog.text
    # O ataque vale para uma mensagem só; a conversa continua
    await send(demo.alice, "bob", "depois")
    assert await receive(demo.bob) == ChatMessage("alice", "depois")


async def test_replay_is_rejected_by_recipient(demo, caplog):
    await send(demo.alice, "bob", "uma vez")
    assert await receive(demo.bob) == ChatMessage("alice", "uma vez")
    await demo.proxy.replay_last()
    assert await receive(demo.bob) is None
    assert "replay" in caplog.text
    await send(demo.alice, "bob", "de novo, legítima")
    assert await receive(demo.bob) == ChatMessage("alice", "de novo, legítima")


async def test_replay_right_after_bitflip_is_still_a_replay(demo, caplog):
    """'b' e depois 'r': o replay reenvia a última mensagem ACEITA, não o original da adulterada."""
    await send(demo.alice, "bob", "aceita")
    assert await receive(demo.bob) == ChatMessage("alice", "aceita")
    demo.proxy.arm_bitflip()
    await send(demo.alice, "bob", "adulterada")
    assert await receive(demo.bob) is None
    await demo.proxy.replay_last()
    assert await receive(demo.bob) is None
    assert "replay" in caplog.text


async def test_replay_without_previous_message_does_nothing(demo):
    await demo.proxy.replay_last()
    assert "nada para reenviar" in demo.proxy.shown[-1]


async def test_swapped_peer_key_is_rejected_by_signature(demo, identity):
    demo.proxy.arm_swap_key()
    carol = await connect(demo.server_port, identity[1], "carol")
    with pytest.raises(crypto.AuthenticationError, match="assinatura"):
        await process(demo.alice, 1)
    assert demo.alice.client.peer_by_name("carol") is None
    await carol.close()


# --- Interface de linha de comando ---


async def test_keyboard_commands(demo, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("b\nk\nr\n???\nq\nb\n"))
    await mitm_proxy.read_commands(demo.proxy)
    text = "\n".join(demo.proxy.shown)
    assert "bitflip armado" in text
    assert "troca de chave armada" in text
    assert "nada para reenviar" in text
    assert text.count(mitm_proxy.HELP) == 2  # ao iniciar e no comando desconhecido
    # O "b" depois do "q" não chega a ser lido como comando
    assert text.count("bitflip armado") == 1


async def test_keyboard_eof_stops_commands(demo, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    await mitm_proxy.read_commands(demo.proxy)


def test_upstream_argument():
    assert mitm_proxy._upstream("192.168.0.16:9000") == ("192.168.0.16", 9000)
    for bad in ("9000", "host:", "host:porta"):
        with pytest.raises(argparse.ArgumentTypeError):
            mitm_proxy._upstream(bad)


async def test_proxy_output_has_no_secrets_in_logs(demo, caplog):
    caplog.set_level(logging.DEBUG)
    await send(demo.alice, "bob", "segredo-123")
    await receive(demo.bob)
    assert "segredo-123" not in caplog.text
