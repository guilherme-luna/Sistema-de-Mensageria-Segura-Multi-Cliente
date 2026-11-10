"""Política de logs: uma sessão completa, com ataques, não deixa nenhum segredo no log.

Roda handshake, troca de mensagens, bitflip, replay e saída de peer com log em DEBUG
e procura cada segredo da sessão no texto do log, em hex e em repr de bytes.
"""

import logging

from cryptography.hazmat.primitives import serialization
from helpers import connect, next_frame, process, running_server

from common import crypto
from common.messages import PeerJoin
from common.protocol import E2EFrame, MsgType
from tools.mitm_proxy import MitmProxy

PLAINTEXTS = ["primeira-mensagem-secreta", "resposta-secreta-do-bob", "mensagem-que-sera-adulterada"]


def forms(secret: bytes) -> list[str]:
    """Formas em que um segredo poderia aparecer num log: hex e repr de bytes."""
    return [secret.hex(), repr(secret)[2:-1]]


def raw_private(sk) -> bytes:
    return sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())


async def test_full_session_logs_no_secrets(identity, caplog):
    caplog.set_level(logging.DEBUG)
    secrets: dict[str, bytes] = {}
    async with running_server(identity) as (relay, server_port):
        proxy = MitmProxy("127.0.0.1", server_port, show=lambda _: None)
        async with proxy.serving() as proxy_port:
            alice = await connect(proxy_port, identity[1], "alice")
            bob = await connect(server_port, identity[1], "bob")
            joins = [PeerJoin.parse(f.body) for f in await process(alice, 1) + await process(bob, 1)]

            # Troca normal nas duas direções
            sent = []
            for sender, receiver, to, text in [(alice, bob, "bob", PLAINTEXTS[0]),
                                               (bob, alice, "alice", PLAINTEXTS[1])]:
                frame = sender.client.encrypt(to, text)
                sent.append(E2EFrame.parse(frame[5:]))
                sender.writer.write(frame)
                assert receiver.client.handle_frame(await next_frame(receiver)).text == text

            # Bitflip e replay pelo proxy: os dois são rejeitados e logados
            proxy.arm_bitflip()
            alice.writer.write(alice.client.encrypt("bob", PLAINTEXTS[2]))
            assert bob.client.handle_frame(await next_frame(bob)) is None
            await proxy.replay_last()
            assert bob.client.handle_frame(await next_frame(bob)) is None

            # Segredos da sessão, coletados antes de alguém sair
            for name, conn in (("alice", alice), ("bob", bob)):
                secrets[f"{name}: chave privada X25519"] = raw_private(conn.client._sk)
                secrets[f"{name}: salt da sessão"] = conn.client.session_salt
                for peer in conn.client.peers.values():
                    secrets[f"{name}: chave de envio"] = peer.send_key
                    secrets[f"{name}: chave de recebimento"] = peer.recv_key
                    secrets[f"{name}: IV_base"] = peer.iv_base
            secrets["segredo ECDH"] = crypto.x25519_shared_secret(alice.client._sk, bob.client.pk)
            secrets["salt_AB"] = joins[0].salt_ab
            for i, e2e in enumerate(sent):
                secrets[f"nonce {i}"] = e2e.nonce
                secrets[f"ciphertext {i}"] = e2e.ciphertext
            for session in relay.sessions.values():
                secrets[f"servidor: salt de {session.name}"] = session.salt

            await bob.close()
            assert (await next_frame(alice)).msg_type == MsgType.PEER_LEAVE
            await alice.close()

    text = caplog.text
    # O log registrou os eventos de verdade: o teste não passa por log vazio
    assert "frame adulterado" in text and "replay" in text and "handshake de alice" in text

    for label, secret in secrets.items():
        for form in forms(secret):
            assert form not in text, f"{label} apareceu no log"
    for plaintext in PLAINTEXTS:
        assert plaintext not in text, "texto de mensagem apareceu no log"
    key_pem = identity[0].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
    assert key_pem.splitlines()[1] not in text, "chave privada RSA apareceu no log"
