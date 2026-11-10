import asyncio
import logging
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path
from queue import Queue
from threading import Event
from unittest.mock import AsyncMock, Mock

import pytest
from helpers import connect, next_frame, process, running_server

import client.client as cli
from common.config import ClientConfig
from common.framing import FrameError
from common.protocol import MAX_PLAINTEXT_LEN


@pytest.mark.parametrize(("line", "expected"), [
    ("/peers", ("/peers", "", "")),
    ("  /quit  ", ("/quit", "", "")),
    ("/msg bob olá mundo", ("/msg", "bob", "olá mundo")),
    (" /msg\tbob  dois   espaços  ", ("/msg", "bob", "dois   espaços")),
    ("", ("/help", "", "")),
    ("/msg", ("/help", "", "")),
    ("/msg bob   ", ("/help", "", "")),
    ("/peers extra", ("/help", "", "")),
    ("/quit extra", ("/help", "", "")),
    ("/desconhecido", ("/help", "", "")),
    ("texto sem comando", ("/help", "", "")),
])
def test_parse_command(line, expected):
    assert cli.parse_command(line) == expected


def scripted_input(monkeypatch, lines):
    lines = iter(lines)

    def read(stopped):
        try:
            return next(lines)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(cli, "_terminal_input", read)


async def test_commands_list_send_help_and_quit(identity, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        bob = await connect(port, identity[1], "bob")
        try:
            await process(alice, 1)
            await process(bob, 1)
            scripted_input(monkeypatch, ["/peers", "/msg", "/msg bob mensagem privada", "/quit"])
            await asyncio.wait_for(cli.read_commands(alice.client, alice.writer, Event()), 2)
            message = bob.client.handle_frame(await next_frame(bob))
            assert message == cli.ChatMessage("alice", "mensagem privada")
            output = capsys.readouterr().out
            assert bob.client.name in output
            assert str(uuid.UUID(bytes=bob.client.client_id)) in output
            assert output.count(cli.HELP) == 2
            assert "mensagem privada" not in caplog.text
        finally:
            await alice.close()
            await bob.close()


async def test_send_errors_keep_commands_open(identity, monkeypatch, capsys):
    client = cli.ChatClient(identity[1], "alice", uuid.uuid4().bytes)
    writer = Mock(drain=AsyncMock())
    # Cada falha deve voltar à leitura; /peers comprova que o chat continua aberto.
    scripted_input(monkeypatch, ["/msg ausente oi", "/peers", "/quit"])
    await cli.read_commands(client, writer, Event())
    output = capsys.readouterr().out
    assert "Não foi possível enviar" in output
    assert "Nenhum participante" in output
    writer.write.assert_not_called()


async def test_long_message_then_valid_message(identity, monkeypatch, capsys):
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        bob = await connect(port, identity[1], "bob")
        try:
            await process(alice, 1)
            await process(bob, 1)
            scripted_input(monkeypatch, [f"/msg bob {'x' * (MAX_PLAINTEXT_LEN + 1)}", "/msg bob ok", "/quit"])
            await cli.read_commands(alice.client, alice.writer, Event())
            assert "excede o limite" in capsys.readouterr().out
            assert bob.client.handle_frame(await next_frame(bob)) == cli.ChatMessage("alice", "ok")
        finally:
            await alice.close()
            await bob.close()


async def test_input_eof(monkeypatch, identity):
    scripted_input(monkeypatch, [])
    writer = Mock(drain=AsyncMock())
    await cli.read_commands(cli.ChatClient(identity[1], "alice", uuid.uuid4().bytes), writer, Event())
    writer.write.assert_not_called()


async def test_received_text_only_on_screen(monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    client = Mock(handle_frame=Mock(return_value=cli.ChatMessage("bob", "segredo recebido")))
    monkeypatch.setattr(cli, "read_frame", AsyncMock(side_effect=[object(), None]))
    await cli.receive_messages(client, Mock())
    assert "[bob] segredo recebido" in capsys.readouterr().out
    assert "segredo recebido" not in caplog.text


async def test_receives_while_waiting_for_keyboard(identity, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    lines = Queue()
    monkeypatch.setattr("builtins.input", lines.get)
    received = asyncio.Event()
    original_print = print

    def show(*args, **kwargs):
        original_print(*args, **kwargs)
        if args == ("[bob] chegou durante a espera",):
            received.set()

    monkeypatch.setattr("builtins.print", show)
    async with running_server(identity) as (_, port):
        alice = await connect(port, identity[1], "alice")
        bob = await connect(port, identity[1], "bob")
        task = None
        try:
            await process(alice, 1)
            await process(bob, 1)
            task = asyncio.create_task(cli.chat(alice.client, alice.reader, alice.writer))
            bob.writer.write(bob.client.encrypt("alice", "chegou durante a espera"))
            await bob.writer.drain()
            await asyncio.wait_for(received.wait(), 2)
            assert not task.done()
            lines.put("/quit")
            await asyncio.wait_for(task, 2)
            assert "[bob] chegou durante a espera" in capsys.readouterr().out
            assert "chegou durante a espera" not in caplog.text
        finally:
            lines.put("/quit")
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await alice.close()
            await bob.close()


@pytest.mark.parametrize("ending", ["quit", "eof", "server", "frame_error", "connection_error", "cancel"])
async def test_run_closes_and_cancels_other_task(ending, identity, monkeypatch):
    writer = Mock(wait_closed=AsyncMock())
    monkeypatch.setattr(cli.crypto, "load_certificate", Mock(return_value=identity[1]))
    monkeypatch.setattr(cli.ChatClient, "handshake", AsyncMock())
    monkeypatch.setattr(cli.asyncio, "open_connection", AsyncMock(return_value=(Mock(), writer)))
    started = asyncio.Event()
    cancelled = asyncio.Event()
    stop_events = []

    async def commands(client, writer, stopped):
        stop_events.append(stopped)
        if ending in ("quit", "eof"):
            await started.wait()
            return
        started.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    async def receive(client, reader):
        if ending in ("quit", "eof", "cancel"):
            started.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
        await started.wait()
        if ending == "frame_error":
            raise FrameError("tamanho inválido")
        if ending == "connection_error":
            raise ConnectionResetError

    monkeypatch.setattr(cli, "read_commands", commands)
    monkeypatch.setattr(cli, "receive_messages", receive)
    config = ClientConfig("127.0.0.1", 9000, Path("unused.crt"), "INFO")
    task = asyncio.create_task(cli.run(config, "alice", uuid.uuid4()))
    if ending == "cancel":
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await asyncio.wait_for(task, 2)
    assert cancelled.is_set()
    assert stop_events[0].is_set()
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


def test_process_exits_with_input_still_blocked():
    # stdin permanece ABERTO e sem Enter. Testar só a coroutine ocultaria o
    # travamento no shutdown_default_executor() executado por asyncio.run().
    code = textwrap.dedent('''
        import asyncio
        import builtins
        from functools import partial
        from threading import Event
        from client.client import _terminal_input

        original_input = builtins.input
        reading = Event()
        def blocked_input():
            reading.set()
            return original_input()
        builtins.input = blocked_input

        async def main():
            stopped = Event()
            task = asyncio.create_task(asyncio.to_thread(partial(_terminal_input, stopped)))
            while not reading.is_set():
                await asyncio.sleep(0.01)
            print("aguardando teclado", flush=True)
            stopped.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        asyncio.run(main())
        print("encerrado", flush=True)
        # Mesmo caminho do main() do cliente; sem ele o Python 3.10 aborta na finalização
        from client.client import finish
        finish()
    ''')
    process = subprocess.Popen(
        [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        process.wait(timeout=10)
        out, err = process.communicate(timeout=2)
        assert process.returncode == 0, err
        assert "aguardando teclado" in out
        assert "encerrado" in out
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


@pytest.mark.parametrize("error", [EOFError, OSError])
def test_terminal_input_handles_closed_stdin(monkeypatch, error):
    monkeypatch.setattr("builtins.input", Mock(side_effect=error))
    with pytest.raises(EOFError):
        cli._terminal_input(Event())


def test_terminal_input_does_not_start_after_stop(monkeypatch):
    input_mock = Mock()
    monkeypatch.setattr("builtins.input", input_mock)
    stopped = Event()
    stopped.set()
    with pytest.raises(EOFError):
        cli._terminal_input(stopped)
    input_mock.assert_not_called()
