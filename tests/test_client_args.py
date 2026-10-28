import sys
import uuid

import pytest

from client.client import parse_args
from common.config import ClientConfig


@pytest.fixture
def config(tmp_path):
    return ClientConfig(host="127.0.0.1", port=9000, pinned_cert_path=tmp_path / "server.crt", log_level="INFO")


def run_parse(monkeypatch, config, *argv):
    monkeypatch.setattr(sys, "argv", ["client", *argv])
    return parse_args(config)


def test_generates_new_uuid4_each_run(monkeypatch, config):
    _, _, id1 = run_parse(monkeypatch, config, "--name", "alice")
    _, _, id2 = run_parse(monkeypatch, config, "--name", "alice")
    assert id1.version == 4 and id1 != id2


def test_reuses_given_id(monkeypatch, config):
    given = uuid.uuid4()
    _, name, client_id = run_parse(monkeypatch, config, "--name", "alice", "--id", str(given))
    assert (name, client_id) == ("alice", given)


@pytest.mark.parametrize("argv", [
    ["--name", "com espaço"],
    ["--name", "a" * 33],
    ["--name", "alice", "--id", "nao-e-uuid"],
    ["--name", "alice", "--id", str(uuid.uuid1())],  # UUID válido, mas não v4
])
def test_rejects_invalid_args(monkeypatch, config, argv):
    with pytest.raises(SystemExit):
        run_parse(monkeypatch, config, *argv)
