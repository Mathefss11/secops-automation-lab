import socket

import pytest


class NetworkAccessError(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Every test runs offline: any attempt to open a connection fails loudly."""

    def refuse(*args, **kwargs):
        raise NetworkAccessError("tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
