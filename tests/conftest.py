from __future__ import annotations

import pytest

from tests.simulators import servers


@pytest.fixture
def controller_port():
    server = servers.http_server(servers.DanfossHandler)
    port = servers.start(server)
    yield port
    server.shutdown()
    server.server_close()


@pytest.fixture
def printer_port():
    server = servers.http_server(servers.PlainHandler)
    port = servers.start(server)
    yield port
    server.shutdown()
    server.server_close()


@pytest.fixture
def modbus_port():
    server = servers.tcp_listener()
    port = servers.start(server)
    yield port
    server.shutdown()
    server.server_close()


@pytest.fixture
def gateway(controller_port):
    """Fake router forwarding public port 8081 to the fake controller."""
    handler = servers.make_igd_handler(
        [
            {
                "external_port": 8081,
                "internal_port": controller_port,
                "internal_ip": "127.0.0.1",
                "description": "frigo",
            },
            {"external_port": 3389, "internal_port": 3389, "internal_ip": "192.168.1.50"},
        ],
        wan_ip="93.184.216.34",
    )
    server = servers.http_server(handler)
    port = servers.start(server)
    yield f"http://127.0.0.1:{port}/desc.xml"
    server.shutdown()
    server.server_close()
